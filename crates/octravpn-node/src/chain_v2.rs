//! Chain integration for the node daemon (v2 / Circle-native).
//!
//! This module mirrors `chain.rs` but talks to `program/main-v2.aml`.
//! v2 swaps "operator = wallet" for "operator = Circle":
//!
//!   1. The operator wallet **deploys a circle** by submitting a tx with
//!      `op_type="deploy_circle"`. The deployed `circle_id` is the
//!      base58 prefix derived deterministically from
//!      `(deployer, nonce, deploy_payload)` — see
//!      `octra_core::circle::circle_id_of_deploy`.
//!   2. The wallet **uploads the policy bundle** (endpoint URL, WG
//!      pubkey, region, prices, attestation timestamp) into the circle
//!      as a sealed asset at `/policy.json`. The encryption uses the
//!      per-tailnet shared passphrase via
//!      `encrypt_sealed_bytes(circle_id, "default", passphrase, ...)`.
//!   3. The wallet **registers + bonds atomically** by calling
//!      `register_circle(circle, region, price_shared, price_internal,
//!      receipt_pk_b64, hfhe_pk, hfhe_zero_ct)` against the v2 program
//!      with `value = min_circle_stake`. v2's payable register avoids
//!      the v1.1 chicken-and-egg where bond required an owner that
//!      only register set.
//!   4. **Settlement** uses the same `settle_claim(session_id, bytes)`
//!      method on v2 — only the caller-vs-owner check differs: v2
//!      enforces caller == circles[c].owner, so the wallet that
//!      deployed the circle is the one that must submit settle_claim.
//!
//! Things NOT here:
//!   * The operator-circle inner program (`program/operator-circle.aml`)
//!     is design-only for now and isn't deployed by this code.
//!   * HFHE keys are placeholder strings — same as v1.1 — until
//!     `libpvac` bindings land.
//!   * The v2 program's tailnet / open_session / settle_confirm
//!     surface is exercised by the **client**, not by us.

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    address::Address,
    circle::{
        canonical_payload_json, circle_id_of_deploy, encrypt_sealed_bytes, resource_key,
        CircleDeployPayload, PaddingClass,
    },
    rpc::RpcClient,
    sig::KeyPair,
    tx as octra_tx,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::debug;

/// Path inside the circle where we store the encrypted operator
/// policy bundle. Constant so clients know where to look.
pub(crate) const POLICY_ASSET_PATH: &str = "/policy.json";

/// Key id we tag the sealed asset with. Single-key per circle today.
/// Bumping this requires re-uploading the asset under a new key.
pub(crate) const POLICY_KEY_ID: &str = "default";

/// Default fee in OU for a `deploy_circle` tx. Matches the webcli
/// default.
const DEPLOY_CIRCLE_FEE_DEFAULT: u64 = 200_000;

/// Default fee in OU for a sealed-asset put tx. Matches the webcli
/// default.
const ASSET_PUT_FEE_DEFAULT: u64 = 5_000;

/// MIN_CIRCLE_STAKE default in OU. Mirrors the v2 AML constructor
/// requirement `min_circle_stake >= 100_000_000 OU`. Stored locally so
/// the daemon can fail fast before submitting a register tx that would
/// revert.
pub(crate) const MIN_CIRCLE_STAKE_DEFAULT: u64 = 1_000_000_000;

/// All v2 chain interactions. Owns the same RPC + wallet primitives
/// as `ChainCtx` (v1.1), but talks to the v2 program and the circle
/// surface. Keep this struct local to the v2 code path so legacy v1.1
/// flows stay unaffected.
pub(crate) struct ChainCtxV2 {
    pub rpc: RpcClient,
    /// v2 main program (the slim registry — `program/main-v2.aml`).
    pub program_addr: Address,
    /// Operator wallet address (becomes `circles[c].owner`).
    pub wallet_addr: Address,
    pub wallet: KeyPair,
    /// v2 tx-envelope chain-id binding (P1-5b). See `ChainCtx::chain_id`.
    /// Empty ⇒ v1 wallet-compat signing.
    pub chain_id: String,
}

impl ChainCtxV2 {
    /// v1-shape constructor (no chain-id binding). Retained for the
    /// in-tree test fixtures + symmetry with `ChainCtxV3::new`;
    /// production boot routes through `new_with_chain_id`.
    #[allow(dead_code)]
    pub(crate) fn new(rpc: RpcClient, program_addr: Address, wallet: KeyPair) -> Self {
        Self::new_with_chain_id(rpc, program_addr, wallet, String::new())
    }

    /// Variant of [`new`] that pins a v2 chain-id binding for every tx
    /// signed by this context. Mainnet boots pass `"octra-mainnet"`;
    /// devnet boots pass `"octra-devnet"`. Empty string ⇒ legacy v1
    /// (wallet-compat) signing.
    pub(crate) fn new_with_chain_id(
        rpc: RpcClient,
        program_addr: Address,
        wallet: KeyPair,
        chain_id: String,
    ) -> Self {
        let wallet_addr = Address::from_pubkey(&wallet.public.0);
        Self {
            rpc,
            program_addr,
            wallet_addr,
            wallet,
            chain_id,
        }
    }

    pub(crate) async fn nonce(&self) -> Result<u64> {
        let b = self.rpc.balance(&self.wallet_addr).await?;
        // Matches v1.1's convention (see `ChainCtx::nonce`): the
        // existing OctraVPN code treats `pending_nonce` as the next
        // available nonce (so `.max(nonce)` returns the value to use
        // for the next tx). The real Octra devnet sometimes ships
        // pending_nonce = nonce + N_in_flight; the in-process mock
        // returns pending_nonce already pointing at the next slot.
        // Either way, `.max(nonce)` is the value to use.
        Ok(b.pending_nonce.max(b.nonce))
    }

    pub(crate) async fn fee(&self, op: &str) -> Result<u64> {
        let f = self.rpc.recommended_fee(Some(op)).await?;
        Ok(f.recommended)
    }

    /// Predict the circle_id that `deploy_circle` with this nonce
    /// would yield. Pure: no chain hit.
    pub(crate) fn predict_circle_id(&self, nonce: u64, payload: &CircleDeployPayload) -> String {
        circle_id_of_deploy(self.wallet_addr.display(), nonce, payload)
    }

    /// Resource key for the policy asset inside the circle. Clients
    /// fetch by `circle_asset_ciphertext_by_resource_key` so the path
    /// (`/policy.json`) is hidden from the chain observer.
    #[allow(clippy::unused_self)] // method form is more ergonomic at call sites
    pub(crate) fn policy_resource_key(&self, circle_id: &str) -> String {
        resource_key(circle_id, POLICY_ASSET_PATH)
    }

    /// Check whether the circle has already been registered on chain.
    /// Returns true iff `circles[circle].active == 1`. The v2 program
    /// exposes the registry status via `get_circle(circle)`.
    pub(crate) async fn is_circle_registered(&self, circle_id: &str) -> Result<bool> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "get_circle",
                &[json!(circle_id)],
                Some(&self.wallet_addr),
            )
            .await
            .context("get_circle")?;
        // The v2 view returns `bool`. Devnet wraps it; the RPC
        // wrapper already strips the envelope.
        Ok(v.as_bool().unwrap_or(false))
    }

    /// Check whether the circle has been (permanently) slashed.
    pub(crate) async fn is_circle_slashed(&self, circle_id: &str) -> Result<bool> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "is_circle_slashed",
                &[json!(circle_id)],
                Some(&self.wallet_addr),
            )
            .await
            .context("is_circle_slashed")?;
        Ok(v.as_bool().unwrap_or(false))
    }

    /// Whether the chain reports the circle is known via `circle_info`
    /// (deployed but not necessarily registered with the v2 registry).
    /// Used during boot so we can tell "circle exists, just needs
    /// register_circle" apart from "deploy_circle still required".
    ///
    /// Best-effort: real devnet returns a JSON object with circle
    /// metadata; the in-process mock RPC may return null. Any non-null
    /// non-error response is treated as "deployed".
    pub(crate) async fn is_circle_deployed(&self, circle_id: &str) -> Result<bool> {
        match self.rpc.raw_call("circle_info", json!([circle_id])).await {
            Ok(v) => Ok(!v.is_null()),
            Err(e) => {
                debug!(error = %e, %circle_id, "circle_info failed; assuming not deployed");
                Ok(false)
            }
        }
    }

    /// Build a `deploy_circle` envelope. The tx carries the canonical
    /// JSON payload as `message`; the wallet signs the standard
    /// canonical bytes via `sign_call`.
    pub(crate) fn build_deploy_circle_tx(
        &self,
        payload: &CircleDeployPayload,
        circle_id: &str,
        nonce: u64,
        fee: u64,
    ) -> Value {
        let message = canonical_payload_json(payload);
        json!({
            "from": self.wallet_addr.display(),
            "to_": circle_id,
            "amount": "0",
            "nonce": nonce,
            "ou": fee.to_string(),
            "timestamp": current_timestamp_f64(),
            "op_type": "deploy_circle",
            "message": message,
        })
    }

    /// Build a `circle_asset_put_encrypted` envelope. Encrypts the
    /// plaintext under the sealed-asset scheme (PBKDF2 + AES-GCM) using
    /// the per-tailnet passphrase and emits the tx the chain expects.
    pub(crate) fn build_put_encrypted_tx(
        &self,
        circle_id: &str,
        path: &str,
        plaintext: &[u8],
        passphrase: &str,
        nonce: u64,
        fee: u64,
    ) -> Result<PutEncryptedTx> {
        let (ciphertext_b64, plaintext_hash) = encrypt_sealed_bytes(
            circle_id,
            POLICY_KEY_ID,
            passphrase,
            plaintext,
            PaddingClass::None,
        )?;
        let payload = json!({
            "path": path,
            "content_type": "application/json",
            "key_id": POLICY_KEY_ID,
            "plaintext_hash": &plaintext_hash,
        });
        let tx = json!({
            "from": self.wallet_addr.display(),
            "to_": circle_id,
            "amount": "0",
            "nonce": nonce,
            "ou": fee.to_string(),
            "timestamp": current_timestamp_f64(),
            "op_type": "circle_asset_put_encrypted",
            "encrypted_data": ciphertext_b64,
            "message": payload.to_string(),
        });
        Ok(PutEncryptedTx { tx, plaintext_hash })
    }

    /// Build the `register_circle` contract-call. Payable: `value`
    /// becomes the initial bond. The v2 AML enforces
    /// `value + circle_stake[circle] >= min_circle_stake` so we always
    /// pass at least MIN_CIRCLE_STAKE here.
    pub(crate) fn build_register_circle_call(&self, p: &RegisterCircleParams<'_>) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.wallet_addr.display(),
            "to": self.program_addr.display(),
            "method": "register_circle",
            "params": [
                p.circle_id,
                p.region,
                p.price_per_mb_shared,
                p.price_per_mb_internal,
                p.receipt_pubkey_b64,
                p.op_pk_hfhe,
                p.op_zero_ct_hfhe,
            ],
            "value": p.stake_amount,
            "fee": p.fee,
            "nonce": p.nonce,
        })
    }

    /// Build a `bond_endpoint(circle)` top-up. Used after the initial
    /// atomic register+bond if the operator wants to add more stake.
    /// Not yet wired to a CLI subcommand (a future `Cmd::BondV2` will);
    /// kept here so the path is in one module.
    #[allow(dead_code)]
    pub(crate) fn build_bond_circle_call(
        &self,
        circle_id: &str,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.wallet_addr.display(),
            "to": self.program_addr.display(),
            "method": "bond_endpoint",
            "params": [circle_id],
            "value": amount,
            "fee": fee,
            "nonce": nonce,
        })
    }

    /// Build a `settle_claim(session_id, bytes_used)` against the v2
    /// program. v2 enforces caller == circle.owner, but the wire shape
    /// is identical to v1.1.
    pub(crate) fn build_settle_claim_call(
        &self,
        session_id: u64,
        bytes_used: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.wallet_addr.display(),
            "to": self.program_addr.display(),
            "method": "settle_claim",
            "params": [session_id, bytes_used],
            "value": 0,
            "fee": fee,
            "nonce": nonce,
        })
    }

    /// Sign whatever `Value` we just built using the operator wallet
    /// key. Same `sign_call` the v1.1 path uses — translates legacy
    /// `kind:contract_call` shape to the on-the-wire OctraTx envelope.
    pub(crate) fn sign_call(&self, mut call: Value) -> Result<Value> {
        // v2 chain-id binding (P1-5b). Splice the configured chain id
        // into the canonical envelope before signing so the signature
        // commits to the chain. Empty string ⇒ skip (v1 compat).
        if !self.chain_id.is_empty() {
            if let Some(obj) = call.as_object_mut() {
                obj.entry("chain_id")
                    .or_insert_with(|| json!(self.chain_id.clone()));
            }
        }
        octra_tx::sign_call(&self.wallet, call).map_err(|e| anyhow!("sign_call: {e}"))
    }

    /// Sign a pre-shaped OctraTx envelope (e.g. the deploy_circle /
    /// asset_put envelopes which already use `to_`, `amount`, `ou`,
    /// `op_type` and don't need legacy translation).
    pub(crate) fn sign_envelope(&self, mut env: Value) -> Result<Value> {
        if !self.chain_id.is_empty() {
            if let Some(obj) = env.as_object_mut() {
                obj.entry("chain_id")
                    .or_insert_with(|| json!(self.chain_id.clone()));
            }
        }
        octra_tx::sign_call(&self.wallet, env).map_err(|e| anyhow!("sign_envelope: {e}"))
    }

    pub(crate) async fn submit_signed_tx(&self, signed: &Value) -> Result<String> {
        let r = self.rpc.submit(signed).await?;
        debug!(hash = %r.hash, "submitted tx");
        Ok(r.hash)
    }
}

/// Inputs to `register_circle`. Borrowed so call sites don't have to
/// clone every slice.
pub(crate) struct RegisterCircleParams<'a> {
    pub circle_id: &'a str,
    pub region: &'a str,
    pub price_per_mb_shared: u64,
    pub price_per_mb_internal: u64,
    /// Base64-encoded Ed25519 receipt pubkey. v2 AML's `ed25519_ok`
    /// decodes base64 natively (not hex).
    pub receipt_pubkey_b64: &'a str,
    pub op_pk_hfhe: &'a str,
    pub op_zero_ct_hfhe: &'a str,
    pub stake_amount: u64,
    pub fee: u64,
    pub nonce: u64,
}

/// Output of `build_put_encrypted_tx`: the unsigned tx plus the
/// plaintext hash hex we need to mirror into the in-circle policy
/// pointer (and that we cache for cross-restart consistency).
pub(crate) struct PutEncryptedTx {
    pub tx: Value,
    pub plaintext_hash: String,
}

/// Default fee for `deploy_circle` if the RPC's recommended-fee gives
/// us nothing useful (zero / unreachable).
pub(crate) fn deploy_circle_fee_fallback() -> u64 {
    DEPLOY_CIRCLE_FEE_DEFAULT
}

/// Default fee for `circle_asset_put_encrypted` similarly.
pub(crate) fn asset_put_fee_fallback() -> u64 {
    ASSET_PUT_FEE_DEFAULT
}

// ============================================================
// Local circle-id cache (state/<role>/circle.toml)
// ============================================================

/// Persisted record of "this is the circle this operator deployed".
///
/// Written after a successful boot so we don't have to re-derive the
/// circle_id (which depends on the deploy nonce — a value that changes
/// every time the wallet sends a tx) on every restart.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CircleState {
    /// The `oct…` circle id we deployed against. Derived from
    /// (wallet, deploy_nonce, deploy_payload).
    pub circle_id: String,
    /// Nonce that was used for the deploy_circle tx — recorded for
    /// audit and to let operators re-run `circle_id_of_deploy` and
    /// sanity-check the id.
    pub deploy_nonce: u64,
    /// Tx hash of the deploy_circle submission. Empty until that tx is
    /// recorded.
    #[serde(default)]
    pub deploy_tx_hash: String,
    /// Tx hash of the most recent put-encrypted policy upload.
    #[serde(default)]
    pub policy_tx_hash: String,
    /// Tx hash of the register_circle submission.
    #[serde(default)]
    pub register_tx_hash: String,
    /// Hex-encoded sha256 of the policy plaintext we uploaded; used to
    /// detect drift (e.g. the operator changed pricing on disk but
    /// didn't reupload).
    #[serde(default)]
    pub policy_plaintext_hash: String,
}

impl CircleState {
    pub(crate) fn load(path: &std::path::Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read circle state {}", path.display()))?;
        let s: Self = toml::from_str(&raw)
            .with_context(|| format!("parse circle state {}", path.display()))?;
        Ok(Some(s))
    }

    pub(crate) fn save(&self, path: &std::path::Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        let raw = toml::to_string_pretty(self).context("serialize circle state")?;
        std::fs::write(path, raw)
            .with_context(|| format!("write circle state {}", path.display()))?;
        Ok(())
    }
}

/// What goes into `/policy.json` inside the circle. Clients decrypt
/// this with the per-tailnet shared passphrase and use it to build
/// their WireGuard config + onion handshake.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PolicyBundle {
    /// `host:port` the client dials.
    pub endpoint: String,
    /// X25519 noise pubkey (hex; the client wraps onion layers with this).
    pub wg_pubkey_hex: String,
    /// e.g. "eu-west".
    pub region: String,
    pub price_per_mb_shared: u64,
    pub price_per_mb_internal: u64,
    /// Unix-seconds. So clients can detect a stale policy bundle.
    pub attestation_ts: u64,
    /// Ed25519 attestation pubkey (base64). Mirrors what the operator
    /// stores in the on-chain CircleRecord.receipt_pubkey.
    pub receipt_pubkey_b64: String,
    /// Placeholder HFHE pubkey (same one stored on chain). Until
    /// libpvac lands, this is a deterministic string for parity.
    pub hfhe_pubkey: String,
    /// Free-form schema version so future operators can extend without
    /// breaking older clients.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
}

fn default_schema_version() -> u32 {
    1
}

/// Wall-clock seconds-since-epoch as f64. Mirrors the wire-format
/// `timestamp` Python `time.time()` produces.
fn current_timestamp_f64() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

impl PolicyBundle {
    pub(crate) fn to_json_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("serialize policy bundle")
    }
}
