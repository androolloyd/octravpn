//! Chain integration for the node daemon (v3 / chain-minimal).
//!
//! Sibling to `chain.rs` (v1.1) and `chain_v2.rs` (v2 Circle-native).
//! This module talks to `program/main-v3.aml`, the "chain-minimal,
//! circle-resident" registry deployed on devnet at
//! `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`.
//!
//! v3's chain surface is intentionally narrow:
//!
//!   * The circle registry stores ONLY:
//!       - `circle_owner` (the wallet that registered)
//!       - `circle_receipt_pk` (base64 ed25519 pubkey for slash)
//!       - `circle_state_root` (64-char hex sha256 anchor — see
//!         `octravpn_core::v3_state_root::StateRoot`)
//!       - bond / unbond / slash bookkeeping
//!   * Policy, WG pubkey, region, member count, etc. live in the
//!     operator's circle as a sealed `state-root.json`. The chain
//!     never decodes it; integrity is enforced by a verifier fetching
//!     the JSON, recomputing sha256, and comparing against the
//!     on-chain anchor.
//!   * No HFHE. Earnings are tracked as a plaintext running total +
//!     a sha256 hash chain seeded by `sha256(state_root)`.
//!
//! Each `build_*` method here returns the legacy
//! `{"kind":"contract_call",...}` shape that `octra_core::tx::sign_call`
//! translates to the on-wire OctraTx envelope. The JSON envelope
//! construction itself lives in [`octravpn_core::v3_calls`] so the
//! client crate gets the same shape verbatim; each `build_*_call`
//! wrapper below simply forwards its inputs to the shared builder.
//! Method names + param ordering mirror the JSON shape sent by
//! `docker/devnet/v3-smoke.sh` and `docker/devnet/e2e-adversarial-v3.sh`
//! so a unit test can cross-check the wire bytes against the shell
//! harness without re-implementing the cast tool here.

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    address::Address, rpc::RpcClient, sig::KeyPair, tx as octra_tx, v3_calls::ContractCallBuilder,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::debug;

/// `min_circle_stake` floor enforced by the v3 program's constructor
/// (`require(min_circle_stake >= 100_000_000)`). Stored locally so the
/// daemon can fail fast before submitting a register tx that would
/// revert. Mirrors `chain_v2::MIN_CIRCLE_STAKE_DEFAULT`.
pub(crate) const MIN_CIRCLE_STAKE_DEFAULT: u64 = 1_000_000_000;

/// Default contract-call fee fallback when the chain's
/// `octra_recommendedFee` returns 0 / unreachable for an unknown op
/// type. Matches the value the v2 path uses for the same situation.
pub(crate) const CALL_FEE_FALLBACK: u64 = 1_000;

/// All v3 chain interactions. Holds the same RPC + wallet primitives
/// as `ChainCtx` / `ChainCtxV2`, but talks exclusively to the v3
/// program. Keep this struct local to the v3 code path so legacy
/// v1.1 and v2 flows stay unaffected.
///
/// Most `build_*` methods are not yet called from the boot path
/// (rotate / retire / unbond / slash / tailnet / open_session /
/// settle_confirm / claim_no_show / sweep / claim_earnings are
/// follow-up CLI subcommands or client-side flows). They live here so
/// the full v3 surface is in one module and tests can cross-check
/// wire shapes against `e2e-adversarial-v3.sh` without re-implementing
/// the cast tool.
pub(crate) struct ChainCtxV3 {
    pub rpc: RpcClient,
    /// v3 main program address — `program/main-v3.aml` deployment.
    pub program_addr: Address,
    /// Operator wallet address. Becomes `circle_owner[circle]` once
    /// `register_circle` lands.
    pub wallet_addr: Address,
    pub wallet: KeyPair,
}

// The v3 surface is wider than the boot-flow's immediate consumers
// because we want the full entrypoint set in one module for ease of
// review + cross-reference against `e2e-adversarial-v3.sh`. The methods
// below are exercised by unit tests; production call sites for the
// non-boot entrypoints land in follow-up CLI subcommands. Allow dead
// code on the whole impl rather than tagging every method individually.
#[allow(dead_code)]
impl ChainCtxV3 {
    pub(crate) fn new(rpc: RpcClient, program_addr: Address, wallet: KeyPair) -> Self {
        let wallet_addr = Address::from_pubkey(&wallet.public.0);
        Self {
            rpc,
            program_addr,
            wallet_addr,
            wallet,
        }
    }

    /// Construct the shared `ContractCallBuilder` bound to this
    /// daemon's program addr + wallet addr. All `build_*_call`
    /// methods below delegate through this so the JSON wire shape is
    /// owned by `octravpn_core::v3_calls` rather than re-hand-rolled
    /// here.
    fn call_builder(&self) -> ContractCallBuilder {
        ContractCallBuilder::new(self.program_addr.clone(), self.wallet_addr.clone())
    }

    pub(crate) async fn nonce(&self) -> Result<u64> {
        let b = self.rpc.balance(&self.wallet_addr).await?;
        Ok(b.pending_nonce.max(b.nonce))
    }

    pub(crate) async fn fee(&self, op: &str) -> Result<u64> {
        let f = self.rpc.recommended_fee(Some(op)).await?;
        Ok(f.recommended)
    }

    /// Convenience: fee with fallback to `CALL_FEE_FALLBACK` if the
    /// chain returns 0 / errors. The v2 path uses the same logic
    /// inline; v3 routes through this helper so the unit tests can
    /// assert the same fallback semantics without re-running RPC.
    pub(crate) async fn fee_or_fallback(&self, op: &str) -> u64 {
        self.fee(op)
            .await
            .ok()
            .filter(|f| *f > 0)
            .unwrap_or(CALL_FEE_FALLBACK)
    }

    /// Current chain epoch (used by the v3 boot flow to stamp the
    /// `epoch` field of `state-root.json`). Falls back to 0 if
    /// `node_status` is unreachable — the v3 state-root schema treats
    /// `epoch` as informational, not a hard reject condition.
    pub(crate) async fn current_epoch(&self) -> Result<u64> {
        let s = self.rpc.node_status().await?;
        Ok(s.epoch)
    }

    // ============================================================
    // Views
    // ============================================================

    /// `get_circle_active(circle) -> bool` view. Returns true iff the
    /// circle is registered AND not retired. The v3 program exposes
    /// this view via `get_circle_active`.
    pub(crate) async fn get_circle_active(&self, circle: &str) -> Result<bool> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "get_circle_active",
                &[json!(circle)],
                Some(&self.wallet_addr),
            )
            .await
            .context("get_circle_active")?;
        Ok(v.as_bool().unwrap_or(false))
    }

    /// `is_circle_slashed(circle) -> bool` view.
    pub(crate) async fn is_circle_slashed(&self, circle: &str) -> Result<bool> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "is_circle_slashed",
                &[json!(circle)],
                Some(&self.wallet_addr),
            )
            .await
            .context("is_circle_slashed")?;
        Ok(v.as_bool().unwrap_or(false))
    }

    /// `get_circle_state_root(circle) -> bytes` (64-char hex). Returns
    /// `None` when the chain reports a zero / unset value (the AML
    /// `bytes` default is the literal string `"0"`, not the empty
    /// string — we treat both as "no anchor yet").
    pub(crate) async fn get_circle_state_root(&self, circle: &str) -> Result<Option<String>> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "get_circle_state_root",
                &[json!(circle)],
                Some(&self.wallet_addr),
            )
            .await
            .context("get_circle_state_root")?;
        let s = v.as_str().unwrap_or("").to_string();
        if s.is_empty() || s == "0" {
            return Ok(None);
        }
        Ok(Some(s))
    }

    /// `get_circle_state_version(circle) -> int` view.
    #[allow(dead_code)]
    pub(crate) async fn get_circle_state_version(&self, circle: &str) -> Result<u64> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "get_circle_state_version",
                &[json!(circle)],
                Some(&self.wallet_addr),
            )
            .await
            .context("get_circle_state_version")?;
        Ok(v.as_u64().unwrap_or(0))
    }

    /// `endpoint_stake_of(circle) -> int` view (current bonded stake).
    #[allow(dead_code)]
    pub(crate) async fn endpoint_stake_of(&self, circle: &str) -> Result<u64> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "endpoint_stake_of",
                &[json!(circle)],
                Some(&self.wallet_addr),
            )
            .await
            .context("endpoint_stake_of")?;
        Ok(v.as_u64().unwrap_or(0))
    }

    // ============================================================
    // Circle registry — register / update / rotate / retire
    // ============================================================

    /// `payable register_circle(circle, state_root, receipt_pubkey)` —
    /// atomic register + bond. `state_root` is the 64-char hex sha256
    /// of `oct://<circle>/state-root.json` (produced via
    /// `octravpn_core::v3_state_root::StateRoot::anchor_hex`).
    /// `receipt_pubkey` is the base64-encoded ed25519 pubkey the chain
    /// uses to verify `slash_double_sign` signatures.
    pub(crate) fn build_register_circle_call(&self, p: &RegisterCircleParams<'_>) -> Value {
        self.call_builder().register_circle_call(
            &[
                json!(p.circle_id),
                json!(p.state_root_hex),
                json!(p.receipt_pubkey_b64),
            ],
            p.stake_amount,
            p.fee,
            p.nonce,
        )
    }

    /// `update_circle_state(circle, new_state_root)` — bump the on-chain
    /// anchor when the operator re-seals their `state-root.json` (policy
    /// change, attestation refresh, member-count update, …). The AML
    /// auto-increments `circle_state_version`. Caller MUST be
    /// `circle_owner[circle]`.
    pub(crate) fn build_update_circle_state_call(
        &self,
        circle_id: &str,
        new_state_root_hex: &str,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder().update_circle_state_call(
            &[json!(circle_id), json!(new_state_root_hex)],
            0,
            fee,
            nonce,
        )
    }

    /// `rotate_receipt_pubkey(circle, new_pubkey)` — swap the on-chain
    /// ed25519 pubkey used for `slash_double_sign`. The old pubkey is
    /// dropped; future witnesses must adopt the new key from this
    /// epoch on.
    pub(crate) fn build_rotate_receipt_pubkey_call(
        &self,
        circle_id: &str,
        new_pubkey_b64: &str,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder().rotate_receipt_pubkey_call(
            &[json!(circle_id), json!(new_pubkey_b64)],
            0,
            fee,
            nonce,
        )
    }

    /// `retire_circle(circle)` — flip `circle_active[circle] = 0`. The
    /// stake remains until `finalize_unbond` (assuming an `unbond`
    /// already ran). Caller MUST be `circle_owner[circle]`.
    pub(crate) fn build_retire_circle_call(&self, circle_id: &str, fee: u64, nonce: u64) -> Value {
        self.call_builder()
            .retire_circle_call(&[json!(circle_id)], 0, fee, nonce)
    }

    // ============================================================
    // Bond / unbond / finalize
    // ============================================================

    /// `payable bond_endpoint(circle)` — top-up stake after the initial
    /// `register_circle` bond. The full `value` is added to
    /// `circle_bond[circle]`. v3 enforces caller == circle_owner +
    /// !unbonding + !slashed.
    pub(crate) fn build_bond_endpoint_call(
        &self,
        circle_id: &str,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder()
            .bond_endpoint_call(&[json!(circle_id)], amount, fee, nonce)
    }

    /// `unbond_endpoint(circle)` — start the grace period. The full
    /// live stake moves to `circle_unbonding[circle]`; client-facing
    /// `circle_active` does NOT flip here (the operator can still
    /// `retire_circle` separately).
    pub(crate) fn build_unbond_endpoint_call(
        &self,
        circle_id: &str,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder()
            .unbond_endpoint_call(&[json!(circle_id)], 0, fee, nonce)
    }

    /// `nonreentrant finalize_unbond(circle)` — claim the unbonded
    /// stake once `epoch >= circle_unbond_unlock_epoch[circle]`.
    pub(crate) fn build_finalize_unbond_call(
        &self,
        circle_id: &str,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder()
            .finalize_unbond_call(&[json!(circle_id)], 0, fee, nonce)
    }

    // ============================================================
    // Slash
    // ============================================================

    /// `slash_double_sign(circle, payload_a, sig_a, payload_b, sig_b)`
    /// — slash a circle on producing two distinct signed payloads under
    /// the SAME `circle_receipt_pk[circle]`. Sigs are base64-encoded
    /// ed25519 over the raw payload bytes; the AML's `ed25519_ok`
    /// builtin decodes them natively.
    pub(crate) fn build_slash_double_sign_call(&self, p: &SlashDoubleSignParams<'_>) -> Value {
        self.call_builder().slash_double_sign_call(
            &[
                json!(p.circle_id),
                json!(p.payload_a),
                json!(p.sig_a_b64),
                json!(p.payload_b),
                json!(p.sig_b_b64),
            ],
            0,
            p.fee,
            p.nonce,
        )
    }

    // ============================================================
    // Tailnets (treasury + members-root commitment)
    // ============================================================

    /// `payable create_tailnet(members_root)` — register a new tailnet
    /// with a fresh on-chain id (the next `tailnet_count`). `members_root`
    /// is the 64-char hex sha256 of `oct://<owner-circle>/tailnet-{id}/members.json`.
    /// Returns the assigned id off-chain via the tx receipt; the
    /// operator boot path doesn't need to fetch it since the result is
    /// observable via the standard `octra_transaction` envelope.
    pub(crate) fn build_create_tailnet_call(
        &self,
        members_root_hex: &str,
        deposit: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder()
            .create_tailnet_call(&[json!(members_root_hex)], deposit, fee, nonce)
    }

    /// `update_members_root(tailnet_id, new_members_root)` — bump the
    /// tailnet's members root anchor after re-sealing `members.json`.
    pub(crate) fn build_update_members_root_call(
        &self,
        tailnet_id: u64,
        new_members_root_hex: &str,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder().update_members_root_call(
            &[json!(tailnet_id), json!(new_members_root_hex)],
            0,
            fee,
            nonce,
        )
    }

    /// `retire_tailnet(tailnet_id)` — flip `tailnet_retired = 1`.
    pub(crate) fn build_retire_tailnet_call(&self, tailnet_id: u64, fee: u64, nonce: u64) -> Value {
        self.call_builder()
            .retire_tailnet_call(&[json!(tailnet_id)], 0, fee, nonce)
    }

    /// `payable deposit_to_tailnet(tailnet_id)` — top up the tailnet
    /// treasury. Anyone can call; membership is enforced off-chain.
    pub(crate) fn build_deposit_to_tailnet_call(
        &self,
        tailnet_id: u64,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder()
            .deposit_to_tailnet_call(&[json!(tailnet_id)], amount, fee, nonce)
    }

    /// `withdraw_tailnet_treasury(tailnet_id, amount)` — owner-only
    /// withdrawal from a tailnet's treasury back to the tailnet owner's
    /// wallet. Mirrors the AML signature at `program/main-v3.aml:466`.
    pub(crate) fn build_withdraw_tailnet_treasury_call(
        &self,
        tailnet_id: u64,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder().withdraw_tailnet_treasury_call(
            &[json!(tailnet_id), json!(amount)],
            0,
            fee,
            nonce,
        )
    }

    // ============================================================
    // Sessions
    // ============================================================

    /// `open_session(tailnet_id, circle, max_pay) -> int`. The chain
    /// returns the assigned `session_id`; callers read it via
    /// `octra_transaction(hash)`.
    pub(crate) fn build_open_session_call(
        &self,
        tailnet_id: u64,
        circle_id: &str,
        max_pay: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder().open_session_call(
            &[json!(tailnet_id), json!(circle_id), json!(max_pay)],
            0,
            fee,
            nonce,
        )
    }

    /// `settle_claim(session_id, bytes_used)` — operator-side first
    /// half of the two-tx settle. The AML enforces caller ==
    /// `circle_owner[session_exit[sid]]` and refunds the session on
    /// equivocation (different `bytes_used` from a prior claim under
    /// the same sid).
    pub(crate) fn build_settle_claim_call(
        &self,
        session_id: u64,
        bytes_used: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder().settle_claim_call(
            &[json!(session_id), json!(bytes_used)],
            0,
            fee,
            nonce,
        )
    }

    /// `nonreentrant settle_confirm(session_id, bytes_used, net,
    /// settle_blinding)` — opener-side second half. `net` is the
    /// pre-agreed plaintext credit (price * bytes after class rules);
    /// `settle_blinding` is a per-session secret string fed into the
    /// earnings hash chain so auditors can detect tampering.
    pub(crate) fn build_settle_confirm_call(&self, p: &SettleConfirmParams<'_>) -> Value {
        self.call_builder().settle_confirm_call(
            &[
                json!(p.session_id),
                json!(p.bytes_used),
                json!(p.net),
                json!(p.settle_blinding),
            ],
            0,
            p.fee,
            p.nonce,
        )
    }

    /// `claim_no_show(session_id)` — opener-side abort path. Fires once
    /// `epoch >= opened_at + session_grace_epochs` and the operator
    /// hasn't called `settle_claim`. Refunds the deposit to the
    /// tailnet treasury.
    pub(crate) fn build_claim_no_show_call(&self, session_id: u64, fee: u64, nonce: u64) -> Value {
        self.call_builder()
            .claim_no_show_call(&[json!(session_id)], 0, fee, nonce)
    }

    /// `nonreentrant sweep_expired_session(session_id)` — any caller
    /// can sweep an OPEN session past `opened_at +
    /// session_grace_epochs * sweep_grace_multiplier`. Pays a
    /// `sweep_bounty_bps` bounty to the caller; the remainder refunds
    /// the tailnet.
    pub(crate) fn build_sweep_expired_session_call(
        &self,
        session_id: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder()
            .sweep_expired_session_call(&[json!(session_id)], 0, fee, nonce)
    }

    // ============================================================
    // Earnings
    // ============================================================

    /// `nonreentrant claim_earnings(circle, amount)` — pull `amount`
    /// OU from the v3 earnings ledger to the circle owner. Bounded by
    /// `circle_earnings_total - circle_earnings_claimed`. The chain
    /// auto-tracks `circle_earnings_claimed[circle]`; off-chain
    /// auditors verify the hash chain seeded by `sha256(state_root)`.
    pub(crate) fn build_claim_earnings_call(
        &self,
        circle_id: &str,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder()
            .claim_earnings_call(&[json!(circle_id), json!(amount)], 0, fee, nonce)
    }

    // ============================================================
    // Submit / sign
    // ============================================================

    /// Sign whatever `Value` we just built. Same `sign_call` the v1.1
    /// and v2 paths use — translates legacy `kind:contract_call`
    /// envelopes to the on-the-wire OctraTx shape.
    pub(crate) fn sign_call(&self, call: Value) -> Result<Value> {
        octra_tx::sign_call(&self.wallet, call).map_err(|e| anyhow!("sign_call: {e}"))
    }

    pub(crate) async fn submit_signed_tx(&self, signed: &Value) -> Result<String> {
        let r = self.rpc.submit(signed).await?;
        debug!(hash = %r.hash, "submitted tx (v3)");
        Ok(r.hash)
    }
}

// ============================================================
// Param structs — borrowed so call sites can reuse short-lived
// references without cloning. Mirrors the chain_v2 pattern.
// ============================================================

/// Inputs to `register_circle`.
pub(crate) struct RegisterCircleParams<'a> {
    pub circle_id: &'a str,
    /// 64-char lowercase hex sha256 of canonical `state-root.json`.
    pub state_root_hex: &'a str,
    /// Base64 ed25519 receipt pubkey (44 chars including padding).
    pub receipt_pubkey_b64: &'a str,
    pub stake_amount: u64,
    pub fee: u64,
    pub nonce: u64,
}

#[allow(dead_code)]
pub(crate) struct SlashDoubleSignParams<'a> {
    pub circle_id: &'a str,
    pub payload_a: &'a str,
    pub sig_a_b64: &'a str,
    pub payload_b: &'a str,
    pub sig_b_b64: &'a str,
    pub fee: u64,
    pub nonce: u64,
}

#[allow(dead_code)]
pub(crate) struct SettleConfirmParams<'a> {
    pub session_id: u64,
    pub bytes_used: u64,
    pub net: u64,
    pub settle_blinding: &'a str,
    pub fee: u64,
    pub nonce: u64,
}

// ============================================================
// Local v3 boot state — cached anchor + tx hashes so subsequent
// restarts can short-circuit the register/update path.
// ============================================================

/// Persisted record of the operator's v3 boot state. Updated each
/// time the daemon submits register/update against the v3 program.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct CircleV3State {
    /// The `oct…` circle id this operator commits state-root anchors
    /// against. Read from `cfg.chain.circle_id` on first boot and
    /// pinned here so a later config typo doesn't silently bind us to
    /// a different circle.
    pub circle_id: String,
    /// Hex anchor (sha256 of canonical state-root.json) most recently
    /// committed on chain. Empty until the first register / update.
    #[serde(default)]
    pub last_anchor_hex: String,
    /// Tx hash of the most recent `register_circle` submission.
    #[serde(default)]
    pub register_tx_hash: String,
    /// Tx hash of the most recent `update_circle_state` submission.
    #[serde(default)]
    pub last_update_tx_hash: String,
}

impl CircleV3State {
    pub(crate) fn load(path: &std::path::Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read v3 circle state {}", path.display()))?;
        let s: Self = toml::from_str(&raw)
            .with_context(|| format!("parse v3 circle state {}", path.display()))?;
        Ok(Some(s))
    }

    pub(crate) fn save(&self, path: &std::path::Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        let raw = toml::to_string_pretty(self).context("serialize v3 circle state")?;
        std::fs::write(path, raw)
            .with_context(|| format!("write v3 circle state {}", path.display()))?;
        Ok(())
    }
}

// ============================================================
// Tests — wire-shape assertions per entrypoint. Cross-reference
// `docker/devnet/v3-smoke.sh` + `docker/devnet/e2e-adversarial-v3.sh`
// for the source-of-truth JSON shapes.
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `ChainCtxV3` backed by a deterministic 32-byte secret so
    /// `wallet_addr` is stable across runs and assertions can pin the
    /// `from` field. The RPC client is constructed against a bogus
    /// URL — these tests never hit the network.
    fn ctx() -> ChainCtxV3 {
        let secret = [7u8; 32];
        let wallet = KeyPair::from_secret_bytes(&secret);
        let program_addr = Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3");
        let rpc = RpcClient::new("http://127.0.0.1:0/unused");
        ChainCtxV3::new(rpc, program_addr, wallet)
    }

    fn anchor_64() -> String {
        // Deterministic 64-char hex anchor for shape checks.
        "1111111111111111111111111111111111111111111111111111111111111111".to_string()
    }

    #[test]
    fn register_circle_call_shape() {
        let c = ctx();
        let p = RegisterCircleParams {
            circle_id: "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun",
            state_root_hex: &anchor_64(),
            receipt_pubkey_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            stake_amount: 150_000_000,
            fee: 1_000,
            nonce: 42,
        };
        let call = c.build_register_circle_call(&p);
        assert_eq!(call["method"], "register_circle");
        assert_eq!(call["to"], c.program_addr.display());
        assert_eq!(call["from"], c.wallet_addr.display());
        assert_eq!(call["value"], 150_000_000);
        assert_eq!(call["fee"], 1_000);
        assert_eq!(call["nonce"], 42);
        // Param ordering: [circle, state_root, receipt_pubkey] — matches
        // `v3-smoke.sh:69` and `e2e-adversarial-v3.sh:182`.
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun");
        assert_eq!(params[1], anchor_64());
        assert_eq!(params[2], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    }

    #[test]
    fn update_circle_state_call_shape() {
        let c = ctx();
        let call = c.build_update_circle_state_call(
            "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun",
            &anchor_64(),
            500,
            7,
        );
        assert_eq!(call["method"], "update_circle_state");
        assert_eq!(call["value"], 0);
        assert_eq!(call["fee"], 500);
        assert_eq!(call["nonce"], 7);
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun");
        assert_eq!(params[1], anchor_64());
    }

    #[test]
    fn rotate_receipt_pubkey_call_shape() {
        let c = ctx();
        let call = c.build_rotate_receipt_pubkey_call(
            "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun",
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
            500,
            9,
        );
        assert_eq!(call["method"], "rotate_receipt_pubkey");
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun");
        assert_eq!(params[1], "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=");
    }

    #[test]
    fn retire_circle_call_shape() {
        let c = ctx();
        let call =
            c.build_retire_circle_call("oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun", 500, 10);
        assert_eq!(call["method"], "retire_circle");
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun");
    }

    #[test]
    fn bond_endpoint_call_shape() {
        let c = ctx();
        let call = c.build_bond_endpoint_call(
            "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun",
            50_000_000,
            500,
            11,
        );
        assert_eq!(call["method"], "bond_endpoint");
        assert_eq!(call["value"], 50_000_000);
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun");
    }

    #[test]
    fn unbond_and_finalize_call_shapes() {
        let c = ctx();
        let cid = "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun";
        let u = c.build_unbond_endpoint_call(cid, 500, 12);
        assert_eq!(u["method"], "unbond_endpoint");
        assert_eq!(u["value"], 0);
        assert_eq!(u["params"].as_array().unwrap().len(), 1);
        assert_eq!(u["params"][0], cid);

        let f = c.build_finalize_unbond_call(cid, 500, 13);
        assert_eq!(f["method"], "finalize_unbond");
        assert_eq!(f["value"], 0);
        assert_eq!(f["params"].as_array().unwrap().len(), 1);
        assert_eq!(f["params"][0], cid);
    }

    #[test]
    fn slash_double_sign_call_shape() {
        let c = ctx();
        let p = SlashDoubleSignParams {
            circle_id: "oct9SLZH51VyVumXxBHE6PvxBwYukmEvKfQAcRHBnxLfRLg",
            payload_a: "receipt-v1|sid=99|bytes=100",
            sig_a_b64: "AAAA",
            payload_b: "receipt-v1|sid=99|bytes=200",
            sig_b_b64: "BBBB",
            fee: 500,
            nonce: 14,
        };
        let call = c.build_slash_double_sign_call(&p);
        assert_eq!(call["method"], "slash_double_sign");
        let params = call["params"].as_array().unwrap();
        // [circle, payload_a, sig_a, payload_b, sig_b] — matches
        // e2e-adversarial-v3.sh S2/S3/S5 invocations.
        assert_eq!(params.len(), 5);
        assert_eq!(params[0], "oct9SLZH51VyVumXxBHE6PvxBwYukmEvKfQAcRHBnxLfRLg");
        assert_eq!(params[1], "receipt-v1|sid=99|bytes=100");
        assert_eq!(params[2], "AAAA");
        assert_eq!(params[3], "receipt-v1|sid=99|bytes=200");
        assert_eq!(params[4], "BBBB");
    }

    #[test]
    fn create_tailnet_call_shape() {
        let c = ctx();
        let call = c.build_create_tailnet_call(&anchor_64(), 10_000_000, 500, 15);
        assert_eq!(call["method"], "create_tailnet");
        assert_eq!(call["value"], 10_000_000);
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], anchor_64());
    }

    #[test]
    fn update_members_root_call_shape() {
        let c = ctx();
        let call = c.build_update_members_root_call(0, &anchor_64(), 500, 16);
        assert_eq!(call["method"], "update_members_root");
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], 0);
        assert_eq!(params[1], anchor_64());
    }

    #[test]
    fn retire_tailnet_call_shape() {
        let c = ctx();
        let call = c.build_retire_tailnet_call(3, 500, 17);
        assert_eq!(call["method"], "retire_tailnet");
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], 3);
    }

    #[test]
    fn deposit_to_tailnet_call_shape() {
        let c = ctx();
        let call = c.build_deposit_to_tailnet_call(2, 500_000, 500, 18);
        assert_eq!(call["method"], "deposit_to_tailnet");
        assert_eq!(call["value"], 500_000);
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], 2);
    }

    #[test]
    fn withdraw_tailnet_treasury_call_shape() {
        let c = ctx();
        let call = c.build_withdraw_tailnet_treasury_call(2, 100_000, 500, 11);
        assert_eq!(call["method"], "withdraw_tailnet_treasury");
        assert_eq!(call["to"], c.program_addr.display());
        assert_eq!(call["from"], c.wallet_addr.display());
        assert_eq!(call["value"], 0);
        assert_eq!(call["fee"], 500);
        assert_eq!(call["nonce"], 11);
        let params = call["params"].as_array().unwrap();
        // [tailnet_id, amount] — matches AML
        // `withdraw_tailnet_treasury(tailnet_id, amount)` at
        // program/main-v3.aml:466.
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], 2);
        assert_eq!(params[1], 100_000);
    }

    #[test]
    fn open_session_call_shape() {
        let c = ctx();
        let call = c.build_open_session_call(
            0,
            "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL",
            1500,
            500,
            19,
        );
        assert_eq!(call["method"], "open_session");
        let params = call["params"].as_array().unwrap();
        // [tailnet_id, circle, max_pay] — matches v3-smoke.sh:77.
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], 0);
        assert_eq!(params[1], "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL");
        assert_eq!(params[2], 1500);
    }

    #[test]
    fn settle_claim_call_shape() {
        let c = ctx();
        let call = c.build_settle_claim_call(0, 1_048_576, 500, 20);
        assert_eq!(call["method"], "settle_claim");
        let params = call["params"].as_array().unwrap();
        // [session_id, bytes_used] — matches v3-smoke.sh:80.
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], 0);
        assert_eq!(params[1], 1_048_576);
    }

    #[test]
    fn settle_confirm_call_shape() {
        let c = ctx();
        let p = SettleConfirmParams {
            session_id: 0,
            bytes_used: 1_048_576,
            net: 1000,
            settle_blinding: "f8d1aa00bb22cc33",
            fee: 500,
            nonce: 21,
        };
        let call = c.build_settle_confirm_call(&p);
        assert_eq!(call["method"], "settle_confirm");
        let params = call["params"].as_array().unwrap();
        // [sid, bytes_used, net, blinding] — matches v3-smoke.sh:84.
        assert_eq!(params.len(), 4);
        assert_eq!(params[0], 0);
        assert_eq!(params[1], 1_048_576);
        assert_eq!(params[2], 1000);
        assert_eq!(params[3], "f8d1aa00bb22cc33");
    }

    #[test]
    fn claim_no_show_call_shape() {
        let c = ctx();
        let call = c.build_claim_no_show_call(5, 500, 22);
        assert_eq!(call["method"], "claim_no_show");
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], 5);
    }

    #[test]
    fn sweep_expired_session_call_shape() {
        let c = ctx();
        let call = c.build_sweep_expired_session_call(5, 500, 23);
        assert_eq!(call["method"], "sweep_expired_session");
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], 5);
    }

    #[test]
    fn claim_earnings_call_shape() {
        let c = ctx();
        let call = c.build_claim_earnings_call(
            "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL",
            995,
            500,
            24,
        );
        assert_eq!(call["method"], "claim_earnings");
        let params = call["params"].as_array().unwrap();
        // [circle, amount] — matches v3-smoke.sh:101.
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL");
        assert_eq!(params[1], 995);
    }

    #[test]
    fn sign_call_round_trips_to_envelope() {
        // Confirm the sign + envelope-translation pipeline accepts what
        // we produce. Method name should round-trip through the
        // OctraTx envelope's `encrypted_data` field.
        let c = ctx();
        let p = RegisterCircleParams {
            circle_id: "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun",
            state_root_hex: &anchor_64(),
            receipt_pubkey_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            stake_amount: 150_000_000,
            fee: 1_000,
            nonce: 42,
        };
        let call = c.build_register_circle_call(&p);
        let signed = c.sign_call(call).expect("sign_call");
        // Signed envelope must carry signature + public_key.
        assert!(signed["signature"].is_string());
        assert!(signed["public_key"].is_string());
        // And `from` must round-trip.
        assert_eq!(signed["from"], c.wallet_addr.display());
    }

    #[test]
    fn circle_v3_state_load_save_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("circle-v3.toml");
        let s = CircleV3State {
            circle_id: "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun".into(),
            last_anchor_hex: anchor_64(),
            register_tx_hash: "deadbeef".into(),
            last_update_tx_hash: String::new(),
        };
        s.save(&path).expect("save");
        let loaded = CircleV3State::load(&path).expect("load").expect("Some");
        assert_eq!(loaded.circle_id, s.circle_id);
        assert_eq!(loaded.last_anchor_hex, s.last_anchor_hex);
        assert_eq!(loaded.register_tx_hash, s.register_tx_hash);
    }

    #[test]
    fn circle_v3_state_load_missing_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nope.toml");
        assert!(CircleV3State::load(&path).expect("load").is_none());
    }
}
