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
    address::Address,
    chain_tx_queue::ChainTxQueueHandle,
    rpc::{next_nonce, RpcClient},
    sig::KeyPair,
    tx as octra_tx,
    v3_calls::ContractCallBuilder,
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

/// `program/main-v4.aml` session status for an armed relay lane.
pub(crate) const SESSION_RELAY_ARMED: u64 = 3;

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
    /// v2 tx-envelope chain-id binding (P1-5b). See `ChainCtx::chain_id`.
    /// Empty ⇒ v1 wallet-compat signing.
    pub chain_id: String,
    /// Optional single-owner tx queue for long-lived v3 operator submitters.
    pub tx_queue: Option<ChainTxQueueHandle>,
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
        Self::new_with_chain_id(rpc, program_addr, wallet, String::new())
    }

    /// Variant of [`new`] that would pin a tx-envelope chain-id (P1-5b).
    /// CURRENTLY ALWAYS PASS `String::new()` (empty): reading the real node
    /// (octra-labs/lite_node) confirmed the tx envelope has NO chain_id field
    /// and `Transaction.verify` reconstructs the signed message without it, so
    /// signing over a non-empty chain_id → `octra_submit` 101. Retained only for
    /// if/when a chain actually verifies one. (Separate from the RECEIPT chain_id.)
    pub(crate) fn new_with_chain_id(
        rpc: RpcClient,
        program_addr: Address,
        wallet: KeyPair,
        chain_id: String,
    ) -> Self {
        Self::new_with_chain_id_and_queue(rpc, program_addr, wallet, chain_id, None)
    }

    pub(crate) fn new_with_chain_id_and_queue(
        rpc: RpcClient,
        program_addr: Address,
        wallet: KeyPair,
        chain_id: String,
        tx_queue: Option<ChainTxQueueHandle>,
    ) -> Self {
        let wallet_addr = Address::from_pubkey(&wallet.public.0);
        Self {
            rpc,
            program_addr,
            wallet_addr,
            wallet,
            chain_id,
            tx_queue,
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
        Ok(next_nonce(&b))
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

    /// `get_session_status(sid) -> int` view. v4 relay claim uses this
    /// to make sure the operator only reveals for armed sessions.
    pub(crate) async fn get_session_status(&self, session_id: u64) -> Result<u64> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "get_session_status",
                &[json!(session_id)],
                Some(&self.wallet_addr),
            )
            .await
            .context("get_session_status")?;
        Ok(v.as_u64().unwrap_or(0))
    }

    /// `get_relay_deadline(sid) -> int` view.
    pub(crate) async fn get_relay_deadline(&self, session_id: u64) -> Result<u64> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "get_relay_deadline",
                &[json!(session_id)],
                Some(&self.wallet_addr),
            )
            .await
            .context("get_relay_deadline")?;
        Ok(v.as_u64().unwrap_or(0))
    }

    /// `get_relay_settlement_hash(sid) -> bytes` view: the on-chain committed
    /// H (64-char hex) the opener armed with. Empty string if unset.
    pub(crate) async fn get_relay_settlement_hash(&self, session_id: u64) -> Result<String> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "get_relay_settlement_hash",
                &[json!(session_id)],
                Some(&self.wallet_addr),
            )
            .await
            .context("get_relay_settlement_hash")?;
        Ok(v.as_str().unwrap_or_default().to_string())
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

    /// `transfer_tailnet_ownership(tailnet_id, new_owner)` — current
    /// tailnet owner transfers owner-gated authority.
    pub(crate) fn build_transfer_tailnet_ownership_call(
        &self,
        tailnet_id: u64,
        new_owner: &str,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder().transfer_tailnet_ownership_call(
            &[json!(tailnet_id), json!(new_owner)],
            0,
            fee,
            nonce,
        )
    }

    /// `authorize_tailnet_spender(tailnet_id, spender)` — owner-managed
    /// delegation for sponsored session funding.
    pub(crate) fn build_authorize_tailnet_spender_call(
        &self,
        tailnet_id: u64,
        spender: &str,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder().authorize_tailnet_spender_call(
            &[json!(tailnet_id), json!(spender)],
            0,
            fee,
            nonce,
        )
    }

    /// `revoke_tailnet_spender(tailnet_id, spender)` — clear sponsored
    /// session funding delegation.
    pub(crate) fn build_revoke_tailnet_spender_call(
        &self,
        tailnet_id: u64,
        spender: &str,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder().revoke_tailnet_spender_call(
            &[json!(tailnet_id), json!(spender)],
            0,
            fee,
            nonce,
        )
    }

    // ============================================================
    // Sessions
    // ============================================================

    /// `payable open_session(tailnet_id, circle, max_pay) -> int`.
    /// The tx `value` is set to `max_pay`, which becomes the self-funded
    /// session escrow. The chain returns the assigned `session_id`; callers
    /// read it via `octra_transaction(hash)`.
    pub(crate) fn build_open_session_call(
        &self,
        tailnet_id: u64,
        circle_id: &str,
        max_pay: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder()
            .open_session_call(tailnet_id, circle_id, max_pay, fee, nonce)
    }

    /// `open_session_from_treasury(tailnet_id, circle, max_pay) -> int`.
    /// Sponsored path; AML allows only the tailnet owner or an authorized
    /// spender and the tx value remains zero.
    pub(crate) fn build_open_session_from_treasury_call(
        &self,
        tailnet_id: u64,
        circle_id: &str,
        max_pay: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder()
            .open_session_from_treasury_call(tailnet_id, circle_id, max_pay, fee, nonce)
    }

    /// `open_relay_session(...) -> int` — self-funded open + relay arm in
    /// one payable tx. The tx `value` is set to `max_pay`.
    pub(crate) fn build_open_relay_session_call(&self, p: &OpenRelaySessionParams<'_>) -> Value {
        self.call_builder().open_relay_session_call(
            p.tailnet_id,
            p.circle_id,
            p.max_pay,
            p.settlement_hash_hex,
            p.net,
            p.relay_expiry_epochs,
            p.fee,
            p.nonce,
        )
    }

    /// `open_relay_session_from_treasury(...) -> int` — sponsored open +
    /// relay arm in one zero-value tx.
    pub(crate) fn build_open_relay_session_from_treasury_call(
        &self,
        p: &OpenRelaySessionParams<'_>,
    ) -> Value {
        self.call_builder().open_relay_session_from_treasury_call(
            p.tailnet_id,
            p.circle_id,
            p.max_pay,
            p.settlement_hash_hex,
            p.net,
            p.relay_expiry_epochs,
            p.fee,
            p.nonce,
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

    /// HFHE-2 swap-ready settle-claim builder. Trailing positional
    /// `bytes` arg carrying the encrypted `bytes_used` ciphertext
    /// (or `""` when the PVAC sidecar is disabled). The on-chain
    /// `program/main-v3.aml::settle_claim` does NOT yet consume
    /// this third positional — call sites that submit tx today
    /// MUST keep using [`Self::build_settle_claim_call`]. This
    /// builder lives here so the shape lands in one place and
    /// tests pin it.
    #[allow(dead_code)] // wired by HFHE-3 swap diff
    pub(crate) fn build_settle_claim_with_shadow_call(
        &self,
        session_id: u64,
        bytes_used: u64,
        enc_bytes_used: &str,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder().settle_claim_with_shadow_call(
            session_id,
            bytes_used,
            enc_bytes_used,
            0,
            fee,
            nonce,
        )
    }

    /// HFHE-2: produce the encrypted-bytes_used ciphertext for the
    /// settle_claim shadow position. `Ok("")` (the empty-string
    /// sentinel) when the sidecar is `None`; otherwise the sidecar
    /// encrypts `bytes_used` under the supplied circle pubkey.
    pub(crate) async fn build_settle_claim_args(
        &self,
        bytes_used: u64,
        pvac: Option<&crate::pvac::PvacClient>,
        circle_pk: Option<&str>,
        circle_sk: Option<&str>,
        seed_hex: &str,
    ) -> Result<String> {
        match (pvac, circle_pk, circle_sk) {
            (Some(client), Some(pk), Some(sk)) => client
                .encrypt_const(pk, sk, bytes_used, seed_hex)
                .await
                .map_err(|e| anyhow!("pvac encrypt_const(bytes_used): {e}")),
            _ => Ok(String::new()),
        }
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

    /// `arm_relay(session_id, settlement_hash, net, relay_expiry_epochs)` —
    /// opener-side v4 promotion from OPEN into the unilateral relay lane.
    /// `settlement_hash` is the 64-char hex bytes string returned by
    /// `SignedReceipt::settlement_hash()`. Expiry is normalized to the
    /// AML-accepted band before encoding.
    pub(crate) fn build_arm_relay_call(&self, p: &ArmRelayParams<'_>) -> Value {
        self.call_builder().arm_relay_call(
            p.session_id,
            p.settlement_hash_hex,
            p.net,
            p.relay_expiry_epochs,
            0,
            p.fee,
            p.nonce,
        )
    }

    /// `relay_claim(session_id, preimage)` — circle-owner-only v4
    /// unilateral settlement. `preimage` is
    /// `SignedReceipt::settlement_preimage()` (standard padded base64).
    pub(crate) fn build_relay_claim_call(
        &self,
        session_id: u64,
        settlement_preimage_b64: &str,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder()
            .relay_claim_call(session_id, settlement_preimage_b64, 0, fee, nonce)
    }

    /// `relay_refund(session_id)` — opener-side recovery after the
    /// relay deadline.
    pub(crate) fn build_relay_refund_call(&self, session_id: u64, fee: u64, nonce: u64) -> Value {
        self.call_builder()
            .relay_refund_call(session_id, 0, fee, nonce)
    }

    /// HFHE-2 swap-ready settle-confirm builder. Two trailing
    /// positional `bytes` args carry `enc_bytes_used` + `enc_net`
    /// ciphertexts. Same swap-ready posture as
    /// [`Self::build_settle_claim_with_shadow_call`].
    #[allow(dead_code)] // wired by HFHE-3 swap diff
    pub(crate) fn build_settle_confirm_with_shadow_call(
        &self,
        p: &SettleConfirmParams<'_>,
        enc_bytes_used: &str,
        enc_net: &str,
    ) -> Value {
        self.call_builder().settle_confirm_with_shadow_call(
            p.session_id,
            p.bytes_used,
            p.net,
            p.settle_blinding,
            enc_bytes_used,
            enc_net,
            0,
            p.fee,
            p.nonce,
        )
    }

    /// HFHE-2: produce the (enc_bytes_used, enc_net) ciphertext
    /// pair for the settle_confirm shadow positions. Returns
    /// `Ok(("", ""))` when the sidecar is unwired; otherwise asks
    /// the sidecar to encrypt each value under the circle pubkey,
    /// with independent derived seeds.
    pub(crate) async fn build_settle_confirm_args(
        &self,
        bytes_used: u64,
        net: u64,
        pvac: Option<&crate::pvac::PvacClient>,
        circle_pk: Option<&str>,
        circle_sk: Option<&str>,
        seed_hex: &str,
    ) -> Result<(String, String)> {
        match (pvac, circle_pk, circle_sk) {
            (Some(client), Some(pk), Some(sk)) => {
                let seed_b = derive_seed(seed_hex, b"bytes");
                let seed_n = derive_seed(seed_hex, b"net");
                let enc_b = client
                    .encrypt_const(pk, sk, bytes_used, &seed_b)
                    .await
                    .map_err(|e| anyhow!("pvac encrypt_const(bytes_used): {e}"))?;
                let enc_n = client
                    .encrypt_const(pk, sk, net, &seed_n)
                    .await
                    .map_err(|e| anyhow!("pvac encrypt_const(net): {e}"))?;
                Ok((enc_b, enc_n))
            }
            _ => Ok((String::new(), String::new())),
        }
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

    /// HFHE-2 swap-ready claim-earnings builder.
    #[allow(dead_code)] // wired by HFHE-3 swap diff
    pub(crate) fn build_claim_earnings_with_shadow_call(
        &self,
        circle_id: &str,
        amount: u64,
        enc_amount: &str,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder()
            .claim_earnings_with_shadow_call(circle_id, amount, enc_amount, 0, fee, nonce)
    }

    /// HFHE-2: encrypted-amount ciphertext for the claim_earnings
    /// shadow position. `Ok("")` when the sidecar is disabled.
    pub(crate) async fn build_claim_earnings_args(
        &self,
        amount: u64,
        pvac: Option<&crate::pvac::PvacClient>,
        circle_pk: Option<&str>,
        circle_sk: Option<&str>,
        seed_hex: &str,
    ) -> Result<String> {
        match (pvac, circle_pk, circle_sk) {
            (Some(client), Some(pk), Some(sk)) => client
                .encrypt_const(pk, sk, amount, seed_hex)
                .await
                .map_err(|e| anyhow!("pvac encrypt_const(amount): {e}")),
            _ => Ok(String::new()),
        }
    }

    // ============================================================
    // Submit / sign
    // ============================================================

    /// Sign whatever `Value` we just built. Same `sign_call` the v1.1
    /// and v2 paths use — translates legacy `kind:contract_call`
    /// envelopes to the on-the-wire OctraTx shape.
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

    pub(crate) async fn submit_signed_tx(&self, signed: &Value) -> Result<String> {
        let r = self.rpc.submit(signed).await?;
        debug!(hash = %r.hash, "submitted tx (v3)");
        Ok(r.hash)
    }

    /// Submit an unsigned tx/call through the single nonce owner when
    /// present; otherwise preserve the legacy nonce -> sign -> submit path.
    pub(crate) async fn submit_call(&self, mut unsigned_call: Value) -> Result<String> {
        if let Some(tx_queue) = &self.tx_queue {
            return tx_queue
                .submit(unsigned_call)
                .await
                .map_err(|e| anyhow!("chain tx queue submit: {e}"));
        }

        let nonce = self.nonce().await?;
        set_unsigned_nonce(&mut unsigned_call, nonce)?;
        let signed = self.sign_call(unsigned_call)?;
        self.submit_signed_tx(&signed).await
    }
}

fn set_unsigned_nonce(call: &mut Value, nonce: u64) -> Result<()> {
    let obj = call
        .as_object_mut()
        .ok_or_else(|| anyhow!("v3 submit_call expects a JSON object"))?;
    obj.insert("nonce".to_string(), json!(nonce));
    Ok(())
}

/// HFHE-2: derive a 32-byte (64-char hex) seed from a parent seed
/// plus a short label by sha256-ing the concatenation. Used by
/// `build_settle_confirm_args` to split a single per-receipt seed
/// into independent per-ciphertext seeds so two ciphertexts on the
/// same receipt are not encrypted under the same randomness.
fn derive_seed(parent_hex: &str, label: &[u8]) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(parent_hex.as_bytes());
    h.update(b"|");
    h.update(label);
    hex::encode(h.finalize())
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

#[allow(dead_code)]
pub(crate) struct OpenRelaySessionParams<'a> {
    pub tailnet_id: u64,
    pub circle_id: &'a str,
    pub max_pay: u64,
    /// 64-char lowercase hex sha256 returned by
    /// `SignedReceipt::settlement_hash()`.
    pub settlement_hash_hex: &'a str,
    pub net: u64,
    pub relay_expiry_epochs: u64,
    pub fee: u64,
    pub nonce: u64,
}

#[allow(dead_code)]
pub(crate) struct ArmRelayParams<'a> {
    pub session_id: u64,
    /// 64-char lowercase hex sha256 returned by
    /// `SignedReceipt::settlement_hash()`.
    pub settlement_hash_hex: &'a str,
    pub net: u64,
    pub relay_expiry_epochs: u64,
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

    use std::{net::SocketAddr, sync::Arc};

    use axum::{extract::State as AxumState, http::StatusCode, routing::post, Json, Router};
    use parking_lot::Mutex;
    use tokio::sync::oneshot;

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

    #[derive(Debug)]
    struct SubmitMock {
        last_used_nonce: u64,
        balance_calls: usize,
        submit_calls: u64,
        submitted: Vec<Value>,
    }

    type SharedSubmitMock = Arc<Mutex<SubmitMock>>;

    async fn submit_mock_handler(
        AxumState(state): AxumState<SharedSubmitMock>,
        Json(req): Json<Value>,
    ) -> Result<Json<Value>, StatusCode> {
        let method = req
            .get("method")
            .and_then(Value::as_str)
            .ok_or(StatusCode::BAD_REQUEST)?;
        let id = req.get("id").cloned().unwrap_or(json!(1));
        let params = req.get("params").cloned().unwrap_or(json!([]));

        let result = match method {
            "octra_balance" => {
                let mut g = state.lock();
                g.balance_calls += 1;
                json!({
                    "balance": "100.000000",
                    "balance_raw": "100000000",
                    "nonce": g.last_used_nonce,
                    "pending_nonce": g.last_used_nonce,
                })
            }
            "octra_submit" => {
                let mut g = state.lock();
                g.submit_calls += 1;
                let tx = params
                    .as_array()
                    .and_then(|a| a.first())
                    .cloned()
                    .ok_or(StatusCode::BAD_REQUEST)?;
                if let Some(nonce) = tx.get("nonce").and_then(Value::as_u64) {
                    g.last_used_nonce = g.last_used_nonce.max(nonce);
                }
                g.submitted.push(tx);
                json!({
                    "tx_hash": format!("{:064x}", g.submit_calls),
                    "status": "accepted",
                })
            }
            _ => Value::Null,
        };

        Ok(Json(
            json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        ))
    }

    async fn spawn_submit_mock(
        last_used_nonce: u64,
    ) -> (String, SharedSubmitMock, oneshot::Sender<()>) {
        let state = Arc::new(Mutex::new(SubmitMock {
            last_used_nonce,
            balance_calls: 0,
            submit_calls: 0,
            submitted: Vec::new(),
        }));
        let app = Router::new()
            .route("/", post(submit_mock_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind submit mock");
        let addr = listener.local_addr().expect("submit mock addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service())
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        (format!("http://{addr}/"), state, shutdown_tx)
    }

    fn submitted_nonces(state: &SharedSubmitMock) -> Vec<u64> {
        state
            .lock()
            .submitted
            .iter()
            .map(|tx| {
                tx.get("nonce")
                    .and_then(Value::as_u64)
                    .expect("submitted tx nonce")
            })
            .collect()
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
    fn tailnet_owner_and_spender_call_shapes() {
        let c = ctx();
        let transfer = c.build_transfer_tailnet_ownership_call(
            7,
            "octG3oQBw9W6tnPJNn7tyL9ugHHkwSaExxWy3Nbi3iFiDRh",
            500,
            30,
        );
        assert_eq!(transfer["method"], "transfer_tailnet_ownership");
        assert_eq!(transfer["value"], 0);
        assert_eq!(
            transfer["params"],
            json!([7u64, "octG3oQBw9W6tnPJNn7tyL9ugHHkwSaExxWy3Nbi3iFiDRh"])
        );

        let authorize = c.build_authorize_tailnet_spender_call(
            7,
            "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL",
            500,
            31,
        );
        assert_eq!(authorize["method"], "authorize_tailnet_spender");
        assert_eq!(authorize["value"], 0);
        assert_eq!(
            authorize["params"],
            json!([7u64, "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL"])
        );

        let revoke = c.build_revoke_tailnet_spender_call(
            7,
            "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL",
            500,
            32,
        );
        assert_eq!(revoke["method"], "revoke_tailnet_spender");
        assert_eq!(revoke["value"], 0);
        assert_eq!(revoke["params"], authorize["params"]);
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
        assert_eq!(call["value"], 1500);
        let params = call["params"].as_array().unwrap();
        // [tailnet_id, circle, max_pay]; value carries the self-funded escrow.
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], 0);
        assert_eq!(params[1], "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL");
        assert_eq!(params[2], 1500);
    }

    #[test]
    fn sponsored_and_relay_session_call_shapes() {
        let c = ctx();
        let sponsored = c.build_open_session_from_treasury_call(
            0,
            "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL",
            1_500,
            500,
            20,
        );
        assert_eq!(sponsored["method"], "open_session_from_treasury");
        assert_eq!(sponsored["value"], 0);
        assert_eq!(
            sponsored["params"],
            json!([
                0u64,
                "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL",
                1_500u64
            ])
        );

        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let p = OpenRelaySessionParams {
            tailnet_id: 0,
            circle_id: "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL",
            max_pay: 1_500,
            settlement_hash_hex: hash,
            net: 1_000,
            relay_expiry_epochs: 200,
            fee: 500,
            nonce: 21,
        };
        let relay = c.build_open_relay_session_call(&p);
        assert_eq!(relay["method"], "open_relay_session");
        assert_eq!(relay["value"], 1_500);
        assert_eq!(
            relay["params"],
            json!([
                0u64,
                "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL",
                1_500u64,
                hash,
                1_000u64,
                200u64
            ])
        );

        let sponsored_relay = c.build_open_relay_session_from_treasury_call(&p);
        assert_eq!(
            sponsored_relay["method"],
            "open_relay_session_from_treasury"
        );
        assert_eq!(sponsored_relay["value"], 0);
        assert_eq!(sponsored_relay["params"], relay["params"]);
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
    fn arm_relay_call_shape() {
        let c = ctx();
        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let p = ArmRelayParams {
            session_id: 7,
            settlement_hash_hex: hash,
            net: 1_000,
            relay_expiry_epochs: 200,
            fee: 500,
            nonce: 25,
        };
        let call = c.build_arm_relay_call(&p);
        assert_eq!(call["method"], "arm_relay");
        assert_eq!(call["value"], 0);
        assert_eq!(call["fee"], 500);
        assert_eq!(call["nonce"], 25);
        let params = call["params"].as_array().unwrap();
        // [sid, settlement_hash, net, relay_expiry_epochs].
        assert_eq!(params.len(), 4);
        assert_eq!(params[0], 7);
        assert_eq!(params[1], hash);
        assert_eq!(params[2], 1_000);
        assert_eq!(params[3], 200);
    }

    #[test]
    fn relay_claim_and_refund_call_shapes() {
        let c = ctx();
        let preimage = "b2N0cmF2cG4tc2V0dGxlLXYxfA==";
        let claim = c.build_relay_claim_call(7, preimage, 500, 26);
        assert_eq!(claim["method"], "relay_claim");
        assert_eq!(claim["value"], 0);
        let claim_params = claim["params"].as_array().unwrap();
        assert_eq!(claim_params.len(), 2);
        assert_eq!(claim_params[0], 7);
        assert_eq!(claim_params[1], preimage);

        let refund = c.build_relay_refund_call(7, 500, 27);
        assert_eq!(refund["method"], "relay_refund");
        assert_eq!(refund["value"], 0);
        let refund_params = refund["params"].as_array().unwrap();
        assert_eq!(refund_params.len(), 1);
        assert_eq!(refund_params[0], 7);
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

    // ============================================================
    // HFHE-2 shadow-builder tests.
    // ============================================================

    #[tokio::test]
    async fn settle_claim_args_no_sidecar_returns_empty_string() {
        let c = ctx();
        let out = c
            .build_settle_claim_args(1_048_576, None, None, None, &"00".repeat(32))
            .await
            .expect("no-sidecar path is infallible");
        assert_eq!(out, "");
    }

    #[tokio::test]
    async fn settle_confirm_args_no_sidecar_returns_empty_pair() {
        let c = ctx();
        let (a, b) = c
            .build_settle_confirm_args(1_048_576, 1000, None, None, None, &"00".repeat(32))
            .await
            .expect("no-sidecar path is infallible");
        assert_eq!(a, "");
        assert_eq!(b, "");
    }

    #[tokio::test]
    async fn claim_earnings_args_no_sidecar_returns_empty_string() {
        let c = ctx();
        let out = c
            .build_claim_earnings_args(995, None, None, None, &"00".repeat(32))
            .await
            .expect("no-sidecar path is infallible");
        assert_eq!(out, "");
    }

    #[test]
    fn settle_claim_with_shadow_call_shape_empty() {
        let c = ctx();
        let call = c.build_settle_claim_with_shadow_call(0, 1_048_576, "", 500, 20);
        assert_eq!(call["method"], "settle_claim");
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], 0);
        assert_eq!(params[1], 1_048_576);
        assert_eq!(params[2], "");
    }

    #[test]
    fn settle_claim_with_shadow_call_shape_populated() {
        let c = ctx();
        let call = c.build_settle_claim_with_shadow_call(7, 1000, "hfhe_v1|CT", 500, 22);
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params[2], "hfhe_v1|CT");
    }

    #[test]
    fn settle_confirm_with_shadow_call_shape() {
        let c = ctx();
        let p = SettleConfirmParams {
            session_id: 0,
            bytes_used: 1_048_576,
            net: 1000,
            settle_blinding: "f8d1aa00bb22cc33",
            fee: 500,
            nonce: 21,
        };
        let call = c.build_settle_confirm_with_shadow_call(&p, "hfhe_v1|BB", "hfhe_v1|NN");
        assert_eq!(call["method"], "settle_confirm");
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 6);
        assert_eq!(params[4], "hfhe_v1|BB");
        assert_eq!(params[5], "hfhe_v1|NN");
    }

    #[test]
    fn claim_earnings_with_shadow_call_shape_empty() {
        let c = ctx();
        let call = c.build_claim_earnings_with_shadow_call("octCID", 995, "", 500, 24);
        assert_eq!(call["method"], "claim_earnings");
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], "octCID");
        assert_eq!(params[1], 995);
        assert_eq!(params[2], "");
    }

    #[tokio::test]
    async fn queue_backed_submit_call_serializes_concurrent_nonces() {
        let (url, state, _shutdown) = spawn_submit_mock(10).await;
        let secret = [7u8; 32];
        let wallet = KeyPair::from_secret_bytes(&secret);
        let queue_wallet = Arc::new(KeyPair::from_secret_bytes(&secret));
        let program_addr = Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3");
        let queue =
            octravpn_core::chain_tx_queue::spawn(RpcClient::new(&url), queue_wallet, String::new());
        let ctx = ChainCtxV3::new_with_chain_id_and_queue(
            RpcClient::new(&url),
            program_addr,
            wallet,
            String::new(),
            Some(queue),
        );
        let call_a = ctx.build_bond_endpoint_call(
            "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun",
            1_000,
            500,
            0,
        );
        let call_b = ctx.build_unbond_endpoint_call(
            "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun",
            500,
            0,
        );

        let (hash_a, hash_b) = tokio::join!(ctx.submit_call(call_a), ctx.submit_call(call_b));

        hash_a.expect("first submit");
        hash_b.expect("second submit");
        assert_eq!(submitted_nonces(&state), vec![11, 12]);
        assert_eq!(state.lock().balance_calls, 1);
    }

    #[tokio::test]
    async fn submit_call_without_queue_matches_legacy_nonce_sign_submit_bytes() {
        let (url, state, _shutdown) = spawn_submit_mock(10).await;
        let wallet = KeyPair::from_secret_bytes(&[7u8; 32]);
        let program_addr = Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3");
        let ctx = ChainCtxV3::new_with_chain_id(
            RpcClient::new(&url),
            program_addr,
            wallet,
            "octra-devnet".to_string(),
        );
        let call = ctx.build_bond_endpoint_call(
            "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun",
            1_000,
            500,
            0,
        );
        let mut legacy_call = call.clone();
        set_unsigned_nonce(&mut legacy_call, 11).expect("set nonce");
        let legacy_signed = ctx.sign_call(legacy_call).expect("legacy sign_call");

        ctx.submit_call(call).await.expect("submit_call fallback");

        let g = state.lock();
        assert_eq!(g.balance_calls, 1);
        assert_eq!(g.submitted.len(), 1);
        assert_eq!(g.submitted[0], legacy_signed);
    }

    #[tokio::test]
    async fn r3_queue_path_omits_chain_id_even_when_ctx_has_a_non_empty_one() {
        // R3: production builds the ctx with a (now-vestigial) envelope chain_id
        // but the ChainTxQueue with EMPTY. The real node does not verify an
        // envelope chain_id -- signing over one is octra_submit 101 -- so the
        // queue path must sign WITHOUT chain_id regardless of the ctx's field.
        let (url, state, _shutdown) = spawn_submit_mock(10).await;
        let secret = [7u8; 32];
        let wallet = KeyPair::from_secret_bytes(&secret);
        let queue_wallet = Arc::new(KeyPair::from_secret_bytes(&secret));
        let program_addr = Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3");
        let queue =
            octravpn_core::chain_tx_queue::spawn(RpcClient::new(&url), queue_wallet, String::new());
        let ctx = ChainCtxV3::new_with_chain_id_and_queue(
            RpcClient::new(&url),
            program_addr,
            wallet,
            "octra-devnet".to_string(),
            Some(queue),
        );
        let call = ctx.build_bond_endpoint_call(
            "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun",
            1_000,
            500,
            0,
        );
        ctx.submit_call(call).await.expect("submit_call via queue");
        let g = state.lock();
        assert_eq!(g.submitted.len(), 1);
        assert!(
            g.submitted[0].get("chain_id").is_none(),
            "queue path must sign WITHOUT a chain_id field; got {:?}",
            g.submitted[0]
        );
    }

    #[test]
    fn derive_seed_is_deterministic_and_differs_per_label() {
        let parent = "ab".repeat(32);
        let a = derive_seed(&parent, b"bytes");
        let b = derive_seed(&parent, b"bytes");
        let c = derive_seed(&parent, b"net");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
