//! Client-side chain integration for the v3 (chain-minimal,
//! circle-resident) program (`program/main-v3.aml`, devnet
//! `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`).
//!
//! Sibling to `discover_v2.rs` (v2 sealed-policy flow). This module is
//! deliberately a thin subset of `octravpn-node::chain_v3` — only the
//! client-facing entrypoints (open_session / settle_confirm /
//! claim_no_show / sweep_expired_session) plus the view wrappers a
//! client needs to render its session state. We do NOT depend on the
//! node crate; the shared schema lives in `octravpn-core::v3_state_root`.
//!
//! Each `build_*` method returns the legacy `{"kind":"contract_call",
//! ...}` shape that `octravpn_core::tx::sign_call` translates into the
//! on-wire OctraTx envelope — the same path the v2 runner uses for
//! `open_session_v2`. The JSON envelope construction itself lives in
//! [`octravpn_core::v3_calls`] so the node crate emits identical bytes;
//! each `build_*_call` wrapper below just forwards its inputs to the
//! shared builder. Method names and param ordering mirror
//! `docker/devnet/v3-smoke.sh`; unit tests at the bottom pin both.

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    address::Address, rpc::RpcClient, sig::KeyPair, tx as octra_tx,
    v3_calls::ContractCallBuilder,
};
use serde_json::{json, Value};

/// Default contract-call fee fallback when the chain's
/// `octra_recommendedFee` returns 0 / unreachable. Matches the value
/// the v1.1 / v2 paths use for the same situation.
pub(crate) const CALL_FEE_FALLBACK: u64 = 1_000;

/// All v3 chain interactions the client needs. Sibling to the node's
/// `ChainCtxV3` but with the operator-only entrypoints stripped.
pub(crate) struct ChainCtxV3<'a> {
    rpc: &'a RpcClient,
    program_addr: &'a Address,
    wallet_addr: Address,
    wallet: &'a KeyPair,
}

impl<'a> ChainCtxV3<'a> {
    pub(crate) fn new(rpc: &'a RpcClient, program_addr: &'a Address, wallet: &'a KeyPair) -> Self {
        let wallet_addr = Address::from_pubkey(&wallet.public.0);
        Self {
            rpc,
            program_addr,
            wallet_addr,
            wallet,
        }
    }

    #[allow(dead_code)] // referenced by integration tests + future status display.
    pub(crate) fn wallet_addr(&self) -> &Address {
        &self.wallet_addr
    }

    /// Construct the shared `ContractCallBuilder` bound to this
    /// client's program addr + wallet addr. All `build_*_call` methods
    /// below delegate through this so the JSON wire shape is owned by
    /// `octravpn_core::v3_calls`.
    fn call_builder(&self) -> ContractCallBuilder {
        ContractCallBuilder::new(self.program_addr.clone(), self.wallet_addr.clone())
    }

    pub(crate) async fn nonce(&self) -> Result<u64> {
        let b = self.rpc.balance(&self.wallet_addr).await?;
        Ok(b.pending_nonce.max(b.nonce))
    }

    /// Fee with fallback to [`CALL_FEE_FALLBACK`] if the chain returns
    /// 0 or errors. Mirrors `chain_v3::fee_or_fallback` on the node.
    pub(crate) async fn fee_or_fallback(&self, op: &str) -> u64 {
        self.rpc
            .recommended_fee(Some(op))
            .await
            .ok()
            .map(|f| f.recommended)
            .filter(|f| *f > 0)
            .unwrap_or(CALL_FEE_FALLBACK)
    }

    // ============================================================
    // Views
    // ============================================================

    /// `get_circle_state_root(circle) -> bytes` (64-char hex). Returns
    /// `None` when the chain reports a zero / unset value (the AML
    /// `bytes` default is the literal `"0"`, not the empty string).
    pub(crate) async fn get_circle_state_root(&self, circle: &str) -> Result<Option<String>> {
        let v = self
            .rpc
            .contract_call(
                self.program_addr,
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

    /// `get_tailnet_members_root(tid) -> bytes` (64-char hex). `None`
    /// when no `members_root` has been committed yet (AML default).
    pub(crate) async fn get_tailnet_members_root(&self, tailnet_id: u64) -> Result<Option<String>> {
        let v = self
            .rpc
            .contract_call(
                self.program_addr,
                "get_tailnet_members_root",
                &[json!(tailnet_id)],
                Some(&self.wallet_addr),
            )
            .await
            .context("get_tailnet_members_root")?;
        let s = v.as_str().unwrap_or("").to_string();
        if s.is_empty() || s == "0" {
            return Ok(None);
        }
        Ok(Some(s))
    }

    /// `get_session_status(sid) -> int` view. The AML uses the
    /// constants `SESSION_OPEN = 1`, `SESSION_SETTLED = 2`,
    /// `SESSION_REFUNDED = 3`; values below 1 indicate "not found".
    #[allow(dead_code)] // surfaced for status displays + integration tests.
    pub(crate) async fn get_session_status(&self, session_id: u64) -> Result<u64> {
        let v = self
            .rpc
            .contract_call(
                self.program_addr,
                "get_session_status",
                &[json!(session_id)],
                Some(&self.wallet_addr),
            )
            .await
            .context("get_session_status")?;
        Ok(v.as_u64().unwrap_or(0))
    }

    /// `get_earnings_total(circle) -> int` — sanity-display only.
    #[allow(dead_code)]
    pub(crate) async fn get_earnings_total(&self, circle: &str) -> Result<u64> {
        let v = self
            .rpc
            .contract_call(
                self.program_addr,
                "get_earnings_total",
                &[json!(circle)],
                Some(&self.wallet_addr),
            )
            .await
            .context("get_earnings_total")?;
        Ok(v.as_u64().unwrap_or(0))
    }

    /// Fetch the raw bytes of a sealed-asset by path inside a circle.
    ///
    /// v3 `policy.json` and `state-root.json` are stored as plaintext
    /// canonical JSON inside the operator circle. The chain hosts them
    /// via the same `circle_asset` RPC family that v2 uses for sealed
    /// envelopes; the difference is just that v3's bytes are plaintext
    /// JSON and the anchor lives on chain (`circle_state_root[circle]`),
    /// so no key id / passphrase is involved at the fetch boundary.
    ///
    /// Returns `Ok(None)` when the RPC reports the asset is absent
    /// (either a `null` result or an error string carrying "not found"
    /// / "no such" — matches the discover_v2 distinction between
    /// `Unpublished` and `Error`). The response shape is one of:
    ///
    /// * `null`                               → `Ok(None)`
    /// * a bare UTF-8 string of the bytes     → `Ok(Some(bytes))`
    /// * `{"bytes":"<base64>", ...}`          → `Ok(Some(decoded))`
    /// * `{"plaintext":"<utf8>", ...}`        → `Ok(Some(bytes))`
    /// * `{"content":"<utf8>", ...}`          → `Ok(Some(bytes))`
    ///
    /// Anything else surfaces as a hard error so the caller can flag
    /// a chain/RPC-schema drift loudly rather than silently fall back.
    pub(crate) async fn fetch_circle_asset_bytes(
        &self,
        circle_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>> {
        let v = match self
            .rpc
            .raw_call("circle_asset", json!([circle_id, path]))
            .await
        {
            Ok(v) => v,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("not found") || msg.contains("no such") {
                    return Ok(None);
                }
                return Err(anyhow!("circle_asset({circle_id}, {path}): {e}"));
            }
        };
        if v.is_null() {
            return Ok(None);
        }
        if let Some(s) = v.as_str() {
            return Ok(Some(s.as_bytes().to_vec()));
        }
        if let Some(obj) = v.as_object() {
            // Direct UTF-8 / plaintext shapes first — v3 canonical bytes
            // are plain UTF-8 JSON, so this is the expected fast path
            // once the chain settles on a field name.
            for key in ["plaintext", "content", "json"] {
                if let Some(s) = obj.get(key).and_then(Value::as_str) {
                    return Ok(Some(s.as_bytes().to_vec()));
                }
            }
            // Base64-encoded byte string fallback (matches the v2
            // sealed-asset RPC convention).
            if let Some(s) = obj.get("bytes").and_then(Value::as_str) {
                use base64::engine::general_purpose::STANDARD as BASE64_STD;
                use base64::Engine as _;
                let decoded = BASE64_STD
                    .decode(s.as_bytes())
                    .map_err(|e| anyhow!("circle_asset bytes base64: {e}"))?;
                return Ok(Some(decoded));
            }
            if let Some(s) = obj.get("bytes_b64").and_then(Value::as_str) {
                use base64::engine::general_purpose::STANDARD as BASE64_STD;
                use base64::Engine as _;
                let decoded = BASE64_STD
                    .decode(s.as_bytes())
                    .map_err(|e| anyhow!("circle_asset bytes_b64 base64: {e}"))?;
                return Ok(Some(decoded));
            }
        }
        Err(anyhow!(
            "circle_asset({circle_id}, {path}): unexpected response shape: {v}"
        ))
    }

    // ============================================================
    // Sessions
    // ============================================================

    /// `open_session(tailnet_id, circle, max_pay) -> int`. The chain
    /// returns the assigned `session_id` via the tx's `SessionOpened`
    /// event; callers should observe it through `octra_transaction`.
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

    /// `nonreentrant settle_confirm(session_id, bytes_used, net,
    /// settle_blinding)` — opener-side second half of the two-tx
    /// settle. `net = bytes_used * price` computed off-chain;
    /// `settle_blinding` is a freshly-generated 32-byte hex string
    /// fed into the earnings hash chain.
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

    /// `claim_no_show(session_id)` — opener-side abort path. Fires
    /// once `epoch >= opened_at + session_grace_epochs` and the
    /// operator hasn't called `settle_claim`. Refunds the deposit to
    /// the tailnet treasury.
    pub(crate) fn build_claim_no_show_call(
        &self,
        session_id: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call_builder()
            .claim_no_show_call(&[json!(session_id)], 0, fee, nonce)
    }

    /// `nonreentrant sweep_expired_session(session_id)` — any caller
    /// can sweep an OPEN session past the sweep-grace cutoff. Pays a
    /// `sweep_bounty_bps` bounty to the caller; the remainder refunds
    /// the tailnet.
    #[allow(dead_code)]
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
    // Submit / sign
    // ============================================================

    /// Sign + envelope-translate whatever `Value` we just built. Same
    /// pipeline as the v1.1 / v2 paths.
    pub(crate) fn sign_call(&self, call: Value) -> Result<Value> {
        octra_tx::sign_call(self.wallet, call).map_err(|e| anyhow!("sign_call: {e}"))
    }

    pub(crate) async fn submit_signed(&self, signed: &Value) -> Result<String> {
        let r = self.rpc.submit(signed).await?;
        Ok(r.hash)
    }
}

/// Inputs to `settle_confirm`. Borrowed so the call site doesn't need
/// to clone the per-session blinding hex.
pub(crate) struct SettleConfirmParams<'a> {
    pub session_id: u64,
    pub bytes_used: u64,
    pub net: u64,
    /// 64-char lowercase hex of the freshly-generated 32-byte blinding.
    pub settle_blinding: &'a str,
    pub fee: u64,
    pub nonce: u64,
}

// ============================================================
// Tests — wire-shape assertions per entrypoint. Cross-check
// against `docker/devnet/v3-smoke.sh` for source-of-truth shapes.
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(
        rpc: &'a RpcClient,
        program_addr: &'a Address,
        wallet: &'a KeyPair,
    ) -> ChainCtxV3<'a> {
        ChainCtxV3::new(rpc, program_addr, wallet)
    }

    fn fixtures() -> (RpcClient, Address, KeyPair) {
        let secret = [7u8; 32];
        let wallet = KeyPair::from_secret_bytes(&secret);
        let program_addr =
            Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3");
        let rpc = RpcClient::new("http://127.0.0.1:0/unused");
        (rpc, program_addr, wallet)
    }

    #[test]
    fn open_session_call_shape() {
        let (rpc, prog, wallet) = fixtures();
        let c = ctx(&rpc, &prog, &wallet);
        let call = c.build_open_session_call(
            0,
            "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL",
            1_500,
            500,
            19,
        );
        assert_eq!(call["method"], "open_session");
        assert_eq!(call["to"], prog.display());
        assert_eq!(call["from"], c.wallet_addr().display());
        assert_eq!(call["value"], 0);
        assert_eq!(call["fee"], 500);
        assert_eq!(call["nonce"], 19);
        let params = call["params"].as_array().unwrap();
        // [tailnet_id, circle, max_pay] — matches v3-smoke.sh:77.
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], 0);
        assert_eq!(params[1], "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL");
        assert_eq!(params[2], 1_500);
    }

    #[test]
    fn settle_confirm_call_shape() {
        let (rpc, prog, wallet) = fixtures();
        let c = ctx(&rpc, &prog, &wallet);
        let p = SettleConfirmParams {
            session_id: 0,
            bytes_used: 1_048_576,
            net: 1_000,
            settle_blinding:
                "f8d1aa00bb22cc33f8d1aa00bb22cc33f8d1aa00bb22cc33f8d1aa00bb22cc33",
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
        assert_eq!(params[2], 1_000);
        assert_eq!(
            params[3],
            "f8d1aa00bb22cc33f8d1aa00bb22cc33f8d1aa00bb22cc33f8d1aa00bb22cc33"
        );
    }

    #[test]
    fn claim_no_show_call_shape() {
        let (rpc, prog, wallet) = fixtures();
        let c = ctx(&rpc, &prog, &wallet);
        let call = c.build_claim_no_show_call(5, 500, 22);
        assert_eq!(call["method"], "claim_no_show");
        assert_eq!(call["value"], 0);
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], 5);
    }

    #[test]
    fn sweep_expired_session_call_shape() {
        let (rpc, prog, wallet) = fixtures();
        let c = ctx(&rpc, &prog, &wallet);
        let call = c.build_sweep_expired_session_call(5, 500, 23);
        assert_eq!(call["method"], "sweep_expired_session");
        let params = call["params"].as_array().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], 5);
    }

    #[test]
    fn sign_call_round_trips_to_envelope() {
        // Confirm the sign + envelope-translation pipeline accepts what
        // we produce. Method name should round-trip through the
        // OctraTx envelope's `encrypted_data` field.
        let (rpc, prog, wallet) = fixtures();
        let c = ctx(&rpc, &prog, &wallet);
        let call = c.build_open_session_call(
            0,
            "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL",
            1_500,
            500,
            19,
        );
        let signed = c.sign_call(call).expect("sign_call");
        assert!(signed["signature"].is_string());
        assert!(signed["public_key"].is_string());
        assert_eq!(signed["op_type"], "call");
        assert_eq!(signed["encrypted_data"], "open_session");
    }
}
