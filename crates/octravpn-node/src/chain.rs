//! Chain integration for the node daemon (v1).
//!
//! Wraps `octravpn-core::rpc::RpcClient` with v1 OctraVPN actions:
//! bond/unbond/finalize-unbond, register/claim endpoint, claim
//! earnings, observe current epoch. The v1 AML gates registration on
//! in-program stake (not Octra-validator status).
//!
//! The claim_earnings call is two-step: this module issues the AML
//! call which verifies an FHE zero-proof and transfers plaintext OU;
//! the operator's wallet is responsible for the follow-up native
//! op_type="stealth" tx if they want unlinkable payout.

use anyhow::{Context, Result};
use octravpn_core::{address::Address, rpc::RpcClient, sig::KeyPair};
use serde_json::{json, Value};
use tracing::{debug, info};

pub(crate) struct ChainCtx {
    pub rpc: RpcClient,
    pub program_addr: Address,
    pub validator_addr: Address,
    pub wallet: KeyPair,
}

/// Inputs to `register_endpoint`. Borrowed so call sites don't have
/// to clone every slice. Per v1 AML signature.
pub(crate) struct RegisterEndpointParams<'a> {
    pub endpoint: &'a str,
    /// X25519 noise pubkey (hex, used by clients to wrap onion layers).
    pub wg_pubkey_hex: &'a str,
    /// HFHE pubkey (string). Real Octra clients generate via libpvac;
    /// for v1 testnet operators may use a placeholder until the SDK
    /// surfaces real HFHE keygen.
    pub hfhe_pubkey: &'a str,
    /// Pre-computed enc_pk(0) ciphertext (string).
    pub initial_enc_zero: &'a str,
    pub region: &'a str,
    pub price_per_mb: u64,
    /// Ed25519 pubkey the operator will sign off-chain receipts with
    /// (the same key referenced by `slash_double_sign` on chain).
    /// Per v1.1 AML; required.
    pub receipt_pubkey_hex: &'a str,
    pub fee: u64,
    pub nonce: u64,
}

impl ChainCtx {
    #[allow(dead_code)]
    pub(crate) async fn current_epoch(&self) -> Result<u64> {
        let s = self.rpc.node_status().await?;
        Ok(s.epoch)
    }

    /// Read the operator's in-program stake. The v1 AML gate requires
    /// `endpoint_stake >= MIN_ENDPOINT_STAKE`. Pre-checked here so
    /// the node can fail fast with a clear error before submitting
    /// a register tx that would revert.
    pub(crate) async fn read_endpoint_stake(&self) -> Result<u64> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "get_endpoint_stake",
                &[json!(self.validator_addr.display())],
                Some(&self.validator_addr),
            )
            .await
            .context("get_endpoint_stake")?;
        Ok(v.as_u64().unwrap_or(0))
    }

    /// Returns true iff the operator is marked permanently slashed.
    pub(crate) async fn read_endpoint_slashed(&self) -> Result<bool> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "is_endpoint_slashed",
                &[json!(self.validator_addr.display())],
                Some(&self.validator_addr),
            )
            .await
            .context("is_endpoint_slashed")?;
        Ok(v.as_bool().unwrap_or(false))
    }

    /// Read the current endpoint record for this operator, if any.
    /// `None` indicates "not registered yet". Uses the raw RPC
    /// envelope so it can see the storage block (devnet wraps view
    /// returns as `{result, storage}`); the mock's bare-value path
    /// also works since we treat any non-null/non-empty response as
    /// "registered."
    pub(crate) async fn read_endpoint_record(&self) -> Result<Option<Value>> {
        let raw = self
            .rpc
            .contract_call_raw(
                &self.program_addr,
                "get_endpoint",
                &[json!(self.validator_addr.display())],
                Some(&self.validator_addr),
            )
            .await
            .context("get_endpoint")?;
        if raw.is_null() {
            return Ok(None);
        }
        let validator = self.validator_addr.display();
        let active_key = format!("endpoints:{validator}:active");
        // Real devnet path: look in the storage block.
        if let Some(storage) = raw.get("storage").and_then(|s| s.as_object()) {
            let active = storage
                .get(&active_key)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            if active == 0 {
                return Ok(None);
            }
            return Ok(Some(raw));
        }
        // Mock / bare-value path: heuristic.
        let v = raw;
        if v.get("active")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            == 0
        {
            return Ok(None);
        }
        Ok(Some(v))
    }

    pub(crate) fn build_register_endpoint_call(&self, p: &RegisterEndpointParams<'_>) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.validator_addr.display(),
            "to": self.program_addr.display(),
            "method": "register_endpoint",
            "params": [
                p.endpoint,
                p.wg_pubkey_hex,
                p.hfhe_pubkey,
                p.initial_enc_zero,
                p.region,
                p.price_per_mb,
                p.receipt_pubkey_hex,
            ],
            "value": 0,
            "fee": p.fee,
            "nonce": p.nonce,
        })
    }

    /// `bond_endpoint()` — value-bearing call. The `amount` becomes
    /// the locked operator stake.
    pub(crate) fn build_bond_call(&self, amount: u64, fee: u64, nonce: u64) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.validator_addr.display(),
            "to": self.program_addr.display(),
            "method": "bond_endpoint",
            "params": [],
            "value": amount,
            "fee": fee,
            "nonce": nonce,
        })
    }

    /// `unbond_endpoint()` — starts the grace period.
    pub(crate) fn build_unbond_call(&self, fee: u64, nonce: u64) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.validator_addr.display(),
            "to": self.program_addr.display(),
            "method": "unbond_endpoint",
            "params": [],
            "value": 0,
            "fee": fee,
            "nonce": nonce,
        })
    }

    /// `finalize_unbond()` — claims the unbonded stake after grace.
    pub(crate) fn build_finalize_unbond_call(&self, fee: u64, nonce: u64) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.validator_addr.display(),
            "to": self.program_addr.display(),
            "method": "finalize_unbond",
            "params": [],
            "value": 0,
            "fee": fee,
            "nonce": nonce,
        })
    }

    /// `claim_earnings(amount, proof)`. The `proof` is the FHE
    /// zero-proof opening produced by the operator's HFHE library.
    pub(crate) fn build_claim_call(
        &self,
        claimed_amount: u64,
        proof_hex: &str,
        fee: u64,
        nonce: u64,
    ) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.validator_addr.display(),
            "to": self.program_addr.display(),
            "method": "claim_earnings",
            "params": [
                claimed_amount,
                proof_hex,
            ],
            "value": 0,
            "fee": fee,
            "nonce": nonce,
        })
    }

    /// `settle_claim(session_id, bytes_used)` — operator-side first
    /// half of the two-tx settlement. The AML enforces caller =
    /// session's exit and slashes on equivocation.
    pub(crate) fn build_settle_claim_call(
        &self,
        session_id: u64,
        bytes_used: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.validator_addr.display(),
            "to": self.program_addr.display(),
            "method": "settle_claim",
            "params": [session_id, bytes_used],
            "value": 0,
            "fee": fee,
            "nonce": nonce,
        })
    }

    pub(crate) async fn submit_signed_tx(&self, signed: &Value) -> Result<String> {
        let r = self.rpc.submit(signed).await?;
        debug!(hash = %r.hash, "submitted tx");
        Ok(r.hash)
    }

    pub(crate) async fn nonce(&self) -> Result<u64> {
        let b = self.rpc.balance(&self.validator_addr).await?;
        Ok(b.pending_nonce.max(b.nonce))
    }

    pub(crate) async fn fee(&self, op: &str) -> Result<u64> {
        let f = self.rpc.recommended_fee(Some(op)).await?;
        Ok(f.recommended)
    }

    /// Sign a constructed call payload with the wallet key.
    pub(crate) fn sign_call(&self, call: Value) -> Result<Value> {
        let signed = octravpn_core::tx::sign_call(&self.wallet, call)?;
        info!(
            method = %signed.get("method").and_then(serde_json::Value::as_str).unwrap_or("?"),
            "signed tx"
        );
        Ok(signed)
    }
}
