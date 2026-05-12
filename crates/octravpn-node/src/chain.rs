//! Chain integration for the node daemon.
//!
//! Wraps `octravpn-core::rpc::RpcClient` with the dVPN endpoint actions:
//! pre-flight Octra-validator check, register endpoint, claim earnings,
//! observe current epoch. Bonding/attestation/slashing live on the Octra
//! protocol layer — this module does not duplicate them.

use anyhow::{anyhow, Context, Result};
use octravpn_core::{address::Address, rpc::RpcClient, sig::KeyPair};
use serde_json::{json, Value};
use tracing::{debug, info};

pub(crate) struct ChainCtx {
    pub rpc: RpcClient,
    pub program_addr: Address,
    pub validator_addr: Address,
    pub wallet: KeyPair,
}

/// Inputs to `register_endpoint`. Borrowed so call sites don't have to
/// clone every byte slice they hold.
pub(crate) struct RegisterEndpointParams<'a> {
    pub endpoint: &'a str,
    /// X25519 noise pubkey (used by clients to wrap onion layers).
    pub wg_pubkey: &'a [u8; 32],
    /// ed25519 receipt-signing pubkey.
    pub receipt_pubkey: &'a [u8; 32],
    pub view_pubkey: &'a [u8; 32],
    pub region: &'a str,
    pub price_per_mb: u64,
    pub fee: u64,
    pub nonce: u64,
}

impl ChainCtx {
    #[allow(dead_code)]
    pub(crate) async fn current_epoch(&self) -> Result<u64> {
        let s = self.rpc.node_status().await?;
        Ok(s.epoch)
    }

    /// Returns true iff the configured wallet is currently an Octra
    /// protocol validator. The program-side gate enforces this at
    /// registration; we pre-check so the node can fail fast with a
    /// clear error message instead of waiting for the tx to revert.
    pub(crate) async fn is_octra_validator(&self) -> Result<bool> {
        self.rpc
            .is_octra_validator(&self.validator_addr)
            .await
            .context("octra_isValidator")
            .map_err(|e| anyhow!(e))
    }

    /// Read the current endpoint record for this validator, if any.
    /// `None` indicates "not registered yet" (the program returns a
    /// zeroed record where `active == 0`).
    pub(crate) async fn read_endpoint_record(&self) -> Result<Option<Value>> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "get_endpoint",
                &[json!(self.validator_addr.display())],
                Some(&self.validator_addr),
            )
            .await
            .context("get_endpoint")?;
        if v.is_null() {
            return Ok(None);
        }
        if v.get("active")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            == 0
        {
            return Ok(None);
        }
        Ok(Some(v))
    }

    /// Build a `register_endpoint` call.
    pub(crate) fn build_register_endpoint_call(
        &self,
        p: &RegisterEndpointParams<'_>,
    ) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.validator_addr.display(),
            "to": self.program_addr.display(),
            "method": "register_endpoint",
            "params": [
                p.endpoint,
                hex::encode(p.wg_pubkey),
                hex::encode(p.receipt_pubkey),
                hex::encode(p.view_pubkey),
                p.region,
                p.price_per_mb,
            ],
            "value": 0,
            "fee": p.fee,
            "nonce": p.nonce,
        })
    }

    pub(crate) fn build_claim_call(
        &self,
        claimed_amount: u64,
        claimed_blind: &[u8; 32],
        stealth_output: &[u8; 32],
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
                hex::encode(claimed_blind),
                hex::encode(stealth_output),
            ],
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
