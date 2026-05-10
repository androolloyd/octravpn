//! Chain integration for the node daemon.
//!
//! Wraps `octravpn-core::rpc::RpcClient` with the validator-specific
//! actions: register, refresh attestation, claim earnings, observe
//! current epoch.

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    address::Address,
    rpc::RpcClient,
    sig::KeyPair,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

pub const TAG_ATTEST: &[u8] = b"octravpn-validator-attest";
pub const TAG_BOND: &[u8] = b"octravpn-validator-bond";

pub struct ChainCtx {
    pub rpc: RpcClient,
    pub program_addr: Address,
    pub validator_addr: Address,
    pub wallet: KeyPair,
}

impl ChainCtx {
    pub async fn current_epoch(&self) -> Result<u64> {
        let s = self.rpc.node_status().await?;
        Ok(s.epoch)
    }

    /// Build the attestation signature: sign sha256(self_addr || tag || epoch).
    /// `self_addr` is the program address (the verifier identity), matching
    /// the on-chain `self_addr` built-in inside `register_validator`.
    pub fn sign_attestation(&self, tag: &[u8], epoch: u64) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(&self.program_addr.raw);
        h.update(tag);
        h.update(epoch.to_be_bytes());
        let msg = h.finalize();
        self.wallet.sign(&msg).0.to_vec()
    }

    pub async fn read_validator_record(&self) -> Result<Option<Value>> {
        let v = self
            .rpc
            .contract_call(
                &self.program_addr,
                "get_validator",
                &[json!(self.validator_addr.display)],
                Some(&self.validator_addr),
            )
            .await
            .context("get_validator")?;
        if v.is_null() {
            return Ok(None);
        }
        // `bond == 0` indicates "not registered" in our schema.
        if v.get("bond").and_then(|x| x.as_u64()).unwrap_or(0) == 0 {
            return Ok(None);
        }
        Ok(Some(v))
    }

    /// Build a `register_validator` call. We construct the inner method-call
    /// payload here; signing the outer transaction is delegated to the
    /// caller via `submit_signed_tx` once the wallet handler signs.
    pub fn build_register_call(
        &self,
        endpoint: &str,
        wg_pubkey: &[u8; 32],
        view_pubkey: &[u8; 32],
        region: &str,
        price_per_mb: u64,
        attest_sig: &[u8],
        bond: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.validator_addr.display,
            "to": self.program_addr.display,
            "method": "register_validator",
            "params": [
                endpoint,
                hex::encode(wg_pubkey),
                hex::encode(view_pubkey),
                region,
                price_per_mb,
                hex::encode(attest_sig),
            ],
            "value": bond,
            "fee": fee,
            "nonce": nonce,
        })
    }

    pub fn build_attest_call(
        &self,
        attest_sig: &[u8],
        fee: u64,
        nonce: u64,
    ) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.validator_addr.display,
            "to": self.program_addr.display,
            "method": "refresh_attestation",
            "params": [hex::encode(attest_sig)],
            "value": 0,
            "fee": fee,
            "nonce": nonce,
        })
    }

    pub fn build_claim_call(
        &self,
        claimed_amount: u64,
        claimed_blind: &[u8; 32],
        stealth_output: &[u8; 32],
        fee: u64,
        nonce: u64,
    ) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.validator_addr.display,
            "to": self.program_addr.display,
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

    pub async fn submit_signed_tx(&self, signed: &Value) -> Result<String> {
        let r = self.rpc.submit(signed).await?;
        debug!(hash = %r.hash, "submitted tx");
        Ok(r.hash)
    }

    pub async fn nonce(&self) -> Result<u64> {
        let b = self.rpc.balance(&self.validator_addr).await?;
        Ok(b.pending_nonce.max(b.nonce))
    }

    pub async fn fee(&self, op: &str) -> Result<u64> {
        let f = self.rpc.recommended_fee(Some(op)).await?;
        Ok(f.recommended)
    }

    /// Sign a constructed call payload with the wallet key. The signing
    /// scheme follows the documented `octra_submit` shape: the caller is
    /// responsible for embedding `signature` and `public_key` fields. We
    /// produce the canonical signed-tx envelope here.
    pub fn sign_call(&self, mut call: Value) -> Result<Value> {
        let canonical = canonical_tx_bytes(&call)?;
        let sig = self.wallet.sign(&canonical);
        let map = call
            .as_object_mut()
            .ok_or_else(|| anyhow!("call must be object"))?;
        map.insert("signature".into(), json!(hex::encode(sig.0)));
        map.insert(
            "public_key".into(),
            json!(hex::encode(self.wallet.public.0)),
        );
        info!(method = %map.get("method").and_then(|v| v.as_str()).unwrap_or("?"), "signed tx");
        Ok(call)
    }
}

/// Canonical serialization for signing. Sorts keys, drops `signature` and
/// `public_key` fields if present, and produces deterministic bytes.
fn canonical_tx_bytes(call: &Value) -> Result<Vec<u8>> {
    let mut clone = call.clone();
    if let Some(map) = clone.as_object_mut() {
        map.remove("signature");
        map.remove("public_key");
    }
    let mut out = Vec::new();
    canonicalize(&clone, &mut out)?;
    Ok(out)
}

fn canonicalize(v: &Value, out: &mut Vec<u8>) -> Result<()> {
    match v {
        Value::Null => out.extend_from_slice(b"n"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"t" } else { b"f" }),
        Value::Number(n) => {
            out.extend_from_slice(b"i");
            out.extend_from_slice(n.to_string().as_bytes());
            out.push(b';');
        }
        Value::String(s) => {
            out.extend_from_slice(b"s");
            out.extend_from_slice(&(s.len() as u32).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(arr) => {
            out.extend_from_slice(b"a");
            out.extend_from_slice(&(arr.len() as u32).to_be_bytes());
            for x in arr {
                canonicalize(x, out)?;
            }
        }
        Value::Object(map) => {
            out.extend_from_slice(b"o");
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
            for k in keys {
                out.extend_from_slice(&(k.len() as u32).to_be_bytes());
                out.extend_from_slice(k.as_bytes());
                canonicalize(&map[k], out)?;
            }
        }
    }
    Ok(())
}
