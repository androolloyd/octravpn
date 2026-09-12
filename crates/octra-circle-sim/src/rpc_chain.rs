//! `RpcChain` — the [`MockChain`] impl that drives the real
//! `octra-mock-rpc` HTTP surface (or, eventually, a live Octra node).
//!
//! Mirrors what an operator's Circle would do at runtime: read
//! the v2 OctraVPN session row off chain, submit `settle_claim_v2`
//! signed by the proxy's keypair.

use std::sync::Arc;

use async_trait::async_trait;
use octravpn_core::{
    address::Address,
    rpc::{next_nonce, RpcClient},
    sig::KeyPair,
    tx::sign_call,
};
use serde_json::{json, Value};

use crate::acl::ExitClass;
use crate::chain::{ChainError, MockChain, SessionOnChain, SessionStatus};

/// Drives the real (mock-)Octra RPC as the proxy. Submits
/// `settle_claim_v2` signed by `proxy_kp`; reads session state via
/// `get_session_v2`.
pub struct RpcChain {
    rpc: Arc<RpcClient>,
    program_addr: Address,
    proxy_addr: Address,
    proxy_kp: Arc<KeyPair>,
}

impl RpcChain {
    pub fn new(
        rpc: Arc<RpcClient>,
        program_addr: Address,
        proxy_addr: Address,
        proxy_kp: Arc<KeyPair>,
    ) -> Self {
        Self {
            rpc,
            program_addr,
            proxy_addr,
            proxy_kp,
        }
    }

    pub fn proxy_addr(&self) -> &Address {
        &self.proxy_addr
    }
}

fn class_from_int(v: u64) -> ExitClass {
    if v == 0 {
        ExitClass::Shared
    } else {
        ExitClass::Internal
    }
}

fn status_from_int(v: u64) -> SessionStatus {
    match v {
        0 => SessionStatus::Open,
        1 => SessionStatus::Settled,
        _ => SessionStatus::Refunded,
    }
}

fn val_u64(v: &Value, key: &str) -> Result<u64, ChainError> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| ChainError::Rpc(format!("session view missing u64 `{key}`")))
}

fn val_str(v: &Value, key: &str) -> Result<String, ChainError> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| ChainError::Rpc(format!("session view missing string `{key}`")))
}

#[async_trait]
impl MockChain for RpcChain {
    async fn get_session(&self, sid: u64) -> Result<SessionOnChain, ChainError> {
        let v = self
            .rpc
            .contract_call(&self.program_addr, "get_session_v2", &[json!(sid)], None)
            .await
            .map_err(|e| ChainError::Rpc(e.to_string()))?;
        // The mock returns `null` for missing sessions; surface that as
        // SessionNotFound rather than a generic parse error.
        if v.is_null() {
            return Err(ChainError::SessionNotFound(sid));
        }
        // Sessions whose `opener` is empty / sid==0 also indicate missing.
        let opener = val_str(&v, "opener").unwrap_or_default();
        if opener.is_empty() {
            return Err(ChainError::SessionNotFound(sid));
        }
        Ok(SessionOnChain {
            session_id: val_u64(&v, "session_id").unwrap_or(sid),
            tailnet_id: val_u64(&v, "tailnet_id")?,
            opener,
            proxy: val_str(&v, "proxy")?,
            class: class_from_int(val_u64(&v, "class").unwrap_or(0)),
            price_per_mb: val_u64(&v, "price_per_mb").unwrap_or(0),
            deposit: val_u64(&v, "deposit").unwrap_or(0),
            status: status_from_int(val_u64(&v, "status").unwrap_or(0)),
        })
    }

    async fn submit_settle_claim(&self, sid: u64, bytes_used: u64) -> Result<(), ChainError> {
        let bal = self
            .rpc
            .balance(&self.proxy_addr)
            .await
            .map_err(|e| ChainError::Rpc(format!("balance: {e}")))?;
        let fee = self
            .rpc
            .recommended_fee(Some("contract_call"))
            .await
            .map_err(|e| ChainError::Rpc(format!("recommended_fee: {e}")))?
            .recommended;
        let call = json!({
            "kind": "contract_call",
            "from": self.proxy_addr.display(),
            "to": self.program_addr.display(),
            "method": "settle_claim_v2",
            "params": [sid, bytes_used],
            "value": 0u64,
            "fee": fee,
            "nonce": next_nonce(&bal),
        });
        let signed = sign_call(&self.proxy_kp, call)
            .map_err(|e| ChainError::Rpc(format!("sign_call: {e}")))?;
        self.rpc
            .submit(&signed)
            .await
            .map_err(|e| ChainError::Rpc(format!("submit: {e}")))?;
        Ok(())
    }
}
