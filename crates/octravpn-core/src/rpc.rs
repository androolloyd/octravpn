//! Octra JSON-RPC 2.0 client.
//!
//! Implements the subset of methods OctraVPN actually needs (per the
//! developer-docs RPC scheme page):
//!
//!   - node_status           (current epoch)
//!   - octra_balance         (account state)
//!   - octra_recommendedFee  (fee discovery)
//!   - octra_submit          (signed tx submission)
//!   - octra_transaction     (submission status)
//!   - contract_call         (read-only program method)
//!   - octra_compileAmlMulti (used in CI to verify program builds)
//!   - octra_listContracts   (discovery)
//!   - octra_privateTransfer (stealth payment, used by validators on claim)
//!   - octra_stealthOutputs  (used by client/node to discover incoming stealth)
//!   - octra_viewPubkey      (look up stealth view key for a node)
//!
//! All params are positional arrays (per the spec).

use std::time::Duration;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{address::Address, CoreError, CoreResult};

#[derive(Clone)]
pub struct RpcClient {
    endpoint: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    #[allow(dead_code)]
    #[serde(default)]
    jsonrpc: String,
    #[allow(dead_code)]
    #[serde(default)]
    id: u64,
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: Value,
}

impl RpcClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client");
        Self {
            endpoint: endpoint.into(),
            http,
        }
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> CoreResult<T> {
        let req = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        };
        let resp = self
            .http
            .post(&self.endpoint)
            .json(&req)
            .send()
            .await
            .map_err(|e| CoreError::Rpc(format!("send {method}: {e}")))?;
        let resp: RpcResponse<T> = resp
            .json()
            .await
            .map_err(|e| CoreError::Rpc(format!("decode {method}: {e}")))?;
        if let Some(err) = resp.error {
            return Err(CoreError::Rpc(format!(
                "rpc {method} error {}: {}",
                err.code, err.message
            )));
        }
        resp.result
            .ok_or_else(|| CoreError::Rpc(format!("rpc {method}: empty result")))
    }

    pub async fn node_status(&self) -> CoreResult<NodeStatus> {
        self.call("node_status", json!([])).await
    }

    pub async fn balance(&self, addr: &Address) -> CoreResult<BalanceResult> {
        self.call("octra_balance", json!([addr.display])).await
    }

    pub async fn recommended_fee(&self, op_type: Option<&str>) -> CoreResult<FeeResult> {
        let params = match op_type {
            Some(t) => json!([t]),
            None => json!([]),
        };
        self.call("octra_recommendedFee", params).await
    }

    pub async fn contract_call(
        &self,
        program_addr: &Address,
        method: &str,
        params: &[Value],
        caller: Option<&Address>,
    ) -> CoreResult<Value> {
        let mut p = vec![
            json!(program_addr.display),
            json!(method),
            json!(params),
        ];
        if let Some(c) = caller {
            p.push(json!(c.display));
        }
        self.call("contract_call", json!(p)).await
    }

    pub async fn submit(&self, signed_tx: &Value) -> CoreResult<SubmitResult> {
        self.call("octra_submit", json!([signed_tx])).await
    }

    pub async fn transaction(&self, hash: &str) -> CoreResult<Value> {
        self.call("octra_transaction", json!([hash])).await
    }

    pub async fn list_contracts(&self) -> CoreResult<Vec<Value>> {
        self.call("octra_listContracts", json!([])).await
    }

    pub async fn view_pubkey(&self, addr: &Address) -> CoreResult<ViewPubkeyResult> {
        self.call("octra_viewPubkey", json!([addr.display])).await
    }

    pub async fn private_transfer(&self, tx: &Value) -> CoreResult<SubmitResult> {
        self.call("octra_privateTransfer", json!([tx])).await
    }

    pub async fn stealth_outputs(
        &self,
        from_epoch: Option<u64>,
    ) -> CoreResult<Vec<Value>> {
        let params = match from_epoch {
            Some(e) => json!([e]),
            None => json!([]),
        };
        self.call("octra_stealthOutputs", params).await
    }
}

#[derive(Debug, Deserialize)]
pub struct NodeStatus {
    pub epoch: u64,
    #[serde(default)]
    pub validator: Option<String>,
    #[serde(default)]
    pub state_root: Option<String>,
    #[serde(default)]
    pub timestamp: Option<u64>,
    #[serde(default)]
    pub network_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BalanceResult {
    pub formatted: String,
    pub raw: String,
    pub nonce: u64,
    #[serde(default)]
    pub pending_nonce: u64,
    #[serde(default)]
    pub public_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FeeResult {
    pub min: u64,
    pub base: u64,
    pub recommended: u64,
    pub fast: u64,
}

#[derive(Debug, Deserialize)]
pub struct SubmitResult {
    pub hash: String,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ViewPubkeyResult {
    pub view_pubkey: String,
}
