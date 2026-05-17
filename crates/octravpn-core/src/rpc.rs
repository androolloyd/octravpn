//! Octra JSON-RPC 2.0 client.
//!
//! Implements the subset of methods `OctraVPN` actually needs (per the
//! developer-docs RPC scheme page):
//!
//!   - `node_status`           (current epoch)
//!   - `octra_balance`         (account state)
//!   - `octra_recommendedFee`  (fee discovery)
//!   - `octra_submit`          (signed tx submission)
//!   - `octra_transaction`     (submission status)
//!   - `contract_call`         (read-only program method)
//!   - `octra_compileAmlMulti` (used in CI to verify program builds)
//!   - `octra_listContracts`   (discovery)
//!   - `octra_privateTransfer` (stealth payment, used by validators on claim)
//!   - `octra_stealthOutputs`  (used by client/node to discover incoming stealth)
//!   - `octra_viewPubkey`      (look up stealth view key for a node)
//!
//! All params are positional arrays (per the spec).

use std::time::Duration;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{address::Address, CoreError, CoreResult};

/// Heuristic: retry on network/server errors but not on client-side
/// errors (bad params, missing method, invalid signature). Real Octra
/// returns these in the json-rpc `error` field; HTTP 5xx and timeouts
/// are likely transient.
fn is_retryable(e: &CoreError) -> bool {
    if let CoreError::Rpc(msg) = e {
        msg.starts_with("send ") || msg.contains("HTTP 5") || msg.contains("timeout")
    } else {
        false
    }
}

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

    /// Construct an RPC client whose TLS trust roots are *exactly* the
    /// supplied PEM blobs — system trust store is disabled. Use this
    /// when you want to pin to a specific issuer chain (e.g.
    /// LetsEncrypt's ISRG Root X1 for `devnet.octrascan.io`) so that
    /// a compromised CA in the OS / corporate-proxy trust store can't
    /// MITM the chain RPC. Each PEM blob may carry multiple
    /// certificates; an empty `pem_roots` vec falls back to system
    /// trust (caller probably wants `new` in that case).
    ///
    /// P0-2 from docs/v2-threat-model.md.
    pub fn new_with_pinned_roots(
        endpoint: impl Into<String>,
        pem_roots: &[Vec<u8>],
    ) -> CoreResult<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .tls_built_in_root_certs(false);
        for blob in pem_roots {
            // `from_pem_bundle` parses any number of certs from a single
            // PEM blob — operators can ship the whole issuer chain as
            // one file.
            let certs = reqwest::Certificate::from_pem_bundle(blob)
                .map_err(|e| CoreError::Rpc(format!("pinned cert parse: {e}")))?;
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        let http = builder
            .build()
            .map_err(|e| CoreError::Rpc(format!("build pinned tls client: {e}")))?;
        Ok(Self {
            endpoint: endpoint.into(),
            http,
        })
    }

    async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> CoreResult<T> {
        // Exponential backoff with jitter on transient failures (5xx,
        // network errors). Up to 4 attempts, capped at ~3s total wait.
        let mut last_err: Option<CoreError> = None;
        let mut delay_ms: u64 = 100;
        for attempt in 0..4 {
            match self.call_once::<T>(method, &params).await {
                Ok(v) => return Ok(v),
                Err(e) if !is_retryable(&e) => return Err(e),
                Err(e) => {
                    last_err = Some(e);
                    if attempt == 3 {
                        break;
                    }
                    let jitter = (rand::random::<u64>() % 50).saturating_add(1);
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms + jitter)).await;
                    delay_ms = (delay_ms * 2).min(1500);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| CoreError::Rpc(format!("rpc {method}: retries exhausted"))))
    }

    async fn call_once<T: DeserializeOwned>(&self, method: &str, params: &Value) -> CoreResult<T> {
        let req = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method,
            params: params.clone(),
        };
        let resp = self
            .http
            .post(&self.endpoint)
            .json(&req)
            .send()
            .await
            .map_err(|e| CoreError::Rpc(format!("send {method}: {e}")))?;
        let status = resp.status();
        if status.is_server_error() {
            return Err(CoreError::Rpc(format!("rpc {method} HTTP {status}")));
        }
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
        self.call("octra_balance", json!([addr.display()])).await
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
        let raw = self
            .contract_call_raw(program_addr, method, params, caller)
            .await?;
        // Real Octra wraps the return as `{ "result": <value>, "storage": {...} }`.
        // Mock returns bare. Strip + normalise stringified u64 so callers
        // see one shape.
        if let Some(inner) = raw.as_object().and_then(|o| o.get("result")) {
            if let Some(s) = inner.as_str() {
                if let Ok(n) = s.parse::<u64>() {
                    return Ok(json!(n));
                }
            }
            return Ok(inner.clone());
        }
        Ok(raw)
    }

    /// Same as `contract_call`, but returns the raw `{result, storage}`
    /// envelope without unwrapping. Useful when callers need to read
    /// per-field storage entries (e.g. detecting whether a struct-typed
    /// record exists).
    pub async fn contract_call_raw(
        &self,
        program_addr: &Address,
        method: &str,
        params: &[Value],
        caller: Option<&Address>,
    ) -> CoreResult<Value> {
        let mut p = vec![json!(program_addr.display()), json!(method), json!(params)];
        if let Some(c) = caller {
            p.push(json!(c.display()));
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
        self.call("octra_viewPubkey", json!([addr.display()])).await
    }

    pub async fn private_transfer(&self, tx: &Value) -> CoreResult<SubmitResult> {
        self.call("octra_privateTransfer", json!([tx])).await
    }

    pub async fn stealth_outputs(&self, from_epoch: Option<u64>) -> CoreResult<Vec<Value>> {
        let params = match from_epoch {
            Some(e) => json!([e]),
            None => json!([]),
        };
        self.call("octra_stealthOutputs", params).await
    }

    /// Escape hatch for tests / new RPC methods not yet wrapped above.
    /// Returns the raw `result` field on success.
    pub async fn raw_call(&self, method: &str, params: Value) -> CoreResult<Value> {
        self.call(method, params).await
    }

    /// `octra_isValidator(addr)` — true iff `addr` is a current Octra
    /// protocol validator. Used by `register_endpoint` callers as a
    /// pre-check (the program-side gate is the authoritative one).
    pub async fn is_octra_validator(&self, addr: &Address) -> CoreResult<bool> {
        self.call("octra_isValidator", json!([addr.display()]))
            .await
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

/// Balance result. Devnet returns `{"balance":"99.997000",
/// "balance_raw":"99997000", "nonce":..., "pending_nonce":...,
/// "address":"...", "has_public_key":...}`. The in-process mock has
/// historically used `formatted`/`raw`. Custom deserialize accepts
/// both.
#[derive(Debug)]
pub struct BalanceResult {
    pub formatted: String,
    pub raw: String,
    pub nonce: u64,
    pub pending_nonce: u64,
    pub public_key: Option<String>,
}

impl<'de> Deserialize<'de> for BalanceResult {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = Value::deserialize(d)?;
        let pick_str = |a: &str, b: &str| -> String {
            v.get(a)
                .or_else(|| v.get(b))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string()
        };
        let pick_u64 = |k: &str| -> u64 {
            v.get(k)
                .and_then(|x| {
                    x.as_u64()
                        .or_else(|| x.as_str().and_then(|s| s.parse::<u64>().ok()))
                })
                .unwrap_or(0)
        };
        Ok(Self {
            formatted: pick_str("balance", "formatted"),
            raw: pick_str("balance_raw", "raw"),
            nonce: pick_u64("nonce"),
            pending_nonce: pick_u64("pending_nonce"),
            public_key: v
                .get("public_key")
                .and_then(|x| x.as_str().map(str::to_string)),
        })
    }
}

/// Real Octra's `octra_recommendedFee` returns string fields:
/// `{"minimum":"1000","recommended":"1000","fast":"2000"}`. The
/// in-process mock returns `min`/`base`/`recommended`/`fast` as u64.
/// Accept both via custom parsing in `Deserialize`.
#[derive(Debug)]
pub struct FeeResult {
    pub min: u64,
    pub base: u64,
    pub recommended: u64,
    pub fast: u64,
}

impl<'de> Deserialize<'de> for FeeResult {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = Value::deserialize(d)?;
        let pick = |k: &str| -> u64 {
            v.get(k)
                .and_then(|x| {
                    x.as_u64()
                        .or_else(|| x.as_str().and_then(|s| s.parse::<u64>().ok()))
                })
                .unwrap_or(0)
        };
        // Devnet uses "minimum"; mock uses "min"/"base".
        let min = if v.get("min").is_some() {
            pick("min")
        } else {
            pick("minimum")
        };
        let base = if v.get("base").is_some() {
            pick("base")
        } else {
            pick("minimum")
        };
        Ok(Self {
            min,
            base,
            recommended: pick("recommended"),
            fast: pick("fast"),
        })
    }
}

/// `octra_submit` returns different field names on the real RPC
/// (`tx_hash`, `status`) vs the in-process mock (`hash`).
#[derive(Debug, Deserialize)]
pub struct SubmitResult {
    #[serde(alias = "tx_hash")]
    pub hash: String,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ViewPubkeyResult {
    pub view_pubkey: String,
}
