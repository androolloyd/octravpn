//! A pragmatic JSON-RPC dispatcher used by every subcommand.
//!
//! Why not just `octravpn_core::rpc::RpcClient`? Two reasons:
//!
//!   1. The CLI needs to make arbitrary-method calls (`cast rpc`), not
//!      only the typed surface in `octravpn-core`. We dispatch raw
//!      `(method, params)` pairs and return raw `Value`.
//!   2. We want the same code path for integration tests, which run
//!      against the in-process `octravpn_mock_rpc` without any network.
//!      `Endpoint::InProcess` carries an `AppState` we can poke
//!      directly via `submit_tx` / `contract_call`-equivalent reads.
//!
//! For HTTP endpoints, this is a thin wrapper around `reqwest`. The
//! retry policy lives one level up — at the call site — because
//! different subcommands want different timeouts.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use octravpn_mock_rpc::AppState;
use parking_lot::RwLock;
use serde_json::{json, Value};

/// Where to talk to. `Url` -> HTTP JSON-RPC. `InProcess` -> direct
/// function call into the mock with no IO.
#[derive(Clone)]
pub enum Endpoint {
    Url(String),
    InProcess(AppState),
}

/// Convenience constructor for tests: build a fresh in-process endpoint
/// with epoch=1 and the given program address.
pub fn in_process(program_addr: impl Into<String>) -> Endpoint {
    let app = AppState {
        state: Arc::new(RwLock::new(octravpn_mock_rpc::ChainState {
            epoch: 1,
            ..Default::default()
        })),
        program_addr: program_addr.into(),
    };
    Endpoint::InProcess(app)
}

/// Build an endpoint from a URL. URLs starting with `inprocess://<prog>`
/// resolve to a fresh in-memory mock; useful for integration tests.
pub fn endpoint_from_url(url: &str) -> Endpoint {
    if let Some(prog) = url.strip_prefix("inprocess://") {
        in_process(prog)
    } else {
        Endpoint::Url(url.to_string())
    }
}

/// Make a JSON-RPC call. For the in-process backend, only the methods
/// the mock implements are routed; everything else returns an error
/// matching the HTTP backend's behaviour.
///
/// `params` is taken by value so call sites can use the ergonomic
/// `json!([...])` literal directly without an extra `&` everywhere.
#[allow(clippy::needless_pass_by_value)]
pub fn call(endpoint: &Endpoint, method: &str, params: Value) -> Result<Value> {
    match endpoint {
        Endpoint::Url(url) => call_http(url, method, &params),
        Endpoint::InProcess(app) => call_in_process(app, method, &params),
    }
}

fn call_http(url: &str, method: &str, params: &Value) -> Result<Value> {
    // Run the entire HTTP roundtrip inside a fresh single-thread tokio
    // runtime. reqwest 0.12 stores its connector behind a tokio handle,
    // so every call — build, send, json-decode — must happen inside
    // `block_on(...)` or it panics with "there is no reactor running".
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build blocking runtime")?;
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let url = url.to_string();
    let method = method.to_string();
    runtime.block_on(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("build reqwest client")?;
        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        let v: Value = resp
            .json()
            .await
            .with_context(|| format!("decode response for {method}"))?;
        if let Some(err) = v.get("error") {
            return Err(anyhow!(
                "rpc {method} failed: {}",
                serde_json::to_string(err).unwrap_or_default()
            ));
        }
        if !status.is_success() {
            return Err(anyhow!("rpc {method}: HTTP {status}"));
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    })
}

fn call_in_process(app: &AppState, method: &str, params: &Value) -> Result<Value> {
    match method {
        "node_status" => Ok(json!({
            "epoch": app.state.read().epoch,
            "validator": null,
            "state_root": "00".repeat(32),
            "timestamp": 0,
            "network_version": "in-process-mock",
        })),
        "octra_balance" => Ok(json!({
            "formatted": "1000.0",
            "raw": "1000000000",
            "nonce": 0u64,
            "pending_nonce": 0u64,
            "public_key": Value::Null,
        })),
        "octra_recommendedFee" => Ok(json!({
            "min": 1u64, "base": 5u64, "recommended": 10u64, "fast": 25u64
        })),
        "octra_submit" => {
            let arr = params.as_array().ok_or_else(|| anyhow!("params not array"))?;
            let tx = arr.first().ok_or_else(|| anyhow!("tx missing"))?;
            let (hash, _events) = octravpn_mock_rpc::submit_tx(app, tx)
                .map_err(|e| anyhow!("submit failed: {e}"))?;
            Ok(json!({"hash": hash, "status": "confirmed"}))
        }
        "octra_transaction" => {
            let arr = params.as_array().ok_or_else(|| anyhow!("params not array"))?;
            let hash = arr
                .first()
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow!("hash missing"))?;
            let s = app.state.read();
            let row = s
                .txs
                .get(hash)
                .ok_or_else(|| anyhow!("tx not found: {hash}"))?;
            Ok(json!({
                "hash": hash,
                "method": row.method,
                "from": row.from,
                "status": row.status,
                "events": row.events,
            }))
        }
        "contract_call" => {
            let arr = params.as_array().ok_or_else(|| anyhow!("params not array"))?;
            let method = arr
                .get(1)
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow!("method missing"))?;
            let p = arr.get(2).cloned().unwrap_or_else(|| json!([]));
            let p_arr = p.as_array().cloned().unwrap_or_default();
            octravpn_mock_rpc::read_call(app, method, &p_arr)
                .map_err(|e| anyhow!("read failed: {e}"))
        }
        "octra_listContracts" => Ok(json!([{
            "address": app.program_addr,
            "name": "OctraVPN"
        }])),
        "octra_compileAml" | "octra_compileAmlMulti" | "epoch_get" => {
            // The in-process branch reuses the same compile / epoch stubs
            // by going through the HTTP router. To avoid a real server,
            // we directly call the helpers via a synthetic dispatch.
            in_process_extras(app, method, params)
        }
        "octra_isValidator" => {
            let addr = params
                .as_array()
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Ok(json!(app.state.read().octra_validators.contains(addr)))
        }
        "octra_test_grantValidator" => {
            if let Some(addr) = params
                .as_array()
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
            {
                app.add_octra_validator(addr);
            }
            Ok(Value::Bool(true))
        }
        "octra_test_revokeValidator" => {
            if let Some(addr) = params
                .as_array()
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
            {
                app.remove_octra_validator(addr);
            }
            Ok(Value::Bool(true))
        }
        other => Err(anyhow!("unknown method in mock: {other}")),
    }
}

fn in_process_extras(app: &AppState, method: &str, params: &Value) -> Result<Value> {
    // The mock keeps its compile helpers private; the cleanest way to
    // share their behaviour is to hit the same code path via a small
    // round-trip through `serve()`-equivalent dispatch. Since they're
    // pure functions of `(method, params)`, we duplicate the minimal
    // shape here. Keeping them in sync with the mock is part of the
    // mock's contract and asserted via integration tests.
    match method {
        "octra_compileAml" => Ok(mock_compile_one(params)?),
        "octra_compileAmlMulti" => Ok(mock_compile_multi(params)?),
        "epoch_get" => {
            let id = params
                .as_array()
                .and_then(|a| a.first())
                .and_then(serde_json::Value::as_u64);
            let s = app.state.read();
            let epoch = id.unwrap_or(s.epoch);
            Ok(json!({
                "epoch_id": epoch,
                "finalized_by": null,
                "tx_count": s.txs.len(),
                "timestamp": 0u64,
            }))
        }
        _ => Err(anyhow!("not an in-process extra: {method}")),
    }
}

fn mock_compile_one(params: &Value) -> Result<Value> {
    let arr = params
        .as_array()
        .ok_or_else(|| anyhow!("params not array"))?;
    let source = arr
        .first()
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("source missing"))?;
    let name = arr
        .get(1)
        .and_then(|x| x.as_str())
        .unwrap_or("Program")
        .to_string();
    Ok(crate::forge::compile::synthesize_artifact(&name, source))
}

fn mock_compile_multi(params: &Value) -> Result<Value> {
    let arr = params
        .as_array()
        .ok_or_else(|| anyhow!("params not array"))?;
    let files = arr
        .first()
        .and_then(|x| x.as_object())
        .ok_or_else(|| anyhow!("files missing"))?;
    let mut out = serde_json::Map::new();
    for (path, val) in files {
        let source = val.as_str().unwrap_or_default();
        let name = crate::forge::compile::infer_program_name(path, source);
        out.insert(path.clone(), crate::forge::compile::synthesize_artifact(&name, source));
    }
    Ok(Value::Object(out))
}
