//! In-memory mock of the Octra JSON-RPC surface OctraVPN exercises.
//!
//! Implements just enough of the documented method surface for the
//! e2e tests: register/attest validators, open/settle/refund sessions,
//! claim earnings, list active validators, fetch tx events.
//!
//! The mock advances epoch by one each accepted submission so
//! attestation grace logic can be exercised in tests.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};

use axum::{
    extract::State,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use parking_lot::RwLock;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint,
    scalar::Scalar, traits::Identity,
};

fn scalar_from_canonical_bytes(b: [u8; 32]) -> Option<Scalar> {
    let ct = Scalar::from_canonical_bytes(b);
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

#[derive(Clone, Default)]
pub struct ChainState {
    pub epoch: u64,
    pub validators: HashMap<String, ValidatorRow>,
    pub sessions: HashMap<String, SessionRow>,
    pub balances: HashMap<String, u64>,
    pub txs: HashMap<String, TxRow>,
    pub stealth_outputs: Vec<Value>,
    pub earnings: HashMap<String, RistrettoPoint>,
}

#[derive(Clone)]
pub struct ValidatorRow {
    pub addr: String,
    pub bond: u64,
    pub endpoint: String,
    pub wg_pubkey: String,
    pub view_pubkey: String,
    pub region: String,
    pub price_per_mb: u64,
    pub registered_at: u64,
    pub last_attest_epoch: u64,
    pub jailed_at: u64,
    pub reputation: i64,
}

#[derive(Clone)]
pub struct SessionRow {
    pub deposit: u64,
    pub opened_at: u64,
    pub status: u8, // 0 open, 1 settled, 2 refunded, 3 slashed
    pub last_seq: u64,
    pub route_commit: Vec<String>,
    pub client_session_pubkey: String,
    pub refund_stealth_output: String,
}

#[derive(Clone)]
pub struct TxRow {
    pub method: String,
    pub from: String,
    pub events: Vec<Value>,
    pub status: String,
}

#[derive(Clone)]
pub struct AppState {
    pub state: Arc<RwLock<ChainState>>,
    pub program_addr: String,
}

pub fn build_router(app: AppState) -> Router {
    Router::new()
        .route("/rpc", post(rpc_handler))
        .with_state(app)
}

#[derive(Deserialize)]
struct RpcReq {
    #[serde(default)]
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

async fn rpc_handler(
    State(app): State<AppState>,
    Json(req): Json<RpcReq>,
) -> impl IntoResponse {
    let _ = req.jsonrpc;
    let result = match req.method.as_str() {
        "node_status" => Ok(node_status(&app)),
        "octra_balance" => octra_balance(&app, &req.params),
        "octra_recommendedFee" => Ok(json!({
            "min": 1, "base": 5, "recommended": 10, "fast": 25
        })),
        "octra_submit" => octra_submit(&app, &req.params),
        "octra_transaction" => octra_transaction(&app, &req.params),
        "octra_listContracts" => Ok(json!([{
            "address": app.program_addr,
            "name": "OctraVPN"
        }])),
        "contract_call" => contract_call(&app, &req.params),
        "octra_viewPubkey" => Ok(json!({"view_pubkey": "00".repeat(32)})),
        "octra_privateTransfer" => Ok(json!({"hash": "deadbeef"})),
        "octra_stealthOutputs" => {
            let s = app.state.read();
            Ok(json!(s.stealth_outputs))
        }
        _ => Err(format!("unknown method: {}", req.method)),
    };
    match result {
        Ok(r) => Json(json!({"jsonrpc": "2.0", "id": req.id, "result": r})),
        Err(e) => Json(json!({
            "jsonrpc": "2.0",
            "id": req.id,
            "error": { "code": -32000, "message": e }
        })),
    }
}

fn node_status(app: &AppState) -> Value {
    let s = app.state.read();
    json!({
        "epoch": s.epoch,
        "validator": null,
        "state_root": "00".repeat(32),
        "timestamp": 0,
        "network_version": "mock-1.0",
    })
}

fn octra_balance(app: &AppState, params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let addr = arr.first().and_then(|x| x.as_str()).ok_or("addr missing")?;
    let s = app.state.read();
    let b = s.balances.get(addr).copied().unwrap_or(1_000_000_000);
    Ok(json!({
        "formatted": (b as f64 / 1e9).to_string(),
        "raw": b.to_string(),
        "nonce": 0u64,
        "pending_nonce": 0u64,
        "public_key": null,
    }))
}

fn h_generator() -> RistrettoPoint {
    use sha2::Sha512;
    let mut h = Sha512::new();
    h.update(b"octravpn-earnings-H-v1");
    RistrettoPoint::from_uniform_bytes(&h.finalize().into())
}

fn octra_submit(app: &AppState, params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let tx = arr.first().ok_or("tx missing")?;
    let method = tx
        .get("method")
        .and_then(|x| x.as_str())
        .ok_or("method missing")?
        .to_string();
    let from = tx
        .get("from")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let mut hash_bytes = Sha256::new();
    hash_bytes.update(serde_json::to_vec(tx).unwrap_or_default());
    let hash = hex::encode(hash_bytes.finalize());

    let events = match method.as_str() {
        "register_validator" => apply_register(app, tx, &from)?,
        "refresh_attestation" => apply_attest(app, &from)?,
        "open_session" => apply_open_session(app, tx, &from, &hash)?,
        "settle_session" => apply_settle(app, tx)?,
        "claim_no_show" => apply_claim_no_show(app, tx)?,
        "claim_earnings" => apply_claim_earnings(app, tx)?,
        _ => Vec::new(),
    };

    {
        let mut s = app.state.write();
        s.txs.insert(
            hash.clone(),
            TxRow {
                method,
                from,
                events,
                status: "confirmed".into(),
            },
        );
        s.epoch += 1;
    }

    Ok(json!({"hash": hash, "status": "confirmed"}))
}

fn apply_register(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx.get("params").and_then(|x| x.as_array()).ok_or("params")?;
    let endpoint = p[0].as_str().unwrap_or("").to_string();
    let wg = p[1].as_str().unwrap_or("").to_string();
    let view = p[2].as_str().unwrap_or("").to_string();
    let region = p[3].as_str().unwrap_or("").to_string();
    let price = p[4].as_u64().unwrap_or(0);
    let bond = tx.get("value").and_then(|x| x.as_u64()).unwrap_or(0);
    let mut s = app.state.write();
    let epoch = s.epoch;
    s.validators.insert(
        from.to_string(),
        ValidatorRow {
            addr: from.to_string(),
            bond,
            endpoint: endpoint.clone(),
            wg_pubkey: wg,
            view_pubkey: view,
            region: region.clone(),
            price_per_mb: price,
            registered_at: epoch,
            last_attest_epoch: epoch,
            jailed_at: 0,
            reputation: 0,
        },
    );
    s.earnings.insert(from.to_string(), RistrettoPoint::identity());
    Ok(vec![json!({
        "name": "ValidatorRegistered",
        "validator": from,
        "bond": bond,
        "endpoint": endpoint,
        "region": region,
    })])
}

fn apply_attest(app: &AppState, from: &str) -> Result<Vec<Value>, String> {
    let mut s = app.state.write();
    let epoch = s.epoch;
    let v = s.validators.get_mut(from).ok_or("validator not registered")?;
    v.last_attest_epoch = epoch;
    Ok(vec![json!({
        "name": "AttestationRefreshed",
        "validator": from,
        "epoch": epoch,
    })])
}

fn apply_open_session(
    app: &AppState,
    tx: &Value,
    _from: &str,
    hash: &str,
) -> Result<Vec<Value>, String> {
    let p = tx.get("params").and_then(|x| x.as_array()).ok_or("params")?;
    let route_commit = p[0]
        .as_array()
        .ok_or("route_commit not array")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect::<Vec<_>>();
    let csp = p[1].as_str().unwrap_or("").to_string();
    let stealth = p[2].as_str().unwrap_or("").to_string();
    let deposit = tx.get("value").and_then(|x| x.as_u64()).unwrap_or(0);

    let mut h = Sha256::new();
    h.update(b"octravpn-session");
    h.update(hash.as_bytes());
    let sid = hex::encode(h.finalize());

    let mut s = app.state.write();
    let opened_at = s.epoch;
    s.sessions.insert(
        sid.clone(),
        SessionRow {
            deposit,
            opened_at,
            status: 0,
            last_seq: 0,
            route_commit: route_commit.clone(),
            client_session_pubkey: csp,
            refund_stealth_output: stealth,
        },
    );

    Ok(vec![json!({
        "name": "SessionOpened",
        "session_id": sid,
        "hops": route_commit.len(),
        "deposit": deposit,
        "opened_at": opened_at,
    })])
}

fn apply_settle(app: &AppState, tx: &Value) -> Result<Vec<Value>, String> {
    let p = tx.get("params").and_then(|x| x.as_array()).ok_or("params")?;
    let sid = p[0].as_str().unwrap_or("").to_string();
    let seq = p[1].as_u64().unwrap_or(0);
    let bytes_used = p[2].as_u64().unwrap_or(0);
    let blind_hex = p[3].as_str().unwrap_or("");
    let openings = p[6]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let blind_bytes = hex::decode(blind_hex).map_err(|e| format!("blind hex: {e}"))?;
    if blind_bytes.len() != 32 {
        return Err("blind not 32 bytes".into());
    }
    let mut blind_arr = [0u8; 32];
    blind_arr.copy_from_slice(&blind_bytes);
    let blind_scalar = scalar_from_canonical_bytes(blind_arr)
        .ok_or_else(|| "blind not canonical".to_string())?;

    let mut s = app.state.write();
    let sess = s.sessions.get_mut(&sid).ok_or("session not found")?;
    if sess.status != 0 {
        return Err("session not open".into());
    }
    if seq <= sess.last_seq {
        return Err("seq not monotonic".into());
    }
    sess.status = 1;
    sess.last_seq = seq;

    let deposit = sess.deposit;
    let mut total_paid: u64 = 0;
    for op in &openings {
        let node_addr = op
            .get("node_addr")
            .and_then(|x| x.as_str())
            .ok_or("opening node_addr")?;
        let split_bps = op
            .get("split_bps")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let v = s
            .validators
            .get(node_addr)
            .ok_or("opening node not registered")?;
        let pay_v = bytes_used
            .checked_mul(v.price_per_mb)
            .ok_or("overflow pay")?
            .checked_mul(split_bps)
            .ok_or("overflow split")?
            / 10_000;
        total_paid = total_paid
            .checked_add(pay_v)
            .ok_or("overflow total")?;
        let entry = s.earnings.entry(node_addr.to_string()).or_insert_with(RistrettoPoint::identity);
        let scalar_pay = Scalar::from(pay_v);
        let g = &scalar_pay * RISTRETTO_BASEPOINT_TABLE;
        let h = blind_scalar * h_generator();
        *entry += g + h;
    }
    if total_paid > deposit {
        return Err("claim exceeds escrow".into());
    }
    let refund = deposit - total_paid;

    Ok(vec![json!({
        "name": "SessionSettled",
        "session_id": sid,
        "seq": seq,
        "total_paid": total_paid,
        "refund": refund,
    })])
}

fn apply_claim_no_show(app: &AppState, tx: &Value) -> Result<Vec<Value>, String> {
    let p = tx.get("params").and_then(|x| x.as_array()).ok_or("params")?;
    let sid = p[0].as_str().unwrap_or("").to_string();
    let mut s = app.state.write();
    let sess = s.sessions.get_mut(&sid).ok_or("session not found")?;
    sess.status = 2;
    Ok(vec![json!({
        "name": "SessionRefunded",
        "session_id": sid,
        "reason": "no-show",
    })])
}

fn apply_claim_earnings(app: &AppState, tx: &Value) -> Result<Vec<Value>, String> {
    let p = tx.get("params").and_then(|x| x.as_array()).ok_or("params")?;
    let claimed = p[0].as_u64().unwrap_or(0);
    let blind_hex = p[1].as_str().unwrap_or("");
    let stealth = p[2].as_str().unwrap_or("").to_string();

    let blind_bytes = hex::decode(blind_hex).map_err(|e| format!("blind: {e}"))?;
    if blind_bytes.len() != 32 {
        return Err("blind not 32".into());
    }
    let mut blind_arr = [0u8; 32];
    blind_arr.copy_from_slice(&blind_bytes);
    let blind_scalar = scalar_from_canonical_bytes(blind_arr)
        .ok_or_else(|| "blind not canonical".to_string())?;

    let from = tx
        .get("from")
        .and_then(|x| x.as_str())
        .ok_or("from missing")?
        .to_string();

    let mut s = app.state.write();
    let entry = s
        .earnings
        .get(&from)
        .copied()
        .unwrap_or_else(RistrettoPoint::identity);
    let scalar_claimed = Scalar::from(claimed);
    let recomputed =
        &scalar_claimed * RISTRETTO_BASEPOINT_TABLE + blind_scalar * h_generator();
    if entry != recomputed {
        return Err("bad opening".into());
    }
    s.earnings.insert(from.clone(), RistrettoPoint::identity());
    s.stealth_outputs.push(json!({
        "to": stealth,
        "amount": claimed,
    }));

    Ok(vec![json!({
        "name": "EarningsClaimed",
        "validator": from,
        "amount": claimed,
    })])
}

fn octra_transaction(app: &AppState, params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let hash = arr.first().and_then(|x| x.as_str()).ok_or("hash missing")?;
    let s = app.state.read();
    let row = s.txs.get(hash).ok_or("not found")?;
    Ok(json!({
        "hash": hash,
        "method": row.method,
        "from": row.from,
        "status": row.status,
        "events": row.events,
    }))
}

fn contract_call(app: &AppState, params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let _addr = arr[0].as_str().ok_or("addr missing")?;
    let method = arr[1].as_str().ok_or("method missing")?;
    let pp = arr[2].as_array().cloned().unwrap_or_default();
    match method {
        "list_active_validators" => {
            let s = app.state.read();
            let active: Vec<String> = s
                .validators
                .values()
                .filter(|v| v.bond > 0 && v.jailed_at == 0)
                .map(|v| v.addr.clone())
                .collect();
            Ok(json!(active))
        }
        "get_validator" => {
            let addr = pp.first().and_then(|x| x.as_str()).ok_or("addr")?;
            let s = app.state.read();
            match s.validators.get(addr) {
                Some(v) => Ok(json!({
                    "bond": v.bond,
                    "endpoint": v.endpoint,
                    "wg_pubkey": v.wg_pubkey,
                    "view_pubkey": v.view_pubkey,
                    "region": v.region,
                    "price_per_mb": v.price_per_mb,
                    "registered_at": v.registered_at,
                    "last_attest_epoch": v.last_attest_epoch,
                    "jailed_at": v.jailed_at,
                    "reputation": v.reputation,
                })),
                None => Ok(json!({"bond": 0})),
            }
        }
        "get_session" => {
            let sid = pp.first().and_then(|x| x.as_str()).ok_or("sid")?;
            let s = app.state.read();
            match s.sessions.get(sid) {
                Some(sess) => Ok(json!({
                    "deposit": sess.deposit,
                    "opened_at": sess.opened_at,
                    "status": sess.status,
                    "last_seq": sess.last_seq,
                    "route_commit": sess.route_commit,
                    "client_session_pubkey": sess.client_session_pubkey,
                    "refund_stealth_output": sess.refund_stealth_output,
                })),
                None => Ok(json!(null)),
            }
        }
        "get_encrypted_earnings" => {
            let addr = pp.first().and_then(|x| x.as_str()).ok_or("addr")?;
            let s = app.state.read();
            let p = s
                .earnings
                .get(addr)
                .copied()
                .unwrap_or_else(RistrettoPoint::identity);
            Ok(json!(hex::encode(p.compress().to_bytes())))
        }
        "get_params" => Ok(json!({
            "min_bond": 100,
            "min_session_deposit": 10,
            "attest_grace_epochs": 5,
            "session_grace_epochs": 100,
            "unbond_epochs": 10,
            "slash_bounty_bps": 1000,
            "slash_burn_bps": 5000,
            "slash_treasury_bps": 4000,
        })),
        other => Err(format!("unknown read method {other}")),
    }
}

pub async fn serve(addr: SocketAddr, program_addr: String) -> anyhow::Result<()> {
    let app = AppState {
        state: Arc::new(RwLock::new(ChainState {
            epoch: 1,
            ..Default::default()
        })),
        program_addr,
    };
    let router = build_router(app);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(?addr, "mock RPC listening");
    axum::serve(listener, router).await?;
    Ok(())
}
