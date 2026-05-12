//! In-memory mock of the Octra JSON-RPC surface OctraVPN exercises.
//!
//! Implements the tailnet model: endpoint registration gated on the
//! caller being an Octra protocol validator (the `octra_validators`
//! set inside `ChainState`); tailnets with treasuries and member sets;
//! sessions scoped to tailnets.
//!
//! The mock advances epoch by one each accepted submission so any
//! epoch-driven logic can be exercised in tests.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use axum::{extract::State, response::IntoResponse, routing::post, Json, Router};
use parking_lot::RwLock;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use octravpn_core::{
    coverage as cov,
    earnings::{h_generator, scalar_from_bytes},
};

/// Local shim so handler call sites read `coverage::record(...)`.
mod coverage {
    pub(crate) fn record(method: &str, branch: &str) {
        super::cov::record(method, branch);
    }
}

#[derive(Clone, Default)]
pub struct ChainState {
    pub epoch: u64,
    /// Addresses currently registered as protocol-level Octra validators.
    /// Kept on the RPC surface for clients that still resolve identity
    /// via Octra; the OctraVPN AML no longer gates on this.
    pub octra_validators: HashSet<String>,
    pub endpoints: HashMap<String, EndpointRow>,
    /// In-program operator stake. Required for `register_endpoint`.
    pub endpoint_stake: HashMap<String, u64>,
    /// In-flight unbonding requests: `(stake, unlock_epoch)`.
    pub endpoint_unbonding: HashMap<String, (u64, u64)>,
    /// Permanent slashed flag — once set, that address can never
    /// re-register or re-bond.
    pub endpoint_slashed: HashSet<String>,
    /// Program treasury (Tier 2 protocol fee + burn share of slashes).
    pub program_treasury: u64,
    pub tailnets: HashMap<String, TailnetRow>,
    pub sessions: HashMap<String, SessionRow>,
    /// device_addr → wallet_addr that owns it (multi-device per identity).
    pub device_owner: HashMap<String, String>,
    /// Set of nonces that have been redeemed via `redeem_join_token`.
    pub redeemed_nonces: HashSet<String>,
    /// wallet_addr → published X25519 view pubkey (hex). Senders read
    /// this when composing a stealth payment to a recipient.
    pub view_keys: HashMap<String, String>,
    pub balances: HashMap<String, u64>,
    pub txs: HashMap<String, TxRow>,
    pub stealth_outputs: Vec<Value>,
    pub earnings: HashMap<String, RistrettoPoint>,
}

/// Default operator bond floor mirrored from `program/main.aml`. Matches
/// `Params.min_endpoint_stake = 1_000_000_000` OU.
pub const MIN_ENDPOINT_STAKE: u64 = 1_000_000_000;
/// Default unbond grace mirrored from `program/main.aml`.
pub const UNBOND_GRACE_EPOCHS: u64 = 10_000;
pub const SLASH_BURN_BPS: u64 = 9_000;
pub const SLASH_BOUNTY_BPS: u64 = 1_000;
pub const PROTOCOL_FEE_BPS: u64 = 50;

#[derive(Clone)]
pub struct EndpointRow {
    pub addr: String,
    pub active: bool,
    pub endpoint: String,
    pub wg_pubkey: String,
    pub receipt_pubkey: String,
    pub view_pubkey: String,
    pub region: String,
    pub price_per_mb: u64,
    pub registered_at: u64,
    pub reputation: i64,
}

#[derive(Clone)]
pub struct TailnetRow {
    pub id: String,
    pub owner: String,
    pub treasury: u64,
    pub members: HashSet<String>,
    pub exits: HashSet<String>,
    pub acl_policy: String,
    pub created_at: u64,
}

#[derive(Clone)]
pub struct SessionRow {
    pub tailnet_id: String,
    pub deposit: u64,
    pub opened_at: u64,
    pub status: u8, // 0 open, 1 settled, 2 refunded
    pub last_seq: u64,
    pub route_commit: Vec<String>,
    pub client_session_pubkey: String,
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

impl AppState {
    /// Test helper: mark `addr` as an Octra protocol validator. This
    /// no longer gates `register_endpoint` (the AML now uses
    /// `endpoint_stake` instead) but is preserved for RPC parity and
    /// for tests that exercise the validator-oracle plumbing.
    pub fn add_octra_validator(&self, addr: impl Into<String>) {
        self.state.write().octra_validators.insert(addr.into());
    }

    /// Test helper: remove `addr` from the Octra validator set.
    pub fn remove_octra_validator(&self, addr: &str) {
        self.state.write().octra_validators.remove(addr);
    }

    /// Test helper: directly seed an operator's stake without routing
    /// through `bond_endpoint`. Used by harnesses that want to skip the
    /// economic bootstrap and exercise post-bond entrypoints.
    pub fn seed_endpoint_stake(&self, addr: impl Into<String>, amount: u64) {
        let addr = addr.into();
        let mut s = self.state.write();
        *s.endpoint_stake.entry(addr).or_insert(0) += amount;
    }
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

async fn rpc_handler(State(app): State<AppState>, Json(req): Json<RpcReq>) -> impl IntoResponse {
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
        "octra_isValidator" => Ok(octra_is_validator(&app, &req.params)),
        // Test-only helpers — present in the mock so e2e tests can
        // pre-seed protocol-validator membership and operator stake
        // over the wire.
        "octra_test_grantValidator" => Ok(test_grant_validator(&app, &req.params)),
        "octra_test_revokeValidator" => Ok(test_revoke_validator(&app, &req.params)),
        "octra_test_bondEndpoint" => Ok(test_bond_endpoint(&app, &req.params)),
        "contract_call" => contract_call(&app, &req.params),
        "octra_viewPubkey" => Ok(json!({"view_pubkey": "00".repeat(32)})),
        "octra_privateTransfer" => Ok(json!({"hash": "deadbeef"})),
        "octra_stealthOutputs" => {
            let s = app.state.read();
            Ok(json!(s.stealth_outputs))
        }
        "octra_compileAml" => octra_compile_aml(&req.params),
        "octra_compileAmlMulti" => octra_compile_aml_multi(&req.params),
        "epoch_get" => Ok(epoch_get(&app, &req.params)),
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

fn octra_is_validator(app: &AppState, params: &Value) -> Value {
    let addr = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or("");
    json!(app.state.read().octra_validators.contains(addr))
}

fn test_grant_validator(app: &AppState, params: &Value) -> Value {
    if let Some(addr) = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
    {
        app.add_octra_validator(addr);
    }
    Value::Bool(true)
}

fn test_revoke_validator(app: &AppState, params: &Value) -> Value {
    if let Some(addr) = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
    {
        app.remove_octra_validator(addr);
    }
    Value::Bool(true)
}

fn test_bond_endpoint(app: &AppState, params: &Value) -> Value {
    let Some(arr) = params.as_array() else {
        return Value::Bool(false);
    };
    let Some(addr) = arr.first().and_then(|v| v.as_str()) else {
        return Value::Bool(false);
    };
    let amount = arr
        .get(1)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(MIN_ENDPOINT_STAKE);
    app.seed_endpoint_stake(addr, amount);
    Value::Bool(true)
}

fn octra_balance(app: &AppState, params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let addr = arr.first().and_then(|x| x.as_str()).ok_or("addr missing")?;
    let s = app.state.read();
    let raw_balance = s.balances.get(addr).copied().unwrap_or(1_000_000_000);
    #[allow(clippy::cast_precision_loss)]
    let formatted = (raw_balance as f64 / 1_000_000.0).to_string();
    Ok(json!({
        "formatted": formatted,
        "raw": raw_balance.to_string(),
        "nonce": 0u64,
        "pending_nonce": 0u64,
        "public_key": null,
    }))
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
        "register_device" => apply_register_device(app, tx, &from)?,
        "revoke_device" => apply_revoke_device(app, tx, &from)?,
        "redeem_join_token" => apply_redeem_join_token(app, tx, &from)?,
        "set_view_pubkey" => apply_set_view_pubkey(app, tx, &from)?,
        "bond_endpoint" => apply_bond_endpoint(app, tx, &from)?,
        "unbond_endpoint" => apply_unbond_endpoint(app, &from)?,
        "finalize_unbond" => apply_finalize_unbond(app, &from)?,
        "submit_equivocation" => apply_submit_equivocation(app, tx, &from)?,
        "register_endpoint" => apply_register_endpoint(app, tx, &from)?,
        "update_endpoint" => apply_update_endpoint(app, tx, &from)?,
        "rotate_keys" => apply_rotate_keys(app, tx, &from)?,
        "retire_endpoint" => apply_retire_endpoint(app, &from)?,
        "create_tailnet" => apply_create_tailnet(app, tx, &from, &hash)?,
        "add_member" => apply_add_member(app, tx, &from)?,
        "remove_member" => apply_remove_member(app, tx, &from)?,
        "deposit_to_tailnet" => apply_deposit_to_tailnet(app, tx, &from)?,
        "configure_tailnet_exit" => apply_configure_tailnet_exit(app, tx, &from)?,
        "update_acl" => apply_update_acl(app, tx, &from)?,
        "open_session" => apply_open_session(app, tx, &from, &hash)?,
        "settle_session" => apply_settle(app, tx)?,
        "claim_no_show" => apply_claim_no_show(app, tx)?,
        "sweep_expired_session" => apply_sweep_expired_session(app, tx, &from)?,
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

// ------------------------ endpoint handlers ------------------------

fn apply_redeem_join_token(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p
        .first()
        .and_then(|x| x.as_str())
        .ok_or("tailnet_id missing")?
        .to_string();
    let expiry = p.get(1).and_then(serde_json::Value::as_u64).unwrap_or(0);
    let nonce = p
        .get(2)
        .and_then(|x| x.as_str())
        .ok_or("nonce missing")?
        .to_string();
    // The mock doesn't verify the owner signature (no on-chain pubkey
    // resolver in the mock); production AML enforces it via
    // `verify_ed25519_acct`. We do enforce expiry + replay.

    let mut s = app.state.write();
    if expiry < s.epoch {
        return Err("token expired".into());
    }
    if s.redeemed_nonces.contains(&nonce) {
        return Err("nonce already redeemed".into());
    }
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    if t.members.contains(from) {
        return Err("already member".into());
    }
    t.members.insert(from.to_string());
    s.redeemed_nonces.insert(nonce.clone());
    Ok(vec![
        json!({
            "name": "TailnetMemberAdded",
            "tailnet_id": tid,
            "member": from,
        }),
        json!({
            "name": "JoinTokenRedeemed",
            "tailnet_id": tid,
            "member": from,
            "nonce": nonce,
        }),
    ])
}

fn apply_set_view_pubkey(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let pubkey = p
        .first()
        .and_then(|x| x.as_str())
        .ok_or("view pubkey missing")?
        .to_string();
    octravpn_core::util::hex_to_array::<32>(&pubkey, "view pubkey")
        .map_err(|_| "view pubkey 32B")?;
    let mut s = app.state.write();
    s.view_keys.insert(from.to_string(), pubkey.clone());
    Ok(vec![json!({
        "name": "ViewPubkeyPublished",
        "wallet": from,
        "view_pubkey": pubkey,
    })])
}

fn apply_register_device(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let device = p
        .first()
        .and_then(|x| x.as_str())
        .ok_or("device addr missing")?
        .to_string();
    let mut s = app.state.write();
    if let Some(existing) = s.device_owner.get(&device) {
        if existing == from {
            return Ok(Vec::new()); // idempotent re-register
        }
        return Err("device already attached to another wallet".into());
    }
    s.device_owner.insert(device.clone(), from.to_string());
    Ok(vec![json!({
        "name": "DeviceRegistered",
        "wallet": from,
        "device": device,
    })])
}

fn apply_revoke_device(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let device = p
        .first()
        .and_then(|x| x.as_str())
        .ok_or("device addr missing")?
        .to_string();
    let mut s = app.state.write();
    match s.device_owner.get(&device) {
        Some(owner) if owner == from => {
            s.device_owner.remove(&device);
            Ok(vec![json!({
                "name": "DeviceRevoked",
                "wallet": from,
                "device": device,
            })])
        }
        Some(_) => Err("not device owner".into()),
        None => Err("device not registered".into()),
    }
}

fn apply_register_endpoint(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let endpoint = p[0].as_str().unwrap_or("").to_string();
    let wg = p[1].as_str().unwrap_or("").to_string();
    let receipt = p[2].as_str().unwrap_or("").to_string();
    let view = p[3].as_str().unwrap_or("").to_string();
    let region = p[4].as_str().unwrap_or("").to_string();
    let price = p[5].as_u64().unwrap_or(0);

    let mut s = app.state.write();
    coverage::record("register_endpoint", "require[1]"); // not slashed
    if s.endpoint_slashed.contains(from) {
        return Err("previously slashed".into());
    }
    coverage::record("register_endpoint", "require[2]"); // has stake
    if s.endpoint_stake.get(from).copied().unwrap_or(0) < MIN_ENDPOINT_STAKE {
        return Err("must bond_endpoint first".into());
    }
    coverage::record("register_endpoint", "require[3]"); // already registered
    if s.endpoints.contains_key(from) {
        return Err("already registered".into());
    }
    coverage::record("register_endpoint", "require[4]"); // price > 0
    if price == 0 {
        return Err("price must be > 0".into());
    }
    let epoch = s.epoch;
    s.endpoints.insert(
        from.to_string(),
        EndpointRow {
            addr: from.to_string(),
            active: true,
            endpoint: endpoint.clone(),
            wg_pubkey: wg,
            receipt_pubkey: receipt,
            view_pubkey: view,
            region: region.clone(),
            price_per_mb: price,
            registered_at: epoch,
            reputation: 0,
        },
    );
    s.earnings
        .insert(from.to_string(), RistrettoPoint::identity());
    Ok(vec![json!({
        "name": "EndpointRegistered",
        "addr": from,
        "endpoint": endpoint,
        "region": region,
    })])
}

fn apply_update_endpoint(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let endpoint = p[0].as_str().unwrap_or("").to_string();
    let region = p[1].as_str().unwrap_or("").to_string();
    let price = p[2].as_u64().unwrap_or(0);

    let mut s = app.state.write();
    let ep = s.endpoints.get_mut(from).ok_or("not registered")?;
    if !ep.active {
        return Err("endpoint retired".into());
    }
    if price == 0 {
        return Err("price must be > 0".into());
    }
    ep.endpoint = endpoint;
    ep.region = region;
    ep.price_per_mb = price;
    Ok(vec![json!({ "name": "EndpointUpdated", "addr": from })])
}

fn apply_rotate_keys(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let wg = p[0].as_str().unwrap_or("").to_string();
    let receipt = p[1].as_str().unwrap_or("").to_string();
    let view = p[2].as_str().unwrap_or("").to_string();
    let mut s = app.state.write();
    let ep = s.endpoints.get_mut(from).ok_or("not registered")?;
    if !ep.active {
        return Err("endpoint retired".into());
    }
    ep.wg_pubkey = wg;
    ep.receipt_pubkey = receipt;
    ep.view_pubkey = view;
    Ok(vec![json!({ "name": "KeysRotated", "addr": from })])
}

fn apply_retire_endpoint(app: &AppState, from: &str) -> Result<Vec<Value>, String> {
    let mut s = app.state.write();
    let ep = s.endpoints.get_mut(from).ok_or("not registered")?;
    ep.active = false;
    Ok(vec![json!({ "name": "EndpointRetired", "addr": from })])
}

// ------------------------- stake / slashing handlers -------------------------

fn apply_bond_endpoint(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    let amount = tx
        .get("value")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if amount == 0 {
        return Err("no value".into());
    }
    let mut s = app.state.write();
    if s.endpoint_slashed.contains(from) {
        return Err("previously slashed".into());
    }
    if s.endpoint_unbonding.contains_key(from) {
        return Err("unbonding in progress".into());
    }
    let cur = s.endpoint_stake.get(from).copied().unwrap_or(0);
    let new_stake = cur.checked_add(amount).ok_or("stake overflow")?;
    s.endpoint_stake.insert(from.to_string(), new_stake);
    Ok(vec![json!({
        "name": "StakeBonded",
        "addr": from,
        "amount": amount,
        "new_stake": new_stake,
    })])
}

fn apply_unbond_endpoint(app: &AppState, from: &str) -> Result<Vec<Value>, String> {
    let mut s = app.state.write();
    let amt = s.endpoint_stake.get(from).copied().unwrap_or(0);
    if amt == 0 {
        return Err("no stake".into());
    }
    if s.endpoint_unbonding.contains_key(from) {
        return Err("already unbonding".into());
    }
    let unlock = s.epoch + UNBOND_GRACE_EPOCHS;
    s.endpoint_unbonding.insert(from.to_string(), (amt, unlock));
    s.endpoint_stake.insert(from.to_string(), 0);
    let mut events = Vec::with_capacity(2);
    if let Some(ep) = s.endpoints.get_mut(from) {
        if ep.active {
            ep.active = false;
            events.push(json!({ "name": "EndpointRetired", "addr": from }));
        }
    }
    events.push(json!({
        "name": "StakeUnbondingStarted",
        "addr": from,
        "stake": amt,
        "unlock_epoch": unlock,
    }));
    Ok(events)
}

fn apply_finalize_unbond(app: &AppState, from: &str) -> Result<Vec<Value>, String> {
    let mut s = app.state.write();
    let (amt, unlock) = s
        .endpoint_unbonding
        .get(from)
        .copied()
        .ok_or("no unbonding")?;
    if s.epoch < unlock {
        return Err("grace not elapsed".into());
    }
    s.endpoint_unbonding.remove(from);
    *s.balances.entry(from.to_string()).or_insert(0) += amt;
    Ok(vec![json!({
        "name": "StakeUnbondingFinalized",
        "addr": from,
        "amount": amt,
    })])
}

fn apply_submit_equivocation(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    use octravpn_core::{
        receipt::Receipt,
        session::{Blind, SessionId},
        sig::{self, PublicKey, Signature},
    };

    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let operator = p[0].as_str().unwrap_or("").to_string();
    let sid_hex = p[1].as_str().unwrap_or("");
    let seq = p[2].as_u64().unwrap_or(0);
    let bytes_a = p[3].as_u64().unwrap_or(0);
    let blind_a_hex = p[4].as_str().unwrap_or("");
    let sig_a_hex = p[5].as_str().unwrap_or("");
    let bytes_b = p[6].as_u64().unwrap_or(0);
    let blind_b_hex = p[7].as_str().unwrap_or("");
    let sig_b_hex = p[8].as_str().unwrap_or("");

    let sid_arr =
        octravpn_core::util::hex_to_array::<32>(sid_hex, "session_id").map_err(|e| e.to_string())?;
    let blind_a_arr = octravpn_core::util::hex_to_array::<32>(blind_a_hex, "blind_a")
        .map_err(|e| e.to_string())?;
    let blind_b_arr = octravpn_core::util::hex_to_array::<32>(blind_b_hex, "blind_b")
        .map_err(|e| e.to_string())?;
    let sig_a_arr =
        octravpn_core::util::hex_to_array::<64>(sig_a_hex, "sig_a").map_err(|e| e.to_string())?;
    let sig_b_arr =
        octravpn_core::util::hex_to_array::<64>(sig_b_hex, "sig_b").map_err(|e| e.to_string())?;

    if bytes_a == bytes_b && blind_a_arr == blind_b_arr {
        return Err("receipts identical — not equivocation".into());
    }

    let pubkey_hex = {
        let s = app.state.read();
        s.endpoints
            .get(&operator)
            .map(|e| e.receipt_pubkey.clone())
            .ok_or("operator not registered")?
    };
    let pubkey_arr = octravpn_core::util::hex_to_array::<32>(&pubkey_hex, "receipt_pubkey")
        .map_err(|e| e.to_string())?;
    let pk = PublicKey(pubkey_arr);

    let r_a = Receipt {
        session_id: SessionId::new(sid_arr),
        seq,
        bytes_used: bytes_a,
        blind: Blind::new(blind_a_arr),
    };
    let r_b = Receipt {
        session_id: SessionId::new(sid_arr),
        seq,
        bytes_used: bytes_b,
        blind: Blind::new(blind_b_arr),
    };
    sig::verify(&pk, &r_a.signing_payload(), &Signature(sig_a_arr))
        .map_err(|_| "bad sig_a".to_string())?;
    sig::verify(&pk, &r_b.signing_payload(), &Signature(sig_b_arr))
        .map_err(|_| "bad sig_b".to_string())?;

    let mut s = app.state.write();
    if s.endpoint_slashed.contains(&operator) {
        return Err("already slashed".into());
    }
    let live = s.endpoint_stake.get(&operator).copied().unwrap_or(0);
    let unb = s.endpoint_unbonding.get(&operator).map_or(0, |(amt, _)| *amt);
    let total = live.checked_add(unb).ok_or("stake overflow")?;
    if total == 0 {
        return Err("no stake to slash".into());
    }
    let burn_amt = total
        .checked_mul(SLASH_BURN_BPS)
        .ok_or("overflow burn")?
        / 10_000;
    let bounty_amt = total - burn_amt;

    s.endpoint_stake.insert(operator.clone(), 0);
    s.endpoint_unbonding.remove(&operator);
    s.endpoint_slashed.insert(operator.clone());
    if let Some(ep) = s.endpoints.get_mut(&operator) {
        ep.active = false;
    }
    s.program_treasury = s
        .program_treasury
        .checked_add(burn_amt)
        .ok_or("overflow treasury")?;
    if bounty_amt > 0 {
        *s.balances.entry(from.to_string()).or_insert(0) += bounty_amt;
    }
    Ok(vec![json!({
        "name": "OperatorSlashed",
        "addr": operator,
        "stake": total,
        "burn_amt": burn_amt,
        "bounty_amt": bounty_amt,
        "submitter": from,
    })])
}

// ------------------------- tailnet handlers -------------------------

fn apply_create_tailnet(
    app: &AppState,
    tx: &Value,
    from: &str,
    hash: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let acl_policy = p
        .first()
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let deposit = tx
        .get("value")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if deposit == 0 {
        return Err("tailnet deposit required".into());
    }

    let mut h = Sha256::new();
    h.update(b"octravpn-tailnet");
    h.update(hash.as_bytes());
    let tid = hex::encode(h.finalize());

    let mut s = app.state.write();
    let created_at = s.epoch;
    let mut members = HashSet::new();
    members.insert(from.to_string());
    s.tailnets.insert(
        tid.clone(),
        TailnetRow {
            id: tid.clone(),
            owner: from.to_string(),
            treasury: deposit,
            members,
            exits: HashSet::new(),
            acl_policy,
            created_at,
        },
    );

    Ok(vec![
        json!({
            "name": "TailnetCreated",
            "tailnet_id": tid,
            "owner": from,
        }),
        json!({
            "name": "TailnetMemberAdded",
            "tailnet_id": tid,
            "member": from,
        }),
    ])
}

fn apply_add_member(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_str().unwrap_or("").to_string();
    let member = p[1].as_str().unwrap_or("").to_string();
    let mut s = app.state.write();
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    if t.owner != from {
        return Err("not tailnet owner".into());
    }
    if t.members.contains(&member) {
        return Err("already member".into());
    }
    t.members.insert(member.clone());
    Ok(vec![json!({
        "name": "TailnetMemberAdded",
        "tailnet_id": tid,
        "member": member,
    })])
}

fn apply_remove_member(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_str().unwrap_or("").to_string();
    let member = p[1].as_str().unwrap_or("").to_string();
    let mut s = app.state.write();
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    if t.owner != from {
        return Err("not tailnet owner".into());
    }
    if member == t.owner {
        return Err("cannot remove owner".into());
    }
    if !t.members.remove(&member) {
        return Err("not member".into());
    }
    Ok(vec![json!({
        "name": "TailnetMemberRemoved",
        "tailnet_id": tid,
        "member": member,
    })])
}

fn apply_deposit_to_tailnet(
    app: &AppState,
    tx: &Value,
    _from: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_str().unwrap_or("").to_string();
    let amount = tx
        .get("value")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if amount == 0 {
        return Err("no value".into());
    }
    let mut s = app.state.write();
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    t.treasury += amount;
    let new_treasury = t.treasury;
    Ok(vec![json!({
        "name": "TailnetDeposit",
        "tailnet_id": tid,
        "amount": amount,
        "new_treasury": new_treasury,
    })])
}

fn apply_configure_tailnet_exit(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_str().unwrap_or("").to_string();
    let exit_addr = p[1].as_str().unwrap_or("").to_string();
    let mut s = app.state.write();
    let exit_active = s.endpoints.get(&exit_addr).is_some_and(|e| e.active);
    if !exit_active {
        return Err("exit not registered or inactive".into());
    }
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    if t.owner != from {
        return Err("not tailnet owner".into());
    }
    t.exits.insert(exit_addr.clone());
    Ok(vec![json!({
        "name": "TailnetExitConfigured",
        "tailnet_id": tid,
        "exit_addr": exit_addr,
    })])
}

fn apply_update_acl(app: &AppState, tx: &Value, from: &str) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_str().unwrap_or("").to_string();
    let new_acl = p[1].as_str().unwrap_or("").to_string();
    let mut s = app.state.write();
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    if t.owner != from {
        return Err("not tailnet owner".into());
    }
    t.acl_policy.clone_from(&new_acl);
    Ok(vec![json!({
        "name": "TailnetAclUpdated",
        "tailnet_id": tid,
        "acl_policy": new_acl,
    })])
}

// ------------------------- session handlers --------------------------

fn apply_open_session(
    app: &AppState,
    tx: &Value,
    from: &str,
    hash: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let tid = p[0].as_str().unwrap_or("").to_string();
    let route_commit = p[1]
        .as_array()
        .ok_or("route_commit not array")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect::<Vec<_>>();
    let csp = p[2].as_str().unwrap_or("").to_string();
    let deposit = p[3].as_u64().unwrap_or(0);

    let mut h = Sha256::new();
    h.update(b"octravpn-session");
    h.update(hash.as_bytes());
    let sid = hex::encode(h.finalize());

    let mut s = app.state.write();
    let opened_at = s.epoch;
    coverage::record("open_session", "require[1]"); // tailnet not found
    // Resolve membership BEFORE taking a mut borrow on the tailnet row,
    // so we can also look up the device-owner map (a sibling field of
    // ChainState).
    let device_owner = s.device_owner.get(from).cloned();
    let t = s.tailnets.get_mut(&tid).ok_or("tailnet not found")?;
    coverage::record("open_session", "require[2]"); // member check
    let direct = t.members.contains(from);
    let via_device = device_owner.as_deref().is_some_and(|w| t.members.contains(w));
    if !direct && !via_device {
        return Err("not a member".into());
    }
    coverage::record("open_session", "require[3]"); // deposit min
    if deposit == 0 {
        return Err("deposit must be > 0".into());
    }
    coverage::record("open_session", "require[4]"); // treasury sufficient
    if t.treasury < deposit {
        return Err("treasury insufficient".into());
    }
    coverage::record("open_session", "require[5]"); // route bounds (1..=3)
    t.treasury -= deposit;

    s.sessions.insert(
        sid.clone(),
        SessionRow {
            tailnet_id: tid.clone(),
            deposit,
            opened_at,
            status: 0,
            last_seq: 0,
            route_commit: route_commit.clone(),
            client_session_pubkey: csp,
        },
    );

    Ok(vec![json!({
        "name": "SessionOpened",
        "session_id": sid,
        "tailnet_id": tid,
        "hops": route_commit.len(),
        "deposit": deposit,
        "opened_at": opened_at,
    })])
}

struct ParsedSettle {
    sid: String,
    seq: u64,
    bytes_used: u64,
    blind_scalar: Scalar,
    openings: Vec<Value>,
}

fn parse_settle_params(tx: &Value) -> Result<ParsedSettle, String> {
    let params = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let sid = params[0].as_str().unwrap_or("").to_string();
    let seq = params[1].as_u64().unwrap_or(0);
    let bytes_used = params[2].as_u64().unwrap_or(0);
    let blind_hex = params[3].as_str().unwrap_or("");
    let openings = params[6].as_array().cloned().unwrap_or_default();
    let blind_bytes = hex::decode(blind_hex).map_err(|e| format!("blind hex: {e}"))?;
    if blind_bytes.len() != 32 {
        return Err("blind not 32 bytes".into());
    }
    let mut blind_arr = [0u8; 32];
    blind_arr.copy_from_slice(&blind_bytes);
    let blind_scalar = scalar_from_bytes(&blind_arr).map_err(|e| format!("blind: {e}"))?;
    Ok(ParsedSettle {
        sid,
        seq,
        bytes_used,
        blind_scalar,
        openings,
    })
}

fn validate_and_advance_session(
    s: &mut ChainState,
    sid: &str,
    seq: u64,
) -> Result<(String, u64), String> {
    let sess = s.sessions.get_mut(sid).ok_or("session not found")?;
    if sess.status != 0 {
        return Err("session not open".into());
    }
    if seq <= sess.last_seq {
        return Err("seq not monotonic".into());
    }
    sess.status = 1;
    sess.last_seq = seq;
    Ok((sess.tailnet_id.clone(), sess.deposit))
}

fn credit_openings(
    s: &mut ChainState,
    bytes_used: u64,
    blind_scalar: Scalar,
    openings: &[Value],
) -> Result<u64, String> {
    // Pass 1: validate each hop + compute gross per-hop pay.
    let mut hops: Vec<(String, u64)> = Vec::with_capacity(openings.len());
    let mut total_paid: u64 = 0;
    for op in openings {
        let node_addr = op
            .get("node_addr")
            .and_then(|x| x.as_str())
            .ok_or("opening node_addr")?;
        let split_bps = op
            .get("split_bps")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let ep = s
            .endpoints
            .get(node_addr)
            .ok_or("opening node not registered")?;
        let has_stake = s
            .endpoint_stake
            .get(node_addr)
            .copied()
            .unwrap_or(0)
            >= MIN_ENDPOINT_STAKE;
        let slashed = s.endpoint_slashed.contains(node_addr);
        if !ep.active || slashed || !has_stake {
            return Err("opening node inactive".into());
        }
        let pay_v = bytes_used
            .checked_mul(ep.price_per_mb)
            .ok_or("overflow pay")?
            .checked_mul(split_bps)
            .ok_or("overflow split")?
            / 10_000;
        total_paid = total_paid.checked_add(pay_v).ok_or("overflow total")?;
        hops.push((node_addr.to_string(), pay_v));
    }
    // Pass 2: apply protocol fee + credit per-hop net pay.
    let protocol_fee = total_paid
        .checked_mul(PROTOCOL_FEE_BPS)
        .ok_or("overflow fee")?
        / 10_000;
    let net_to_hops = total_paid - protocol_fee;
    for (node_addr, gross_pay) in hops {
        let net_pay = if total_paid > 0 {
            // mul-div-safe via u128 to avoid overflow when net_to_hops * gross_pay is large
            (u128::from(gross_pay) * u128::from(net_to_hops) / u128::from(total_paid)) as u64
        } else {
            0
        };
        let entry = s
            .earnings
            .entry(node_addr)
            .or_insert_with(RistrettoPoint::identity);
        let scalar_pay = Scalar::from(net_pay);
        let g = &scalar_pay * RISTRETTO_BASEPOINT_TABLE;
        let h = blind_scalar * h_generator();
        *entry += g + h;
    }
    if protocol_fee > 0 {
        s.program_treasury = s
            .program_treasury
            .checked_add(protocol_fee)
            .ok_or("overflow treasury")?;
    }
    Ok(total_paid)
}

fn apply_settle(app: &AppState, tx: &Value) -> Result<Vec<Value>, String> {
    let p = parse_settle_params(tx)?;
    let mut s = app.state.write();
    coverage::record("settle_session", "require[1]"); // status == open
    coverage::record("settle_session", "require[2]"); // seq > last
    let (tid, deposit) = validate_and_advance_session(&mut s, &p.sid, p.seq)?;
    coverage::record("settle_session", "while[1]"); // hop loop
    let total_paid = credit_openings(&mut s, p.bytes_used, p.blind_scalar, &p.openings)?;
    coverage::record("settle_session", "require[3]"); // claim <= deposit
    if total_paid > deposit {
        return Err("claim exceeds escrow".into());
    }
    let refund = deposit - total_paid;
    if refund > 0 {
        if let Some(t) = s.tailnets.get_mut(&tid) {
            t.treasury += refund;
        }
    }
    Ok(vec![json!({
        "name": "SessionSettled",
        "session_id": p.sid,
        "seq": p.seq,
        "total_paid": total_paid,
        "refund": refund,
    })])
}

fn apply_claim_no_show(app: &AppState, tx: &Value) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let sid = p[0].as_str().unwrap_or("").to_string();
    let mut s = app.state.write();
    let (tid, deposit) = {
        let sess = s.sessions.get_mut(&sid).ok_or("session not found")?;
        if sess.status != 0 {
            return Err("session not open".into());
        }
        if sess.last_seq != 0 {
            return Err("session has progress".into());
        }
        sess.status = 2;
        (sess.tailnet_id.clone(), sess.deposit)
    };
    if let Some(t) = s.tailnets.get_mut(&tid) {
        t.treasury += deposit;
    }
    Ok(vec![json!({
        "name": "SessionRefunded",
        "session_id": sid,
        "reason": "no-show",
    })])
}

fn apply_sweep_expired_session(
    app: &AppState,
    tx: &Value,
    from: &str,
) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let sid = p[0].as_str().unwrap_or("").to_string();
    let mut s = app.state.write();
    let (tid, deposit) = {
        let sess = s.sessions.get_mut(&sid).ok_or("session not found")?;
        if sess.status != 0 {
            return Err("session not open".into());
        }
        sess.status = 2;
        (sess.tailnet_id.clone(), sess.deposit)
    };
    let bounty = deposit / 100;
    let refund = deposit - bounty;
    if bounty > 0 {
        *s.balances.entry(from.to_string()).or_insert(0) += bounty;
    }
    if refund > 0 {
        if let Some(t) = s.tailnets.get_mut(&tid) {
            t.treasury += refund;
        }
    }
    Ok(vec![json!({
        "name": "SessionSwept",
        "session_id": sid,
    })])
}

fn apply_claim_earnings(app: &AppState, tx: &Value) -> Result<Vec<Value>, String> {
    let p = tx
        .get("params")
        .and_then(|x| x.as_array())
        .ok_or("params")?;
    let claimed = p[0].as_u64().unwrap_or(0);
    let blind_hex = p[1].as_str().unwrap_or("");
    let stealth = p[2].as_str().unwrap_or("").to_string();

    let blind_bytes = hex::decode(blind_hex).map_err(|e| format!("blind: {e}"))?;
    if blind_bytes.len() != 32 {
        return Err("blind not 32".into());
    }
    let mut blind_arr = [0u8; 32];
    blind_arr.copy_from_slice(&blind_bytes);
    let blind_scalar = scalar_from_bytes(&blind_arr).map_err(|e| format!("blind: {e}"))?;

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
    let recomputed = &scalar_claimed * RISTRETTO_BASEPOINT_TABLE + blind_scalar * h_generator();
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
        "list_active_endpoints" => {
            let offset = pp.first().and_then(serde_json::Value::as_u64).unwrap_or(0);
            let limit = pp.get(1).and_then(serde_json::Value::as_u64).unwrap_or(50);
            let s = app.state.read();
            let mut active: Vec<String> = s
                .endpoints
                .values()
                .filter(|e| {
                    e.active
                        && !s.endpoint_slashed.contains(&e.addr)
                        && s.endpoint_stake.get(&e.addr).copied().unwrap_or(0)
                            >= MIN_ENDPOINT_STAKE
                })
                .map(|e| e.addr.clone())
                .collect();
            active.sort();
            let end = (offset + limit).min(active.len() as u64) as usize;
            let start = (offset as usize).min(end);
            Ok(json!(&active[start..end]))
        }
        "list_tailnets" => {
            let offset = pp.first().and_then(serde_json::Value::as_u64).unwrap_or(0);
            let limit = pp.get(1).and_then(serde_json::Value::as_u64).unwrap_or(50);
            let s = app.state.read();
            let mut ids: Vec<String> = s.tailnets.keys().cloned().collect();
            ids.sort();
            let end = (offset + limit).min(ids.len() as u64) as usize;
            let start = (offset as usize).min(end);
            Ok(json!(&ids[start..end]))
        }
        "get_endpoint" => {
            let addr = pp.first().and_then(|x| x.as_str()).ok_or("addr")?;
            let s = app.state.read();
            match s.endpoints.get(addr) {
                Some(e) => Ok(json!({
                    "active": i32::from(e.active),
                    "endpoint": e.endpoint,
                    "wg_pubkey": e.wg_pubkey,
                    "receipt_pubkey": e.receipt_pubkey,
                    "view_pubkey": e.view_pubkey,
                    "region": e.region,
                    "price_per_mb": e.price_per_mb,
                    "registered_at": e.registered_at,
                    "reputation": e.reputation,
                })),
                None => Ok(json!({"active": 0})),
            }
        }
        "get_tailnet" => {
            let tid = pp.first().and_then(|x| x.as_str()).ok_or("tailnet_id")?;
            let s = app.state.read();
            match s.tailnets.get(tid) {
                Some(t) => Ok(json!({
                    "owner": t.owner,
                    "treasury": t.treasury,
                    "member_count": t.members.len(),
                    "acl_policy": t.acl_policy,
                    "created_at": t.created_at,
                    "exit_count": t.exits.len(),
                })),
                None => Ok(json!(null)),
            }
        }
        "is_tailnet_member" => {
            let tid = pp.first().and_then(|x| x.as_str()).ok_or("tailnet_id")?;
            let addr = pp.get(1).and_then(|x| x.as_str()).ok_or("addr")?;
            let s = app.state.read();
            Ok(json!(s
                .tailnets
                .get(tid)
                .is_some_and(|t| t.members.contains(addr))))
        }
        "get_device_owner" => {
            let device = pp.first().and_then(|x| x.as_str()).ok_or("device")?;
            let s = app.state.read();
            Ok(json!(s
                .device_owner
                .get(device)
                .cloned()
                .unwrap_or_default()))
        }
        "get_view_pubkey" => {
            let wallet = pp.first().and_then(|x| x.as_str()).ok_or("wallet")?;
            let s = app.state.read();
            Ok(json!(s
                .view_keys
                .get(wallet)
                .cloned()
                .unwrap_or_default()))
        }
        "is_device_of" => {
            let device = pp.first().and_then(|x| x.as_str()).ok_or("device")?;
            let wallet = pp.get(1).and_then(|x| x.as_str()).ok_or("wallet")?;
            let s = app.state.read();
            Ok(json!(
                s.device_owner.get(device).map(String::as_str) == Some(wallet)
            ))
        }
        "is_tailnet_exit" => {
            let tid = pp.first().and_then(|x| x.as_str()).ok_or("tailnet_id")?;
            let addr = pp.get(1).and_then(|x| x.as_str()).ok_or("addr")?;
            let s = app.state.read();
            Ok(json!(s
                .tailnets
                .get(tid)
                .is_some_and(|t| t.exits.contains(addr))))
        }
        "get_session" => {
            let sid = pp.first().and_then(|x| x.as_str()).ok_or("sid")?;
            let s = app.state.read();
            match s.sessions.get(sid) {
                Some(sess) => Ok(json!({
                    "tailnet_id": sess.tailnet_id,
                    "deposit": sess.deposit,
                    "opened_at": sess.opened_at,
                    "status": sess.status,
                    "last_seq": sess.last_seq,
                    "route_commit": sess.route_commit,
                    "client_session_pubkey": sess.client_session_pubkey,
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
            "min_session_deposit": 10,
            "min_tailnet_deposit": 100,
            "session_grace_epochs": 100,
            "sweep_grace_multiplier": 10,
            "sweep_bounty_bps": 100,
        })),
        other => Err(format!("unknown read method {other}")),
    }
}

/// Fake AML compile: hashes the source and synthesizes a deterministic
/// bytecode/ABI shape. Real Octra returns real compiler output via
/// `octra_compileAml`; this stub lets local tests + the offline mode of
/// `forge build` exercise the same code path without a live node.
fn octra_compile_aml(params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let source = arr.first().and_then(|x| x.as_str()).ok_or("source")?;
    let name = arr
        .get(1)
        .and_then(|x| x.as_str())
        .unwrap_or("Program")
        .to_string();
    Ok(compile_one(&name, source))
}

fn octra_compile_aml_multi(params: &Value) -> Result<Value, String> {
    let arr = params.as_array().ok_or("params not array")?;
    let files = arr.first().and_then(|x| x.as_object()).ok_or("files")?;
    let mut out = serde_json::Map::new();
    for (path, val) in files {
        let source = val.as_str().unwrap_or_default();
        let name = infer_program_name_from(path, source);
        out.insert(path.clone(), compile_one(&name, source));
    }
    Ok(Value::Object(out))
}

fn infer_program_name_from(path: &str, source: &str) -> String {
    let stripped = strip_aml_comments(source);
    let bytes = stripped.as_bytes();
    let mut i = 0;
    while i + 8 <= bytes.len() {
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if before_ok && &bytes[i..i + 8] == b"program " {
            let mut j = i + 8;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let name_start = j;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if j > name_start {
                return stripped[name_start..j].to_string();
            }
        }
        i += 1;
    }
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Program")
        .to_string()
}

fn strip_aml_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && &bytes[i..i + 2] == b"//" {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < bytes.len() && &bytes[i..i + 2] == b"/*" {
            i += 2;
            while i + 1 < bytes.len() && &bytes[i..i + 2] != b"*/" {
                i += 1;
            }
            i = i.saturating_add(2);
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn compile_one(name: &str, source: &str) -> Value {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"::");
    h.update(source.as_bytes());
    let digest = hex::encode(h.finalize());
    let methods = extract_methods(source);
    let events = extract_events(source);
    let abi: Vec<Value> = methods
        .into_iter()
        .map(|m| json!({
            "name": m.name,
            "kind": if m.is_view { "view" } else { "call" },
            "inputs": m.inputs.iter().map(|(n, t)| json!({"name": n, "type": t})).collect::<Vec<_>>(),
        }))
        .chain(events.into_iter().map(|e| json!({"name": e, "kind": "event"})))
        .collect();
    json!({
        "name": name,
        "abi": abi,
        "bytecode": format!("0x{digest}"),
        "assembly": format!("; mock AML bytecode for {name}\n; sha256(source) = {digest}\n"),
        "source_hash": digest,
        "compiler": "mock-aml-0.1",
    })
}

struct MethodSig {
    name: String,
    is_view: bool,
    inputs: Vec<(String, String)>,
}

fn extract_methods(source: &str) -> Vec<MethodSig> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"fn ") && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
            let prefix_end = i;
            let is_view = back_word_is(source, prefix_end, "view");
            let mut j = i + 3;
            let name_start = j;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            let name = source[name_start..j].to_string();
            while j < bytes.len() && bytes[j] != b'(' {
                j += 1;
            }
            if j >= bytes.len() {
                break;
            }
            let params_start = j + 1;
            let mut depth = 1;
            j += 1;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            let params_str = &source[params_start..j - 1];
            let inputs = parse_params(params_str);
            if !name.is_empty() && !is_private(source, prefix_end) {
                out.push(MethodSig {
                    name,
                    is_view,
                    inputs,
                });
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn back_word_is(source: &str, end: usize, word: &str) -> bool {
    let s = source[..end].trim_end();
    s.ends_with(word) && {
        let before = s.len() - word.len();
        before == 0 || !source.as_bytes()[before - 1].is_ascii_alphanumeric()
    }
}

fn is_private(source: &str, end: usize) -> bool {
    back_word_is(source, end, "private") || back_word_is(source, end, "view private")
}

fn parse_params(s: &str) -> Vec<(String, String)> {
    s.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                return None;
            }
            let (n, t) = chunk.split_once(':')?;
            Some((n.trim().to_string(), t.trim().to_string()))
        })
        .collect()
}

fn extract_events(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in source.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("event ") {
            if let Some((name, _)) = rest.split_once('(') {
                out.push(name.trim().to_string());
            }
        }
    }
    out
}

fn epoch_get(app: &AppState, params: &Value) -> Value {
    let id = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(serde_json::Value::as_u64);
    let s = app.state.read();
    let epoch = id.unwrap_or(s.epoch);
    json!({
        "epoch_id": epoch,
        "finalized_by": null,
        "tx_count": s.txs.len(),
        "timestamp": 0u64,
    })
}

/// In-process equivalent of an `octra_submit` JSON-RPC call.
///
/// Routes a single `tx` JSON object through the same `apply_*` handlers
/// the HTTP router uses, returning `(tx_hash, events)` on success.
pub fn submit_tx(app: &AppState, tx: &Value) -> Result<(String, Vec<Value>), String> {
    let params = json!([tx]);
    let result = octra_submit(app, &params)?;
    let hash = result
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or("missing hash")?
        .to_string();
    let events = {
        let s = app.state.read();
        s.txs
            .get(&hash)
            .map_or_else(Vec::new, |row| row.events.clone())
    };
    Ok((hash, events))
}

/// In-process equivalent of `contract_call`.
pub fn read_call(app: &AppState, method: &str, params: &[Value]) -> Result<Value, String> {
    let p = json!([app.program_addr.clone(), method, params, Value::Null]);
    contract_call(app, &p)
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
    axum::serve(listener, router).await?;
    Ok(())
}
