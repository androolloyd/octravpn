//! Integration test for the v3 client flow.
//!
//! Walks the full `connect-v3` shape (open_session → settle_confirm)
//! against a mock JSON-RPC server, then exercises the alternate
//! `claim_no_show` branch in a second test. Mirrors the structure of
//! `octravpn-node/tests/v3_boot_integration.rs` — the client crate is
//! a binary (no library target), so we can't import its private
//! `ChainCtxV3` directly. Instead, the test reproduces the exact
//! wire calls the client emits, against the mock, and asserts the
//! mock state transitions correctly.
//!
//! Coverage:
//!
//!   * `cold_open_session_then_settle_confirm` — opener calls
//!     `open_session(tid, circle, max_pay)`, the mock records a
//!     `SessionOpened(session_id=42)` event, the client polls it
//!     back, then submits `settle_confirm(sid, bytes_used, net,
//!     blinding)`. Confirms the param order + wire shape.
//!   * `claim_no_show_when_operator_stalls` — operator never claims;
//!     the client falls back to `claim_no_show(sid)`. Confirms the
//!     opener-side abort path.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use octravpn_core::{
    address::Address, rpc::RpcClient, sig::KeyPair, v3_policy::OperatorPolicy,
    v3_state_root::StateRoot,
};
use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

// ----------------------------------------------------------------
// Mock JSON-RPC server (shared by both tests).
// ----------------------------------------------------------------

#[derive(Default)]
struct MockState {
    /// Submitted txs in order of receipt. Keyed by the deterministic
    /// hash we hand back from `octra_submit`.
    submitted: Vec<(String, Value)>,
    /// `circle_state_root[circle]` map (64-char hex).
    anchors: HashMap<String, String>,
    /// `tailnet_members_root[tailnet_id]` map (64-char hex).
    members_roots: HashMap<u64, String>,
    /// Sealed-asset store: `(circle_id, path)` → raw bytes. Served by
    /// the mock's `circle_asset` handler so v3 policy / state-root
    /// fetches resolve to the operator's published JSON.
    circle_assets: HashMap<(String, String), Vec<u8>>,
    /// Next nonce to return from `octra_balance`.
    next_nonce: u64,
    /// Current epoch returned by `node_status`.
    epoch: u64,
    /// Counter for synthesising deterministic tx hashes.
    tx_counter: u64,
    /// Synthetic session id to emit in the next `SessionOpened` event.
    next_session_id: u64,
    /// Map tx_hash → emitted events. Drives `octra_transaction` polling.
    tx_events: HashMap<String, Vec<Value>>,
}

impl MockState {
    fn new() -> Self {
        Self {
            next_nonce: 7,
            epoch: 1234,
            next_session_id: 42,
            ..Default::default()
        }
    }
}

type SharedMock = Arc<Mutex<MockState>>;

async fn rpc_handler(
    State(state): State<SharedMock>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    let method = req
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let id = req.get("id").cloned().unwrap_or(json!(1));
    let params = req.get("params").cloned().unwrap_or(json!([]));

    let result = match method {
        "node_status" => {
            let g = state.lock();
            json!({ "epoch": g.epoch })
        }
        "octra_balance" => {
            let g = state.lock();
            json!({
                "balance": "100.000000",
                "balance_raw": "100000000",
                "nonce": g.next_nonce,
                "pending_nonce": g.next_nonce,
            })
        }
        "octra_recommendedFee" => {
            json!({ "minimum": "1000", "recommended": "1000", "fast": "2000" })
        }
        "contract_call" => {
            // params: [program_addr, method, [args...], maybe caller]
            let arr = params.as_array().ok_or(StatusCode::BAD_REQUEST)?;
            let m = arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
            let args = arr.get(2).cloned().unwrap_or(json!([]));
            let g = state.lock();
            match m {
                "get_circle_state_root" => {
                    let c = args[0].as_str().unwrap_or("");
                    let v = g.anchors.get(c).cloned().unwrap_or_else(|| "0".to_string());
                    json!({ "result": v, "storage": {} })
                }
                "get_tailnet_members_root" => {
                    let t = args[0].as_u64().unwrap_or(0);
                    let v = g
                        .members_roots
                        .get(&t)
                        .cloned()
                        .unwrap_or_else(|| "0".to_string());
                    json!({ "result": v, "storage": {} })
                }
                _ => json!({ "result": null, "storage": {} }),
            }
        }
        "octra_submit" => {
            let mut g = state.lock();
            g.tx_counter += 1;
            let hash = format!("{:064x}", g.tx_counter);
            let tx = params
                .as_array()
                .and_then(|a| a.first())
                .cloned()
                .unwrap_or(Value::Null);
            // Mirror tx effects into mock state so subsequent reads
            // observe the side effects.
            let events = apply_tx_side_effects(&mut g, &tx);
            g.tx_events.insert(hash.clone(), events);
            g.submitted.push((hash.clone(), tx));
            g.next_nonce += 1;
            json!({ "tx_hash": hash, "status": "accepted" })
        }
        "octra_transaction" => {
            // params: [tx_hash]
            let arr = params.as_array().cloned().unwrap_or_default();
            let tx_hash = arr.first().and_then(|v| v.as_str()).unwrap_or("");
            let g = state.lock();
            let events = g.tx_events.get(tx_hash).cloned().unwrap_or_default();
            json!({
                "status": "confirmed",
                "events": events,
            })
        }
        "circle_asset" => {
            // params: [circle_id, path] — returns the canonical
            // plaintext bytes the operator sealed at that path. We use
            // the `{"plaintext": "<utf8>"}` envelope shape; the v3
            // runner's `fetch_circle_asset_bytes` accepts that variant.
            let arr = params.as_array().cloned().unwrap_or_default();
            let circle = arr
                .first()
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let path = arr
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let g = state.lock();
            match g.circle_assets.get(&(circle, path)) {
                Some(bytes) => {
                    let s = std::str::from_utf8(bytes).expect("v3 mock fixtures are UTF-8 JSON");
                    json!({ "plaintext": s })
                }
                None => Value::Null,
            }
        }
        _ => json!(null),
    };

    Ok(Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })))
}

/// Inspect a signed v3 tx envelope (post-`sign_call` translation) and
/// emit the events the v3 program would have emitted for the same
/// call. Returns the event list so the mock can hand it back via
/// `octra_transaction` on the next poll. Mirrors the apply-effects
/// helper in `octravpn-node/tests/v3_boot_integration.rs`.
fn apply_tx_side_effects(state: &mut MockState, tx: &Value) -> Vec<Value> {
    let method = tx
        .get("encrypted_data")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let msg = tx.get("message").and_then(|v| v.as_str()).unwrap_or("[]");
    let params: Value = serde_json::from_str(msg).unwrap_or(json!([]));
    let p = params.as_array().cloned().unwrap_or_default();
    match method {
        "open_session" => {
            let sid = state.next_session_id;
            state.next_session_id += 1;
            let tid = p.first().and_then(Value::as_u64).unwrap_or(0);
            let circle = p.get(1).and_then(Value::as_str).unwrap_or("").to_string();
            vec![json!({
                "name": "SessionOpened",
                "session_id": sid,
                "tailnet_id": tid,
                "circle": circle,
            })]
        }
        "settle_confirm" => {
            let sid = p.first().and_then(Value::as_u64).unwrap_or(0);
            vec![json!({
                "name": "SessionSettled",
                "session_id": sid,
            })]
        }
        "claim_no_show" => {
            let sid = p.first().and_then(Value::as_u64).unwrap_or(0);
            vec![json!({
                "name": "SessionRefunded",
                "session_id": sid,
                "reason": "no_show",
            })]
        }
        _ => Vec::new(),
    }
}

/// Seed the mock with a matching (policy.json, state-root.json) pair
/// for `circle_id`, AND the on-chain anchor that commits them. Uses
/// the worked-example values from `docs/v3-policy-schema.md` §6 so the
/// canonical bytes (and therefore hashes) are byte-identical to the
/// fixtures pinned in the v3_policy / v3_state_root unit tests.
///
/// Returns the `OperatorPolicy` so the test can assert against its
/// `price_per_mb_shared` (which is what flows into `compute_net`).
fn seed_v3_fixtures(mock: &SharedMock, circle_id: &str) -> OperatorPolicy {
    // Worked-example policy (matches docs/v3-policy-schema.md §6).
    let raw_key = [0x11_u8; 32];
    let wg_b64 = BASE64_STD.encode(raw_key);
    let policy = OperatorPolicy::new_v1(
        "wg://relay.example:51820",
        wg_b64,
        "us-east-1",
        1_000, // price_per_mb_shared — pinned for net calculation below.
        0,
        12_345,
        1_705_000_000,
        Some("https://op.example/attestation".to_string()),
    );
    let policy_bytes = policy.canonical_bytes().expect("policy canonical bytes");
    let policy_hash = policy.hash_hex().expect("policy hash");
    // wg_pubkey_hash is sha256 of the *raw* 32-byte WG pubkey, not its
    // base64 form — see crates/octravpn-core/src/v3_state_root.rs.
    let wg_pubkey_hash = hex::encode(Sha256::digest(raw_key));

    let state_root = StateRoot::new_v1(
        circle_id,
        policy_hash,
        wg_pubkey_hash,
        None,
        "us-east-1",
        1,
        12_345,
        1_705_000_000,
    );
    let sr_bytes = state_root
        .canonical_bytes()
        .expect("state-root canonical bytes");
    let anchor = state_root.anchor_hex().expect("state-root anchor");

    let mut g = mock.lock();
    g.anchors.insert(circle_id.to_string(), anchor);
    g.circle_assets.insert(
        (circle_id.to_string(), "/policy.json".to_string()),
        policy_bytes,
    );
    g.circle_assets.insert(
        (circle_id.to_string(), "/state-root.json".to_string()),
        sr_bytes,
    );
    policy
}

async fn spawn_mock_rpc() -> (String, SharedMock, oneshot::Sender<()>) {
    let state = Arc::new(Mutex::new(MockState::new()));
    let app = Router::new()
        .route("/", post(rpc_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind mock rpc");
    let addr = listener.local_addr().expect("local_addr");
    let url = format!("http://{addr}/");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        let svc = app.into_make_service();
        let server = axum::serve(listener, svc);
        let _ = server
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });
    (url, state, shutdown_tx)
}

// ----------------------------------------------------------------
// Local builders — mirror the production `ChainCtxV3` exactly. The
// chain_v3 unit tests already pin the production shapes against
// `v3-smoke.sh`; this test pins the mock-side end-to-end contract.
// ----------------------------------------------------------------

fn build_open_session_call(
    from: &str,
    program_addr: &str,
    tailnet_id: u64,
    circle_id: &str,
    max_pay: u64,
    fee: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "contract_call",
        "from": from,
        "to": program_addr,
        "method": "open_session",
        "params": [tailnet_id, circle_id, max_pay],
        "value": 0,
        "fee": fee,
        "nonce": nonce,
    })
}

fn build_settle_confirm_call(
    from: &str,
    program_addr: &str,
    session_id: u64,
    bytes_used: u64,
    net: u64,
    blinding_hex: &str,
    fee: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "contract_call",
        "from": from,
        "to": program_addr,
        "method": "settle_confirm",
        "params": [session_id, bytes_used, net, blinding_hex],
        "value": 0,
        "fee": fee,
        "nonce": nonce,
    })
}

fn build_claim_no_show_call(
    from: &str,
    program_addr: &str,
    session_id: u64,
    fee: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "contract_call",
        "from": from,
        "to": program_addr,
        "method": "claim_no_show",
        "params": [session_id],
        "value": 0,
        "fee": fee,
        "nonce": nonce,
    })
}

/// Poll the synthetic tx envelope until a `SessionOpened` event
/// surfaces; returns the embedded `session_id`. Mirrors the
/// production v3 runner's `poll_session_id_v3`.
async fn poll_session_id(rpc: &RpcClient, tx_hash: &str) -> u64 {
    for _ in 0..10 {
        let v = rpc.transaction(tx_hash).await.expect("transaction");
        if let Some(events) = v.get("events").and_then(|x| x.as_array()) {
            for e in events {
                if e.get("name").and_then(Value::as_str) == Some("SessionOpened") {
                    if let Some(sid) = e.get("session_id").and_then(Value::as_u64) {
                        return sid;
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("session id not observed in mock");
}

// ----------------------------------------------------------------
// Tests
// ----------------------------------------------------------------

#[tokio::test]
async fn cold_open_session_then_settle_confirm() {
    let (url, mock, _shutdown) = spawn_mock_rpc().await;
    let rpc = RpcClient::new(&url);

    let secret = [9u8; 32];
    let wallet = KeyPair::from_secret_bytes(&secret);
    let wallet_addr = Address::from_pubkey(&wallet.public.0);
    let from = wallet_addr.display();
    let program_addr = Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3");
    let circle_id = "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun".to_string();
    let tailnet_id: u64 = 0;
    let max_pay: u64 = 1_500;

    // Pre-seed sealed policy + state-root + on-chain anchor. The
    // helper picks `price_per_mb_shared = 1_000` so the net assertion
    // below stays meaningful when the v3 runner now reads from policy.
    let seeded_policy = seed_v3_fixtures(&mock, &circle_id);
    assert_eq!(
        seeded_policy.price_per_mb_shared, 1_000,
        "fixture pins the price the test asserts against below"
    );
    {
        let mut g = mock.lock();
        g.members_roots.insert(
            tailnet_id,
            "2222222222222222222222222222222222222222222222222222222222222222".into(),
        );
    }

    // ---- step 1: client reads the anchor ------------------------
    let anchor = rpc
        .contract_call(
            &program_addr,
            "get_circle_state_root",
            &[json!(circle_id)],
            None,
        )
        .await
        .expect("get_circle_state_root");
    let anchor_str = anchor
        .as_str()
        .expect("get_circle_state_root returns a hex string")
        .to_string();
    assert_eq!(anchor_str.len(), 64, "anchor must be a 64-char hex SHA-256",);

    // ---- step 1b: validate the operator's sealed policy against
    //               the on-chain anchor. This is the critical step
    //               that replaced DEFAULT_PRICE_PER_MB.
    let policy_bytes_resp = rpc
        .raw_call("circle_asset", json!([circle_id.clone(), "/policy.json"]))
        .await
        .expect("circle_asset(policy.json)");
    let policy_bytes = policy_bytes_resp
        .get("plaintext")
        .and_then(Value::as_str)
        .expect("mock returns {plaintext: ...}")
        .as_bytes()
        .to_vec();
    let fetched_policy = OperatorPolicy::decode_lenient(&policy_bytes).expect("decode policy");
    let sr_bytes_resp = rpc
        .raw_call(
            "circle_asset",
            json!([circle_id.clone(), "/state-root.json"]),
        )
        .await
        .expect("circle_asset(state-root.json)");
    let sr_bytes = sr_bytes_resp
        .get("plaintext")
        .and_then(Value::as_str)
        .expect("mock returns {plaintext: ...}")
        .as_bytes()
        .to_vec();
    let served_sr = StateRoot::decode_lenient(&sr_bytes).expect("decode state-root");
    // Anchor consistency: served state-root.json must rehash to anchor.
    assert_eq!(
        served_sr.anchor_hex().unwrap(),
        anchor_str,
        "state-root.json bytes must match the on-chain anchor",
    );
    // Policy consistency: state-root.policy_hash must equal H(policy).
    assert_eq!(
        served_sr.policy_hash,
        fetched_policy.hash_hex().unwrap(),
        "policy.json bytes must match the policy_hash inside state-root.json",
    );
    // Self-binding: state-root.json is for this exact circle.
    assert_eq!(served_sr.circle_id, circle_id);
    // The price tier we're about to charge against now flows from
    // policy, not from a placeholder constant.
    let price_per_mb = fetched_policy.price_per_mb_shared;
    assert_eq!(price_per_mb, 1_000);

    // ---- step 2: open_session -----------------------------------
    let balance = rpc.balance(&wallet_addr).await.expect("balance");
    let nonce = balance.pending_nonce.max(balance.nonce);
    let fee = rpc
        .recommended_fee(Some("contract_call"))
        .await
        .expect("fee")
        .recommended;
    let prog = program_addr.display();
    #[allow(clippy::needless_borrow)]
    let open_call =
        build_open_session_call(&from, &prog, tailnet_id, &circle_id, max_pay, fee, nonce);
    let signed = octravpn_core::tx::sign_call(&wallet, open_call).expect("sign open");
    let submit = rpc.submit(&signed).await.expect("submit open");
    assert!(!submit.hash.is_empty());

    let session_id = poll_session_id(&rpc, &submit.hash).await;
    assert_eq!(session_id, 42, "mock should emit SessionOpened with sid=42");

    // ---- step 3: settle_confirm ---------------------------------
    let bytes_used: u64 = 2 * 1_048_576; // 2 MiB
                                         // The price now comes from the operator's policy.json (validated
                                         // above against the chain anchor), not from a placeholder constant.
    let net = (bytes_used / 1_048_576) * price_per_mb;
    assert_eq!(net, 2_000);
    // 64-char lowercase hex blinding (32 bytes). The production code
    // generates this freshly via OsRng; the test pins it deterministically
    // so we can pin the wire shape.
    let blinding_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let balance2 = rpc.balance(&wallet_addr).await.expect("balance");
    let nonce2 = balance2.pending_nonce.max(balance2.nonce);
    let prog2 = program_addr.display();
    #[allow(clippy::needless_borrow)]
    let settle_call = build_settle_confirm_call(
        &from,
        &prog2,
        session_id,
        bytes_used,
        net,
        blinding_hex,
        fee,
        nonce2,
    );
    let signed_settle = octravpn_core::tx::sign_call(&wallet, settle_call).expect("sign settle");
    let r2 = rpc.submit(&signed_settle).await.expect("submit settle");
    assert!(!r2.hash.is_empty());

    // ---- verify both envelopes recorded properly ----------------
    let g = mock.lock();
    assert_eq!(g.submitted.len(), 2, "expected open + settle txs only");
    let (_, open_env) = &g.submitted[0];
    assert_eq!(open_env["op_type"], "call");
    assert_eq!(open_env["encrypted_data"], "open_session");
    let open_params: Value = serde_json::from_str(open_env["message"].as_str().unwrap()).unwrap();
    let open_params = open_params.as_array().unwrap();
    assert_eq!(open_params[0], tailnet_id);
    assert_eq!(open_params[1], circle_id);
    assert_eq!(open_params[2], max_pay);

    let (_, settle_env) = &g.submitted[1];
    assert_eq!(settle_env["op_type"], "call");
    assert_eq!(settle_env["encrypted_data"], "settle_confirm");
    let settle_params: Value =
        serde_json::from_str(settle_env["message"].as_str().unwrap()).unwrap();
    let settle_params = settle_params.as_array().unwrap();
    assert_eq!(settle_params[0], session_id);
    assert_eq!(settle_params[1], bytes_used);
    assert_eq!(settle_params[2], net);
    assert_eq!(settle_params[3], blinding_hex);
}

#[tokio::test]
async fn claim_no_show_when_operator_stalls() {
    // The opener opens a session, the operator never `settle_claim`s,
    // and the opener falls back to `claim_no_show(sid)` to refund the
    // tailnet treasury.
    let (url, mock, _shutdown) = spawn_mock_rpc().await;
    let rpc = RpcClient::new(&url);

    let secret = [11u8; 32];
    let wallet = KeyPair::from_secret_bytes(&secret);
    let wallet_addr = Address::from_pubkey(&wallet.public.0);
    let from = wallet_addr.display();
    let program_addr = Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3");
    let circle_id = "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL".to_string();
    let tailnet_id: u64 = 3;

    // Seed sealed policy + state-root + on-chain anchor + members_root.
    // This `claim_no_show` test exercises the abort path but the v3
    // runner still validates policy before opening the session, so
    // the fixtures need to be consistent.
    let _seeded_policy = seed_v3_fixtures(&mock, &circle_id);
    {
        let mut g = mock.lock();
        g.members_roots.insert(
            tailnet_id,
            "4444444444444444444444444444444444444444444444444444444444444444".into(),
        );
    }

    // ---- open_session -------------------------------------------
    let balance = rpc.balance(&wallet_addr).await.expect("balance");
    let nonce = balance.pending_nonce.max(balance.nonce);
    let fee = rpc
        .recommended_fee(Some("contract_call"))
        .await
        .expect("fee")
        .recommended;
    let prog = program_addr.display();
    #[allow(clippy::needless_borrow)]
    let open_call = build_open_session_call(&from, &prog, tailnet_id, &circle_id, 1500, fee, nonce);
    let signed = octravpn_core::tx::sign_call(&wallet, open_call).expect("sign open");
    let submit = rpc.submit(&signed).await.expect("submit open");
    let session_id = poll_session_id(&rpc, &submit.hash).await;
    assert_eq!(session_id, 42);

    // ---- operator never claims; client runs claim_no_show -------
    let balance2 = rpc.balance(&wallet_addr).await.expect("balance");
    let nonce2 = balance2.pending_nonce.max(balance2.nonce);
    let prog2 = program_addr.display();
    #[allow(clippy::needless_borrow)]
    let nshow = build_claim_no_show_call(&from, &prog2, session_id, fee, nonce2);
    let signed_nshow = octravpn_core::tx::sign_call(&wallet, nshow).expect("sign no-show");
    let r2 = rpc.submit(&signed_nshow).await.expect("submit no-show");
    assert!(!r2.hash.is_empty());

    let g = mock.lock();
    assert_eq!(
        g.submitted.len(),
        2,
        "expected open + no-show txs (no settle_confirm)"
    );
    let (_, env) = &g.submitted[1];
    assert_eq!(env["op_type"], "call");
    assert_eq!(env["encrypted_data"], "claim_no_show");
    let params: Value = serde_json::from_str(env["message"].as_str().unwrap()).unwrap();
    let params = params.as_array().unwrap();
    assert_eq!(params.len(), 1);
    assert_eq!(params[0], session_id);

    // Confirm the mock surfaced a `SessionRefunded` event for the
    // no-show tx so a future runner can render the right user
    // message based on event-stream parsing.
    let events = g.tx_events.get(&r2.hash).cloned().unwrap_or_default();
    assert!(events.iter().any(|e| e["name"] == "SessionRefunded"));
}
