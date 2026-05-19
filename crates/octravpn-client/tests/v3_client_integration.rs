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
use octravpn_core::{address::Address, rpc::RpcClient, sig::KeyPair};
use parking_lot::Mutex;
use serde_json::{json, Value};
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
            let circle = p
                .get(1)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
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
    let program_addr =
        Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3");
    let circle_id = "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun".to_string();
    let tailnet_id: u64 = 0;
    let max_pay: u64 = 1_500;

    // Pre-seed the on-chain anchor + members_root so the v3 runner's
    // sanity reads succeed (matching the operator's `register_circle`
    // landing before the client connects).
    {
        let mut g = mock.lock();
        g.anchors.insert(
            circle_id.clone(),
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
        );
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
    assert_eq!(
        anchor,
        json!("1111111111111111111111111111111111111111111111111111111111111111"),
        "client should see the pre-seeded anchor",
    );

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
    // Mirror v3_runner::compute_net + DEFAULT_PRICE_PER_MB (= 1000).
    let net = (bytes_used / 1_048_576) * 1_000;
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
    let signed_settle =
        octravpn_core::tx::sign_call(&wallet, settle_call).expect("sign settle");
    let r2 = rpc.submit(&signed_settle).await.expect("submit settle");
    assert!(!r2.hash.is_empty());

    // ---- verify both envelopes recorded properly ----------------
    let g = mock.lock();
    assert_eq!(g.submitted.len(), 2, "expected open + settle txs only");
    let (_, open_env) = &g.submitted[0];
    assert_eq!(open_env["op_type"], "call");
    assert_eq!(open_env["encrypted_data"], "open_session");
    let open_params: Value =
        serde_json::from_str(open_env["message"].as_str().unwrap()).unwrap();
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
    let program_addr =
        Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3");
    let circle_id = "octEPUyqvqAQ6Y6jp1WqaPVnPNghYjN4tFr95mvSuLcvFTL".to_string();
    let tailnet_id: u64 = 3;

    // Pre-seed anchor + members_root.
    {
        let mut g = mock.lock();
        g.anchors.insert(
            circle_id.clone(),
            "3333333333333333333333333333333333333333333333333333333333333333".into(),
        );
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
