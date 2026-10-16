//! Guard tests use an RPC fixture; paid execution is qualified separately.
use super::*;
use axum::{extract::State, routing::post, Json, Router};
use octravpn_core::rpc::RpcClient;
use parking_lot::Mutex;
use serde_json::json;

struct Fixture {
    version: Value,
    net_set: u64,
    net: u64,
    status: u64,
    calls: Mutex<Vec<Value>>,
}
async fn serve(State(f): State<Arc<Fixture>>, Json(request): Json<Value>) -> Json<Value> {
    f.calls.lock().push(request.clone());
    let value = match request["method"].as_str().unwrap() {
        "contract_call" => json!({"result":match request["params"][1].as_str().unwrap() {
            "get_settlement_version"=>f.version.clone(),
            "get_claim_net_set"=>json!(f.net_set),
            "get_claim_net"=>json!(f.net),
            "get_session_status"=>json!(f.status),
            other=>panic!("unexpected view {other}"),
        }}),
        "octra_balance" => {
            json!({"balance_raw":"100000000","balance":"100.000000","nonce":0,"pending_nonce":0})
        }
        "octra_recommendedFee" => json!({"minimum":"1000","recommended":"1000","fast":"1000"}),
        "octra_submit" => json!({"tx_hash":"ab".repeat(32),"status":"accepted"}),
        other => panic!("unexpected RPC {other}"),
    };
    Json(json!({"jsonrpc":"2.0","id":request["id"],"result":value}))
}
async fn fixture(
    version: Value,
    net_set: u64,
    net: u64,
    status: u64,
) -> (RpcClient, Arc<Fixture>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(Fixture {
        version,
        net_set,
        net,
        status,
        calls: Mutex::new(vec![]),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
        .route("/", post(serve))
        .with_state(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (
        RpcClient::new(format!("http://{address}").as_str()),
        state,
        task,
    )
}
fn identity() -> (Address, KeyPair) {
    (
        Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3"),
        KeyPair::from_secret_bytes(&[7; 32]),
    )
}
fn submissions(f: &Fixture) -> usize {
    f.calls
        .lock()
        .iter()
        .filter(|request| request["method"] == "octra_submit")
        .count()
}
#[tokio::test]
async fn settlement_guards_reject_legacy_or_missing_abi_before_submitting() {
    for version in [Value::Null, json!(1), json!("two"), json!(3)] {
        let (rpc, state, task) = fixture(version, 1, 1000, 1).await;
        let (program, wallet) = identity();
        let ctx = ChainCtxV3::new(&rpc, &program, &wallet);
        assert!(ctx.require_priced_settlement().await.is_err());
        assert_eq!(submissions(&state), 0);
        task.abort();
    }
}
#[tokio::test]
async fn settlement_guards_reject_missing_or_different_operator_amount() {
    for (flag, net) in [(0, 1000), (1, 0), (1, 999)] {
        let (rpc, state, task) = fixture(json!(2), flag, net, 1).await;
        let (program, wallet) = identity();
        let ctx = ChainCtxV3::new(&rpc, &program, &wallet);
        assert!(run_settle_confirm(&ctx, 42, BYTES_PER_MB, 1000)
            .await
            .is_err());
        assert_eq!(submissions(&state), 0);
        task.abort();
    }
}
#[tokio::test]
async fn settlement_guards_terminal_refund_is_not_a_successful_confirmation() {
    let (rpc, state, task) = fixture(json!(2), 1, 1000, 2).await;
    let (program, wallet) = identity();
    let ctx = ChainCtxV3::new(&rpc, &program, &wallet);
    let error = run_settle_confirm(&ctx, 42, BYTES_PER_MB, 1000)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("status 2"), "{error:#}");
    assert_eq!(submissions(&state), 1);
    task.abort();
}
#[tokio::test]
async fn settlement_guards_zero_byte_close_requires_real_zero_amount_claim() {
    // Native views can encode uint results as decimal strings; the shared RPC
    // adapter normalizes that documented envelope before capability checks.
    let (rpc, state, task) = fixture(json!("2"), 1, 0, 1).await;
    let (program, wallet) = identity();
    let ctx = ChainCtxV3::new(&rpc, &program, &wallet);
    ctx.require_priced_settlement().await.unwrap();
    run_settle_confirm(&ctx, 42, 0, 1000).await.unwrap();
    assert_eq!(submissions(&state), 1);
    task.abort();
}
