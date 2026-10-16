//! Publication must survive availability pauses without changing immutability.
use super::{put, ChainCtxV3};
use axum::{extract::State, routing::post, Json, Router};
use octravpn_core::{address::Address, rpc::RpcClient, sig::KeyPair};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

struct Replies {
    values: Vec<Value>,
    requests: Mutex<Vec<Value>>,
}
struct Fixture {
    chain: ChainCtxV3,
    state: Arc<Replies>,
    server: tokio::task::JoinHandle<()>,
}
impl Fixture {
    fn assert_only_asset_reads(&self, count: usize) {
        let requests = self.state.requests.lock().unwrap();
        assert_eq!(requests.len(), count);
        for request in requests.iter() {
            assert_eq!(request["method"], "circle_asset");
            assert_eq!(request["params"], json!(["circle", "/immutable"]));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
async fn response(State(state): State<Arc<Replies>>, Json(request): Json<Value>) -> Json<Value> {
    let mut requests = state.requests.lock().unwrap();
    let reply = state.values[requests.len().min(state.values.len() - 1)].clone();
    requests.push(request);
    Json(reply)
}
async fn fixture(values: Vec<Value>) -> Fixture {
    let state = Arc::new(Replies {
        values,
        requests: Mutex::new(Vec::new()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc = RpcClient::new(format!("http://{}/", listener.local_addr().unwrap()));
    let wallet = KeyPair::generate();
    let program = Address::from_pubkey(&wallet.public.0);
    let chain = ChainCtxV3::new(rpc, program, wallet);
    let app = Router::new()
        .route("/", post(response))
        .with_state(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Fixture {
        chain,
        state,
        server,
    }
}
fn unavailable() -> Value {
    json!({"jsonrpc":"2.0","id":1,"error":{"code":110,"message":"cache not found; service unavailable"}})
}
fn asset(bytes: &[u8]) -> Value {
    json!({"jsonrpc":"2.0","id":1,"result":{"body_b64":octravpn_core::b64::encode(bytes)}})
}

#[tokio::test]
async fn paused_asset_read_recovers_exact_bytes_without_submitting_again() {
    let server = fixture(vec![unavailable(), asset(b"exact")]).await;
    assert_eq!(
        put(&server.chain, "circle", "/immutable", b"exact")
            .await
            .unwrap(),
        None
    );
    server.assert_only_asset_reads(2);
}

#[tokio::test]
async fn committed_readback_retries_unavailable_without_resubmitting_the_write() {
    let hash = "ab".repeat(32);
    let result = |body| json!({"jsonrpc":"2.0","id":1,"result":body});
    let server = fixture(vec![
        json!({"jsonrpc":"2.0","id":1,"error":{"code":112,"message":"not found"}}),
        result(json!({"recommended":"20000"})),
        result(json!({"balance":"1","balance_raw":"1000000","nonce":0,"pending_nonce":0})),
        result(json!({"tx_hash":hash,"status":"accepted"})),
        unavailable(),
        asset(b"exact"),
    ])
    .await;
    let circle = server.chain.wallet_addr.display();
    assert_eq!(
        put(&server.chain, circle, "/immutable", b"exact")
            .await
            .unwrap(),
        Some(hash)
    );
    let requests = server.state.requests.lock().unwrap();
    let methods = requests
        .iter()
        .map(|request| request["method"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        methods,
        vec![
            "circle_asset",
            "octra_recommendedFee",
            "octra_balance",
            "octra_submit",
            "circle_asset",
            "circle_asset"
        ]
    );
    for request in requests
        .iter()
        .filter(|request| request["method"] == "circle_asset")
    {
        assert_eq!(request["params"], json!([circle, "/immutable"]));
    }
}

#[tokio::test]
async fn unavailable_asset_never_becomes_missing_or_starts_a_write() {
    let server = fixture(vec![unavailable()]).await;
    let error = put(&server.chain, "circle", "/immutable", b"exact")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("error 110"));
    server.assert_only_asset_reads(4);
}

#[tokio::test]
async fn wrong_immutable_bytes_fail_immediately_without_retry_or_write() {
    let server = fixture(vec![asset(b"wrong")]).await;
    let error = put(&server.chain, "circle", "/immutable", b"exact")
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("immutable operator snapshot was replaced"));
    server.assert_only_asset_reads(1);
}

#[tokio::test]
async fn malformed_asset_and_missing_method_do_not_fall_back_to_writes() {
    for value in [
        json!({"jsonrpc":"2.0","id":1,"result":{"body_b64":"!"}}),
        json!({"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}),
        json!({"jsonrpc":"2.0","id":1}),
    ] {
        let server = fixture(vec![value]).await;
        assert!(put(&server.chain, "circle", "/immutable", b"exact")
            .await
            .is_err());
        server.assert_only_asset_reads(1);
    }
}
