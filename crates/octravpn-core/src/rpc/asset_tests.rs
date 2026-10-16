//! Real loopback responses exercise the typed read/write retry boundary.
use super::{json, Duration, RpcClient, Value};
use axum::{extract::State, routing::post, Json, Router};
use std::sync::{Arc, Mutex};

struct Responses {
    replies: Vec<Value>,
    requests: Mutex<Vec<Value>>,
    delay: Duration,
}
struct Fixture {
    client: RpcClient,
    state: Arc<Responses>,
    server: tokio::task::JoinHandle<()>,
}
impl Fixture {
    fn requests(&self) -> Vec<Value> {
        self.state.requests.lock().unwrap().clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
async fn response(State(state): State<Arc<Responses>>, Json(request): Json<Value>) -> Json<Value> {
    let reply = {
        let mut requests = state.requests.lock().unwrap();
        let reply = state.replies[requests.len().min(state.replies.len() - 1)].clone();
        requests.push(request);
        reply
    };
    tokio::time::sleep(state.delay).await;
    Json(reply)
}
async fn fixture(replies: Vec<Value>, delay: Duration) -> Fixture {
    assert!(!replies.is_empty());
    let state = Arc::new(Responses {
        replies,
        requests: Mutex::new(Vec::new()),
        delay,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = RpcClient::new(format!("http://{}/", listener.local_addr().unwrap()));
    let app = Router::new()
        .route("/", post(response))
        .with_state(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Fixture {
        client,
        state,
        server,
    }
}
fn fault(code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":1,"error":{"code":code,"message":message}})
}
fn result(value: &Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"result":value})
}

#[tokio::test]
async fn asset_read_retries_unavailable_and_keeps_exact_request_identity() {
    let body = json!({"body_b64":"ZXhhY3QgYnl0ZXM="});
    let server = fixture(
        vec![
            fault(110, "service unavailable"),
            fault(110, "worker unavailable"),
            result(&body),
        ],
        Duration::ZERO,
    )
    .await;
    assert_eq!(
        server
            .client
            .circle_asset("circle", "/immutable")
            .await
            .unwrap(),
        Some(body)
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    for request in requests {
        assert_eq!(request["method"], "circle_asset");
        assert_eq!(request["params"], json!(["circle", "/immutable"]));
    }
}

#[tokio::test]
async fn exhausted_unavailable_never_becomes_missing_even_with_missing_words() {
    let mut unavailable = fault(110, "cache not found; no such entry");
    unavailable["result"] = Value::Null;
    let server = fixture(vec![unavailable], Duration::ZERO).await;
    let error = server
        .client
        .circle_asset("circle", "/immutable")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("error 110"));
    assert_eq!(server.requests().len(), 4);
}

#[tokio::test]
async fn other_native_codes_are_immediate_and_only112_means_missing() {
    for (code, message) in [
        (-32601, "method not found"),
        (113, "HTTP 500 timeout"),
        (112, "not found"),
    ] {
        let server = fixture(vec![fault(code, message)], Duration::ZERO).await;
        let result = server.client.circle_asset("circle", "/immutable").await;
        if code == 112 {
            assert_eq!(result.unwrap(), None);
        } else {
            assert!(result.is_err());
        }
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn explicit_null_is_missing_but_absent_result_and_decode_errors_are_not() {
    let server = fixture(vec![result(&Value::Null)], Duration::ZERO).await;
    assert_eq!(
        server
            .client
            .circle_asset("circle", "/immutable")
            .await
            .unwrap(),
        None
    );
    assert_eq!(server.requests().len(), 1);
    for malformed in [
        json!({"jsonrpc":"2.0","id":1}),
        json!("not an RPC envelope"),
        json!({"jsonrpc":"2.0","id":1,"error":{"code":"timeout","message":"not found"}}),
    ] {
        let server = fixture(vec![malformed], Duration::ZERO).await;
        assert!(server
            .client
            .circle_asset("circle", "/immutable")
            .await
            .is_err());
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn raw_and_submission_calls_do_not_retry_native_unavailable() {
    for method in ["circle_asset", "octra_submit"] {
        let server = fixture(vec![fault(110, "service unavailable")], Duration::ZERO).await;
        assert!(server.client.raw_call(method, json!([])).await.is_err());
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn absolute_asset_deadline_prevents_another_attempt() {
    let server = fixture(vec![fault(110, "service unavailable")], Duration::ZERO).await;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(40);
    let error = server
        .client
        .circle_asset_until("circle", "/immutable", deadline)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("read deadline exceeded"));
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn absolute_asset_deadline_bounds_an_inflight_request() {
    let server = fixture(vec![result(&json!("late"))], Duration::from_secs(2)).await;
    let start = tokio::time::Instant::now();
    let error = server
        .client
        .circle_asset_until("circle", "/immutable", start + Duration::from_millis(80))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("read deadline exceeded"));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(server.requests().len(), 1);
}
