use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use octra_browser::{
    application::{ApplicationHost, Intent, ReadRequest, ReviewedAction},
    http::Browser,
    Asset, AssetResolver, Error, OctUrl, Provenance, SnapshotIdentity,
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tower::ServiceExt;

struct Resolver;
fn provenance() -> Provenance {
    Provenance::Canonical(SnapshotIdentity {
        chain_id: "test-chain".into(),
        origin: octra_browser::ChainOrigin::Genesis {
            state_root: octra_browser::StateRoot([0; 32]),
        },
        epoch: 4,
        state_root: "11".repeat(32),
        ledger_root: "22".repeat(64),
        irmin_commit: "33".repeat(64),
    })
}
#[async_trait]
impl AssetResolver for Resolver {
    fn provenance(&self) -> Provenance {
        provenance()
    }
    async fn resolve(&self, _: &OctUrl) -> Result<Asset, Error> {
        Ok(Asset {
            bytes: Arc::from(
                b"<script src='app.js'></script><a href='oct://two/'>Other</a>".as_slice(),
            ),
            content_type: "text/html".into(),
            provenance: provenance(),
        })
    }
}
#[derive(Default)]
struct Host {
    reads: Mutex<Vec<ReadRequest>>,
    calls: Mutex<Vec<Intent>>,
    fail: AtomicBool,
}
#[async_trait]
impl ApplicationHost for Host {
    async fn read(&self, request: ReadRequest) -> Result<Value, Error> {
        self.reads.lock().unwrap().push(request);
        Ok(json!({"counter": 4}))
    }
    async fn submit(&self, action: ReviewedAction) -> Result<Value, Error> {
        self.calls.lock().unwrap().push(action.into_intent());
        if self.fail.load(Ordering::Relaxed) {
            return Err(Error::Unavailable("host refused".into()));
        }
        Ok(json!({"hash": "aa".repeat(32)}))
    }
}
fn fixture() -> (Browser, Arc<Host>) {
    let host = Arc::new(Host::default());
    (
        Browser::new(Arc::new(Resolver), "/circles")
            .unwrap()
            .with_application(host.clone())
            .unwrap(),
        host,
    )
}
async fn get(router: Router, path: &str) -> (StatusCode, String) {
    let response = router
        .oneshot(
            Request::builder()
                .uri(path)
                .header("host", "127.0.0.1:8400")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}
async fn session(router: &Router, scope: &str, circle: &str) -> String {
    let (status, html) = get(router.clone(), &format!("/circles/view/{scope}/{circle}/")).await;
    assert_eq!(status, StatusCode::OK);
    html.split("data-token=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .into()
}
async fn post(
    router: Router,
    action: &str,
    token: &str,
    origin: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/circles/app/{action}"))
                .header("host", "127.0.0.1:8400")
                .header("origin", origin)
                .header("x-octra-session", token)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&body)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned())),
    )
}
const ORIGIN: &str = "http://127.0.0.1:8400";
fn call() -> Value {
    json!({"method": "program.call", "params": {"method": "inc", "params": ["</pre><script>bad()</script>"], "amount": "0", "ou": "1000"}})
}

#[tokio::test]
async fn sessions_bind_context_and_require_origin_and_explicit_single_use_review() {
    let (browser, host) = fixture();
    let scope = browser.provenance().id();
    let router = Router::new().nest("/circles", browser.router());
    let one = session(&router, &scope, "one").await;
    let two = session(&router, &scope, "two").await;
    assert_ne!(one, two);
    for origin in ["null", "https://evil.example", "http://127.0.0.1:8401", ""] {
        assert_eq!(
            post(
                router.clone(),
                "request",
                &one,
                origin,
                json!({"method":"wallet.info"})
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    for request in [
        json!({"method":"rpc.anything"}),
        json!({"method":"wallet.info", "params":{"circle":"two"}}),
        json!({"method":"program.view", "params":{"method":"read", "circle_id":"two"}}),
        json!({"method":"wallet.info", "context":{"circle_id":"two"}}),
    ] {
        assert!(!post(router.clone(), "request", &one, ORIGIN, request)
            .await
            .0
            .is_success());
    }
    assert!(host.reads.lock().unwrap().is_empty());
    assert_eq!(
        post(
            router.clone(),
            "request",
            &one,
            ORIGIN,
            json!({"method":"program.view", "params":{"method":"get_counter","params":[]}})
        )
        .await
        .1["result"]["counter"],
        4
    );
    {
        let reads = host.reads.lock().unwrap();
        assert_eq!(reads[0].context.circle_id, "one");
        assert_eq!(reads[0].context.provenance, provenance());
    }
    let proposal = post(router.clone(), "request", &one, ORIGIN, call())
        .await
        .1;
    assert!(host.calls.lock().unwrap().is_empty());
    assert_eq!(proposal["review"]["intent"]["context"]["circle_id"], "one");
    let approval = json!({"id": proposal["review"]["id"], "approve": true});
    assert!(!post(router.clone(), "review", &one, ORIGIN, json!({"id":proposal["review"]["id"],"approve":true,"call":{"method":"other","amount":"999"}})).await.0.is_success());
    assert_eq!(
        post(router.clone(), "review", &two, ORIGIN, approval.clone())
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    // Concurrent duplicate approvals can reach the host only once.
    let (a, b) = tokio::join!(
        post(router.clone(), "review", &one, ORIGIN, approval.clone()),
        post(router.clone(), "review", &one, ORIGIN, approval.clone())
    );
    assert_ne!(a.0.is_success(), b.0.is_success());
    assert_eq!(host.calls.lock().unwrap().len(), 1);
    assert_eq!(
        host.calls.lock().unwrap()[0].call.params,
        vec![json!("</pre><script>bad()</script>")]
    );
    assert_eq!(
        post(router.clone(), "review", &one, ORIGIN, approval)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(router.clone(), "close", &one, ORIGIN, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        post(router, "request", &one, ORIGIN, call()).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn decline_close_failure_and_oversized_input_never_create_replayable_calls() {
    let (browser, host) = fixture();
    let scope = browser.provenance().id();
    let router = Router::new().nest("/circles", browser.router());
    let token = session(&router, &scope, "one").await;
    let proposal = post(router.clone(), "request", &token, ORIGIN, call())
        .await
        .1;
    assert_eq!(
        post(router.clone(), "request", &token, ORIGIN, call())
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let id = &proposal["review"]["id"];
    assert!(post(
        router.clone(),
        "review",
        &token,
        ORIGIN,
        json!({"id":id,"approve":false})
    )
    .await
    .1["error"]
        .is_string());
    assert_eq!(
        post(
            router.clone(),
            "review",
            &token,
            ORIGIN,
            json!({"id":id,"approve":true})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert!(host.calls.lock().unwrap().is_empty());
    host.fail.store(true, Ordering::Relaxed);
    let proposal = post(router.clone(), "request", &token, ORIGIN, call())
        .await
        .1;
    let approval = json!({"id":proposal["review"]["id"],"approve":true});
    assert_eq!(
        post(router.clone(), "review", &token, ORIGIN, approval.clone())
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(router.clone(), "review", &token, ORIGIN, approval)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(host.calls.lock().unwrap().len(), 1);
    assert_eq!(post(router.clone(), "request", &token, ORIGIN, json!({"method":"program.call","params":{"method":"inc","params":["x".repeat(33000)],"amount":"0","ou":"1"}})).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    let proposal = post(router.clone(), "request", &token, ORIGIN, call())
        .await
        .1;
    post(router.clone(), "close", &token, ORIGIN, json!({})).await;
    assert_eq!(
        post(
            router,
            "review",
            &token,
            ORIGIN,
            json!({"id":proposal["review"]["id"],"approve":true})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(host.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn active_documents_are_opt_in_and_never_contain_session_credentials() {
    let (browser, _) = fixture();
    let scope = browser.provenance().id();
    let router = Router::new().nest("/circles", browser.router());
    let token = session(&router, &scope, "one").await;
    let (_, html) = get(router.clone(), &format!("/circles/document/{scope}/one/")).await;
    assert!(html.contains("Object.defineProperty(window, 'OctraCircle'"));
    assert!(html.contains(&format!("src=\"/circles/asset/{scope}/one/app.js\"")));
    assert!(!html.contains(&token));
    let (_, passive) = get(router, &format!("/circles/asset/{scope}/one/")).await;
    assert!(!passive.contains("<script"));
    let browser = Browser::new(Arc::new(Resolver), "").unwrap();
    assert_eq!(
        get(browser.router(), &format!("/document/{scope}/one/"))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn revoked_session_cannot_receive_an_in_flight_wallet_reply() {
    #[derive(Default)]
    struct WaitingHost {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    #[async_trait]
    impl ApplicationHost for WaitingHost {
        async fn read(&self, _: ReadRequest) -> Result<Value, Error> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(json!({"private_wallet_data":"must not be delivered"}))
        }
        async fn submit(&self, _: ReviewedAction) -> Result<Value, Error> {
            panic!("no submission expected")
        }
    }
    let host = Arc::new(WaitingHost::default());
    let browser = Browser::new(Arc::new(Resolver), "/circles")
        .unwrap()
        .with_application(host.clone())
        .unwrap();
    let scope = browser.provenance().id();
    let router = Router::new().nest("/circles", browser.router());
    let token = session(&router, &scope, "one").await;
    let read = tokio::spawn({
        let router = router.clone();
        let token = token.clone();
        async move {
            post(
                router,
                "request",
                &token,
                ORIGIN,
                json!({"method":"wallet.info"}),
            )
            .await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), host.entered.notified())
        .await
        .unwrap();
    assert_eq!(
        post(router, "close", &token, ORIGIN, json!({})).await.0,
        StatusCode::OK
    );
    host.release.notify_one();
    let (status, response) = read.await.unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!response.to_string().contains("private_wallet_data"));
}
