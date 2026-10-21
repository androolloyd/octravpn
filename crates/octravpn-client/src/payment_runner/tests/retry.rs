//! Exact request replay crosses a real HTTP boundary; payment authority still
//! comes only from the independently verified status and its canonical floors.
use super::*;
use axum::body::Bytes;
use std::collections::VecDeque;

#[derive(Clone, Copy)]
enum Reply {
    Status(StatusCode),
    Oversized(StatusCode),
    Hold(StatusCode),
}

#[derive(Clone)]
struct RetryState {
    connect: SignedConnect,
    status: Arc<Mutex<SignedStatus>>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    replies: Arc<Mutex<VecDeque<Reply>>>,
    fallback: Reply,
    calls: watch::Sender<usize>,
    views: watch::Sender<usize>,
    release: Arc<Notify>,
    refuse_status: Arc<AtomicBool>,
}
struct RetryHttp {
    state: RetryState,
    origin: reqwest::Url,
    server: Option<JoinHandle<()>>,
}
impl RetryHttp {
    async fn start(fixture: &Fixture, replies: Vec<Reply>) -> Self {
        let fallback = *replies.last().unwrap();
        let state = RetryState {
            connect: fixture.connect.clone(),
            status: Arc::new(Mutex::new(fixture.initial.clone())),
            bodies: Arc::default(),
            replies: Arc::new(Mutex::new(replies.into())),
            fallback,
            calls: watch::channel(0).0,
            views: watch::channel(0).0,
            release: Arc::default(),
            refuse_status: Arc::default(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin =
            reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let app = Router::new()
            .route("/payments/usage", post(reply))
            .route("/payments/connect", post(status))
            .with_state(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            state,
            origin,
            server: Some(server),
        }
    }
    async fn wait_calls(&self, minimum: usize) {
        let mut calls = self.state.calls.subscribe();
        let observed =
            tokio::time::timeout(Duration::from_secs(3), calls.wait_for(|n| *n >= minimum))
                .await
                .unwrap()
                .unwrap();
        assert!(*observed >= minimum);
    }
    async fn wait_views(&self, minimum: usize) {
        let mut views = self.state.views.subscribe();
        let observed =
            tokio::time::timeout(Duration::from_secs(4), views.wait_for(|n| *n >= minimum))
                .await
                .unwrap()
                .unwrap();
        assert!(*observed >= minimum);
    }
    async fn close(mut self) {
        self.state.release.notify_waiters();
        let server = self.server.take().unwrap();
        server.abort();
        let _ = server.await;
    }
}
impl Drop for RetryHttp {
    fn drop(&mut self) {
        self.state.release.notify_waiters();
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}
async fn reply(State(state): State<RetryState>, raw: Bytes) -> axum::response::Response {
    let receipt: SignedUsage = serde_json::from_slice(&raw).unwrap();
    receipt.verify().unwrap();
    assert_eq!(receipt.usage.binding(), state.connect.request.binding);
    assert_eq!(receipt.receipt_key, state.connect.receipt_key);
    let calls = {
        let mut bodies = state.bodies.lock();
        bodies.push(raw.to_vec());
        bodies.len()
    };
    state.calls.send_replace(calls);
    let next = state.replies.lock().pop_front().unwrap_or(state.fallback);
    match next {
        Reply::Status(code) => code.into_response(),
        Reply::Oversized(code) => (code, vec![b'x'; 1025]).into_response(),
        Reply::Hold(code) => {
            state.release.notified().await;
            code.into_response()
        }
    }
}
async fn status(
    State(state): State<RetryState>,
    Json(connect): Json<SignedConnect>,
) -> axum::response::Response {
    connect.verify().unwrap();
    assert_eq!(connect, state.connect);
    state.views.send_modify(|n| *n += 1);
    if state.refuse_status.load(Ordering::Acquire) {
        return (StatusCode::FORBIDDEN, "canonical plan unavailable").into_response();
    }
    let signed = state.status.lock().clone();
    Json(signed).into_response()
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap()
}
fn purchase(fixture: &Fixture) -> (Vec<SignedUsage>, Vec<u8>) {
    let receipts = fixture.journal.lock().purchases().unwrap();
    let image = std::fs::read(fixture.directory.path().join("plan/state.json")).unwrap();
    (receipts, image)
}
fn unchanged(fixture: &Fixture, receipts: &[SignedUsage], image: &[u8]) {
    assert_eq!(fixture.journal.lock().pending_receipts().unwrap(), receipts);
    assert_eq!(fixture.journal.lock().purchases().unwrap(), receipts);
    assert_eq!(
        fixture.journal.lock().authorized_totals(),
        fixture.plan.prepaid_bytes
    );
    assert_eq!(fixture.journal.lock().totals(), [0]);
    assert_payment_snapshot_unchanged(
        image,
        &std::fs::read(fixture.directory.path().join("plan/state.json")).unwrap(),
    );
}
fn identical_posts(state: &RetryState, count: usize, receipt: &SignedUsage) {
    let expected = serde_json::to_vec(receipt).unwrap();
    let bodies = state.bodies.lock();
    assert_eq!(bodies.len(), count);
    assert!(bodies
        .iter()
        .all(|body| body.as_slice() == expected.as_slice()));
}

#[tokio::test]
async fn transient_503_replays_identical_durable_authorization() {
    let fixture = Fixture::new();
    let (receipts, image) = purchase(&fixture);
    let http = RetryHttp::start(
        &fixture,
        vec![
            Reply::Status(StatusCode::SERVICE_UNAVAILABLE),
            Reply::Status(StatusCode::OK),
        ],
    )
    .await;
    tokio::time::timeout(
        Duration::from_secs(3),
        settle_batch(client(), http.origin.clone(), receipts.clone()),
    )
    .await
    .unwrap()
    .unwrap();
    identical_posts(&http.state, 2, &receipts[0]);
    unchanged(&fixture, &receipts, &image);
    http.close().await;
}

#[tokio::test]
async fn persistent_503_stops_after_exactly_three_posts() {
    let fixture = Fixture::new();
    let (receipts, image) = purchase(&fixture);
    let http = RetryHttp::start(
        &fixture,
        vec![Reply::Status(StatusCode::SERVICE_UNAVAILABLE)],
    )
    .await;
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        settle_batch(client(), http.origin.clone(), receipts.clone()),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error.to_string().contains("canonical payment unavailable"));
    identical_posts(&http.state, 3, &receipts[0]);
    unchanged(&fixture, &receipts, &image);
    http.close().await;
}

#[tokio::test]
async fn non_503_responses_including_403_and_429_never_retry() {
    for code in [400, 401, 403, 404, 408, 409, 429, 500, 502, 504] {
        let fixture = Fixture::new();
        let (receipts, image) = purchase(&fixture);
        let http = RetryHttp::start(
            &fixture,
            vec![Reply::Status(StatusCode::from_u16(code).unwrap())],
        )
        .await;
        let error = tokio::time::timeout(
            Duration::from_secs(3),
            settle_batch(client(), http.origin.clone(), receipts.clone()),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("canonical payment unavailable"));
        identical_posts(&http.state, 1, &receipts[0]);
        unchanged(&fixture, &receipts, &image);
        http.close().await;
    }
}

#[tokio::test]
async fn oversized_200_or_503_response_refuses_without_retry() {
    for code in [StatusCode::OK, StatusCode::SERVICE_UNAVAILABLE] {
        let fixture = Fixture::new();
        let (receipts, image) = purchase(&fixture);
        let http = RetryHttp::start(&fixture, vec![Reply::Oversized(code)]).await;
        let error = tokio::time::timeout(
            Duration::from_secs(3),
            settle_batch(client(), http.origin.clone(), receipts.clone()),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("settlement response exceeds bound"));
        identical_posts(&http.state, 1, &receipts[0]);
        unchanged(&fixture, &receipts, &image);
        http.close().await;
    }
}

#[tokio::test]
async fn cancelling_inflight_retry_preserves_durable_receipt_for_resume() {
    let fixture = Fixture::new();
    let (receipts, image) = purchase(&fixture);
    let http = RetryHttp::start(
        &fixture,
        vec![
            Reply::Status(StatusCode::SERVICE_UNAVAILABLE),
            Reply::Hold(StatusCode::SERVICE_UNAVAILABLE),
        ],
    )
    .await;
    let task = tokio::spawn(settle_batch(
        client(),
        http.origin.clone(),
        receipts.clone(),
    ));
    http.wait_calls(2).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    fixture.journal.wait_idle().await.unwrap();
    identical_posts(&http.state, 2, &receipts[0]);
    unchanged(&fixture, &receipts, &image);
    let path = fixture.directory.path().join("plan");
    drop(fixture.journal);
    let mut resumed = Journal::open(
        &path,
        fixture.plan.binding.clone(),
        fixture.plan.tariff.clone(),
        fixture.plan.original_budget_ou,
        fixture.plan.prepaid_bytes.clone(),
        Arc::new(KeyPair::from_secret_bytes(&[5; 32])),
        OpenMode::Resume,
    )
    .unwrap();
    assert_eq!(resumed.purchases().unwrap(), receipts);
    assert_eq!(resumed.authorized_totals(), fixture.plan.prepaid_bytes);
    assert_eq!(resumed.totals(), [0]);
    assert_eq!(std::fs::read(path.join("state.json")).unwrap(), image);
    http.close().await;
}

#[tokio::test]
async fn retry_then_http_200_still_cannot_open_unpurchased_payload() {
    let fixture = Fixture::new();
    let (receipts, image) = purchase(&fixture);
    let http = RetryHttp::start(
        &fixture,
        vec![
            Reply::Status(StatusCode::SERVICE_UNAVAILABLE),
            Reply::Status(StatusCode::OK),
        ],
    )
    .await;
    let preparing = fixture.prepayer(http.origin.clone());
    http.wait_calls(2).await;
    http.wait_views(3).await;
    assert!(!preparing.is_finished());
    assert!(!purchased(&http.state.status.lock(), &fixture.plan));
    unchanged(&fixture, &receipts, &image);
    identical_posts(&http.state, 2, &receipts[0]);
    *http.state.status.lock() = fixture.paid();
    let ready = tokio::time::timeout(Duration::from_secs(3), preparing)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(purchased(&ready.signed, &fixture.plan));
    unchanged(&fixture, &receipts, &image);
    http.close().await;
}

#[tokio::test]
async fn forbidden_status_cancels_held_retry_without_opening_payload() {
    let fixture = Fixture::new();
    let (receipts, image) = purchase(&fixture);
    let http = RetryHttp::start(
        &fixture,
        vec![
            Reply::Status(StatusCode::SERVICE_UNAVAILABLE),
            Reply::Hold(StatusCode::SERVICE_UNAVAILABLE),
        ],
    )
    .await;
    let preparing = fixture.prepayer(http.origin.clone());
    http.wait_calls(2).await;
    http.state.refuse_status.store(true, Ordering::Release);
    // The second settlement response stays held: status revocation must end
    // prepay and drop its owned retry instead of waiting for that HTTP call.
    let error = tokio::time::timeout(Duration::from_secs(3), preparing)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<reqwest::Error>().unwrap().status(),
        Some(StatusCode::FORBIDDEN)
    );
    assert!(!purchased(&http.state.status.lock(), &fixture.plan));
    fixture.journal.wait_idle().await.unwrap();
    identical_posts(&http.state, 2, &receipts[0]);
    unchanged(&fixture, &receipts, &image);
    http.close().await;
}
