use super::*;
use octra_node_protocol::state_sync::http;
use tokio::time::Instant;

struct ExpiringExecutor {
    inner: ImportExecutor,
    deadline: Instant,
    entered: Arc<tokio::sync::Notify>,
}
#[async_trait::async_trait]
impl Executor for ExpiringExecutor {
    fn graph(&self) -> octra_node_protocol::rules::Graph {
        self.inner.graph()
    }
    fn rules(
        &self,
        parent: &Head,
        header: &EpochHeader,
        context: &octra_node_runtime::execution_rules::Bound,
    ) -> Result<BundleRules> {
        self.inner.rules(parent, header, context)
    }
    async fn execute(&self, request: octra_node::import::Execution<'_>) -> Result<ExecutedEpoch> {
        let executed = self.inner.execute(request).await?;
        self.entered.notify_one();
        // Let the first authenticated epoch finish after the request budget.
        // Publication must finish atomically, but a second epoch must not start.
        tokio::time::sleep_until(self.deadline).await;
        Ok(executed)
    }
}

struct JoinFixture {
    _directory: tempfile::TempDir,
    source: Node<Authority>,
    target: Node<Authority>,
    authority: finality_host::Authority,
    client: octra_node::consensus_join::Client,
    server: tokio::task::JoinHandle<()>,
    first_root: Vec<u8>,
    requests: Arc<Mutex<Vec<i64>>>,
    unavailable: Arc<AtomicBool>,
}
impl JoinFixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let state = genesis(format!("oct{}", "1".repeat(44)).as_bytes());
        let chain = ChainIdentity::genesis(
            "http-join-deadline",
            StateRoot(finality_host::root(None, &state, &[])),
        );
        let authority = finality_host::Authority {
            seed: 1,
            chain: chain.clone(),
        };
        let mut nodes = Vec::new();
        for name in ["source", "target"] {
            let path = directory.path().join(format!("{name}.db"));
            CanonicalStore::create(&path, chain.clone(), state.snapshot(), 0)
                .await
                .unwrap()
                .close()
                .await;
            let checkpoints = Arc::new(
                SqliteCheckpoints::open(&directory.path().join(format!("{name}-exex.db")))
                    .await
                    .unwrap(),
            );
            nodes.push(open(&path, checkpoints, chain.clone(), Arc::default()).await);
        }
        let target = nodes.pop().unwrap();
        let source = nodes.pop().unwrap();
        source.resume().await.unwrap();
        for _ in 0..2 {
            let view = source.snapshot().unwrap();
            let mut executed = execute_received(
                view.head(),
                StateBatch::from_snapshot(view.state().clone()),
                &[],
                &authority,
                None,
                None,
            )
            .unwrap();
            // Match the native import's local commit metadata as well as its
            // certified state, so complete retained heads can be compared.
            executed.message = b"finalized epoch".to_vec();
            let certificate = finality_host::certificate(view.head(), &executed, &authority)
                .encode()
                .unwrap();
            source
                .publish(view.head(), &certificate, executed)
                .await
                .unwrap();
        }
        let octra_node_runtime::finality_queries::Range::Found { records, .. } =
            source.history().range(1, 2).await.unwrap()
        else {
            panic!("signed source history missing");
        };
        let first_root = records[0].state_root.clone();

        let requests = Arc::new(Mutex::new(Vec::new()));
        let unavailable = Arc::new(AtomicBool::new(false));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let router = axum::Router::new().route(
            "/state-sync/range",
            axum::routing::get({
                let requests = requests.clone();
                let unavailable = unavailable.clone();
                move |axum::extract::Query(query): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| {
                    let records = records.clone();
                    let requests = requests.clone();
                    let unavailable = unavailable.clone();
                    async move {
                        let from: i64 = query["from_epoch"].parse().unwrap();
                        let max: i64 = query["max_epochs"].parse().unwrap();
                        requests.lock().unwrap().push(from);
                        if unavailable.load(Ordering::SeqCst) {
                            return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Vec::new());
                        }
                        let query = http::RangeQuery {
                            from_epoch: from,
                            max_epochs: max,
                            part: None,
                            hash: None,
                        };
                        let records = records
                            .into_iter()
                            .filter(|record| record.epoch_id >= from)
                            .take(usize::try_from(max).unwrap())
                            .collect();
                        let body = http::range_response(
                            None,
                            &query,
                            &http::RangeResult::Records {
                                records,
                                next_epoch: None,
                            },
                        )
                        .unwrap();
                        (axum::http::StatusCode::OK, body)
                    }
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = octra_node::consensus_join::Client::capture(|name| {
            (name == "OCTRA_JOIN_RPC").then(|| endpoint.as_bytes().to_vec())
        })
        .unwrap();
        Self {
            _directory: directory,
            source,
            target,
            authority,
            client,
            server,
            first_root,
            requests,
            unavailable,
        }
    }
    async fn shutdown(self) {
        self.target.shutdown().await.unwrap();
        self.source.shutdown().await.unwrap();
        self.server.abort();
        assert!(self.server.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
async fn http_join_deadline_preserves_committed_prefix_before_next_record() {
    let fixture = JoinFixture::new().await;
    let deadline = Instant::now() + Duration::from_secs(5);
    let executor = ExpiringExecutor {
        inner: ImportExecutor::new(&fixture.authority, &fixture.target),
        deadline,
        entered: Arc::default(),
    };
    let progress = fixture
        .client
        .catch_up(&fixture.target, 2, &executor, deadline)
        .await
        .unwrap();
    assert!(!progress.reached);
    assert_eq!(progress.head.cursor.epoch.0, 1);
    assert_eq!(
        progress.head.cursor.state_root.0.as_slice(),
        fixture.first_root
    );
    assert!(fixture.target.snapshot().is_err());
    assert!(fixture.target.resume().await.unwrap());
    assert_eq!(fixture.target.snapshot().unwrap().head(), &progress.head);
    fixture.shutdown().await;
}

#[tokio::test]
async fn http_join_continues_after_a_window_with_verified_progress() {
    let fixture = JoinFixture::new().await;
    let executor = ExpiringExecutor {
        inner: ImportExecutor::new(&fixture.authority, &fixture.target),
        deadline: Instant::now() + Duration::from_secs(6),
        entered: Arc::default(),
    };
    let progress = fixture
        .client
        .catch_up_windows(&fixture.target, 2, &executor, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(progress.reached);
    assert_eq!(progress.head, fixture.source.head().await.unwrap());
    assert_eq!(*fixture.requests.lock().unwrap(), [1, 2]);
    assert!(fixture.target.snapshot().is_err());
    fixture.shutdown().await;
}

#[tokio::test]
async fn http_join_stops_after_a_window_without_progress() {
    let fixture = JoinFixture::new().await;
    fixture.unavailable.store(true, Ordering::SeqCst);
    let executor = ImportExecutor::new(&fixture.authority, &fixture.target);
    let progress = tokio::time::timeout(
        Duration::from_secs(5),
        fixture
            .client
            .catch_up_windows(&fixture.target, 2, &executor, Duration::from_secs(30)),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!progress.reached);
    assert_eq!(progress.head.cursor.epoch.0, 0);
    assert_eq!(*fixture.requests.lock().unwrap(), [1]);
    assert!(fixture.target.snapshot().is_err());
    fixture.shutdown().await;
}

#[tokio::test]
async fn http_join_does_not_retry_failed_execution_as_progress() {
    let fixture = JoinFixture::new().await;
    let executor = ImportExecutor::new(&fixture.authority, &fixture.target);
    executor.fail.store(true, Ordering::SeqCst);
    assert!(fixture
        .client
        .catch_up_windows(&fixture.target, 2, &executor, Duration::from_secs(30))
        .await
        .is_err());
    assert_eq!(fixture.target.head().await.unwrap().cursor.epoch.0, 0);
    assert_eq!(*fixture.requests.lock().unwrap(), [1]);
    assert!(fixture.target.snapshot().is_err());
    fixture.shutdown().await;
}

#[tokio::test]
async fn cancelled_http_join_can_recover_without_partial_publication() {
    let fixture = JoinFixture::new().await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let executor = ExpiringExecutor {
        inner: ImportExecutor::new(&fixture.authority, &fixture.target),
        deadline: Instant::now() + Duration::from_secs(3600),
        entered: entered.clone(),
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            result = fixture.client.catch_up_windows(
                &fixture.target, 2, &executor, Duration::from_secs(30)
            ) => panic!("paused execution completed unexpectedly: {}", result.is_ok()),
            () = entered.notified() => (),
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.target.head().await.unwrap().cursor.epoch.0, 0);
    assert!(fixture.target.snapshot().is_err());
    let executor = ImportExecutor::new(&fixture.authority, &fixture.target);
    let progress = fixture
        .client
        .catch_up_windows(&fixture.target, 2, &executor, Duration::from_secs(30))
        .await
        .unwrap();
    assert!(progress.reached);
    assert_eq!(progress.head, fixture.source.head().await.unwrap());
    assert_eq!(*fixture.requests.lock().unwrap(), [1, 1]);
    fixture.shutdown().await;
}
