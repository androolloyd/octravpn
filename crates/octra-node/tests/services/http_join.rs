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
    directory: tempfile::TempDir,
    source: Node<Authority>,
    target: Node<Authority>,
    authority: finality_host::Authority,
    client: octra_node::consensus_join::Client,
    server: tokio::task::JoinHandle<()>,
    first_root: Vec<u8>,
    requests: Arc<Mutex<Vec<i64>>>,
    unavailable: Arc<AtomicBool>,
    head_response: Arc<Mutex<Option<Vec<u8>>>>,
    invalid_epoch: Arc<std::sync::atomic::AtomicI64>,
    malformed_epoch: Arc<std::sync::atomic::AtomicI64>,
    discontinuous_epoch: Arc<std::sync::atomic::AtomicI64>,
    range_sizes: Arc<Mutex<Vec<i64>>>,
    delay_ms: Arc<std::sync::atomic::AtomicU64>,
}
impl JoinFixture {
    async fn new() -> Self {
        Self::with_epochs(2).await
    }
    async fn with_epochs(epochs: usize) -> Self {
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
        for _ in 0..epochs {
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
        let mut records = Vec::new();
        for from in (1..=epochs).step_by(16) {
            let octra_node_runtime::finality_queries::Range::Found { records: chunk, .. } =
                source.history().range(from as i64, 16).await.unwrap()
            else {
                panic!("signed source history missing")
            };
            records.extend(chunk);
        }
        assert_eq!(records.len(), epochs);
        let first_root = records[0].state_root.clone();

        let requests = Arc::new(Mutex::new(Vec::new()));
        let unavailable = Arc::new(AtomicBool::new(false));
        let invalid_epoch = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let malformed_epoch = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let discontinuous_epoch = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let range_sizes = Arc::new(Mutex::new(Vec::new()));
        let delay_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let base = target.head().await.unwrap();
        let head_response = Arc::new(Mutex::new(Some(http::head_response(
            base.cursor.epoch.0 as i64 + 1,
            Some(&http::Head {
                epoch: base.cursor.epoch.0 as i64,
                state_root: hex::encode(base.cursor.state_root.0).into_bytes(),
                txid_hi: base.txid_hi,
                irmin_commit: None,
            }),
            None,
        ))));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let router = axum::Router::new()
            .route(
                "/state-sync/head",
                axum::routing::get({
                    let head_response = head_response.clone();
                    move || {
                        let response = head_response.lock().unwrap().clone();
                        async move {
                            response.map_or_else(
                                || (axum::http::StatusCode::SERVICE_UNAVAILABLE, Vec::new()),
                                |body| (axum::http::StatusCode::OK, body),
                            )
                        }
                    }
                }),
            )
            .route(
                "/state-sync/range",
                axum::routing::get({
                    let requests = requests.clone();
                    let unavailable = unavailable.clone();
                    let invalid_epoch = invalid_epoch.clone();
                    let malformed_epoch = malformed_epoch.clone();
                    let discontinuous_epoch = discontinuous_epoch.clone();
                    let range_sizes = range_sizes.clone();
                    let delay_ms = delay_ms.clone();
                    move |axum::extract::Query(query): axum::extract::Query<
                        std::collections::HashMap<String, String>,
                    >| {
                        let records = records.clone();
                        let requests = requests.clone();
                        let unavailable = unavailable.clone();
                        let invalid_epoch = invalid_epoch.clone();
                        let malformed_epoch = malformed_epoch.clone();
                        let discontinuous_epoch = discontinuous_epoch.clone();
                        let range_sizes = range_sizes.clone();
                        let delay_ms = delay_ms.clone();
                        async move {
                            let from: i64 = query["from_epoch"].parse().unwrap();
                            let max: i64 = query["max_epochs"].parse().unwrap();
                            requests.lock().unwrap().push(from);
                            range_sizes.lock().unwrap().push(max);
                            tokio::time::sleep(Duration::from_millis(
                                delay_ms.load(Ordering::SeqCst),
                            ))
                            .await;
                            if unavailable.load(Ordering::SeqCst) {
                                return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Vec::new());
                            }
                            let query = http::RangeQuery {
                                from_epoch: from,
                                max_epochs: max,
                                part: None,
                                hash: None,
                            };
                            let mut records: Vec<_> = records
                                .into_iter()
                                .filter(|record| record.epoch_id >= from)
                                .take(usize::try_from(max).unwrap())
                                .collect();
                            for record in &mut records {
                                if record.epoch_id == malformed_epoch.load(Ordering::SeqCst) {
                                    record.txs_json.push(b"{not a transaction}".to_vec());
                                }
                                if record.epoch_id == discontinuous_epoch.load(Ordering::SeqCst) {
                                    record.prev_state_root = vec![0; 32];
                                }
                                if record.epoch_id == invalid_epoch.load(Ordering::SeqCst) {
                                    record
                                        .finality
                                        .as_mut()
                                        .unwrap()
                                        .finalize
                                        .precommits
                                        .clear();
                                }
                            }
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
            directory,
            source,
            target,
            authority,
            client,
            server,
            first_root,
            requests,
            unavailable,
            head_response,
            invalid_epoch,
            malformed_epoch,
            discontinuous_epoch,
            range_sizes,
            delay_ms,
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
async fn http_target_uses_authenticated_successors_with_stale_or_unavailable_head() {
    for unavailable_head in [false, true] {
        let fixture = JoinFixture::new().await;
        if unavailable_head {
            *fixture.head_response.lock().unwrap() = None;
        }
        let membership_store = CanonicalStore::open(
            &fixture.directory.path().join("target.db"),
            &fixture.authority.chain,
        )
        .await
        .unwrap();
        let membership = octra_node_runtime::validator_history::CanonicalValidators::new(
            membership_store.reader(),
            octra_node_runtime::validator_history::Environment::default(),
        );
        let executor = ImportExecutor::new(&fixture.authority, &fixture.target);
        let target = fixture
            .client
            .proved_target(
                &fixture.target,
                &membership,
                &executor,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(target, Some(1));
        assert_eq!(fixture.target.head().await.unwrap().cursor.epoch.0, 0);
        assert!(fixture.target.snapshot().is_err());
        let progress = fixture
            .client
            .catch_up(
                &fixture.target,
                target.unwrap(),
                &executor,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert!(progress.reached);
        assert_eq!(progress.head.cursor.epoch.0, 2);
        assert!(fixture.target.snapshot().is_err());
        assert_eq!(
            fixture.target.head().await.unwrap(),
            fixture.source.head().await.unwrap()
        );
        membership_store.close().await;
        fixture.shutdown().await;
    }
}

#[tokio::test]
async fn http_target_rejects_successors_without_valid_finality_despite_stale_head() {
    let fixture = JoinFixture::new().await;
    fixture.invalid_epoch.store(1, Ordering::SeqCst);
    let membership_store = CanonicalStore::open(
        &fixture.directory.path().join("target.db"),
        &fixture.authority.chain,
    )
    .await
    .unwrap();
    let membership = octra_node_runtime::validator_history::CanonicalValidators::new(
        membership_store.reader(),
        octra_node_runtime::validator_history::Environment::default(),
    );
    let executor = ImportExecutor::new(&fixture.authority, &fixture.target);
    assert_eq!(
        fixture
            .client
            .proved_target(
                &fixture.target,
                &membership,
                &executor,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap(),
        None
    );
    assert_eq!(*fixture.requests.lock().unwrap(), [1]);
    assert_eq!(fixture.target.head().await.unwrap().cursor.epoch.0, 0);
    assert!(fixture.target.snapshot().is_err());
    membership_store.close().await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn http_target_does_not_promote_an_unproved_suffix_to_a_persistent_target() {
    let fixture = JoinFixture::new().await;
    fixture.invalid_epoch.store(2, Ordering::SeqCst);
    let membership_store = CanonicalStore::open(
        &fixture.directory.path().join("target.db"),
        &fixture.authority.chain,
    )
    .await
    .unwrap();
    let membership = octra_node_runtime::validator_history::CanonicalValidators::new(
        membership_store.reader(),
        octra_node_runtime::validator_history::Environment::default(),
    );
    let executor = ImportExecutor::new(&fixture.authority, &fixture.target);
    let first = fixture
        .client
        .proved_target(
            &fixture.target,
            &membership,
            &executor,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(first, Some(1));
    assert_eq!(fixture.target.head().await.unwrap().cursor.epoch.0, 0);
    let progress = fixture
        .client
        .catch_up(
            &fixture.target,
            first.unwrap(),
            &executor,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(progress.reached);
    assert_eq!(progress.head.cursor.epoch.0, 1);
    assert_eq!(
        progress.head.cursor.state_root.0.as_slice(),
        fixture.first_root
    );
    assert_eq!(
        fixture
            .client
            .proved_target(
                &fixture.target,
                &membership,
                &executor,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap(),
        None
    );
    assert_eq!(fixture.target.head().await.unwrap(), progress.head);
    assert!(fixture.target.snapshot().is_err());
    membership_store.close().await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn http_join_tries_secondary_after_primary_head_stalls() {
    let fixture = JoinFixture::new().await;
    let source_head = fixture.source.head().await.unwrap();
    let octra_node_runtime::finality_queries::Range::Found { records, .. } =
        fixture.source.history().range(1, 2).await.unwrap()
    else {
        panic!("signed source history missing");
    };
    let response = http::head_response(
        source_head.cursor.epoch.0 as i64 + 1,
        Some(&http::Head {
            epoch: source_head.cursor.epoch.0 as i64,
            state_root: hex::encode(source_head.cursor.state_root.0).into_bytes(),
            txid_hi: source_head.txid_hi,
            irmin_commit: None,
        }),
        None,
    );
    let primary_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let primary = format!("http://{}", primary_listener.local_addr().unwrap());
    let primary_server = tokio::spawn(async move {
        axum::serve(
            primary_listener,
            axum::Router::new().route(
                "/state-sync/head",
                axum::routing::get(|| async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    (axum::http::StatusCode::SERVICE_UNAVAILABLE, Vec::new())
                }),
            ),
        )
        .await
        .unwrap();
    });
    let secondary_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let secondary = format!("http://{}", secondary_listener.local_addr().unwrap());
    let head_seen = Arc::new(AtomicBool::new(false));
    let range_seen = Arc::new(AtomicBool::new(false));
    let secondary_server = tokio::spawn({
        let head_seen = head_seen.clone();
        let range_seen = range_seen.clone();
        async move {
            let router = axum::Router::new()
                .route(
                    "/state-sync/head",
                    axum::routing::get(move || {
                        let response = response.clone();
                        let head_seen = head_seen.clone();
                        async move {
                            head_seen.store(true, Ordering::SeqCst);
                            response
                        }
                    }),
                )
                .route(
                    "/state-sync/range",
                    axum::routing::get(
                        move |axum::extract::Query(query): axum::extract::Query<
                            std::collections::HashMap<String, String>,
                        >| {
                            let records = records.clone();
                            let range_seen = range_seen.clone();
                            async move {
                                range_seen.store(true, Ordering::SeqCst);
                                let from: i64 = query["from_epoch"].parse().unwrap();
                                let max: i64 = query["max_epochs"].parse().unwrap();
                                let request = http::RangeQuery {
                                    from_epoch: from,
                                    max_epochs: max,
                                    part: None,
                                    hash: None,
                                };
                                http::range_response(
                                    None,
                                    &request,
                                    &http::RangeResult::Records {
                                        records: records
                                            .into_iter()
                                            .filter(|record| record.epoch_id >= from)
                                            .take(max as usize)
                                            .collect(),
                                        next_epoch: None,
                                    },
                                )
                                .unwrap()
                            }
                        },
                    ),
                );
            axum::serve(secondary_listener, router).await.unwrap();
        }
    });
    let sources = format!("{primary},{secondary}");
    let client = octra_node::consensus_join::Client::capture(|name| {
        (name == "OCTRA_JOIN_RPC").then(|| sources.as_bytes().to_vec())
    })
    .unwrap();
    let membership_store = CanonicalStore::open(
        &fixture.directory.path().join("target.db"),
        &fixture.authority.chain,
    )
    .await
    .unwrap();
    let membership = octra_node_runtime::validator_history::CanonicalValidators::new(
        membership_store.reader(),
        octra_node_runtime::validator_history::Environment::default(),
    );
    let executor = ImportExecutor::new(&fixture.authority, &fixture.target);
    let proved = client
        .proved_target(
            &fixture.target,
            &membership,
            &executor,
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(proved, Some(1));
    assert!(!head_seen.swap(false, Ordering::SeqCst));
    assert!(range_seen.swap(false, Ordering::SeqCst));
    membership_store.close().await;
    let report = client
        .synchronize(
            &fixture.target,
            &executor,
            fixture.directory.path(),
            &SigningKey::from_bytes(&[99; 32]),
            false,
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert!(report.synced, "{:#?}", report.error);
    assert_eq!(report.records_verified, 2);
    let canonical_secondary = format!("{secondary}/");
    assert_eq!(report.source.as_deref(), Some(canonical_secondary.as_str()));
    assert!(head_seen.load(Ordering::SeqCst));
    assert!(range_seen.load(Ordering::SeqCst));
    assert_eq!(fixture.target.head().await.unwrap(), source_head);
    primary_server.abort();
    secondary_server.abort();
    fixture.shutdown().await;
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

#[tokio::test]
async fn http_first_verified_target_imports_one_bounded_sixteen_epoch_prefix() {
    let fixture = JoinFixture::with_epochs(17).await;
    let membership_store = CanonicalStore::open(
        &fixture.directory.path().join("target.db"),
        &fixture.authority.chain,
    )
    .await
    .unwrap();
    let membership = octra_node_runtime::validator_history::CanonicalValidators::new(
        membership_store.reader(),
        octra_node_runtime::validator_history::Environment::default(),
    );
    let executor = ImportExecutor::new(&fixture.authority, &fixture.target);
    let target = fixture
        .client
        .proved_target(
            &fixture.target,
            &membership,
            &executor,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(target, Some(1));
    assert_eq!(fixture.target.head().await.unwrap().cursor.epoch.0, 0);
    assert!(fixture.target.snapshot().is_err());
    let progress = fixture
        .client
        .catch_up(
            &fixture.target,
            target.unwrap(),
            &executor,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(progress.reached);
    assert_eq!(progress.head.cursor.epoch.0, 16);
    assert!(fixture.target.snapshot().is_err());
    assert_eq!(*fixture.requests.lock().unwrap(), [1, 1]);
    assert_eq!(*fixture.range_sizes.lock().unwrap(), [16, 16]);
    assert_eq!(
        fixture
            .client
            .proved_target(
                &fixture.target,
                &membership,
                &executor,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap(),
        Some(17)
    );
    assert_eq!(fixture.target.head().await.unwrap(), progress.head);
    assert!(fixture.target.snapshot().is_err());
    membership_store.close().await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn http_corrupt_payload_or_continuity_suffix_rejects_whole_chunk_before_import() {
    for malformed_payload in [true, false] {
        let fixture = JoinFixture::new().await;
        if malformed_payload {
            fixture.malformed_epoch.store(2, Ordering::SeqCst);
        } else {
            fixture.discontinuous_epoch.store(2, Ordering::SeqCst);
        }
        let before = fixture.target.head().await.unwrap();
        let executor = ImportExecutor::new(&fixture.authority, &fixture.target);
        let progress = fixture
            .client
            .catch_up(
                &fixture.target,
                1,
                &executor,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert!(!progress.reached);
        assert_eq!(fixture.target.head().await.unwrap(), before);
        assert_eq!(progress.head, before);
        assert!(fixture.target.snapshot().is_err());
        assert_eq!(*fixture.range_sizes.lock().unwrap(), [16]);
        fixture.shutdown().await;
    }
}

struct FailAfterFirst {
    inner: ImportExecutor,
    fail_rules: bool,
}
#[async_trait::async_trait]
impl Executor for FailAfterFirst {
    fn graph(&self) -> octra_node_protocol::rules::Graph {
        self.inner.graph()
    }
    fn rules(
        &self,
        parent: &Head,
        header: &EpochHeader,
        context: &octra_node_runtime::execution_rules::Bound,
    ) -> Result<BundleRules> {
        if self.fail_rules && header.epoch_id == 2 {
            anyhow::bail!("fixture valid-QC rules failure");
        }
        self.inner.rules(parent, header, context)
    }
    async fn execute(&self, request: octra_node::import::Execution<'_>) -> Result<ExecutedEpoch> {
        if !self.fail_rules && request.finalized.epoch_id == 2 {
            anyhow::bail!("fixture valid-QC execution failure");
        }
        self.inner.execute(request).await
    }
}

#[tokio::test]
async fn http_valid_qc_rules_or_execution_failure_is_not_a_harmless_qc_suffix() {
    for fail_rules in [true, false] {
        let fixture = JoinFixture::new().await;
        let executor = FailAfterFirst {
            inner: ImportExecutor::new(&fixture.authority, &fixture.target),
            fail_rules,
        };
        let error = fixture
            .client
            .catch_up(
                &fixture.target,
                1,
                &executor,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .err()
            .expect("valid-QC rules/execution failure must remain hard");
        let expected = if fail_rules {
            "fixture valid-QC rules failure"
        } else {
            "fixture valid-QC execution failure"
        };
        assert!(format!("{error:#}").contains(expected));
        assert_eq!(fixture.target.head().await.unwrap().cursor.epoch.0, 1);
        assert_eq!(
            fixture
                .target
                .head()
                .await
                .unwrap()
                .cursor
                .state_root
                .0
                .as_slice(),
            fixture.first_root
        );
        assert!(fixture.target.snapshot().is_err());
        fixture.shutdown().await;
    }
}

#[tokio::test]
async fn http_prefix_network_deadline_does_not_start_execution() {
    let fixture = JoinFixture::new().await;
    fixture.delay_ms.store(2_000, Ordering::SeqCst);
    let before = fixture.target.head().await.unwrap();
    let executor = ImportExecutor::new(&fixture.authority, &fixture.target);
    let started = Instant::now();
    let progress = fixture
        .client
        .catch_up(
            &fixture.target,
            1,
            &executor,
            started + Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert!(!progress.reached);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(progress.head, before);
    assert_eq!(fixture.target.head().await.unwrap(), before);
    assert!(fixture.target.snapshot().is_err());
    assert_eq!(*fixture.range_sizes.lock().unwrap(), [16]);
    fixture.shutdown().await;
}

struct SlowSecondQc {
    inner: finality_host::Authority,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    until: Arc<Mutex<Option<Instant>>>,
}
#[async_trait::async_trait]
impl ValidatorHistory for SlowSecondQc {
    async fn resolve(
        &self,
        parent: &Head,
        epoch: u64,
        relief: ReliefSource,
    ) -> Result<EpochRules, String> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        // The first lookup selects this HTTP source; the second belongs to
        // the per-record QC immediately before execution dispatch.
        if epoch == 1 && call == 1 {
            let until = self
                .until
                .lock()
                .unwrap()
                .expect("deadline installed before request");
            tokio::time::sleep_until(until).await;
        }
        self.inner.resolve(parent, epoch, relief).await
    }
}
impl Host for SlowSecondQc {}
struct CountExecution {
    inner: ImportExecutor,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
#[async_trait::async_trait]
impl Executor for CountExecution {
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
    async fn execute(&self, _: octra_node::import::Execution<'_>) -> Result<ExecutedEpoch> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("execution must not start after QC consumed the deadline")
    }
}

#[tokio::test]
async fn http_trusted_qc_lookup_cannot_dispatch_execution_after_absolute_deadline() {
    let fixture = JoinFixture::new().await;
    let state = genesis(format!("oct{}", "1".repeat(44)).as_bytes());
    let store = CanonicalStore::create(
        &fixture.directory.path().join("slow-qc.db"),
        fixture.authority.chain.clone(),
        state.snapshot(),
        0,
    )
    .await
    .unwrap();
    let checkpoint = Arc::new(
        SqliteCheckpoints::open(&fixture.directory.path().join("slow-qc-exex.db"))
            .await
            .unwrap(),
    );
    let until = Arc::new(Mutex::new(None));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let target = Node::open(
        store,
        SlowSecondQc {
            inner: finality_host::Authority {
                seed: fixture.authority.seed,
                chain: fixture.authority.chain.clone(),
            },
            calls: calls.clone(),
            until: until.clone(),
        },
        circle_host::runtime(),
        Arc::new(UnavailableHost),
        checkpoint,
    )
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let before = target.head().await.unwrap();
    let executions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let executor = CountExecution {
        inner: ImportExecutor::new(&fixture.authority, &fixture.target),
        calls: executions.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    *until.lock().unwrap() = Some(deadline + Duration::from_millis(20));
    let progress = tokio::time::timeout(
        Duration::from_secs(3),
        fixture.client.catch_up(&target, 1, &executor, deadline),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(!progress.reached);
    assert_eq!(executions.load(Ordering::SeqCst), 0);
    assert_eq!(progress.head, before);
    assert_eq!(target.head().await.unwrap(), before);
    assert!(target.snapshot().is_err());
    target.shutdown().await.unwrap();
    fixture.shutdown().await;
}
