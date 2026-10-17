//! A root conflict suspends services without undoing authenticated empty epochs.
use super::*;
use octra_exex::{CheckpointStore, CommittedEpochSource, Cursor, Sequence};
use tokio::{sync::Notify, task::JoinHandle};

const WAIT: Duration = Duration::from_secs(10);
const EXTENSION: &str = "root-quarantine";
const GATEWAY_HOST: &str = "circles.example.ts.net";

struct EmptyRecorder(Arc<Mutex<Vec<CommittedEpoch<NativeTransaction>>>>);
impl ExEx<NativeTransaction> for EmptyRecorder {
    fn name(&self) -> &'static str {
        EXTENSION
    }
    async fn on_epoch(&mut self, epoch: &CommittedEpoch<NativeTransaction>) -> Result<(), String> {
        assert!(epoch.events.is_empty());
        self.0.lock().unwrap().push(epoch.clone());
        Ok(())
    }
}
async fn checkpoint<A: Host>(node: &Node<A>, expected: Cursor) {
    let mut status = node.extension_status(EXTENSION).await.unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            if matches!(*status.borrow_and_update(), ExtensionStatus::Running { checkpoint } if checkpoint == expected)
            {
                break;
            }
            status.changed().await.unwrap();
        }
    })
    .await
    .expect("empty epoch did not reach its durable ExEx checkpoint");
}
async fn empty_epoch<A: Host>(
    node: &Node<A>,
    parent: &Committed,
    authority: &finality_host::Authority,
) -> Head {
    let executed = execute_received(
        parent.head(),
        StateBatch::from_snapshot(parent.state().clone()),
        &[],
        authority,
        None,
        None,
    )
    .unwrap();
    assert!(executed.transactions.is_empty());
    let certificate = finality_host::certificate(parent.head(), &executed, authority)
        .encode()
        .unwrap();
    node.publish(parent.head(), &certificate, executed)
        .await
        .unwrap()
        .head
}
struct Running {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<()>>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl Running {
    fn spawn<F: std::future::Future<Output = Result<()>> + Send + 'static>(
        run: impl FnOnce(watch::Receiver<bool>) -> F,
    ) -> Self {
        let (stop, shutdown) = watch::channel(false);
        Self {
            stop,
            task: Some(tokio::spawn(run(shutdown))),
        }
    }
    async fn stop(mut self) {
        self.stop.send_replace(true);
        tokio::time::timeout(WAIT, self.task.as_mut().unwrap())
            .await
            .expect("quarantine service did not stop")
            .unwrap()
            .unwrap();
        let _ = self.task.take();
    }
}
async fn reads(http: &reqwest::Client, urls: &[(String, bool)], expected: u16) {
    for (url, gateway) in urls {
        let request = http.get(url);
        let request = if *gateway {
            request.header("host", GATEWAY_HOST)
        } else {
            request
        };
        assert_eq!(
            request.send().await.unwrap().status().as_u16(),
            expected,
            "{url}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn root_quarantine_revokes_services_without_rewinding_empty_finality_or_exex() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.db");
    let circle = format!("oct{}", "1".repeat(44));
    let state = genesis(circle.as_bytes());
    let chain = ChainIdentity::genesis(
        "root-quarantine-services-fixture",
        StateRoot(finality_host::root(None, &state, &[])),
    );
    CanonicalStore::create(&path, chain.clone(), state.snapshot(), 0)
        .await
        .unwrap()
        .close()
        .await;
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&directory.path().join("exex.db"))
            .await
            .unwrap(),
    );
    let authority = finality_host::Authority {
        seed: 1,
        chain: chain.clone(),
    };
    let node = Arc::new(open(&path, checkpoints.clone(), chain.clone(), Arc::default()).await);
    assert!(node.resume().await.unwrap());
    let events = Arc::new(Mutex::new(vec![]));
    node.register(EmptyRecorder(events.clone())).await.unwrap();
    let genesis = node.snapshot().unwrap();
    let first = empty_epoch(&node, &genesis, &authority).await;
    checkpoint(&node, first.cursor).await;
    let captured = node.snapshot().unwrap();
    assert_eq!(first.txid_hi, genesis.head().txid_hi);
    assert_ne!(first.cursor.state_root, genesis.head().cursor.state_root);

    let (request, mut settlement) = announce();
    Arc::get_mut(&mut settlement).unwrap().session.expires_epoch = 100;
    let domain = settlement.session.domain.clone();
    let admission = node.vpn_authority(settlement.clone());
    let permit = admission
        .authorize(&request, &domain)
        .await
        .unwrap()
        .unwrap();
    assert!(permit.live());
    let services = node
        .bind(
            "127.0.0.1:0".parse().unwrap(),
            vpn_config(&directory.path().join("vpn"), &domain),
            settlement,
        )
        .await
        .unwrap();
    let browser = format!("http://{}", services.browser_addr().unwrap());
    let browser_task = Running::spawn(move |shutdown| services.run(shutdown));
    let gateway = node
        .bind_gateway(octra_node::gateway::Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            origin: format!("https://{GATEWAY_HOST}"),
            sites: std::collections::BTreeMap::new(),
            portal: None,
        })
        .await
        .unwrap();
    let gateway_base = format!("http://{}", gateway.local_addr().unwrap());
    let gateway_task = Running::spawn(move |shutdown| gateway.run(shutdown));
    let http = reqwest::Client::builder().timeout(WAIT).build().unwrap();
    let scope = captured.provenance().id();
    let browser_view = format!("{browser}/view/{scope}/{circle}/index.html");
    let gateway_view = format!("{gateway_base}/circles/{circle}/index.html");
    // Visit the current gateway first so its immutable capability is retained.
    reads(&http, &[(gateway_view.clone(), true)], 200).await;
    let retained_gateway = format!("{gateway_base}/snapshots/{scope}/{circle}/index.html");
    let urls = [
        (format!("{browser}/"), false),
        (browser_view, false),
        (gateway_view.clone(), true),
        (retained_gateway, true),
    ];
    reads(&http, &urls, 200).await;
    let token = view(&http, &browser, &scope, &circle).await;
    assert_eq!(counter(&http, &browser, &token).await.status(), 200);

    assert!(!node
        .quarantine_root_at(genesis.head(), "stale root sample")
        .await
        .unwrap());
    assert!(!node.root_quarantined());
    assert!(permit.live());
    assert!(!node.resume_at(genesis.head()).await.unwrap());
    assert!(matches!(node.status(), Status::Serving(_)));
    assert!(permit.live(), "stale resume revoked the serving head");
    assert!(node
        .quarantine_root_at(&first, "authenticated root conflict")
        .await
        .unwrap());
    assert!(node.root_quarantined());
    assert!(matches!(node.status(), Status::Suspended(_)));
    assert!(!permit.live());
    assert!(node.snapshot().is_err());
    assert!(admission.authorize(&request, &domain).await.is_err());
    reads(&http, &urls, 503).await;
    assert_eq!(counter(&http, &browser, &token).await.status(), 503);
    assert!(!node.resume().await.unwrap());
    assert!(!node.resume_at(&first).await.unwrap());

    let superseded = node.root_quarantine_ticket();
    assert!(node
        .quarantine_root_at(&first, "newer conflict at the same head")
        .await
        .unwrap());
    assert!(!node
        .clear_root_quarantine_at(&first, &superseded)
        .await
        .unwrap());
    assert!(node.root_quarantined());
    let current_ticket = node.root_quarantine_ticket();
    assert!(!node
        .clear_root_quarantine_at(genesis.head(), &current_ticket)
        .await
        .unwrap());

    // Canonical finality can advance while browser and paid admission stay shut.
    let second = empty_epoch(&node, &captured, &authority).await;
    checkpoint(&node, second.cursor).await;
    assert_eq!(second.txid_hi, first.txid_hi);
    assert!(node.root_quarantined());
    assert!(matches!(node.status(), Status::Suspended(_)));
    assert!(!node.resume().await.unwrap());
    assert!(!node.resume_at(&second).await.unwrap());
    reads(&http, &urls, 503).await;
    assert!(!node
        .quarantine_root_at(&first, "late prior-head conflict")
        .await
        .unwrap());
    assert!(!node
        .clear_root_quarantine_at(&first, &current_ticket)
        .await
        .unwrap());
    assert!(node.root_quarantined());
    // Publication and stale samples cannot invalidate the current probe ticket.
    assert!(node
        .clear_root_quarantine_at(&second, &current_ticket)
        .await
        .unwrap());
    assert!(!node.root_quarantined());
    assert!(matches!(node.status(), Status::Suspended(_)));
    reads(&http, &urls, 503).await;
    assert!(node.resume_at(&second).await.unwrap());
    assert!(!permit.live(), "clearing cannot revive captured admission");
    let fresh = admission
        .authorize(&request, &domain)
        .await
        .unwrap()
        .unwrap();
    assert!(fresh.live());
    assert!(!node.resume_at(&first).await.unwrap());
    assert!(matches!(node.status(), Status::Serving(_)));
    assert!(fresh.live(), "old-head resume revoked current admission");
    reads(
        &http,
        &[(format!("{browser}/"), false), (gateway_view, true)],
        200,
    )
    .await;
    assert_eq!(
        checkpoints.load(&chain, EXTENSION).await.unwrap(),
        Some(second.cursor)
    );
    let expected_events = events.lock().unwrap().clone();
    assert_eq!(
        expected_events
            .iter()
            .map(|epoch| epoch.cursor.sequence.0)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    let expected_certificates = {
        let durable = CanonicalStore::open(&path, &chain).await.unwrap();
        let mut certificates = vec![];
        for expected in &expected_events {
            assert_eq!(
                durable
                    .source()
                    .load(expected.cursor.sequence)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(expected)
            );
            certificates.push(durable.certificate(expected.cursor.sequence).await.unwrap());
        }
        durable.close().await;
        certificates
    };
    browser_task.stop().await;
    gateway_task.stop().await;
    node.shutdown().await.unwrap();
    drop(node);

    let restarted = open(&path, checkpoints.clone(), chain.clone(), Arc::default()).await;
    assert!(matches!(restarted.status(), Status::Suspended(_)));
    assert_eq!(restarted.head().await.unwrap(), second);
    restarted
        .register(EmptyRecorder(events.clone()))
        .await
        .unwrap();
    checkpoint(&restarted, second.cursor).await;
    assert!(restarted.resume().await.unwrap());
    restarted.shutdown().await.unwrap();
    assert_eq!(*events.lock().unwrap(), expected_events);
    assert_eq!(
        checkpoints.load(&chain, EXTENSION).await.unwrap(),
        Some(second.cursor)
    );
    let durable = CanonicalStore::open(&path, &chain).await.unwrap();
    assert_eq!(durable.head().await.unwrap(), second);
    assert!(durable.source().load(Sequence(3)).await.unwrap().is_none());
    for (expected, certificate) in expected_events.iter().zip(expected_certificates) {
        assert_eq!(
            durable
                .source()
                .load(expected.cursor.sequence)
                .await
                .unwrap()
                .as_deref(),
            Some(expected)
        );
        assert_eq!(
            durable.certificate(expected.cursor.sequence).await.unwrap(),
            certificate
        );
    }
    durable.close().await;
}

#[derive(Default)]
struct PublicationGate {
    armed: AtomicBool,
    entered: Notify,
    release: Notify,
}
struct PausedAuthority {
    inner: Authority,
    gate: Arc<PublicationGate>,
}
#[async_trait::async_trait]
impl ValidatorHistory for PausedAuthority {
    async fn resolve(
        &self,
        parent: &Head,
        epoch: u64,
        relief: ReliefSource,
    ) -> Result<EpochRules, String> {
        if self.gate.armed.swap(false, Ordering::SeqCst) {
            self.gate.entered.notify_one();
            self.gate.release.notified().await;
        }
        self.inner.resolve(parent, epoch, relief).await
    }
}
impl Host for PausedAuthority {
    fn check_views(&self, head: &Head) -> Result<(), String> {
        self.inner.check_views(head)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quarantine_waits_for_publication_and_canceled_or_stale_waiters_cannot_gate_successor() {
    for cancel in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("chain.db");
        let state = genesis(format!("oct{}", "1".repeat(44)).as_bytes());
        let chain = ChainIdentity::genesis(
            format!("root-quarantine-operation-{cancel}"),
            StateRoot(finality_host::root(None, &state, &[])),
        );
        let store = CanonicalStore::create(&path, chain.clone(), state.snapshot(), 0)
            .await
            .unwrap();
        let checkpoints = Arc::new(
            SqliteCheckpoints::open(&directory.path().join("exex.db"))
                .await
                .unwrap(),
        );
        let authority = finality_host::Authority { seed: 1, chain };
        let gate = Arc::new(PublicationGate::default());
        let node = Arc::new(
            Node::open(
                store,
                PausedAuthority {
                    inner: Authority {
                        finality: authority.clone(),
                        fail_views: Arc::default(),
                    },
                    gate: gate.clone(),
                },
                circle_host::runtime(),
                Arc::new(UnavailableHost),
                checkpoints,
            )
            .await
            .unwrap(),
        );
        assert!(node.resume().await.unwrap());
        let parent = node.snapshot().unwrap();
        let old_head = parent.head().clone();
        gate.armed.store(true, Ordering::SeqCst);
        let publisher = node.clone();
        let publication =
            tokio::spawn(async move { empty_epoch(&publisher, &parent, &authority).await });
        tokio::time::timeout(WAIT, gate.entered.notified())
            .await
            .expect("publication did not acquire its owned operation");
        let controller = node.clone();
        let mut quarantine = tokio::spawn(async move {
            controller
                .quarantine_root_at(&old_head, "probe completed during publication")
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut quarantine)
                .await
                .is_err(),
            "quarantine compared HEAD before the in-flight publication drained"
        );
        if cancel {
            quarantine.abort();
        }
        gate.release.notify_one();
        let head = tokio::time::timeout(WAIT, publication)
            .await
            .unwrap()
            .unwrap();
        if cancel {
            assert!(quarantine.await.unwrap_err().is_cancelled());
        } else {
            assert!(!tokio::time::timeout(WAIT, quarantine)
                .await
                .unwrap()
                .unwrap()
                .unwrap());
        }
        assert_eq!(head.cursor.epoch.0, 1);
        assert_eq!(node.head().await.unwrap(), head);
        assert!(!node.root_quarantined());
        assert!(matches!(node.status(), Status::Serving(_)));
        assert!(node.resume().await.unwrap());
        node.shutdown().await.unwrap();
    }
}
