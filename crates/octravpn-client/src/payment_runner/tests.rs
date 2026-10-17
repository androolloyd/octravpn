//! The control worker uses a real local HTTP boundary and real durable payer
//! state. Canonical confirmation is deliberately held while packet accounting
//! continues; no kernel TUN or public-chain qualification is implied.
use super::*;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use octravpn_core::{
    payments::{Deployment, SignedUsage, Status, TrafficClass, BYTES_PER_MIB},
    Address, KeyPair,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    sync::{watch, Notify},
    task::JoinHandle,
};

struct Fixture {
    _directory: tempfile::TempDir,
    plan: Plan,
    journal: Arc<Mutex<Journal>>,
    connect: SignedConnect,
    initial: SignedStatus,
    operator: KeyPair,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let payer = Arc::new(KeyPair::from_secret_bytes(&[5; 32]));
        let operator = KeyPair::from_secret_bytes(&[6; 32]);
        let tariff = Tariff::new(
            Address::from_pubkey(&operator.public.0),
            vec![TrafficClass {
                name: "default".into(),
                rate_ou_per_mib: BYTES_PER_MIB,
            }],
            Vec::new(),
        )
        .unwrap();
        let binding = PlanBinding {
            deployment: Deployment {
                domain: "a".repeat(64),
                program: Address::from_pubkey(&[1; 32]),
            },
            payer: Address::from_pubkey(&payer.public.0),
            generation: 1,
            plan: 2,
            offer: 3,
            manifest_hash: tariff.hash_hex().unwrap(),
        };
        let plan = Plan {
            binding: binding.clone(),
            tariff: tariff.clone(),
            original_budget_ou: 10_000,
            control_url: "http://127.0.0.1/".into(),
            wireguard_endpoint: "127.0.0.1:51820".into(),
        };
        let mut journal = Journal::open(
            &directory.path().join("plan"),
            binding.clone(),
            tariff.clone(),
            10_000,
            payer,
            OpenMode::Create,
        )
        .unwrap();
        let connect = journal.connect([11; 32]).unwrap();
        let initial = SignedStatus::sign(
            Status {
                binding,
                connect_sequence: 1,
                client_wireguard_key: [11; 32],
                server_wireguard_key: [42; 32],
                tariff,
                original_budget_ou: 10_000,
                remaining_ou: 10_000,
                committed_totals: vec![0],
                redeemed_totals: vec![0],
                canonical_ms: 1_000,
                claim_deadline_ms: 86_401_000,
            },
            &operator,
        )
        .unwrap();
        Self {
            _directory: directory,
            plan,
            journal: Arc::new(Mutex::new(journal)),
            connect,
            initial,
            operator,
        }
    }
    fn worker(
        &self,
        origin: reqwest::Url,
        shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<Result<()>> {
        tokio::spawn(control_loop(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(300))
                .no_proxy()
                .build()
                .unwrap(),
            origin,
            self.connect.clone(),
            self.plan.clone(),
            self.journal.clone(),
            self.initial.clone(),
            shutdown,
        ))
    }
}

#[derive(Clone)]
struct ControlFixture {
    connect: SignedConnect,
    status: Arc<Mutex<SignedStatus>>,
    views: Arc<AtomicUsize>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
    received: Arc<Mutex<Vec<SignedUsage>>>,
}
impl ControlFixture {
    async fn start(
        fixture: &Fixture,
        status: SignedStatus,
    ) -> (Self, reqwest::Url, JoinHandle<()>) {
        let state = Self {
            connect: fixture.connect.clone(),
            status: Arc::new(Mutex::new(status)),
            views: Arc::new(AtomicUsize::new(0)),
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            received: Arc::new(Mutex::new(Vec::new())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin =
            reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let app = Router::new()
            .route("/payments/connect", post(view))
            .route("/payments/usage", post(settle))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (state, origin, server)
    }
}
async fn view(
    State(state): State<ControlFixture>,
    Json(connect): Json<SignedConnect>,
) -> Json<SignedStatus> {
    connect.verify().unwrap();
    assert_eq!(connect, state.connect);
    let status = state.status.lock().clone();
    state.views.fetch_add(1, Ordering::AcqRel);
    Json(status)
}
async fn settle(State(state): State<ControlFixture>, Json(usage): Json<SignedUsage>) -> StatusCode {
    usage.verify().unwrap();
    assert_eq!(usage.receipt_key, state.connect.receipt_key);
    assert_eq!(usage.usage.binding(), state.connect.request.binding);
    state.received.lock().push(usage);
    state.entered.notify_one();
    state.release.notified().await;
    StatusCode::OK
}

fn packet() -> Vec<u8> {
    let mut raw = vec![0_u8; 32];
    raw[0] = 0x45;
    raw[2..4].copy_from_slice(&32_u16.to_be_bytes());
    raw[8] = 64;
    raw[9] = 17;
    raw[12..16].copy_from_slice(&[198, 18, 0, 2]);
    raw[16..20].copy_from_slice(&[8, 8, 8, 8]);
    raw[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    raw[22..24].copy_from_slice(&53_u16.to_be_bytes());
    raw[24..26].copy_from_slice(&12_u16.to_be_bytes());
    let mut sum = raw[..20]
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    raw[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    raw
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canonical_wait_releases_journal_and_shutdown_preserves_durable_receipt() {
    for close_sender in [false, true] {
        let fixture = Fixture::new();
        let packet = packet();
        fixture
            .journal
            .lock()
            .count(&packet, Direction::Outbound)
            .unwrap();
        let mut status = fixture.initial.status.clone();
        status.committed_totals[0] = packet.len() as u64;
        let status = SignedStatus::sign(status, &fixture.operator).unwrap();
        let (server_state, origin, server) = ControlFixture::start(&fixture, status).await;
        let (stop, shutdown) = watch::channel(false);
        let worker = fixture.worker(origin, shutdown);
        tokio::time::timeout(Duration::from_secs(2), server_state.entered.notified())
            .await
            .unwrap();
        assert!(!worker.is_finished());
        // The request is still waiting for finality; a confirmed packet can
        // nevertheless acquire, count and fsync through the same journal.
        let journal = fixture.journal.clone();
        let delivered = packet.clone();
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::task::spawn_blocking(move || {
                journal.lock().count(&delivered, Direction::Outbound)
            }),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(fixture.journal.lock().totals(), [2 * packet.len() as u64]);
        assert_eq!(
            fixture.journal.lock().authorized_totals(),
            [packet.len() as u64]
        );
        let issued = fixture.journal.lock().pending_receipts().unwrap();
        assert_eq!(server_state.received.lock().as_slice(), issued);
        if close_sender {
            drop(stop);
        } else {
            stop.send_replace(true);
        }
        tokio::time::timeout(Duration::from_secs(2), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(fixture.journal.lock().pending_receipts().unwrap(), issued);
        server_state.release.notify_waiters();
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn asynchronous_operator_view_cannot_authorize_a_pending_local_handoff() {
    let fixture = Fixture::new();
    let packet = packet();
    let reservation = reserve(&fixture.journal, packet.clone(), Direction::Outbound)
        .await
        .unwrap();
    let mut status = fixture.initial.status.clone();
    status.committed_totals[0] = packet.len() as u64;
    let operator_totals = status.committed_totals.clone();
    let status = SignedStatus::sign(status, &fixture.operator).unwrap();
    let (server_state, origin, server) = ControlFixture::start(&fixture, status).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    settle_batch(
        client.clone(),
        origin.clone(),
        fixture.journal.clone(),
        operator_totals.clone(),
    )
    .await
    .unwrap();
    assert!(server_state.received.lock().is_empty());
    assert!(fixture
        .journal
        .lock()
        .pending_receipts()
        .unwrap()
        .is_empty());
    finish(&fixture.journal, reservation, true).await.unwrap();
    let journal = fixture.journal.clone();
    let batch = tokio::spawn(settle_batch(client, origin, journal, operator_totals));
    tokio::time::timeout(Duration::from_secs(2), server_state.entered.notified())
        .await
        .unwrap();
    assert_eq!(server_state.received.lock().len(), 1);
    assert_eq!(
        server_state.received.lock()[0].usage.total_bytes,
        packet.len() as u64
    );
    server_state.release.notify_one();
    batch.await.unwrap().unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn changed_operator_transport_or_plan_and_regressing_canonical_clock_stop_worker() {
    for invalid in 0..3 {
        let fixture = Fixture::new();
        let mut status = fixture.initial.status.clone();
        match invalid {
            0 => status.server_wireguard_key = [43; 32],
            1 => status.binding.plan += 1,
            _ => status.canonical_ms -= 1,
        }
        let status = SignedStatus::sign(status, &fixture.operator).unwrap();
        let (_, origin, server) = ControlFixture::start(&fixture, status).await;
        let (_stop, shutdown) = watch::channel(false);
        let error = tokio::time::timeout(Duration::from_secs(2), fixture.worker(origin, shutdown))
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(format!("{error:#}").contains(match invalid {
            0 => "WireGuard identity changed",
            1 => "differs from accepted plan",
            _ => "clock regressed",
        }));
        assert!(fixture
            .journal
            .lock()
            .pending_receipts()
            .unwrap()
            .is_empty());
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test(start_paused = true)]
async fn replayed_same_clock_never_renews_freshness_but_progress_does() {
    let mut freshness = Freshness::new(1_000);
    let first_deadline = freshness.deadline;
    tokio::time::advance(Duration::from_secs(60)).await;
    freshness.observe(1_000).unwrap();
    assert_eq!(freshness.deadline, first_deadline);
    freshness.observe(1_001).unwrap();
    let progressed_deadline = freshness.deadline;
    assert!(progressed_deadline > first_deadline);
    assert!(freshness.observe(999).is_err());
    assert_eq!(freshness.deadline, progressed_deadline);
    tokio::time::advance(Duration::from_secs(119)).await;
    freshness.observe(1_001).unwrap();
    assert_eq!(freshness.deadline, progressed_deadline);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(freshness.observe(1_001).is_err());
    // A response arriving after the deadline cannot revive a stopped worker.
    assert!(freshness.observe(1_002).is_err());
    assert_eq!(freshness.deadline, progressed_deadline);
}

#[tokio::test]
async fn advancing_status_is_polled_while_one_settlement_batch_waits() {
    let fixture = Fixture::new();
    let packet = packet();
    fixture
        .journal
        .lock()
        .count(&packet, Direction::Outbound)
        .unwrap();
    let mut status = fixture.initial.status.clone();
    status.committed_totals[0] = packet.len() as u64;
    let status = SignedStatus::sign(status, &fixture.operator).unwrap();
    let (server_state, origin, server) = ControlFixture::start(&fixture, status).await;
    let (stop, shutdown) = watch::channel(false);
    let worker = fixture.worker(origin, shutdown);
    tokio::time::timeout(Duration::from_secs(2), server_state.entered.notified())
        .await
        .unwrap();
    // The held canonical response spans more than the freshness interval.
    // Independent authenticated clock progress must keep the control alive.
    tokio::time::pause();
    for _ in 0..5 {
        let before = server_state.views.load(Ordering::Acquire);
        let mut status = server_state.status.lock().status.clone();
        status.canonical_ms += 1;
        *server_state.status.lock() = SignedStatus::sign(status, &fixture.operator).unwrap();
        tokio::time::advance(Duration::from_secs(30)).await;
        // Yielding keeps Tokio from automatically advancing virtual time
        // while the real loopback HTTP request/response is being serviced.
        for _ in 0..20_000 {
            if server_state.views.load(Ordering::Acquire) > before {
                break;
            }
            assert!(
                !worker.is_finished(),
                "control stopped while canonical clock advanced"
            );
            tokio::task::yield_now().await;
        }
        assert!(server_state.views.load(Ordering::Acquire) > before);
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert!(!worker.is_finished());
    }
    assert_eq!(server_state.received.lock().len(), 1);
    stop.send_replace(true);
    worker.await.unwrap().unwrap();
    server_state.release.notify_waiters();
    server.abort();
    let _ = server.await;
}
