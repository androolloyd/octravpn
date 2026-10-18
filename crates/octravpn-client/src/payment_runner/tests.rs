//! The control worker uses a real local HTTP boundary and real durable payer
//! state. Canonical confirmation is deliberately held while packet accounting
//! continues; no kernel TUN or public-chain qualification is implied.
use super::*;
use axum::response::IntoResponse as _;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use octravpn_core::{
    payments::{Deployment, SignedUsage, Status, TrafficClass, BYTES_PER_MIB},
    Address, KeyPair,
};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::{
    sync::{watch, Notify},
    task::JoinHandle,
};

struct Fixture {
    directory: tempfile::TempDir,
    plan: Plan,
    journal: Accounting,
    connect: SignedConnect,
    initial: SignedStatus,
    operator: Arc<KeyPair>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_budget(10_000)
    }
    fn with_budget(budget: u64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let payer = Arc::new(KeyPair::from_secret_bytes(&[5; 32]));
        let operator = Arc::new(KeyPair::from_secret_bytes(&[6; 32]));
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
            original_budget_ou: budget,
            prepaid_bytes: vec![128],
            control_url: "http://127.0.0.1/".into(),
            wireguard_endpoint: "127.0.0.1:51820".into(),
        };
        let mut journal = Journal::open(
            &directory.path().join("plan"),
            binding.clone(),
            tariff.clone(),
            budget,
            plan.prepaid_bytes.clone(),
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
                original_budget_ou: budget,
                remaining_ou: budget,
                committed_totals: vec![0],
                redeemed_totals: vec![0],
                canonical_ms: 1_000,
                claim_deadline_ms: 86_401_000,
            },
            &operator,
        )
        .unwrap();
        Self {
            directory,
            plan,
            journal: Accounting::new(journal),
            connect,
            initial,
            operator,
        }
    }
    fn paid(&self) -> SignedStatus {
        let mut status = self.initial.status.clone();
        status.redeemed_totals = self.plan.prepaid_bytes.clone();
        status.remaining_ou -= self
            .plan
            .tariff
            .total_charge(&self.plan.prepaid_bytes)
            .unwrap();
        SignedStatus::sign(status, &self.operator).unwrap()
    }
    fn prepayer(&self, origin: reqwest::Url) -> JoinHandle<Result<Observation>> {
        let plan = self.plan.clone();
        let journal = self.journal.clone();
        let connect = self.connect.clone();
        let initial = self.initial.clone();
        tokio::spawn(async move {
            let http = reqwest::Client::builder()
                .timeout(Duration::from_secs(300))
                .no_proxy()
                .build()
                .unwrap();
            prepay(
                &http,
                &origin,
                &connect,
                &plan,
                &journal,
                Observation::new(initial),
            )
            .await
        })
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
            Observation::new(self.paid()),
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
    operator: Arc<KeyPair>,
    publish: Arc<AtomicBool>,
    refuse: Arc<AtomicBool>,
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
            operator: fixture.operator.clone(),
            publish: Arc::new(AtomicBool::new(true)),
            refuse: Arc::new(AtomicBool::new(false)),
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
) -> axum::response::Response {
    connect.verify().unwrap();
    assert_eq!(connect, state.connect);
    let status = state.status.lock().clone();
    state.views.fetch_add(1, Ordering::AcqRel);
    if state.refuse.load(Ordering::Acquire) {
        (StatusCode::FORBIDDEN, "canonical plan unavailable").into_response()
    } else {
        Json(status).into_response()
    }
}
async fn settle(State(state): State<ControlFixture>, Json(usage): Json<SignedUsage>) -> StatusCode {
    usage.verify().unwrap();
    assert_eq!(usage.receipt_key, state.connect.receipt_key);
    assert_eq!(usage.usage.binding(), state.connect.request.binding);
    state.received.lock().push(usage.clone());
    state.entered.notify_one();
    state.release.notified().await;
    if !state.publish.load(Ordering::Acquire) {
        return StatusCode::OK;
    }
    let mut status = state.status.lock();
    let mut next = status.status.clone();
    let class = usize::from(usage.usage.traffic_class);
    next.redeemed_totals[class] = next.redeemed_totals[class].max(usage.usage.total_bytes);
    next.remaining_ou =
        next.original_budget_ou - next.tariff.total_charge(&next.redeemed_totals).unwrap();
    *status = SignedStatus::sign(next, &state.operator).unwrap();
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

#[tokio::test]
async fn purchase_is_durable_before_http_and_canonical_confirmation_opens_the_barrier() {
    let fixture = Fixture::new();
    let (state, origin, server) = ControlFixture::start(&fixture, fixture.initial.clone()).await;
    let preparing = fixture.prepayer(origin);
    tokio::time::timeout(Duration::from_secs(2), state.entered.notified())
        .await
        .unwrap();
    assert!(!preparing.is_finished());
    let purchases = fixture.journal.lock().pending_receipts().unwrap();
    assert_eq!(purchases.len(), 1);
    assert_eq!(purchases[0].usage.total_bytes, 128);
    assert_eq!(fixture.journal.lock().totals(), [0]);
    assert_eq!(state.received.lock().as_slice(), purchases);
    // A server delivery report has no authority to change the finite purchase.
    assert_eq!(fixture.journal.lock().purchases().unwrap(), purchases);
    state.release.notify_one();
    let confirmed = tokio::time::timeout(Duration::from_secs(3), preparing)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(purchased(&confirmed.signed, &fixture.plan));
    assert_eq!(fixture.journal.lock().authorized_totals(), [128]);
    assert_eq!(fixture.journal.lock().totals(), [0]);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn accepted_http_response_and_delivery_report_cannot_open_the_purchase_barrier() {
    let fixture = Fixture::new();
    let (state, origin, server) = ControlFixture::start(&fixture, fixture.initial.clone()).await;
    state.publish.store(false, Ordering::Release);
    let preparing = fixture.prepayer(origin);
    tokio::time::timeout(Duration::from_secs(2), state.entered.notified())
        .await
        .unwrap();
    let mut partial = fixture.paid().status;
    partial.redeemed_totals = vec![127];
    partial.committed_totals = vec![127];
    partial.remaining_ou += 1;
    *state.status.lock() = SignedStatus::sign(partial, &fixture.operator).unwrap();
    state.release.notify_one();
    let before = state.views.load(Ordering::Acquire);
    tokio::time::timeout(Duration::from_secs(3), async {
        while state.views.load(Ordering::Acquire) < before + 2 {
            assert!(!preparing.is_finished());
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!preparing.is_finished());
    assert_eq!(fixture.journal.lock().totals(), [0]);
    assert_eq!(fixture.journal.lock().authorized_totals(), [128]);
    *state.status.lock() = fixture.paid();
    let ready = tokio::time::timeout(Duration::from_secs(3), preparing)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(purchased(&ready.signed, &fixture.plan));
    assert_eq!(state.received.lock().len(), 1);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn exhausted_class_drops_only_its_packets_and_storage_errors_remain_fatal() {
    use octravpn_core::payments::{IpPrefix, Protocol, Selector};
    let fixture = Fixture::new();
    let tariff = Tariff::new(
        fixture.plan.tariff.operator().clone(),
        vec![
            TrafficClass {
                name: "default".into(),
                rate_ou_per_mib: BYTES_PER_MIB,
            },
            TrafficClass {
                name: "premium".into(),
                rate_ou_per_mib: BYTES_PER_MIB,
            },
        ],
        vec![Selector {
            prefix: IpPrefix::new("8.8.8.8".parse().unwrap(), 32).unwrap(),
            protocol: Protocol::Udp,
            port: Some(53),
            traffic_class: 1,
        }],
    )
    .unwrap();
    let mut binding = fixture.plan.binding.clone();
    binding.manifest_hash = tariff.hash_hex().unwrap();
    let path = fixture.directory.path().join("classes");
    let mut journal = Journal::open(
        &path,
        binding,
        tariff,
        10_000,
        vec![64, 32],
        Arc::new(KeyPair::from_secret_bytes(&[5; 32])),
        OpenMode::Create,
    )
    .unwrap();
    journal.purchases().unwrap();
    let accounting = Accounting::new(journal);
    let premium = packet();
    let reservation = reserve(&accounting, premium.clone(), Direction::Outbound)
        .await
        .unwrap()
        .unwrap();
    finish(&accounting, reservation, true).await.unwrap();
    assert!(reserve(&accounting, premium, Direction::Outbound)
        .await
        .unwrap()
        .is_none());
    let mut ordinary = packet();
    ordinary[16..20].copy_from_slice(&[1, 1, 1, 1]);
    ordinary[10..12].fill(0);
    let mut sum = ordinary[..20]
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    ordinary[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    let reservation = reserve(&accounting, ordinary.clone(), Direction::Outbound)
        .await
        .unwrap()
        .unwrap();
    finish(&accounting, reservation, true).await.unwrap();
    assert_eq!(accounting.lock().totals(), [32, 32]);
    assert_eq!(accounting.lock().authorized_totals(), [64, 32]);
    std::fs::remove_file(path.join("writer.lock")).unwrap();
    assert!(reserve(&accounting, ordinary, Direction::Outbound)
        .await
        .is_err());
}

#[tokio::test]
async fn canonical_floor_cannot_be_replaced_by_delivery_or_same_price_rounding() {
    let fixture = Fixture::new();
    let mut plan = fixture.plan.clone();
    let mut signed = fixture.paid();
    assert!(purchased(&signed, &plan));
    let mut view = signed.status.clone();
    view.redeemed_totals = vec![127];
    view.remaining_ou += 1;
    signed = SignedStatus::sign(view, &fixture.operator).unwrap();
    assert!(!purchased(&signed, &plan));
    let zero = Tariff::new(
        fixture.plan.tariff.operator().clone(),
        vec![TrafficClass {
            name: "operator-free".into(),
            rate_ou_per_mib: 0,
        }],
        vec![],
    )
    .unwrap();
    plan.tariff = zero;
    plan.binding.manifest_hash = plan.tariff.hash_hex().unwrap();
    let mut view = signed.status;
    view.binding = plan.binding.clone();
    view.tariff = plan.tariff.clone();
    view.remaining_ou = view.original_budget_ou;
    signed = SignedStatus::sign(view, &fixture.operator).unwrap();
    assert_eq!(
        plan.tariff.charge(0, 127).unwrap(),
        plan.tariff.charge(0, 128).unwrap()
    );
    assert!(!purchased(&signed, &plan));
}

#[tokio::test]
async fn cancelling_purchase_preserves_identical_authorization_for_resume() {
    let fixture = Fixture::new();
    let (state, origin, server) = ControlFixture::start(&fixture, fixture.initial.clone()).await;
    let preparing = fixture.prepayer(origin);
    tokio::time::timeout(Duration::from_secs(2), state.entered.notified())
        .await
        .unwrap();
    let issued = fixture.journal.lock().pending_receipts().unwrap();
    preparing.abort();
    assert!(preparing.await.unwrap_err().is_cancelled());
    fixture.journal.wait_idle().await.unwrap();
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
    assert_eq!(resumed.purchases().unwrap(), issued);
    assert_eq!(resumed.totals(), [0]);
    assert_eq!(resumed.authorized_totals(), [128]);
    state.release.notify_waiters();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn paid_resume_does_not_send_another_purchase_or_require_unspent_ou() {
    let fixture = Fixture::with_budget(128);
    let plan = fixture.plan.clone();
    let paid = fixture.paid();
    let (state, origin, server) = ControlFixture::start(&fixture, paid.clone()).await;
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let ready = prepay(
        &http,
        &origin,
        &fixture.connect,
        &plan,
        &fixture.journal,
        Observation::new(paid),
    )
    .await
    .unwrap();
    assert!(purchased(&ready.signed, &plan));
    assert_eq!(ready.signed.status.remaining_ou, 0);
    assert!(state.received.lock().is_empty());
    assert_eq!(fixture.journal.lock().totals(), [0]);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn advancing_status_is_polled_while_one_purchase_batch_waits() {
    let fixture = Fixture::new();
    let (state, origin, server) = ControlFixture::start(&fixture, fixture.initial.clone()).await;
    let preparing = fixture.prepayer(origin);
    tokio::time::timeout(Duration::from_secs(2), state.entered.notified())
        .await
        .unwrap();
    tokio::time::pause();
    for _ in 0..5 {
        let before = state.views.load(Ordering::Acquire);
        let mut next = state.status.lock().status.clone();
        next.canonical_ms += 1;
        *state.status.lock() = SignedStatus::sign(next, &fixture.operator).unwrap();
        tokio::time::advance(Duration::from_secs(30)).await;
        for _ in 0..20_000 {
            if state.views.load(Ordering::Acquire) > before {
                break;
            }
            assert!(
                !preparing.is_finished(),
                "purchase stopped while canonical clock advanced"
            );
            tokio::task::yield_now().await;
        }
        assert!(state.views.load(Ordering::Acquire) > before);
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert!(!preparing.is_finished());
    }
    assert_eq!(state.received.lock().len(), 1);
    preparing.abort();
    let _ = preparing.await;
    state.release.notify_waiters();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn changed_transport_plan_clock_or_canonical_capacity_stops_runtime_monitor() {
    for invalid in 0..8 {
        let fixture = Fixture::new();
        let mut status = fixture.paid().status;
        match invalid {
            0 => status.server_wireguard_key = [43; 32],
            1 => status.binding.plan += 1,
            2 => status.canonical_ms -= 1,
            3 => {
                status.redeemed_totals = vec![127];
                status.remaining_ou += 1;
            }
            4 => status.binding.generation += 1,
            5 => {
                let mut classes = status.tariff.classes().to_vec();
                classes[0].rate_ou_per_mib += 1;
                status.tariff = Tariff::new(
                    status.tariff.operator().clone(),
                    classes,
                    status.tariff.selectors().to_vec(),
                )
                .unwrap();
                status.binding.manifest_hash = status.tariff.hash_hex().unwrap();
                status.remaining_ou = status.original_budget_ou
                    - status.tariff.total_charge(&status.redeemed_totals).unwrap();
            }
            6 => status.original_budget_ou += 1,
            _ => status.binding.offer += 1,
        }
        let status = SignedStatus::sign(status, &fixture.operator).unwrap();
        let (state, origin, server) = ControlFixture::start(&fixture, status).await;
        let (_stop, shutdown) = watch::channel(false);
        let error = tokio::time::timeout(Duration::from_secs(2), fixture.worker(origin, shutdown))
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(format!("{error:#}").contains(match invalid {
            0 => "WireGuard identity changed",
            2 => "clock regressed",
            3 => "prepaid capacity regressed",
            _ => "differs from accepted plan",
        }));
        assert!(state.received.lock().is_empty());
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
    tokio::time::advance(Duration::from_secs(120)).await;
    assert!(freshness.observe(1_001).is_err());
    assert!(freshness.observe(1_002).is_err());
    assert_eq!(freshness.deadline, progressed_deadline);
}

fn control(
    fixture: &Fixture,
    origin: reqwest::Url,
    shutdown: watch::Receiver<bool>,
) -> impl std::future::Future<Output = Result<()>> + Send + 'static {
    control_loop(
        reqwest::Client::builder().no_proxy().build().unwrap(),
        origin,
        fixture.connect.clone(),
        fixture.plan.clone(),
        Observation::new(fixture.paid()),
        shutdown,
    )
}

#[tokio::test]
async fn shutdown_cancels_blocked_handoff_without_restoring_spent_purchase() {
    let fixture = Fixture::new();
    fixture.journal.lock().purchases().unwrap();
    let (state, origin, server) = ControlFixture::start(&fixture, fixture.paid()).await;
    let entered = Arc::new(Notify::new());
    let driver = {
        let accounting = fixture.journal.clone();
        let entered = entered.clone();
        async move {
            let _pending = reserve(&accounting, packet(), Direction::Outbound)
                .await?
                .context("fixture prepaid allowance unexpectedly exhausted")?;
            entered.notify_one();
            std::future::pending::<Result<()>>().await
        }
    };
    let (stop, stopped) = watch::channel(false);
    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(supervise(
        fixture.journal.clone(),
        driver,
        control(&fixture, origin, stopped),
        stop,
        async {
            cancelled.await?;
            Ok(())
        },
    ));
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    cancel.send(()).unwrap();
    let summary = tokio::time::timeout(Duration::from_secs(2), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(summary.confirmed_bytes, [0]);
    assert_eq!(summary.held_bytes, [32]);
    assert_eq!(summary.authorized_bytes, [128]);
    assert_eq!(summary.remaining_ou, 9_872);
    assert!(state.received.lock().is_empty());
    state.release.notify_waiters();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn canonical_plan_refusal_cancels_the_packet_driver_without_resetting_purchases() {
    let fixture = Fixture::new();
    let purchases = fixture.journal.lock().purchases().unwrap();
    let (state, origin, server) = ControlFixture::start(&fixture, fixture.paid()).await;
    let entered = Arc::new(Notify::new());
    let driver = {
        let accounting = fixture.journal.clone();
        let entered = entered.clone();
        async move {
            let _pending = reserve(&accounting, packet(), Direction::Outbound)
                .await?
                .context("fixture prepaid allowance unexpectedly exhausted")?;
            entered.notify_one();
            std::future::pending::<Result<()>>().await
        }
    };
    let (stop, stopped) = watch::channel(false);
    let running = tokio::spawn(supervise(
        fixture.journal.clone(),
        driver,
        control(&fixture, origin, stopped),
        stop,
        std::future::pending(),
    ));
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    // The native authority invalidates the old plan when a channel withdrawal
    // changes its generation. This HTTP fixture models that canonical refusal;
    // actual withdrawal and generation transitions belong to the native gate.
    let persisted = std::fs::read(fixture.directory.path().join("plan/state.json")).unwrap();
    state.refuse.store(true, Ordering::Release);
    let error = tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<reqwest::Error>()
            .and_then(reqwest::Error::status),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(fixture.journal.lock().totals(), [0]);
    assert_eq!(fixture.journal.lock().held_totals().unwrap(), [32]);
    assert_eq!(fixture.journal.lock().authorized_totals(), [128]);
    assert_eq!(
        fixture.journal.lock().pending_receipts().unwrap(),
        purchases
    );
    assert_eq!(fixture.journal.lock().remaining_ou().unwrap(), 9_872);
    assert_eq!(
        std::fs::read(fixture.directory.path().join("plan/state.json")).unwrap(),
        persisted
    );
    assert!(state.received.lock().is_empty());
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn paid_status_keeps_the_accepted_purchase_without_fetching_a_replacement_quote() {
    let fixture = Fixture::new();
    let purchases = fixture.journal.lock().purchases().unwrap();
    let mut continued = fixture.paid().status;
    // The canonical host decides whether an old quote's already purchased
    // capacity remains valid. The client imposes no local quote-retirement or
    // payer-withdrawal wait and never discovers/accepts new prices on its own.
    continued.canonical_ms = 86_402_000;
    continued.claim_deadline_ms = u64::MAX;
    let continued = SignedStatus::sign(continued, &fixture.operator).unwrap();
    let (state, origin, server) = ControlFixture::start(&fixture, continued).await;
    let (stop, stopped) = watch::channel(false);
    let worker = fixture.worker(origin, stopped);
    tokio::time::timeout(Duration::from_secs(3), async {
        while state.views.load(Ordering::Acquire) < 2 {
            assert!(!worker.is_finished());
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!worker.is_finished());
    let reservation = reserve(&fixture.journal, packet(), Direction::Outbound)
        .await
        .unwrap()
        .unwrap();
    finish(&fixture.journal, reservation, true).await.unwrap();
    assert_eq!(fixture.journal.lock().totals(), [32]);
    assert_eq!(fixture.journal.lock().authorized_totals(), [128]);
    assert_eq!(
        fixture.journal.lock().pending_receipts().unwrap(),
        purchases
    );
    assert_eq!(fixture.journal.lock().remaining_ou().unwrap(), 9_872);
    assert!(state.received.lock().is_empty());
    stop.send_replace(true);
    worker.await.unwrap().unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test(start_paused = true)]
async fn delayed_service_start_cannot_renew_an_old_status_observation() {
    let fixture = Fixture::new();
    let observation = Observation::new(fixture.paid());
    tokio::time::advance(STATUS_MAX_AGE).await;
    let (_stop, stopped) = watch::channel(false);
    let error = control_loop(
        reqwest::Client::new(),
        reqwest::Url::parse("http://127.0.0.1:9").unwrap(),
        fixture.connect.clone(),
        fixture.plan.clone(),
        observation,
        stopped,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("clock stopped advancing"));
}

mod retry;
