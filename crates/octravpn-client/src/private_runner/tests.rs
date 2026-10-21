//! Authenticated status tests only. This publisher owns no canonical payment
//! authority and these tests do not claim private chain or kernel qualification.
use super::*;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use octravpn_core::payments::ShieldedStatus;
use std::sync::{
    atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
    Mutex,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
};
mod pending;
mod recovery;

struct Publisher {
    funded: AtomicBool,
    calls: AtomicUsize,
    operator: KeyPair,
    plan: Plan,
    http_status: AtomicU16,
    requests: Mutex<Vec<Vec<u8>>>,
}
impl Publisher {
    fn new(plan: Plan, operator: KeyPair, funded: bool) -> Self {
        Self {
            funded: AtomicBool::new(funded),
            calls: AtomicUsize::new(0),
            operator,
            plan,
            http_status: AtomicU16::new(200),
            requests: Mutex::new(Vec::new()),
        }
    }
}
async fn status(
    State(p): State<Arc<Publisher>>,
    Json(connect): Json<SignedConnect>,
) -> std::result::Result<Json<SignedShieldedStatus>, StatusCode> {
    connect.verify().unwrap();
    p.calls.fetch_add(1, Ordering::SeqCst);
    p.requests
        .lock()
        .unwrap()
        .push(serde_json::to_vec(&connect).unwrap());
    let status = StatusCode::from_u16(p.http_status.load(Ordering::SeqCst)).unwrap();
    if status != StatusCode::OK {
        return Err(status);
    }
    let funded = p.funded.load(Ordering::SeqCst);
    Ok(Json(
        SignedShieldedStatus::sign(
            ShieldedStatus {
                connection: connect.request,
                server_wireguard_key: [5; 32],
                tariff: p.plan.tariff.clone(),
                operator_generation: p.plan.operator_generation,
                quote_ceiling_ou: p.plan.quote_ceiling_ou,
                paid_ou: u64::from(funded),
                purchased_totals: vec![if funded { 128 } else { 0 }],
                committed_totals: vec![0],
                held_totals: vec![0],
                canonical_ms: 1000,
                service_sequence: 1,
            },
            &p.operator,
        )
        .unwrap(),
    ))
}
struct Tls {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
    http: JoinHandle<()>,
}

#[tokio::test]
async fn local_private_hop_defers_admission_and_uses_pinned_ip_with_original_tls_hostname() {
    let (mut plan, key, operator) = crate::payments::private::tests::plan();
    let publisher = Arc::new(Publisher::new(plan.clone(), operator, false));
    let tls = Tls::serve(publisher.clone(), &mut plan).await;
    let mut origin = reqwest::Url::parse(&plan.control_url).unwrap();
    let port = origin.port().unwrap();
    origin.set_host(Some("private-operator.invalid")).unwrap();
    plan.control_url = origin.to_string();
    let root = tempfile::tempdir().unwrap();
    let options = |mode| Options {
        plan: plan.clone(),
        journal: root.path().join("plan"),
        receipt_key: key.clone(),
        interface_name: "octprivate0".into(),
        mode,
    };
    let pins = Pins {
        wireguard: "127.0.0.1:51820".parse().unwrap(),
        control: std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port),
    };
    let local = Local::new(options(OpenMode::Create), Some(pins), 1075)
        .await
        .unwrap();
    assert_eq!(publisher.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        local
            .journal
            .with(|j| Ok(j.authorized_totals().to_vec()))
            .await
            .unwrap(),
        [0]
    );
    let error = local.connect().await.err().unwrap();
    assert!(error.to_string().contains("prepaid capacity missing"));
    assert_eq!(publisher.calls.load(Ordering::SeqCst), 1);
    publisher.funded.store(true, Ordering::SeqCst);
    let local = Local::new(options(OpenMode::Resume), Some(pins), 1075)
        .await
        .unwrap();
    assert_eq!(publisher.calls.load(Ordering::SeqCst), 1);
    let prepared = local.connect().await.unwrap();
    assert_eq!(prepared.mtu, 1075);
    assert_eq!(prepared.status().status.connection.sequence, 2);
    assert_eq!(prepared.status().status.purchased_totals, [128]);
    assert_eq!(publisher.calls.load(Ordering::SeqCst), 2);
    drop(prepared);
    tls.close().await;
}
impl Tls {
    async fn serve(publisher: Arc<Publisher>, plan: &mut Plan) -> Self {
        use tokio_rustls::{
            rustls::{self, pki_types::PrivatePkcs8KeyDer},
            TlsAcceptor,
        };
        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".into(),
            "private-operator.invalid".into(),
        ])
        .unwrap();
        plan.control_ca_pem = cert.cert.pem();
        plan.control_spki =
            vec![
                octravpn_core::spki_verifier::SpkiPinVerifier::fingerprint(cert.cert.der())
                    .unwrap(),
            ];
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = backend.local_addr().unwrap();
        let tls = TcpListener::bind("127.0.0.1:0").await.unwrap();
        plan.control_url = format!("https://localhost:{}/", tls.local_addr().unwrap().port());
        let (stop, mut stopped) = watch::channel(false);
        let mut http_stop = stopped.clone();
        let app = Router::new()
            .route("/shielded/connect", post(status))
            .with_state(publisher);
        let http = tokio::spawn(async move {
            axum::serve(backend, app)
                .with_graceful_shutdown(async move {
                    let _ = http_stop.wait_for(|v| *v).await;
                })
                .await
                .unwrap();
        });
        let task = tokio::spawn(async move {
            let mut streams = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _=stopped.wait_for(|v| *v)=>break,
                    accepted=tls.accept()=> {let (stream,_)=accepted.unwrap(); let acceptor=acceptor.clone(); streams.spawn(async move {
                        if let Ok(mut stream)=acceptor.accept(stream).await {
                            let mut backend=TcpStream::connect(address).await.unwrap();
                            let _=tokio::io::copy_bidirectional(&mut stream,&mut backend).await;
                        }
                    });},
                    _=streams.join_next(),if !streams.is_empty()=>(),
                }
            }
            streams.abort_all();
            while streams.join_next().await.is_some() {}
        });
        Self { stop, task, http }
    }
    async fn close(self) {
        self.stop.send(true).unwrap();
        self.task.await.unwrap();
        self.http.await.unwrap();
    }
}

#[tokio::test]
async fn private_preparation_needs_purchased_floor_and_resumes_the_same_encrypted_journal() {
    let (mut plan, key, operator) = crate::payments::private::tests::plan();
    let publisher = Arc::new(Publisher::new(plan.clone(), operator, false));
    let tls = Tls::serve(publisher.clone(), &mut plan).await;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plan");
    let options = |mode| Options {
        plan: plan.clone(),
        journal: path.clone(),
        receipt_key: key.clone(),
        interface_name: "octraprivate0".into(),
        mode,
    };
    let error = Prepared::new(options(OpenMode::Create))
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("prepaid capacity missing"));
    assert_eq!(publisher.calls.load(Ordering::SeqCst), 1);
    publisher.funded.store(true, Ordering::SeqCst);
    let prepared = Prepared::new(options(OpenMode::Resume)).await.unwrap();
    assert_eq!(prepared.status().status.connection.sequence, 2);
    assert_eq!(prepared.status().status.purchased_totals, [128]);
    let raw = std::fs::read(path.join("state.json")).unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&raw).is_err());
    let authorized = prepared
        .journal
        .with(|j| Ok(j.authorized_totals().to_vec()))
        .await
        .unwrap();
    assert_eq!(authorized, vec![128]);
    drop(prepared);
    let prepared = Prepared::new(options(OpenMode::Resume)).await.unwrap();
    assert_eq!(prepared.status().status.connection.sequence, 3);
    assert_eq!(
        prepared
            .journal
            .with(|j| Ok(j.authorized_totals().to_vec()))
            .await
            .unwrap(),
        authorized
    );
    drop(prepared);
    tls.close().await;
}

#[tokio::test]
async fn private_invalid_configuration_refuses_before_a_journal_or_network_request() {
    let (mut plan, key, operator) = crate::payments::private::tests::plan();
    let publisher = Arc::new(Publisher::new(plan.clone(), operator, true));
    let tls = Tls::serve(publisher.clone(), &mut plan).await;
    let root = tempfile::tempdir().unwrap();
    for mutation in 0..7 {
        let mut changed = plan.clone();
        let mut name = "octraprivate0".to_owned();
        match mutation {
            0 => changed.control_url = "http://127.0.0.1:9/".into(),
            1 => changed.control_spki.clear(),
            2 => changed.target.chain_origin = [0; 32],
            3 => changed.operator_generation = 0,
            4 => changed.prepaid_bytes = vec![0],
            5 => changed.binding.payer = Address::from_pubkey(&[4; 32]),
            _ => name = "../bad".into(),
        }
        let path = root.path().join(format!("invalid-{mutation}"));
        assert!(Prepared::new(Options {
            plan: changed,
            journal: path.clone(),
            receipt_key: key.clone(),
            interface_name: name,
            mode: OpenMode::Create
        })
        .await
        .is_err());
        assert!(!path.exists());
    }
    assert_eq!(publisher.calls.load(Ordering::SeqCst), 0);
    tls.close().await;
}

#[tokio::test(start_paused = true)]
async fn an_old_private_observation_cannot_restart_its_freshness_deadline() {
    let (mut plan, key, operator) = crate::payments::private::tests::plan();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    plan.control_ca_pem = cert.cert.pem();
    let control = plan.control(None).unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut journal = Journal::open_private(
        &root.path().join("plan"),
        &plan,
        key.clone(),
        OpenMode::Create,
    )
    .unwrap();
    let connect = journal.connect(wireguard::public_key(&key)).unwrap();
    let signed = SignedShieldedStatus::sign(
        ShieldedStatus {
            connection: connect.request.clone(),
            server_wireguard_key: [5; 32],
            tariff: plan.tariff.clone(),
            operator_generation: 1,
            quote_ceiling_ou: 1000,
            paid_ou: 1,
            purchased_totals: vec![128],
            committed_totals: vec![0],
            held_totals: vec![0],
            canonical_ms: 1000,
            service_sequence: 1,
        },
        &operator,
    )
    .unwrap();
    let initial = monitor::Observation {
        signed,
        freshness: payment_runner::Freshness::new(1000),
    };
    tokio::time::advance(std::time::Duration::from_secs(121)).await;
    let (_stop, stopped) = watch::channel(false);
    assert!(monitor::run(
        control,
        connect,
        plan,
        Accounting::new(journal),
        initial,
        stopped
    )
    .await
    .is_err());
}
