//! External consumers use the library API, without invoking the CLI or opening
//! a privileged TUN for rejected/cancelled startup.
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use octravpn_client::{AcceptedPlan, JournalMode, PaymentClient, PaymentOptions};
use octravpn_core::{
    payments::{Deployment, PlanBinding, SignedConnect, Tariff, TrafficClass},
    Address, KeyPair,
};
use parking_lot::Mutex;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Notify;

fn plan() -> AcceptedPlan {
    let operator = KeyPair::from_secret_bytes(&[17; 32]);
    let payer = KeyPair::from_secret_bytes(&[18; 32]);
    let tariff = Tariff::new(
        Address::from_pubkey(&operator.public.0),
        vec![TrafficClass {
            name: "default".into(),
            rate_ou_per_mib: 1000,
        }],
        vec![],
    )
    .unwrap();
    AcceptedPlan {
        binding: PlanBinding {
            deployment: Deployment {
                domain: "ab".repeat(32),
                program: Address::from_pubkey(&[19; 32]),
            },
            payer: Address::from_pubkey(&payer.public.0),
            generation: 1,
            plan: 7,
            offer: 9,
            manifest_hash: tariff.hash_hex().unwrap(),
        },
        tariff,
        original_budget_ou: 10_000,
        prepaid_bytes: vec![1024],
        control_url: "http://127.0.0.1:9/".into(),
        wireguard_endpoint: "127.0.0.1:51820".into(),
    }
}
fn options(plan: AcceptedPlan, journal: PathBuf, mode: JournalMode) -> PaymentOptions {
    PaymentOptions {
        plan,
        journal,
        mode,
        receipt_key: Arc::new(KeyPair::from_secret_bytes(&[18; 32])),
        interface_name: "octratest0".into(),
    }
}

#[tokio::test]
async fn malformed_public_inputs_fail_before_journal_or_network_side_effects() {
    let directory = tempfile::tempdir().unwrap();
    for invalid in 0..10 {
        let mut accepted = plan();
        match invalid {
            0 => accepted.binding.manifest_hash = "cd".repeat(32),
            1 => accepted.original_budget_ou = 0,
            2 => accepted.control_url = "http://198.51.100.1/".into(),
            3 => accepted.control_url = "https://user:password@example.test/".into(),
            4 => accepted.control_url = "https://example.test/path".into(),
            5 => accepted.wireguard_endpoint = "invalid-endpoint".into(),
            6 => accepted.binding.generation = 0,
            7 => accepted.prepaid_bytes = vec![],
            8 => accepted.prepaid_bytes = vec![0],
            _ => accepted.prepaid_bytes = vec![u64::MAX],
        }
        let path = directory.path().join(format!("plan-{invalid}"));
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            PaymentClient::open(options(accepted, path.clone(), JournalMode::Create)),
        )
        .await
        .unwrap()
        .err()
        .expect("invalid plan must be rejected");
        assert!(
            !path.exists(),
            "startup created a journal before validation: {error:#}"
        );
    }
    let path = directory.path().join("bad-interface");
    let mut request = options(plan(), path.clone(), JournalMode::Create);
    request.interface_name = "../bad".into();
    let error = PaymentClient::open(request).await.err().unwrap();
    assert!(error.to_string().contains("invalid TUN name"));
    assert!(!path.exists());
}

#[test]
fn public_plan_loader_bounds_files_and_rejects_unknown_fields() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("plan.json");
    let expected = plan();
    std::fs::write(&path, serde_json::to_vec(&expected).unwrap()).unwrap();
    let actual = AcceptedPlan::load(&path).unwrap();
    assert_eq!(actual.binding, expected.binding);
    assert_eq!(actual.tariff, expected.tariff);
    assert_eq!(actual.original_budget_ou, expected.original_budget_ou);
    assert_eq!(actual.prepaid_bytes, expected.prepaid_bytes);
    let mut postpaid = serde_json::to_value(&expected).unwrap();
    postpaid.as_object_mut().unwrap().remove("prepaid_bytes");
    std::fs::write(&path, serde_json::to_vec(&postpaid).unwrap()).unwrap();
    assert!(AcceptedPlan::load(&path).is_err());
    let mut value = serde_json::to_value(expected).unwrap();
    value["trust_me"] = true.into();
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(AcceptedPlan::load(&path).is_err());
    std::fs::write(&path, vec![b' '; 131_073]).unwrap();
    assert!(AcceptedPlan::load(&path)
        .err()
        .unwrap()
        .to_string()
        .contains("byte bound"));
}

#[derive(Clone)]
struct Gate {
    requests: Arc<Mutex<Vec<SignedConnect>>>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}
async fn held_connect(State(gate): State<Gate>, Json(connect): Json<SignedConnect>) -> StatusCode {
    connect.verify().unwrap();
    gate.requests.lock().push(connect);
    gate.entered.notify_one();
    gate.release.notified().await;
    StatusCode::SERVICE_UNAVAILABLE
}

#[tokio::test]
async fn cancelled_public_open_preserves_journal_and_resume_advances_watermark() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal");
    let gate = Gate {
        requests: Arc::new(Mutex::new(Vec::new())),
        entered: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut accepted = plan();
    accepted.control_url = format!("http://{}/", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/payments/connect", post(held_connect))
        .with_state(gate.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    for (index, mode) in [JournalMode::Create, JournalMode::Resume]
        .into_iter()
        .enumerate()
    {
        let request = options(accepted.clone(), path.clone(), mode);
        let opening = tokio::spawn(PaymentClient::open(request));
        tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
            .await
            .unwrap();
        assert!(!opening.is_finished());
        opening.abort();
        assert!(opening.await.err().unwrap().is_cancelled());
        let requests = gate.requests.lock();
        assert_eq!(requests.len(), index + 1);
        assert_eq!(requests[index].request.binding, accepted.binding);
        assert_eq!(requests[index].request.sequence, (index + 1) as u64);
        assert!(path.join("state.json").is_file());
    }
    {
        let requests = gate.requests.lock();
        assert_eq!(
            requests[0].request.wireguard_key,
            requests[1].request.wireguard_key
        );
    }
    gate.release.notify_waiters();
    server.abort();
    let _ = server.await;
}
