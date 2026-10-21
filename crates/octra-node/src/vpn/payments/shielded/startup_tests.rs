//! Operator startup uses the same encrypted book and canonical private RPC as
//! embedded hosts. Allocation/replay tests never treat a quote as paid bytes.
use super::*;
use crate::vpn::payments::shielded::{
    startup::{Config, Listen},
    wallet::rpc::Policy,
};
use octravpn_core::{
    payments::{
        PrivateAction, PrivateRequest, PrivateResult, SignedPrivateReply, SignedPrivateRequest,
    },
    KeyPair,
};

async fn send(
    http: &reqwest::Client,
    origin: &str,
    request: &SignedPrivateRequest,
) -> SignedPrivateReply {
    let response = http
        .post(format!("{origin}/shielded/purchase"))
        .json(request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let reply: SignedPrivateReply = response.json().await.unwrap();
    reply.verify(request).unwrap();
    reply
}
pub(super) async fn run(fixture: &Fixture, pool: shielded::Config) {
    let root = fixture.directory.path();
    let master = root.join("startup-master.key");
    crate::storage::publish(&master, &[252; 32]).unwrap();
    let config = Config {
        application: fixture.payments().config,
        pool,
        wallet: root.join("startup-wallet"),
        master_key: master,
        purchases: Policy {
            max_channels: 1,
            max_requests: 4,
            max_ceiling_ou: 10,
            max_invoice_lifetime_ms: 120_000,
        },
        ip_tunnel: None,
    };
    // Public test VK/pins only, for the separately executed CLI smoke. No master
    // key, proving key, invoice association or encrypted wallet is exported.
    let evidence = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../out/private-operator-startup-20261019");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("public-test-pins.json"),serde_json::to_vec_pretty(&json!({"test_only":true,"production_verification_key":false,"application":config.application,"pool":config.pool,"purchases":config.purchases})).unwrap()).unwrap();
    // The CLI initializer intentionally creates only off-chain key/book state.
    // Deployment and funding still have to pass the later canonical checks.
    let paths = crate::devnet::init_with_applications(&root.join("wallet-init-node"), 26000, true)
        .await
        .unwrap();
    let mut offline = crate::devnet::read(&paths[0]).unwrap();
    let mut private = config.clone();
    private.wallet = root.join("offline-initialized-wallet");
    private.application.domain = crate::vpn::payments::application_domain(
        &offline.genesis.chain,
        crate::vpn::payments::Application::Circle,
    );
    offline.shielded = Some(private.clone());
    let runtime = || {
        octra_node_runtime::circle::CircleRuntime::isolated(
            octra_node_runtime::crypto_worker::Pool::open(
                &std::env::current_exe().unwrap(),
                octra_node_runtime::crypto_worker::Limits::from_values(|_| None),
            )
            .unwrap(),
        )
    };
    assert_eq!(
        crate::devnet::init_private_wallet(offline.clone(), runtime())
            .await
            .unwrap(),
        private.wallet
    );
    assert!(
        crate::devnet::init_private_wallet(offline.clone(), runtime())
            .await
            .is_err()
    );
    let mut wrong_role = offline.clone();
    wrong_role.genesis.activated_applications = false;
    assert!(crate::devnet::init_private_wallet(wrong_role, runtime())
        .await
        .is_err());
    let mut relative = private.clone();
    relative.wallet = "relative-wallet".into();
    relative.master_key = "relative.key".into();
    relative.resolve_paths(root);
    assert_eq!(relative.wallet, root.join("relative-wallet"));
    assert_eq!(relative.master_key, root.join("relative.key"));
    let key = payment_host::key(11);
    assert!(config.resume(&fixture.node, &key).await.is_err());
    assert!(!config.wallet.exists());
    let mut wrong = config.clone();
    wrong.pool.verification_key_sha256 = "00".repeat(32);
    wrong.wallet = root.join("refused-startup-wallet");
    assert!(wrong.initialize(&fixture.node, &key).await.is_err());
    assert!(!wrong.wallet.exists());
    config.initialize(&fixture.node, &key).await.unwrap();
    assert!(config.initialize(&fixture.node, &key).await.is_err());
    let wrong_master = root.join("wrong-startup-master.key");
    crate::storage::publish(&wrong_master, &[253; 32]).unwrap();
    let mut wrong = config.clone();
    wrong.master_key = wrong_master;
    assert!(wrong.resume(&fixture.node, &key).await.is_err());
    let wallet = config.resume(&fixture.node, &key).await.unwrap();
    let target = wallet
        .private_target(KeyPair::from_secret_bytes(&[11; 32]).public)
        .unwrap();
    drop(wallet);
    let data = root.join("startup-service");
    std::fs::create_dir(&data).unwrap();
    let listen = Listen {
        browser: "127.0.0.1:0".parse().unwrap(),
        control: "127.0.0.1:0".parse().unwrap(),
        tunnel: "127.0.0.1:0".parse().unwrap(),
    };
    let mut exposed = listen;
    exposed.control = "0.0.0.0:0".parse().unwrap();
    assert!(config
        .bind(&fixture.node, exposed, &data, &key)
        .await
        .is_err());
    assert!(!data.join("private-payments-transport").exists());
    let (service, income) = config
        .bind_with_wallet(&fixture.node, listen, &data, &key)
        .await
        .unwrap();
    assert!(config.resume(&fixture.node, &key).await.is_err());
    assert!(
        income
            .private_target(KeyPair::from_secret_bytes(&[11; 32]).public)
            .unwrap()
            == target
    );
    let origin = format!("http://{}", service.control_addr().unwrap());
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let job = tokio::spawn(service.run(stopped));
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    assert_eq!(
        http.post(format!("{origin}/payments/connect"))
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    let client = KeyPair::from_secret_bytes(&[251; 32]);
    let request = |id: u8, action| {
        SignedPrivateRequest::sign(
            PrivateRequest {
                target: target.clone(),
                id: [id; 32],
                valid_from_ms: millis(fixture),
                expires_ms: millis(fixture) + 120_000,
                action,
            },
            &client,
        )
        .unwrap()
    };
    let open = request(
        1,
        PrivateAction::Open {
            offer: 0,
            ceiling_ou: 10,
        },
    );
    let first = send(&http, &origin, &open).await;
    let PrivateResult::Open { binding, .. } =
        serde_json::from_slice(&first.verify(&open).unwrap()).unwrap()
    else {
        panic!("not open")
    };
    let quote = request(
        2,
        PrivateAction::Quote {
            channel: binding.plan,
            class: 0,
            bytes: 50_000,
            validity_ms: 120_000,
        },
    );
    let quoted = send(&http, &origin, &quote).await;
    assert_eq!(send(&http, &origin, &quote).await.payload, quoted.payload);
    let changed = request(
        2,
        PrivateAction::Quote {
            channel: binding.plan,
            class: 0,
            bytes: 49_999,
            validity_ms: 120_000,
        },
    );
    assert_eq!(
        http.post(format!("{origin}/shielded/purchase"))
            .json(&changed)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    stop.send(true).unwrap();
    job.await.unwrap().unwrap();
    drop(income);
    assert!(fixture.node.resume().await.unwrap());
    let wallet = config.resume(&fixture.node, &key).await.unwrap();
    let info = wallet.channel(binding.plan).await.unwrap();
    assert_eq!(info.paid_ou, 0);
    assert!(!info.purchased.is_empty() && info.purchased.iter().all(|bytes| *bytes == 0));
    drop(wallet);
    let service = config
        .bind(&fixture.node, listen, &data, &key)
        .await
        .unwrap();
    let origin = format!("http://{}", service.control_addr().unwrap());
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let job = tokio::spawn(service.run(stopped));
    assert_eq!(send(&http, &origin, &open).await.payload, first.payload);
    assert_eq!(send(&http, &origin, &quote).await.payload, quoted.payload);
    fixture.node.suspend("private startup source unavailable");
    let fresh = request(
        3,
        PrivateAction::Quote {
            channel: binding.plan,
            class: 0,
            bytes: 1,
            validity_ms: 1000,
        },
    );
    assert_eq!(
        http.post(format!("{origin}/shielded/purchase"))
            .json(&fresh)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    stop.send(true).unwrap();
    job.await.unwrap().unwrap();
    assert!(fixture.node.resume().await.unwrap());
}
