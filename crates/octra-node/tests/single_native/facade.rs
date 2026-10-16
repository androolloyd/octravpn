//! Real Single store/executor/queue through the shared native HTTP dispatcher.
//! No synthetic QC, BFT Host, or substitute pending pool is used.
use super::*;
use ed25519_dalek::Signer;
use octra_node::single::facade::Facade;
use tokio::sync::watch;
#[path = "../../../octra-node-runtime/tests/common/circle_host.rs"]
#[allow(dead_code)] // This suite uses the committed counter fixture, not its alternate runtimes.
mod circle_host;
struct Rpc {
    facade: Arc<Facade>,
    client: reqwest::Client,
    url: String,
    stop: watch::Sender<bool>,
    http: Option<tokio::task::JoinHandle<()>>,
    refresh: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}
impl Rpc {
    async fn start(node: Arc<single::Node>, data: &std::path::Path) -> Self {
        let facade = Facade::open(node, None).await.unwrap();
        let router = facade
            .rpc_router(&SigningKey::from_bytes(&[4; 32]), data)
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (stop, mut shutdown) = watch::channel(false);
        let http = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = shutdown.wait_for(|v| *v).await;
                })
                .await
                .unwrap();
        });
        let refresh = tokio::spawn(facade.clone().run(stop.subscribe()));
        Self {
            facade,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap(),
            url,
            stop,
            http: Some(http),
            refresh: Some(refresh),
        }
    }
    async fn call(&self, method: &str, params: Value) -> Value {
        self.client
            .post(format!("{}/rpc", self.url))
            .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }
    async fn at(&self, epoch: u64) {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if self
                    .facade
                    .snapshot()
                    .is_ok_and(|view| view.head().cursor.epoch.0 == epoch)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    async fn close(mut self) {
        self.stop.send_replace(true);
        self.facade.close();
        self.http.take().unwrap().await.unwrap();
        self.refresh.take().unwrap().await.unwrap().unwrap();
    }
}
impl Drop for Rpc {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        self.facade.close();
    }
}
fn current_time() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}
fn current_transfer() -> Transaction {
    let mut tx = signed_transfer();
    tx.timestamp = current_time();
    tx.signature = STANDARD
        .encode(
            SigningKey::from_bytes(&[1; 32])
                .sign(&tx.signing_bytes().unwrap())
                .to_bytes(),
        )
        .into_bytes();
    tx
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_single_facade_uses_owned_intake_local_proofs_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let node = open_node(dir.path(), 0.).await;
    let rpc = Rpc::start(node.clone(), dir.path()).await;
    let account = String::from_utf8(address(1)).unwrap();
    let balance = rpc
        .call("octra_balance", serde_json::json!([account]))
        .await;
    assert_eq!(balance["result"]["balance_raw"], "1000000");
    let bad = rpc
        .call(
            "octra_registerPublicKey",
            serde_json::json!([
                String::from_utf8(address(1)).unwrap(),
                String::from_utf8(public(2)).unwrap(),
                STANDARD.encode([0; 64])
            ]),
        )
        .await;
    assert_eq!(bad["error"]["message"], "public key does not match address");
    let signature = STANDARD.encode(
        SigningKey::from_bytes(&[1; 32])
            .sign(&[b"register_pubkey:".as_slice(), &address(1)].concat())
            .to_bytes(),
    );
    let registered = rpc
        .call(
            "octra_registerPublicKey",
            serde_json::json!([
                String::from_utf8(address(1)).unwrap(),
                String::from_utf8(public(1)).unwrap(),
                signature
            ]),
        )
        .await;
    assert_eq!(
        registered["result"],
        serde_json::json!({"ok":true,"address":String::from_utf8(address(1)).unwrap()})
    );
    assert_eq!(node.registered_key(&address(1)).unwrap(), Some(public(1)));
    let tx = current_transfer();
    let hash = hex::encode(tx.hash().unwrap());
    let accepted = rpc
        .call(
            "octra_submit",
            serde_json::json!([
                serde_json::from_slice::<Value>(&tx.to_json_bytes().unwrap()).unwrap()
            ]),
        )
        .await;
    assert_eq!(accepted["result"]["tx_hash"], hash);
    assert_eq!(node.queued().unwrap().len(), 1);
    let time = current_time() + 10.;
    let head = node.tick(time, time as i64).await.unwrap().unwrap();
    rpc.at(1).await;
    let summary = rpc.call("epoch_get", serde_json::json!([1])).await;
    assert_eq!(
        summary["result"]["state_root"],
        hex::encode(head.cursor.state_root.0),
        "epoch_get response: {summary}"
    );
    let proof = rpc.call("octra_epochProof", serde_json::json!([1])).await;
    assert!(proof.get("error").is_none(), "{proof}");
    let raw = serde_json::to_string(&proof).unwrap();
    assert!(raw.contains(&hash));
    let statuses = rpc.call("node_status", serde_json::json!([])).await;
    assert!(statuses.get("error").is_none(), "{statuses}");
    let readiness: Value = rpc
        .client
        .get(format!("{}/state-sync/readiness", rpc.url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        readiness.to_string().contains("not_ready") || readiness.to_string().contains("disabled")
    );
    let mut tx = current_transfer();
    tx.nonce = transaction::Nonce::new(2).unwrap();
    tx.signature = STANDARD
        .encode(
            SigningKey::from_bytes(&[1; 32])
                .sign(&tx.signing_bytes().unwrap())
                .to_bytes(),
        )
        .into_bytes();
    let pending_hash = hex::encode(tx.hash().unwrap());
    let accepted = rpc
        .call(
            "octra_submit",
            serde_json::json!([
                serde_json::from_slice::<Value>(&tx.to_json_bytes().unwrap()).unwrap()
            ]),
        )
        .await;
    assert_eq!(accepted["result"]["tx_hash"], pending_hash);
    let wrong = rpc
        .call(
            "staging_remove",
            serde_json::json!([
                pending_hash,
                STANDARD.encode([0; 64]),
                String::from_utf8(public(1)).unwrap()
            ]),
        )
        .await;
    assert_eq!(wrong["error"]["message"], "signature verification failed");
    assert_eq!(node.queued().unwrap().len(), 1);
    let signature = STANDARD.encode(
        SigningKey::from_bytes(&[1; 32])
            .sign(format!("staging_remove|{pending_hash}").as_bytes())
            .to_bytes(),
    );
    let removed = rpc
        .call(
            "staging_remove",
            serde_json::json!([
                pending_hash,
                signature,
                String::from_utf8(public(1)).unwrap()
            ]),
        )
        .await;
    assert_eq!(removed["result"]["removed"], true);
    assert!(node.queued().unwrap().is_empty());
    assert_eq!(node.head().await.unwrap(), head);
    // Keep the actual HTTP listener alive after synchronous publication revoke.
    // Raw durable Core/SQLite heads must not bypass completed-view availability.
    rpc.facade.close();
    assert!(rpc.facade.snapshot().is_err());
    assert_eq!(
        rpc.call("octra_head", serde_json::json!([])).await["error"]["code"],
        110
    );
    assert!(rpc
        .call("epoch_get", serde_json::json!([1]))
        .await
        .get("error")
        .is_some());
    let unavailable = rpc
        .client
        .get(format!("{}/operator/status", rpc.url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        unavailable.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    rpc.close().await;
    node.shutdown().await.unwrap();
    drop(node);
    let reopened = open_node(dir.path(), time).await;
    assert_eq!(reopened.head().await.unwrap(), head);
    let rpc = Rpc::start(reopened.clone(), dir.path()).await;
    assert_eq!(
        rpc.call("octra_epochProof", serde_json::json!([1])).await,
        proof
    );
    assert_eq!(rpc.call("epoch_get", serde_json::json!([1])).await, summary);
    rpc.close().await;
    reopened.shutdown().await.unwrap();
}
fn app_config(dir: &std::path::Path, opt_in: bool) -> single::launch::Config {
    seed_config(dir, opt_in, true, false)
}
fn seed_config(
    dir: &std::path::Path,
    opt_in: bool,
    counter: bool,
    paid: bool,
) -> single::launch::Config {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    const CHAIN: &str = "octra-single-local-0123456789abcdef";
    let fixture: Value =
        serde_json::from_slice(include_bytes!("../fixtures/single-native.json")).unwrap();
    let mut state = initial(&fixture["cases"][0]);
    state.begin().unwrap();
    state.set(&[b"meta",b"local_single"],serde_json::to_vec(&serde_json::json!({"chain_id":CHAIN,"profile":"single_applications_v1","activated_applications":opt_in})).unwrap()).unwrap();
    if counter {
        circle_host::install_counter(&mut state, &address(2), b"4");
    }
    if paid {
        let mut faucet = account_store::load(&state, &address(1)).unwrap().unwrap();
        faucet.balance = 100_000_000_000_u64.into();
        account_store::set(&mut state, &address(1), &faucet, RuleMode::Prior).unwrap();
        let supply = account_store::ledger(&state)
            .unwrap()
            .total_supply()
            .to_string();
        state
            .set(&[b"meta", b"total_supply"], supply.into_bytes())
            .unwrap();
    }
    let root = epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(
            epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
                .unwrap()
                .1,
        )
        .as_bytes(),
    )
    .unwrap();
    let mut image = vec![];
    let written = octra_node_runtime::ledger_image::write(
        &state.snapshot(),
        &mut image,
        octra_node_runtime::ledger_image::Limits::default(),
    )
    .unwrap();
    let image_path = dir.join("genesis.image");
    std::fs::write(&image_path, &image).unwrap();
    let key = dir.join("node.key");
    std::fs::write(&key, [4; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    single::launch::Config {
        chain: octra_exex::ChainIdentity::genesis(CHAIN, StateRoot(root)),
        data: dir.join("data"),
        key,
        seed: single::launch::Seed {
            path: image_path,
            bytes: written.bytes,
            sha256: hex::encode(Sha256::digest(&image)),
            ledger_root: written.root,
            maximum_records: written.records,
            maximum_string_bytes: 1_048_576,
            date: 0,
        },
        settings: settings(),
        execution: single::launch::Execution {
            activated_applications: true,
            release: None,
            crypto_profile: None,
            admit_ops: None,
            emission_guard: false,
            emission_activation: None,
            legacy_total: None,
            sender_key_activation: Some(0),
            private_result_activation: 0,
            maximum_fhe: 32,
            maximum_stealth: 32,
            maximum_multi_exec: 8,
            ready_max_lag: 10,
        },
        rpc: "127.0.0.1:0".parse().unwrap(),
        maximum_http_body: 1_048_576,
        services: None,
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_single_app_opt_in_binds_seed_runtime_and_native_circle_view() {
    let dir = tempfile::tempdir().unwrap();
    let config = app_config(dir.path(), true);
    let node = single::launch::open(&config).await.unwrap();
    let rpc = Rpc::start(node.clone(), &config.data).await;
    let response = rpc
        .call(
            "circle_view",
            serde_json::json!([String::from_utf8(address(2)).unwrap(), "get_counter", []]),
        )
        .await;
    assert_eq!(response["result"]["result"], "4", "{response}");
    let head = node.head().await.unwrap();
    assert_eq!(head.cursor.state_root, config.chain.genesis_root().unwrap());
    let context = node
        .executor()
        .single_context(&head, &node.settings().validators(1))
        .await
        .unwrap();
    assert_eq!(context.fold.context().mode, RuleMode::Prior);
    rpc.close().await;
    node.shutdown().await.unwrap();
    drop(node);
    let mut altered = config.clone();
    altered.execution.activated_applications = false;
    assert!(single::launch::open(&altered)
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("origin or authority differs"));
    let bad = tempfile::tempdir().unwrap();
    let config = app_config(bad.path(), false);
    assert!(single::launch::open(&config)
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("opt-in differs"));
    assert!(
        !config.data.join("canonical.db").exists(),
        "refused opt-in must precede store creation"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_peer_broadcast_uses_actual_committed_epoch_without_state_import() {
    use octra_node_protocol::network::{
        endpoint::Endpoint,
        frame::Frame,
        session::Peer,
        session::Timeouts,
        swarm::{self, Handler, MessageFuture, Swarm},
    };
    struct Capture(tokio::sync::mpsc::Sender<Frame>);
    impl Handler for Capture {
        fn message(&self, _: Peer, frame: Frame) -> MessageFuture {
            let _ = self.0.try_send(frame);
            Box::pin(async { Ok(()) })
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let mut config = app_config(dir.path(), true);
    let node = single::launch::open(&config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_address = listener.local_addr().unwrap();
    let chain = config.chain.chain_id.as_bytes().to_vec();
    let root = config.chain.genesis_root().unwrap().0;
    let peer = Swarm::new(
        swarm::Config {
            chain_id: chain,
            node_address: address(5),
            config_hash: vec![9; 32],
            binary_hash: vec![8; 32],
            require_binary_hash: true,
            upgrade: None,
            profiles: vec![],
            allowed_public_keys: vec![],
            bootstrap: vec![],
            maximum_validators: 16,
            advertised: Endpoint {
                host: b"127.0.0.1".to_vec(),
                port: peer_address.port(),
            },
            timeouts: Timeouts::default(),
            head: Arc::new(move || (0, root)),
        },
        SigningKey::from_bytes(&[5; 32]),
    )
    .unwrap();
    peer.set_validators(vec![SigningKey::from_bytes(&[4; 32])
        .verifying_key()
        .to_bytes()
        .to_vec()])
        .unwrap();
    let (sender, mut received) = tokio::sync::mpsc::channel(64);
    let running = peer.clone();
    let peer_task =
        tokio::spawn(async move { running.run(listener, Arc::new(Capture(sender))).await });
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    config.rpc = reserved.local_addr().unwrap();
    drop(reserved);
    let (stop, shutdown) = watch::channel(false);
    let running_node = node.clone();
    let running_config = config.clone();
    let service = tokio::spawn(async move {
        single::service::run(
            &running_config,
            running_node,
            single::service::Services {
                network: Some(single::network::Config {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    bootstrap: vec![peer_address],
                    config_hash: hex::encode([9; 32]),
                    binary_hash: hex::encode([8; 32]),
                    require_binary_hash: true,
                    maximum_peers: 16,
                    allow_dynamic_peers: true,
                }),
                ..Default::default()
            },
            shutdown,
        )
        .await
    });
    let client = reqwest::Client::new();
    let endpoint = format!("http://{}", config.rpc);
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            if let Ok(response) = client
                .get(format!("{endpoint}/operator/status"))
                .send()
                .await
            {
                if let Ok(value) = response.json::<Value>().await {
                    if value["peers"].as_u64() == Some(1) {
                        break;
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let response = client
        .post(format!("{endpoint}/rpc"))
        .body(vec![b' '; config.maximum_http_body + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    let tx = current_transfer();
    let tx_hash = hex::encode(tx.hash().unwrap());
    let native_json = tx.to_json_bytes().unwrap();
    node.submit(tx, current_time()).await.unwrap();
    let time = current_time() + 10.;
    let head = node.tick(time, time as i64).await.unwrap().unwrap();
    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let frame = received.recv().await.unwrap();
            if frame.message == octra_node_protocol::legacy_epoch::FRAME_TYPE {
                break frame;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        frame.payload,
        octra_node_protocol::legacy_epoch::payload(
            1,
            hex::encode(head.cursor.state_root.0).as_bytes(),
            1,
            &address(4),
            &[native_json],
        )
        .unwrap()
    );
    let broadcast = octra_node_protocol::legacy_epoch::parse(&frame.payload).unwrap();
    assert_eq!(broadcast.epoch, 1);
    assert_eq!(
        broadcast.root,
        hex::encode(head.cursor.state_root.0).as_bytes()
    );
    assert_eq!(broadcast.declared_count, 1);
    assert_eq!(broadcast.transactions.len(), 1);
    assert_eq!(
        hex::encode(broadcast.transactions[0].hash().unwrap()),
        tx_hash
    );
    // A correctly authenticated peer's legacy announcement remains diagnostic.
    let before = node.head().await.unwrap();
    let forged = octra_node_protocol::legacy_epoch::payload(
        900,
        b"untrusted-peer-root",
        0,
        &address(5),
        &[],
    )
    .unwrap();
    peer.broadcast(
        Frame {
            message: octra_node_protocol::legacy_epoch::FRAME_TYPE,
            payload: forged,
        },
        None,
        false,
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(node.head().await.unwrap(), before);
    stop.send_replace(true);
    service.await.unwrap().unwrap();
    peer.stop();
    peer_task.await.unwrap().unwrap();
    node.shutdown().await.unwrap();
}

/// Controlled private-genesis initializer used only by the isolated paid Single
/// harness. It writes funded accounts/metadata; all applications are deployed
/// later through ordinary signed transactions. No program/circle is seeded.
#[test]
#[ignore = "invoked explicitly by network-none private Single paid qualification"]
fn initialize_private_single_paid_fixture() {
    use std::os::unix::fs::PermissionsExt;
    let path = std::path::PathBuf::from(
        std::env::var_os("OCTRA_SINGLE_FIXTURE_DIRECTORY")
            .expect("explicit fresh private fixture directory"),
    );
    assert!(!path.exists(), "private fixture destination must be fresh");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = seed_config(&path, true, false, true);
    let node = path.join("node-0");
    std::fs::create_dir(&node).unwrap();
    std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = node.join("validator.key");
    std::fs::rename(&config.key, &key).unwrap();
    config.key = key;
    config.data = node.join("data");
    config.rpc = "127.0.0.1:19871".parse().unwrap();
    let faucet = path.join("faucet.key");
    std::fs::write(&faucet, [1; 32]).unwrap();
    std::fs::set_permissions(faucet, std::fs::Permissions::from_mode(0o600)).unwrap();
    let base = node.join("single-base.json");
    std::fs::write(&base, serde_json::to_vec(&config).unwrap()).unwrap();
    std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o600)).unwrap();
    let adapter = serde_json::json!({"genesis":{"chain":config.chain,"activated_applications":true},"gateway":{"listen":"127.0.0.1:19875","origin":"https://circles.example.ts.net"}});
    std::fs::write(
        node.join("config.json"),
        serde_json::to_vec(&adapter).unwrap(),
    )
    .unwrap();
}
