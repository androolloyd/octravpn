use super::*;
use ed25519_dalek::Signer as _;
use octra_node_protocol::registration_rpc::{PublicKey, Removal};
use octra_node_runtime::canonical::single::{Authority, Store};
#[cfg(all(feature = "test-helpers", target_os = "linux"))]
use octra_node_runtime::ledger_image;
#[cfg(all(feature = "test-helpers", target_os = "linux"))]
use sha2::{Digest as _, Sha256};
use std::{path::Path, time::Duration};
fn register_request(id: u8) -> PublicKey {
    let address = address(id);
    let key = public(id);
    let signature = STANDARD.encode(
        SigningKey::from_bytes(&[id; 32])
            .sign(&[b"register_pubkey:".as_slice(), &address].concat())
            .to_bytes(),
    );
    let doc = Document::parse(
        &serde_json::to_vec(&serde_json::json!([
            String::from_utf8(address).unwrap(),
            String::from_utf8(key).unwrap(),
            signature
        ]))
        .unwrap(),
    )
    .unwrap();
    PublicKey::parse(&doc, doc.root()).unwrap()
}
fn removal(tx: &Transaction, id: u8) -> Removal {
    let hash = hex::encode(tx.hash().unwrap());
    let signature = STANDARD.encode(
        SigningKey::from_bytes(&[id; 32])
            .sign(format!("staging_remove|{hash}").as_bytes())
            .to_bytes(),
    );
    let doc = Document::parse(
        &serde_json::to_vec(&serde_json::json!([
            hash,
            signature,
            String::from_utf8(public(id)).unwrap()
        ]))
        .unwrap(),
    )
    .unwrap();
    Removal::parse(&doc, doc.root()).unwrap()
}
async fn unregistered_node(path: &Path, genesis: Option<Snapshot>) -> Arc<single::Node> {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("../fixtures/single-native.json")).unwrap();
    let original = initial(&fixture["cases"][0]);
    let original_head = parent(&fixture["cases"][0], &original.snapshot());
    let state = genesis.unwrap_or_else(|| {
        let mut state = StateBatch::from_snapshot(original.snapshot());
        state.begin().unwrap();
        let mut account = account_store::load(&state, &address(1)).unwrap().unwrap();
        account.public_key = None;
        account_store::set(&mut state, &address(1), &account, RuleMode::Prior).unwrap();
        state.acknowledge_commit().unwrap();
        state.snapshot()
    });
    let chain = octra_exex::ChainIdentity::genesis(
        "octra-single-local-native-oracle",
        StateRoot(
            epoch_index::folded_state_root(
                hex::encode(state.root().unwrap()).as_bytes(),
                original_head.index_root.as_bytes(),
            )
            .unwrap(),
        ),
    );
    let cfg = config(path);
    let settings = settings();
    let policy = Native::single_policy_for(&cfg, &settings).unwrap();
    let authority = Authority::new(chain, SigningKey::from_bytes(&[4; 32]), policy).unwrap();
    let db = path.join("canonical.db");
    let store = Arc::new(if db.exists() {
        Store::open(&db, authority).await.unwrap()
    } else {
        Store::create(&db,authority,state,original_head.date,serde_json::to_vec(&serde_json::json!({"entries":[],"preview":octra_node_runtime::staging::Pool::default().preview_state(),"deferred":{"counts":{}},"kats":[]})).unwrap()).await.unwrap()
    });
    let native = Native::new(
        cfg,
        isolated_runtime(),
        Arc::new(single::History(store.clone())),
    )
    .unwrap();
    let checkpoints = Arc::new(
        octra_exex::sqlite::SqliteCheckpoints::open(&path.join("checkpoints.db"))
            .await
            .unwrap(),
    );
    single::Node::open(store, native, settings, checkpoints, 0.)
        .await
        .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_overlay_normalized_queue_restart_and_authenticated_removal() {
    let tmp = tempfile::tempdir().unwrap();
    let node = unregistered_node(tmp.path(), None).await;
    let base = node.head().await.unwrap();
    let (_, state) = node.store().snapshot().await.unwrap();
    let genesis = state.snapshot();
    let account = account_store::load(&state, &address(1)).unwrap();
    assert_eq!(account.as_ref().unwrap().public_key, None);
    node.register_public_key(register_request(1)).await.unwrap();
    node.register_public_key(register_request(3)).await.unwrap();
    assert_eq!(node.registered_key(&address(1)).unwrap(), Some(public(1)));
    assert_eq!(node.registered_key(&address(3)).unwrap(), None);
    assert_eq!(
        node.account_for_read(&address(1), account)
            .unwrap()
            .unwrap()
            .public_key,
        Some(public(1))
    );
    assert_eq!(node.head().await.unwrap(), base);
    assert_eq!(
        account_store::load(&node.store().snapshot().await.unwrap().1, &address(1))
            .unwrap()
            .unwrap()
            .public_key,
        None
    );
    let mut tx = signed_transfer();
    tx.public_key = None;
    tx.signature = STANDARD
        .encode(
            SigningKey::from_bytes(&[1; 32])
                .sign(&tx.signing_bytes().unwrap())
                .to_bytes(),
        )
        .into_bytes();
    node.submit(tx.clone(), tx.timestamp).await.unwrap();
    let queued = node.queued().unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].public_key, Some(public(1)));
    let signed = queued[0].clone();
    assert_eq!(node.inspect_pool(|pool| pool.all().count()).unwrap(), 1);
    assert!(node.remove(removal(&signed, 2)).await.is_err());
    assert_eq!(node.queued().unwrap().len(), 1);
    node.shutdown().await.unwrap();
    drop(node);
    let restored = unregistered_node(tmp.path(), Some(genesis.clone())).await;
    assert_eq!(restored.registered_key(&address(1)).unwrap(), None);
    assert_eq!(restored.queued().unwrap()[0].public_key, Some(public(1)));
    restored.remove(removal(&signed, 1)).await.unwrap();
    assert!(restored.queued().unwrap().is_empty());
    assert_eq!(
        restored.remove(removal(&signed, 1)).await.unwrap_err().code,
        112
    );
    restored.shutdown().await.unwrap();
    drop(restored);
    let resumed = unregistered_node(tmp.path(), Some(genesis)).await;
    assert!(resumed.queued().unwrap().is_empty());
    resumed
        .register_public_key(register_request(1))
        .await
        .unwrap();
    let before = resumed.head().await.unwrap();
    let after = resumed.tick(10., 10).await.unwrap().unwrap();
    assert_eq!(resumed.registered_key(&address(1)).unwrap(), None);
    assert_eq!(
        account_store::load(&resumed.store().snapshot().await.unwrap().1, &address(1))
            .unwrap()
            .unwrap()
            .public_key,
        Some(public(1))
    );
    assert_eq!(
        resumed
            .store()
            .record(after.cursor.sequence)
            .await
            .unwrap()
            .tree_state_root,
        before.ledger_root.as_bytes()
    );
    assert_eq!(
        resumed
            .store()
            .assets()
            .await
            .unwrap()
            .identity()
            .state_root,
        hex::encode(after.cursor.state_root.0)
    );
    resumed.shutdown().await.unwrap();
}
struct Hook {
    events: std::sync::Mutex<Vec<String>>,
    node: std::sync::Mutex<std::sync::Weak<single::Node>>,
}
impl single::PublicationHook for Hook {
    fn revoke(&self) {
        self.events.lock().unwrap().push("revoke".into());
    }
    fn committed(&self, head: &Head) {
        let node = self.node.lock().unwrap().upgrade().unwrap();
        let n = node.inspect_pool(|p| p.all().count()).unwrap();
        assert_eq!(n, 0);
        self.events
            .lock()
            .unwrap()
            .push(format!("commit:{}", head.cursor.sequence.0));
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_wallet_owned_through_cancellation_and_publication_callbacks() {
    let tmp = tempfile::tempdir().unwrap();
    let node = open_node(tmp.path(), 0.).await;
    let initial_metrics: Value = serde_json::from_slice(&node.native_metrics().unwrap()).unwrap();
    assert_eq!(initial_metrics["total_transactions"], 0);
    assert_eq!(
        node.legacy_status().unwrap(),
        octra_node::LegacyStatus { epoch: 1, roots: 0 }
    );
    let hook = Arc::new(Hook {
        events: std::sync::Mutex::default(),
        node: std::sync::Mutex::new(Arc::downgrade(&node)),
    });
    node.set_publication_hook(hook.clone()).await.unwrap();
    let wallet = Arc::new(tokio::sync::Mutex::new(()));
    let lease = Arc::new(wallet.clone().lock_owned().await);
    let (mut blocker, release) = sqlite_blocker(tmp.path(), "operator-wallet").await;
    let task = {
        let node = node.clone();
        let lease = lease.clone();
        tokio::spawn(async move {
            let tx = signed_transfer();
            node.submit_operator(tx.clone(), tx.timestamp, lease).await
        })
    };
    drop(lease);
    wait_queue_publication(&node).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(wallet.try_lock().is_err());
    std::fs::write(release, b"release").unwrap();
    assert!(blocker.wait().await.unwrap().success());
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if wallet.try_lock().is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(node.queued().unwrap().len(), 1);
    node.tick(10., 10).await.unwrap().unwrap();
    assert_eq!(*hook.events.lock().unwrap(), vec!["revoke", "commit:1"]);
    let metric: Value = serde_json::from_slice(&node.native_metrics().unwrap()).unwrap();
    assert_eq!(metric["total_transactions"], 1);
    assert_eq!(metric["last_epoch_txs"], 1);
    assert!(metric["last_epoch_duration"].as_f64().unwrap() > 0.);
    assert!(metric["peak_tps"].as_f64().unwrap() > 0.);
    assert_eq!(
        node.legacy_status().unwrap(),
        octra_node::LegacyStatus { epoch: 2, roots: 0 }
    );
    let mut forged = node.head().await.unwrap();
    forged.cursor.state_root.0[0] ^= 1;
    assert!(node.legacy_status_at(&forged).is_err());
    node.shutdown().await.unwrap();
    assert_eq!(
        *hook.events.lock().unwrap(),
        vec!["revoke", "commit:1", "revoke"]
    );
}
#[cfg(all(feature = "test-helpers", target_os = "linux"))]
fn cli_config(tmp: &Path, case: &Value) -> (single::launch::Config, Transaction) {
    use single::launch::{Config, Execution, Seed};
    use std::os::unix::fs::PermissionsExt as _;
    let state = initial(case);
    let head = parent(case, &state.snapshot());
    let mut image = Vec::new();
    let written = ledger_image::write(
        &state.snapshot(),
        &mut image,
        ledger_image::Limits::default(),
    )
    .unwrap();
    let image_path = tmp.join("seed.image");
    std::fs::write(&image_path, &image).unwrap();
    let key = tmp.join("key");
    std::fs::write(&key, [4; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let rpc = socket.local_addr().unwrap();
    drop(socket);
    let mut settings = settings();
    settings.maximum_defer = 100;
    let config = Config {
        services: None,
        chain: octra_exex::ChainIdentity::genesis(
            "octra-single-local-native-oracle",
            head.cursor.state_root,
        ),
        data: tmp.join("data"),
        key,
        seed: Seed {
            path: image_path,
            bytes: written.bytes,
            sha256: hex::encode(Sha256::digest(&image)),
            ledger_root: written.root,
            maximum_records: written.records,
            maximum_string_bytes: 16 * 1024 * 1024,
            date: head.date,
        },
        settings,
        execution: Execution {
            activated_applications: false,
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
        rpc,
        maximum_http_body: 16 * 1024 * 1024,
    };
    let data = &case["input"]["private"];
    let public = STANDARD.decode(data["public"].as_str().unwrap()).unwrap();
    octra_node_runtime::pvac::Files(config.data.join("pvac"))
        .persist(&public)
        .unwrap();
    let mut tx = Transaction::from_document(
        &Document::parse(
            &STANDARD
                .decode(case["transactions"][0].as_str().unwrap())
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    tx.timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    tx.signature = STANDARD
        .encode(
            SigningKey::from_bytes(&[1; 32])
                .sign(&tx.signing_bytes().unwrap())
                .to_bytes(),
        )
        .into_bytes();
    (config, tx)
}
#[cfg(all(feature = "test-helpers", target_os = "linux"))]
fn start_worker_cli(
    config: &Path,
    log: &Path,
    fault: Option<&str>,
    timeout: &str,
    rss: &str,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_octra-node"));
    command
        .args(["run-single", "--config"])
        .arg(config)
        .env("OCTRA_PVAC_VERIFY_TIMEOUT_SEC", timeout)
        .env("OCTRA_PVAC_VERIFY_MAX_RSS_MB", rss)
        .env("OCTRA_PVAC_VERIFY_WORKERS", "1");
    if let Some(fault) = fault {
        command.env("OCTRA_TEST_SINGLE_RANGE_FAULT", fault);
    } else {
        command.env_remove("OCTRA_TEST_SINGLE_RANGE_FAULT");
    }
    command
        .stderr(std::fs::File::create(log).unwrap())
        .stdout(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}
#[cfg(all(feature = "test-helpers", target_os = "linux"))]
async fn proof_status(client: &reqwest::Client, url: &str, tx: &Transaction) -> Value {
    let response = single_rpc(
        client,
        url,
        "single_proof_status",
        serde_json::json!([hex::encode(tx.hash().unwrap())]),
    )
    .await
    .unwrap();
    assert!(response.get("error").is_none(), "{response}");
    response["result"].clone()
}
#[cfg(all(feature = "test-helpers", target_os = "linux"))]
async fn wait_proof(
    client: &reqwest::Client,
    url: &str,
    tx: &Transaction,
    expected: &str,
) -> Value {
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let value = proof_status(client, url, tx).await;
            if value["status"].as_str().unwrap().contains(expected) && value["pending"] == 0 {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap()
}
#[cfg(all(feature = "test-helpers", target_os = "linux"))]
fn helper_children(pid: u32) -> Vec<u32> {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|row| {
            let id = row.file_name().to_str()?.parse::<u32>().ok()?;
            let status = std::fs::read_to_string(row.path().join("status")).ok()?;
            let parent = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:"))?
                .trim()
                .parse::<u32>()
                .ok()?;
            let cmd = std::fs::read(row.path().join("cmdline")).ok()?;
            (parent == pid
                && cmd
                    .windows(b"single-range-worker".len())
                    .any(|v| v == b"single-range-worker"))
            .then_some(id)
        })
        .collect()
}
#[cfg(all(feature = "test-helpers", target_os = "linux"))]
async fn wait_helper(pid: u32) -> u32 {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(id) = helper_children(pid).first() {
                return *id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}
#[cfg(all(feature = "test-helpers", target_os = "linux"))]
async fn worker_store(config: &single::launch::Config) -> Store {
    let native = super::config(&config.data);
    let policy = Native::single_policy_for(&native, &config.settings).unwrap();
    Store::open(
        &config.data.join("canonical.db"),
        Authority::new(
            config.chain.clone(),
            SigningKey::from_bytes(&[4; 32]),
            policy,
        )
        .unwrap(),
    )
    .await
    .unwrap()
}
#[cfg(all(feature = "test-helpers", target_os = "linux"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_cli_async_range_timeout_death_rss_drop_restart_and_success() {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("../fixtures/single-native.json")).unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["input"]["name"] == "genuine-stealth")
        .unwrap();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    for (fault, timeout, rss, reason) in [
        ("delay", "1", "9216", "timed out"),
        ("death", "600", "9216", "exited"),
        ("rss", "600", "64", "memory limit exceeded"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let (config, tx) = cli_config(tmp.path(), case);
        let path = tmp.path().join("config.json");
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let url = format!("http://{}/rpc", config.rpc);
        let mut child = start_worker_cli(
            &path,
            &tmp.path().join("node.log"),
            Some(fault),
            timeout,
            rss,
        );
        wait_single_head(&mut child, &client, &url, 0, &tmp.path().join("node.log")).await;
        let began = std::time::Instant::now();
        let response = single_rpc(
            &client,
            &url,
            "octra_submit",
            serde_json::json!([
                serde_json::from_slice::<Value>(&tx.to_json_bytes().unwrap()).unwrap()
            ]),
        )
        .await
        .unwrap();
        assert_eq!(
            response["result"]["tx_hash"],
            hex::encode(tx.hash().unwrap()),
            "{response}"
        );
        assert!(began.elapsed() < Duration::from_secs(2));
        let status = wait_proof(&client, &url, &tx, reason).await;
        assert!(status["status"].as_str().unwrap().contains("Unavailable"));
        assert!(helper_children(child.id().unwrap()).is_empty());
        stop_single_fixture(&mut child).await;
        let store = worker_store(&config).await;
        let (head, state) = store.snapshot().await.unwrap();
        let expected = account_store::load(&initial(case), &tx.from).unwrap();
        assert_eq!(account_store::load(&state, &tx.from).unwrap(), expected);
        // Native timer epochs may legitimately advance while a proof is
        // unavailable. None may confirm this transaction or debit its sender.
        assert!(store
            .reader()
            .transaction(
                &head,
                hex::encode(tx.hash().unwrap()).as_bytes(),
                16 * 1024 * 1024,
            )
            .await
            .unwrap()
            .is_none());
    }
    let tmp = tempfile::tempdir().unwrap();
    let (config, tx) = cli_config(tmp.path(), case);
    let path = tmp.path().join("config.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let url = format!("http://{}/rpc", config.rpc);
    let mut child = start_worker_cli(
        &path,
        &tmp.path().join("first.log"),
        Some("delay"),
        "600",
        "9216",
    );
    wait_single_head(&mut child, &client, &url, 0, &tmp.path().join("first.log")).await;
    let submit = single_rpc(
        &client,
        &url,
        "octra_submit",
        serde_json::json!([serde_json::from_slice::<Value>(&tx.to_json_bytes().unwrap()).unwrap()]),
    )
    .await
    .unwrap();
    assert_eq!(
        submit["result"]["tx_hash"],
        hex::encode(tx.hash().unwrap()),
        "{submit}"
    );
    let pid = wait_helper(child.id().unwrap()).await;
    let hash = hex::encode(tx.hash().unwrap());
    let signature = STANDARD.encode(
        SigningKey::from_bytes(&[1; 32])
            .sign(format!("staging_remove|{hash}").as_bytes())
            .to_bytes(),
    );
    let removed = single_rpc(
        &client,
        &url,
        "staging_remove",
        serde_json::json!([hash, signature, String::from_utf8(public(1)).unwrap()]),
    )
    .await
    .unwrap();
    assert_eq!(removed["result"]["removed"], true, "{removed}");
    tokio::time::timeout(Duration::from_secs(5), async {
        while Path::new(&format!("/proc/{pid}")).exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        wait_proof(&client, &url, &tx, "None").await["status"],
        "None"
    );
    let accepted = single_rpc(
        &client,
        &url,
        "octra_submit",
        serde_json::json!([serde_json::from_slice::<Value>(&tx.to_json_bytes().unwrap()).unwrap()]),
    )
    .await
    .unwrap();
    assert_eq!(
        accepted["result"]["tx_hash"],
        hex::encode(tx.hash().unwrap())
    );
    let old = wait_helper(child.id().unwrap()).await;
    child.start_kill().unwrap();
    assert!(!child.wait().await.unwrap().success());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let path = format!("/proc/{old}/status");
            let state = std::fs::read_to_string(path).unwrap_or_default();
            if state.is_empty()
                || state
                    .lines()
                    .any(|l| l.starts_with("State:") && l.contains('Z'))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let durable = worker_store(&config).await;
    let recovered_epoch = durable.head().await.unwrap().cursor.epoch.0;
    drop(durable);
    let mut resumed = start_worker_cli(
        &path,
        &tmp.path().join("resumed.log"),
        Some("death-once"),
        "600",
        "9216",
    );
    wait_single_head(
        &mut resumed,
        &client,
        &url,
        recovered_epoch,
        &tmp.path().join("resumed.log"),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let response = single_rpc(
                &client,
                &url,
                "octra_balance",
                serde_json::json!([String::from_utf8(tx.from.clone()).unwrap()]),
            )
            .await
            .unwrap();
            assert!(response.get("error").is_none(), "{response}");
            if response["result"]["nonce"] == tx.nonce.get() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(helper_children(resumed.id().unwrap()).is_empty());
    stop_single_fixture(&mut resumed).await;
    let store = worker_store(&config).await;
    let (head, state) = store.snapshot().await.unwrap();
    let (_, confirmed) = store
        .reader()
        .transaction(
            &head,
            hex::encode(tx.hash().unwrap()).as_bytes(),
            16 * 1024 * 1024,
        )
        .await
        .unwrap()
        .expect("actual helper-verified transaction committed");
    assert_eq!(confirmed.transaction, tx.identity_bytes().unwrap());
    let expected = case["result"]["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| STANDARD.decode(row[0].as_str().unwrap()).unwrap() == tx.from)
        .unwrap();
    assert_eq!(
        account_store::load(&state, &tx.from)
            .unwrap()
            .unwrap()
            .to_json_bytes(),
        STANDARD.decode(expected[1].as_str().unwrap()).unwrap(),
    );
}

#[tokio::test]
async fn signed_rejection_history_survives_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let node = open_node(tmp.path(), 0.).await;
    let fixture: Value =
        serde_json::from_slice(include_bytes!("../fixtures/single-native.json")).unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["input"]["name"] == "nonce-gap")
        .unwrap();
    let tx = Transaction::from_document(
        &Document::parse(
            &STANDARD
                .decode(case["transactions"][0].as_str().unwrap())
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    node.submit(tx.clone(), 10.).await.unwrap();
    let head = node.tick(10., 10).await.unwrap().unwrap();
    let hash = hex::encode(tx.hash().unwrap());
    async fn check(node: &single::Node, head: &Head, tx: &Transaction, hash: &str) {
        let signed = node.store().record(head.cursor.sequence).await.unwrap();
        let page = node
            .store()
            .reader()
            .rejections(
                head,
                &octra_node_runtime::canonical::HistoryQuery {
                    hash: Some(hash.as_bytes().to_vec()),
                    ..Default::default()
                },
                10,
                0,
                1_000_000,
            )
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.rows.len(), 1);
        let located = &page.rows[0];
        assert_eq!(&located.head, head);
        assert_eq!(located.rejection.tx.hash().unwrap(), tx.hash().unwrap());
        let encoded =
            octra_node_protocol::transaction_outcome::encode_rejection(&located.rejection).unwrap();
        assert!(signed.outcomes.contains(&encoded));
        assert!(located.observed_at.is_some());
    }
    check(&node, &head, &tx, &hash).await;
    node.shutdown().await.unwrap();
    drop(node);
    let resumed = open_node(tmp.path(), 10.).await;
    assert_eq!(resumed.head().await.unwrap(), head);
    check(&resumed, &head, &tx, &hash).await;
    resumed.shutdown().await.unwrap();
}

#[tokio::test]
async fn actual_prepare_failure_keeps_head_tree_queue_metrics_and_serving() {
    let tmp = tempfile::tempdir().unwrap();
    let node = open_node(tmp.path(), 0.).await;
    let tx = signed_transfer();
    node.submit(tx, 10.).await.unwrap();
    let head = node.head().await.unwrap();
    let tree = node.legacy_status().unwrap();
    let metrics = node.native_metrics().unwrap();
    let queued = node.queued().unwrap();
    let hook = Arc::new(Hook {
        events: std::sync::Mutex::default(),
        node: std::sync::Mutex::new(Arc::downgrade(&node)),
    });
    node.set_publication_hook(hook.clone()).await.unwrap();
    async fn sql(path: &Path, statement: &str) {
        let result = tokio::process::Command::new("python3")
            .arg("-c")
            .arg("import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.executescript(sys.argv[2]); c.close()")
            .arg(path.join("canonical.db"))
            .arg(statement)
            .status()
            .await
            .unwrap();
        assert!(result.success());
    }
    sql(tmp.path(), "CREATE TRIGGER controlled_prepare_failure BEFORE INSERT ON node_epochs WHEN NEW.sequence>0 BEGIN SELECT RAISE(FAIL,'controlled Single prepare failure'); END;").await;
    let refused = node.tick(10., 10).await.unwrap_err();
    assert!(format!("{refused:#}").contains("controlled Single prepare failure"));
    assert_eq!(node.head().await.unwrap(), head);
    assert_eq!(node.legacy_status().unwrap(), tree);
    assert_eq!(node.native_metrics().unwrap(), metrics);
    let actual = node.queued().unwrap();
    assert_eq!(actual.len(), queued.len());
    assert_eq!(
        actual[0].identity_bytes().unwrap(),
        queued[0].identity_bytes().unwrap()
    );
    assert!(hook.events.lock().unwrap().is_empty());
    assert_eq!(node.store().snapshot().await.unwrap().0, head);
    sql(tmp.path(), "DROP TRIGGER controlled_prepare_failure;").await;
    let committed = node.tick(10., 10).await.unwrap().unwrap();
    assert_eq!(committed.cursor.epoch, EpochId(1));
    assert_eq!(
        node.legacy_status().unwrap(),
        octra_node::LegacyStatus { epoch: 2, roots: 0 }
    );
    assert_eq!(*hook.events.lock().unwrap(), vec!["revoke", "commit:1"]);
    node.shutdown().await.unwrap();
}
