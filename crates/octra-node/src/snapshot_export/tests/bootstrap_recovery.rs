//! Restoring a suffix must still authenticate the imported floor independently.
use super::*;
use octra_exex::{CommittedEpochSource, Sequence};
use octra_node_runtime::finality::Publisher;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

async fn checkpoint(
    path: &Path,
    source: &Node<TestAuthority>,
    config: &Config,
    key: &SigningKey,
) -> (bootstrap::Authority, Vec<u8>, Vec<u8>, Head) {
    let archive = archive::Archive::open(config).unwrap();
    let id = publish_at(source, config, &archive, key, 65).await;
    let raw = archive.current().unwrap().unwrap();
    let window = fs::read(archive.path(&id).unwrap().join("ready_roots")).unwrap();
    let authority = bootstrap::Authority::new(config.network.clone()).unwrap();
    let head = source.store.reader().head_for_epoch(65).await.unwrap();
    let state = source.store.reader().snapshot_at(&head).await.unwrap();
    let store = CanonicalStore::create_from_checkpoint(
        path,
        config.network.identity.clone(),
        state,
        &raw,
        &window,
        &authority.trust(),
        now().unwrap(),
    )
    .await
    .unwrap();
    let floor = store.head().await.unwrap();
    store.close().await;
    (authority, raw, window, floor)
}

async fn reopen(path: &Path, authority: &bootstrap::Authority) -> CanonicalStore {
    CanonicalStore::open_from_checkpoint(path, &authority.network().identity, &authority.trust())
        .await
        .unwrap()
}

#[tokio::test]
async fn checkpoint_reopen_authenticates_floor_and_suffix_without_synthetic_history() {
    let directory = tempfile::tempdir().unwrap();
    let (source, config, exporter) = Box::pin(fixture(directory.path(), 66)).await;
    let path = directory.path().join("imported.sqlite");
    let (authority, certificate, window, floor) =
        checkpoint(&path, &source, &config, &exporter).await;
    let store = reopen(&path, &authority).await;
    assert_eq!(store.anchor(), &floor);
    assert_eq!(store.head().await.unwrap(), floor);
    assert_eq!(
        store.checkpoint_certificate().await.unwrap(),
        Some(certificate)
    );
    assert_eq!(store.checkpoint_window(), Some(window.as_slice()));
    assert_eq!(
        store
            .snapshot()
            .await
            .unwrap()
            .1
            .get(&[b"meta", b"last_epoch"]),
        Some(b"65".as_slice())
    );
    assert!(store.source().load(Sequence(0)).await.unwrap().is_none());

    let store = Arc::new(store);
    let publisher = Publisher::open(store.clone(), TestAuthority { transition: None })
        .await
        .unwrap();
    let original = source.store.reader().head_for_epoch(66).await.unwrap();
    let record = source.publisher.record(Sequence(66)).await.unwrap();
    assert!(record.txs_json.is_empty());
    let suffix = publisher
        .prepare(
            &floor,
            &source.store.certificate(Sequence(66)).await.unwrap(),
            ExecutedEpoch {
                epoch_observation: None,
                metrics: octra_node_protocol::metrics::Epoch::default(),
                state: source.store.reader().snapshot_at(&original).await.unwrap(),
                transactions: vec![],
                vm_receipts: BTreeMap::new(),
                consensus_receipts: record.receipts_json,
                reward_source: record.reward_source.unwrap(),
                date: original.date,
                message: original.message,
            },
        )
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert_eq!(suffix.cursor.state_root, original.cursor.state_root);
    drop(publisher);
    Arc::try_unwrap(store).ok().unwrap().close().await;

    let store = reopen(&path, &authority).await;
    assert_eq!(store.anchor(), &floor);
    assert_eq!(store.head().await.unwrap(), suffix);
    assert_eq!(
        store
            .snapshot()
            .await
            .unwrap()
            .1
            .get(&[b"meta", b"last_epoch"]),
        Some(b"66".as_slice())
    );
    assert_eq!(
        store
            .reader()
            .snapshot_at(&floor)
            .await
            .unwrap()
            .get(&[b"meta", b"last_epoch"]),
        Some(b"65".as_slice())
    );
    assert_eq!(store.source().head().await.unwrap(), suffix.cursor);
    let event = store.source().load(Sequence(1)).await.unwrap().unwrap();
    assert_eq!(event.cursor, suffix.cursor);
    assert_eq!(event.parent_root, floor.cursor.state_root);
    assert!(event.events.is_empty());
    assert!(store.source().load(Sequence(0)).await.unwrap().is_none());
    store.close().await;

    // The old epoch contents are reachable only from the authenticated floor.
    // A valid latest tree must not let startup skip that floor's object checks.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    let old = octra_node_protocol::irmin::contents_hash(b"65");
    let reachable: bool = sqlx::query_scalar("WITH RECURSIVE reachable(hash) AS (SELECT ? UNION SELECT child FROM node_edges JOIN reachable ON parent=reachable.hash) SELECT EXISTS(SELECT 1 FROM reachable WHERE hash=?)")
        .bind(hex::decode(&suffix.ledger_root).unwrap())
        .bind(old.as_slice()).fetch_one(&pool).await.unwrap();
    assert!(!reachable, "corruption must be isolated to the floor");
    assert_eq!(
        sqlx::query("UPDATE node_objects SET data=? WHERE hash=?")
            .bind(b"corrupt floor".as_slice())
            .bind(old.as_slice())
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    refused(&path, &authority).await;
    sqlx::query("UPDATE node_objects SET data=? WHERE hash=?")
        .bind(b"65".as_slice())
        .bind(old.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    reopen(&path, &authority).await.close().await;

    // Keep the converse check as well: a verified floor cannot bless a damaged
    // latest tree after the anchor allocation is released.
    let latest = octra_node_protocol::irmin::contents_hash(b"66");
    assert_eq!(
        sqlx::query("UPDATE node_objects SET data=? WHERE hash=?")
            .bind(b"corrupt latest".as_slice())
            .bind(latest.as_slice())
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    refused(&path, &authority).await;
    pool.close().await;
    source.shutdown().await.unwrap();
}

async fn refused(path: &Path, authority: &bootstrap::Authority) {
    let error = CanonicalStore::open_from_checkpoint(
        path,
        &authority.network().identity,
        &authority.trust(),
    )
    .await
    .err()
    .expect("corrupt authenticated tree was admitted");
    assert!(
        error
            .to_string()
            .contains("state object commitment differs"),
        "{error}"
    );
}

/// Run in a child so hostile ambient settings cannot leak into parallel tests.
/// The child consumes the parent's genuine finalized epoch65 checkpoint.
#[tokio::test]
async fn captured_network_startup_uses_file_gc_and_worker_limits_once() {
    use octra_node_runtime::{
        canonical::EpochTagRetention,
        crypto_worker::{Limits, Pool},
    };
    const CHILD: &str = "OCTRA_STARTUP_CAPTURE_TEST_CONFIG";
    if let Some(path) = std::env::var_os(CHILD) {
        let config = crate::network::read(Path::new(&path)).unwrap();
        let raw = fs::read(&config.environment).unwrap();
        let values = crate::network_profile::parse_env(&raw).unwrap();
        let settings =
            octra_node_protocol::consensus::profile::Settings::from_values(values).unwrap();
        let retention =
            EpochTagRetention::from_value(settings.get("OCTRA_GC_KEEP_EPOCHS")).unwrap();
        let configured = settings.get("OCTRA_GC_KEEP_EPOCHS").is_some();
        let expected_keep = if configured { 4096 } else { 8192 };
        let authority = bootstrap::Authority::new(config.network.clone()).unwrap();
        // Both configured opening and authenticated checkpoint creation must
        // ignore this child's deliberately invalid ambient GC value.
        assert_eq!(std::env::var("OCTRA_GC_KEEP_EPOCHS").unwrap(), "invalid");
        let (store, migration) = authority
            .reopen_with_migration_with_retention(&config.data, retention)
            .await
            .unwrap();
        assert!(migration.is_none());
        assert_eq!(
            store.reader().epoch_tag_stats().await.unwrap().keep_epochs,
            expected_keep
        );
        let head = store.head().await.unwrap();
        let state = store.snapshot().await.unwrap().1.snapshot();
        let certificate = store.checkpoint_certificate().await.unwrap().unwrap();
        let window = store.checkpoint_window().unwrap().to_vec();
        store.close().await;
        let copy = config.data.join(if configured {
            "configured.sqlite"
        } else {
            "defaults.sqlite"
        });
        let store = CanonicalStore::create_from_checkpoint_with_retention(
            &copy,
            config.network.identity.clone(),
            state,
            &certificate,
            &window,
            &authority.trust(),
            now().unwrap(),
            retention,
        )
        .await
        .unwrap();
        assert_eq!(store.head().await.unwrap(), head);
        assert_eq!(
            store.reader().epoch_tag_stats().await.unwrap().keep_epochs,
            expected_keep
        );
        store.close().await;
        let (stop, shutdown) = tokio::sync::watch::channel(true);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let environment = config.environment.clone();
        crate::network::run_with_runtime_factory(
            config,
            |captured| {
                calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let limits = Limits::from_values(|name| captured.get(name).map(<[u8]>::to_vec));
                let pool = Pool::open(&std::env::current_exe().unwrap(), limits).unwrap();
                let actual = pool.worker().limits();
                assert_eq!(actual.capacity, if configured { 2 } else { 1 });
                assert_eq!(
                    actual.timeout_seconds.to_bits(),
                    (if configured { 1_f64 } else { 600_f64 }).to_bits()
                );
                assert_eq!(actual.rss_mb, if configured { 64 } else { 9216 });
                // A second file read after the runtime factory would now fail.
                // No worker or service process is started by this already-stopped launch.
                fs::write(&environment, b"not an environment assignment").unwrap();
                Ok(CircleRuntime::isolated(pool))
            },
            shutdown,
        )
        .await
        .unwrap();
        drop(stop);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let source_dir = directory.path().join("source");
    fs::create_dir(&source_dir).unwrap();
    let (source, config, exporter) = Box::pin(fixture(&source_dir, 66)).await;
    let data = directory.path().join("imported");
    fs::create_dir(&data).unwrap();
    let (_, _, _, floor) =
        checkpoint(&data.join("canonical.sqlite"), &source, &config, &exporter).await;
    assert_eq!(floor.cursor.epoch.0, 65);
    for configured in [true, false] {
        let environment = directory.path().join(if configured {
            "configured.env"
        } else {
            "absent.env"
        });
        let mut values = format!(
            "OCTRA_CHAIN_ID={}\nOCTRA_CONSENSUS_CONFIG_HASH={}\nOCTRA_VALIDATORS={}\nOCTRA_STATE_SYNC_EXPORTERS={}\n",
            config.network.identity.chain_id, config.network.config_hash,
            config.network.validators.join(","), config.network.exporters.join(","),
        );
        if configured {
            values.push_str("OCTRA_GC_KEEP_EPOCHS=4096\nOCTRA_PVAC_VERIFY_WORKERS=2\nOCTRA_PVAC_VERIFY_TIMEOUT_SEC=1\nOCTRA_PVAC_VERIFY_MAX_RSS_MB=64\n");
        }
        fs::write(&environment, values).unwrap();
        let socket = "127.0.0.1:0".parse().unwrap();
        let network = crate::network::Config {
            network: config.network.clone(),
            environment,
            data: data.clone(),
            key: directory.path().join("unused-node.key"),
            p2p: socket,
            p2p_proxy: None,
            advertised: "127.0.0.1:19000".into(),
            rpc: socket,
            browser: socket,
            control: socket,
            tunnel: socket,
            gateway: None,
            stock_portal: None,
            stock_circle_gateway: None,
            mesh: None,
            compute_provider: false,
            vpn: None,
            payments: None,
            peers: vec![],
            voting: false,
            publisher: false,
            snapshot_limits: crate::snapshot_export::LimitsConfig::default(),
            startup_seconds: 1,
        };
        let path = directory.path().join(if configured {
            "configured.json"
        } else {
            "absent.json"
        });
        fs::write(&path, serde_json::to_vec(&network).unwrap()).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "snapshot_export::tests::bootstrap_recovery::captured_network_startup_uses_file_gc_and_worker_limits_once", "--nocapture"])
            .env(CHILD, &path).env("OCTRA_GC_KEEP_EPOCHS", "invalid")
            .env("OCTRA_PVAC_VERIFY_WORKERS", if configured { "1" } else { "2" })
            .env("OCTRA_PVAC_VERIFY_TIMEOUT_SEC", "1200")
            .env("OCTRA_PVAC_VERIFY_MAX_RSS_MB", "16384")
            .output().unwrap();
        assert!(
            output.status.success(),
            "child failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    }
}
