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
