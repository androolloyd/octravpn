//! Storage/recovery qualification, not network finality qualification. Inputs
//! represent already executed epochs; the consensus-driver tests own signatures.
use octra_exex::{
    native_history::NativeTransaction, sqlite::SqliteCheckpoints, ChainIdentity, CommittedEpoch,
    CommittedEpochSource, ExEx, ExExManager, Sequence, StateRoot,
};
use octra_node_protocol::epoch_index;
use octra_node_runtime::{
    canonical::{AppliedEpoch, CanonicalStore, Head},
    state_batch::StateBatch,
};
use serde_json::Value;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

fn genesis() -> (ChainIdentity, StateBatch) {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    state.set(&[b"meta", b"last_epoch"], b"0".to_vec()).unwrap();
    state
        .set(&[b"accounts", b"\xff\0", b"data"], b"genesis".to_vec())
        .unwrap();
    state.acknowledge_commit().unwrap();
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
    (
        ChainIdentity {
            chain_id: "canonical-recovery-fixture".into(),
            genesis_root: StateRoot(root),
        },
        state,
    )
}

fn transactions() -> Vec<NativeTransaction> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../octra-exex/tests/fixtures/native-history.json"
    ))
    .unwrap();
    let mut transactions: Vec<NativeTransaction> =
        serde_json::from_value(fixture["cases"]["full"]["epochs"][0]["transactions"].clone())
            .unwrap();
    // Reuse native archive bytes in this empty-genesis storage fixture.
    for (txid, transaction) in transactions.iter_mut().enumerate() {
        transaction.txid = txid as i64;
    }
    transactions
}

fn applied(
    base: &Head,
    mut state: StateBatch,
    transactions: Vec<NativeTransaction>,
) -> AppliedEpoch {
    state.begin().unwrap();
    let epoch = base.cursor.epoch.0 + 1;
    state
        .set(&[b"meta", b"last_epoch"], epoch.to_string().into_bytes())
        .unwrap();
    state
        .set(&[b"circle", b"app", b"value"], epoch.to_be_bytes().to_vec())
        .unwrap();
    let items = transactions
        .iter()
        .map(|t| epoch_index::Item {
            txid: t.txid,
            hash: t.hash.as_bytes().to_vec(),
        })
        .collect::<Vec<_>>();
    let (_, index) =
        epoch_index::next_root(base.index_root.as_bytes(), epoch as i64, &items).unwrap();
    let root = epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap();
    AppliedEpoch {
        epoch,
        state: state.snapshot(),
        expected_root: StateRoot(root),
        transactions,
        certificate: b"storage-fixture-only".to_vec(),
        date: 123,
        message: b"epoch\0\xff".to_vec(),
    }
}

async fn fixture(path: &Path) -> CanonicalStore {
    let (chain, state) = genesis();
    CanonicalStore::create(path, chain, state.snapshot(), 0)
        .await
        .unwrap()
}

#[tokio::test]
async fn state_and_outbox_publish_together_or_rollback_and_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.db");
    let store = fixture(&path).await;
    let (base, state) = store.snapshot().await.unwrap();
    let request = applied(&base, state, transactions());
    let pending = store.prepare(&base, request.clone()).await.unwrap();
    assert_eq!(store.head().await.unwrap(), base);
    assert_eq!(store.source().head().await.unwrap(), base.cursor);
    assert!(store.source().load(Sequence(1)).await.unwrap().is_none());
    drop(pending);
    let head = store
        .prepare(&base, request.clone())
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert_eq!(store.source().head().await.unwrap(), head.cursor);
    assert!(store.prepare(&base, request).await.is_err());
    let chain = store.chain().clone();
    store.close().await;
    let reopened = CanonicalStore::open(&path, &chain).await.unwrap();
    let (loaded, state) = reopened.snapshot().await.unwrap();
    assert_eq!(loaded, head);
    assert_eq!(
        state.get(&[b"circle", b"app", b"value"]),
        Some(1u64.to_be_bytes().as_slice())
    );
    assert_eq!(
        state.get(&[b"accounts", b"\xff\0", b"data"]),
        Some(b"genesis".as_slice())
    );
    assert_eq!(
        reopened.certificate(Sequence(1)).await.unwrap(),
        b"storage-fixture-only"
    );
    assert_eq!(
        reopened
            .source()
            .load(Sequence(1))
            .await
            .unwrap()
            .unwrap()
            .events,
        transactions()
    );
    let mut wrong = chain;
    wrong.genesis_root.0[0] ^= 1;
    assert!(CanonicalStore::open(&path, &wrong).await.is_err());
}

async fn raw_pool(path: &Path) -> sqlx::SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(path))
        .await
        .unwrap()
}

#[tokio::test]
async fn refuses_wrong_roots_archive_mutation_and_partial_database_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.db");
    let store = fixture(&path).await;
    let (base, state) = store.snapshot().await.unwrap();
    let valid = applied(&base, state, transactions());
    let mut bad = valid.clone();
    bad.expected_root.0[0] ^= 1;
    assert!(store.prepare(&base, bad).await.is_err());
    let mut bad = valid.clone();
    bad.transactions[0].transaction.push(b' ');
    assert!(store.prepare(&base, bad).await.is_err());
    let mut bad = valid.clone();
    bad.transactions[0].txid += 1;
    assert!(store.prepare(&base, bad).await.is_err());
    let db = raw_pool(&path).await;
    sqlx::query("CREATE TRIGGER refuse_outbox BEFORE INSERT ON exex_committed_epoch BEGIN SELECT RAISE(ABORT,'injected write failure'); END").execute(&db).await.unwrap();
    assert!(store.prepare(&base, valid.clone()).await.is_err());
    assert_eq!(store.head().await.unwrap(), base);
    assert_eq!(store.source().head().await.unwrap(), base.cursor);
    sqlx::query("DROP TRIGGER refuse_outbox")
        .execute(&db)
        .await
        .unwrap();
    store
        .prepare(&base, valid)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    sqlx::query("DELETE FROM exex_committed_epoch")
        .execute(&db)
        .await
        .unwrap();
    db.close().await;
    let chain = store.chain().clone();
    store.close().await;
    assert!(CanonicalStore::open(&path, &chain)
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("outbox gap"));
}

#[tokio::test]
async fn concurrent_hosts_cannot_publish_against_the_same_parent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.db");
    let first = fixture(&path).await;
    let second = CanonicalStore::open(&path, first.chain()).await.unwrap();
    let (base, state) = first.snapshot().await.unwrap();
    let request = applied(&base, state, transactions());
    let pending = first.prepare(&base, request.clone()).await.unwrap();
    let expected = base.clone();
    let competing = tokio::spawn(async move { second.prepare(&expected, request).await });
    tokio::task::yield_now().await;
    pending.commit().await.unwrap();
    assert!(competing.await.unwrap().is_err());
}

#[tokio::test]
async fn altered_object_or_missing_anchor_fails_recovery() {
    for mutation in [
        "UPDATE node_objects SET data=x'00' WHERE contents=1",
        "DELETE FROM exex_epoch_anchor",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.db");
        let store = fixture(&path).await;
        let chain = store.chain().clone();
        store.close().await;
        let pool = raw_pool(&path).await;
        sqlx::query(mutation).execute(&pool).await.unwrap();
        pool.close().await;
        assert!(CanonicalStore::open(&path, &chain).await.is_err());
    }
}

struct Recorder(tokio::sync::mpsc::UnboundedSender<u64>);
impl ExEx<NativeTransaction> for Recorder {
    fn name(&self) -> &'static str {
        "canonical-fixture"
    }
    fn on_epoch(
        &mut self,
        epoch: &CommittedEpoch<NativeTransaction>,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send {
        let result = self
            .0
            .send(epoch.cursor.sequence.0)
            .map_err(|e| e.to_string());
        async move { result }
    }
}

#[tokio::test]
async fn exex_recovers_commit_without_notification_and_resumes_its_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.db");
    let store = fixture(&path).await;
    let (base, state) = store.snapshot().await.unwrap();
    let head = store
        .prepare(&base, applied(&base, state, transactions()))
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&dir.path().join("extension.db"))
            .await
            .unwrap(),
    );
    let mut manager = ExExManager::new(store.source(), checkpoints.clone()).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager.register(Recorder(tx)).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        manager.stop("canonical-fixture").await.unwrap(),
        head.cursor
    );
    drop(manager);
    let mut manager = ExExManager::new(store.source(), checkpoints).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager.register(Recorder(tx)).await.unwrap();
    manager.notify_commit();
    assert!(tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .is_err());
    manager.stop("canonical-fixture").await.unwrap();
}

#[tokio::test]
#[ignore = "spawned by process_crash_recovery at a controlled commit boundary"]
async fn crash_worker() {
    let path = std::path::PathBuf::from(std::env::var_os("OCTRA_CRASH_DB").unwrap());
    let ready = std::path::PathBuf::from(std::env::var_os("OCTRA_CRASH_READY").unwrap());
    let store = CanonicalStore::open(&path, &genesis().0).await.unwrap();
    let (base, state) = store.snapshot().await.unwrap();
    let pending = store
        .prepare(&base, applied(&base, state, transactions()))
        .await
        .unwrap();
    let pending = if std::env::var("OCTRA_CRASH_PHASE").unwrap() == "after" {
        pending.commit().await.unwrap();
        None
    } else {
        Some(pending)
    };
    std::fs::write(ready, b"ready").unwrap();
    std::future::pending::<()>().await;
    drop(pending);
}

#[tokio::test]
async fn process_crash_recovery() {
    for phase in ["before", "after"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.db");
        let ready = dir.path().join("ready");
        let store = fixture(&path).await;
        let chain = store.chain().clone();
        store.close().await;
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_worker", "--ignored", "--nocapture"])
            .env("OCTRA_CRASH_DB", &path)
            .env("OCTRA_CRASH_READY", &ready)
            .env("OCTRA_CRASH_PHASE", phase)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while !ready.exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "crash worker failed before ready"
            );
            if tokio::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("crash worker timeout");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let reopened = CanonicalStore::open(&path, &chain).await.unwrap();
        let (head, state) = reopened.snapshot().await.unwrap();
        assert_eq!(head.cursor.sequence.0, u64::from(phase != "before"));
        assert_eq!(reopened.source().head().await.unwrap(), head.cursor);
        assert_eq!(
            state.get(&[b"circle", b"app", b"value"]).is_some(),
            phase == "after"
        );
    }
}
