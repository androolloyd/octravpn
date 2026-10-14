use std::{path::Path, sync::Arc, time::Duration};

use octra_exex::{
    native_history::{NativeEpochSource, NativeHistory, NativeTransaction},
    sqlite::SqliteCheckpoints,
    ChainIdentity, CheckpointStore, CommittedEpoch, CommittedEpochSource, ExEx, ExExManager,
    ExtensionStatus, Sequence, StateRoot,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};

fn fixture() -> Value {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/native-history.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], sources["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], sources["files"]);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/node-port");
    for (name, hash) in fixture["adapter_sha256"].as_object().unwrap() {
        assert_eq!(
            hex::encode(Sha256::digest(std::fs::read(root.join(name)).unwrap())),
            *hash
        );
    }
    fixture["cases"].clone()
}

fn parse(value: &Value) -> NativeHistory {
    NativeHistory::parse(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn chain() -> ChainIdentity {
    ChainIdentity {
        chain_id: "native-storage-fixture".into(),
        genesis_root: StateRoot([71; 32]),
    }
}

async fn pool(path: &Path) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Full)
                .busy_timeout(Duration::from_secs(2)),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn native_head_crash_window_and_paginated_reopen_preserve_committed_history() {
    let cases = fixture();
    assert_eq!(cases["after_head"], cases["after_recovery"]);
    for name in [
        "before_head",
        "future",
        "oversize",
        "pruned",
        "writer_active",
        "auxiliary_pending",
    ] {
        assert!(
            !cases["refusals"][name].as_str().unwrap().is_empty(),
            "{name}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("history.db");
    let connection = pool(&db).await;
    let first = parse(&cases["first_page"]);
    let anchor = first.anchor().clone();
    let source = NativeEpochSource::open(connection.clone(), chain(), anchor.clone())
        .await
        .unwrap();
    let committed = source.import(&first).await.unwrap();
    assert_eq!(committed.sequence, Sequence(1));
    assert!(source.import(&first).await.is_err());
    assert_eq!(source.native_head().await.unwrap().epoch, 1);
    drop(source);
    connection.close().await;
    let connection = pool(&db).await;
    let source = NativeEpochSource::open(connection.clone(), chain(), anchor)
        .await
        .unwrap();
    assert_eq!(source.head().await.unwrap(), committed);
    assert_eq!(
        source
            .import(&parse(&cases["remaining"]))
            .await
            .unwrap()
            .sequence,
        Sequence(3)
    );
    assert!(source
        .load(Sequence(2))
        .await
        .unwrap()
        .unwrap()
        .events
        .is_empty());
    assert_eq!(
        source
            .load(Sequence(3))
            .await
            .unwrap()
            .unwrap()
            .events
            .len(),
        2
    );
    assert_eq!(
        source.import(&parse(&cases["caught_up"])).await.unwrap(),
        source.head().await.unwrap()
    );
    drop(source);
    connection.close().await;
}

#[tokio::test]
async fn interrupted_page_rolls_back_events_and_native_binding_together() {
    let cases = fixture();
    let history = parse(&cases["full"]);
    let dir = tempfile::tempdir().unwrap();
    let connection = pool(&dir.path().join("history.db")).await;
    let source = NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER interrupt_page BEFORE INSERT ON exex_committed_epoch WHEN NEW.sequence='0000000000000002' BEGIN SELECT RAISE(ABORT,'injected storage failure'); END")
        .execute(&connection).await.unwrap();
    assert!(source.import(&history).await.is_err());
    assert_eq!(source.head().await.unwrap().sequence, Sequence(0));
    assert_eq!(source.native_head().await.unwrap(), *history.anchor());
    assert!(source.load(Sequence(1)).await.unwrap().is_none());
    sqlx::query("DROP TRIGGER interrupt_page")
        .execute(&connection)
        .await
        .unwrap();
    assert_eq!(source.import(&history).await.unwrap().sequence, Sequence(3));
}

#[test]
fn modified_identity_commitments_links_and_missing_history_fail_closed() {
    let cases = fixture();
    let mutations = [
        ("/epochs/0/transactions/0/transaction", json!("{}")),
        ("/epochs/0/transactions/0/identity", json!("{}")),
        ("/epochs/0/transactions/0/hash", json!("a".repeat(64))),
        ("/epochs/0/transactions/0/txid", json!(100)),
        ("/epochs/0/transactions/0/proof", json!("unchecked")),
        ("/epochs/0/parent_root", json!("a".repeat(64))),
        ("/epochs/0/parent_commit", json!("other-tree")),
        ("/epochs/0/start_txid", json!(100)),
        ("/epochs/0/boundary/txid_hi", json!(-1)),
        ("/epochs/0/boundary/ledger_root", json!("other-ledger")),
        ("/epochs/0/boundary/index_hash", json!("a".repeat(64))),
        ("/head/irmin_commit", json!("other-tree")),
        ("/epochs", json!([])),
        ("/head_commit_id", json!("")),
        ("/format", json!("untrusted-v2")),
    ];
    for (path, replacement) in mutations {
        let mut changed = cases["full"].clone();
        *changed.pointer_mut(path).unwrap() = replacement;
        assert!(
            NativeHistory::parse(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "{path}"
        );
    }
    let mut skipped = cases["full"].clone();
    skipped["epochs"].as_array_mut().unwrap().remove(1);
    assert!(NativeHistory::parse(&serde_json::to_vec(&skipped).unwrap()).is_err());
    let mut duplicate = cases["full"].clone();
    duplicate["epochs"]
        .as_array_mut()
        .unwrap()
        .insert(0, cases["full"]["epochs"][0].clone());
    assert!(NativeHistory::parse(&serde_json::to_vec(&duplicate).unwrap()).is_err());
}

#[tokio::test]
async fn missing_outbox_and_changed_binding_cannot_reset_progress() {
    let cases = fixture();
    let history = parse(&cases["full"]);
    let dir = tempfile::tempdir().unwrap();
    let connection = pool(&dir.path().join("history.db")).await;
    let source = NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
        .await
        .unwrap();
    source.import(&history).await.unwrap();
    assert!(
        NativeEpochSource::open(connection.clone(), chain(), history.head().clone())
            .await
            .is_err()
    );
    sqlx::query("DELETE FROM exex_committed_epoch")
        .execute(&connection)
        .await
        .unwrap();
    assert!(source.import(&parse(&cases["caught_up"])).await.is_err());
}

struct DurableSink {
    pool: SqlitePool,
    fail_after_write: bool,
}
impl ExEx<NativeTransaction> for DurableSink {
    fn name(&self) -> &'static str {
        "native-history-test"
    }
    async fn on_epoch(&mut self, epoch: &CommittedEpoch<NativeTransaction>) -> Result<(), String> {
        let value = serde_json::to_string(epoch).unwrap();
        sqlx::query("INSERT INTO sink(sequence,payload) VALUES(?,?) ON CONFLICT DO NOTHING")
            .bind(epoch.cursor.sequence.0 as i64)
            .bind(&value)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        let saved: String = sqlx::query_scalar("SELECT payload FROM sink WHERE sequence=?")
            .bind(epoch.cursor.sequence.0 as i64)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        if saved != value {
            return Err("replay changed a committed payload".into());
        }
        if self.fail_after_write {
            return Err("injected crash after sink write".into());
        }
        Ok(())
    }
}

async fn wait_status(manager: &ExExManager<NativeTransaction>, failed: bool) {
    let mut status = manager.status("native-history-test").unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let done = match &*status.borrow() {
                ExtensionStatus::Failed { .. } => failed,
                ExtensionStatus::Running { checkpoint } => {
                    !failed && checkpoint.sequence == Sequence(3)
                }
                _ => false,
            };
            if done {
                break;
            }
            status.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn consumer_restart_replays_sink_write_without_skipping_empty_epochs() {
    let cases = fixture();
    let history = parse(&cases["full"]);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("history.db");
    let connection = pool(&db).await;
    sqlx::query("CREATE TABLE sink(sequence INTEGER PRIMARY KEY,payload TEXT NOT NULL)")
        .execute(&connection)
        .await
        .unwrap();
    let source = Arc::new(
        NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
            .await
            .unwrap(),
    );
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&dir.path().join("checkpoints.db"))
            .await
            .unwrap(),
    );
    let mut manager = ExExManager::new(source.clone(), checkpoints.clone()).unwrap();
    manager
        .register(DurableSink {
            pool: connection.clone(),
            fail_after_write: true,
        })
        .await
        .unwrap();
    source.import(&history).await.unwrap();
    manager.notify_commit();
    wait_status(&manager, true).await;
    assert!(manager.stop("native-history-test").await.is_err());
    assert!(checkpoints
        .load(&chain(), "native-history-test")
        .await
        .unwrap()
        .is_none());
    drop(manager);
    drop(source);
    connection.close().await;
    let connection = pool(&db).await;
    let source = Arc::new(
        NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
            .await
            .unwrap(),
    );
    let mut manager = ExExManager::new(source, checkpoints).unwrap();
    manager
        .register(DurableSink {
            pool: connection.clone(),
            fail_after_write: false,
        })
        .await
        .unwrap();
    // Registration discovers persisted backlog even with no new commit wakeup.
    wait_status(&manager, false).await;
    assert_eq!(
        manager.stop("native-history-test").await.unwrap().sequence,
        Sequence(3)
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sink")
        .fetch_one(&connection)
        .await
        .unwrap();
    assert_eq!(count, 3);
}
