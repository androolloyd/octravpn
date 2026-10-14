use octra_exex::{
    sqlite::SqliteCheckpoints, sqlite_source::SqliteEpochSource, ChainIdentity, CheckpointStore,
    CommittedEpoch, CommittedEpochSource, Cursor, EpochId, ExEx, ExExManager, Sequence, StateRoot,
};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    Row,
};
use std::{path::Path, sync::Arc, time::Duration};

struct Recorder(tokio::sync::mpsc::UnboundedSender<u64>);

impl ExEx<String> for Recorder {
    fn name(&self) -> &'static str {
        "vpn"
    }

    fn on_epoch(
        &mut self,
        epoch: &CommittedEpoch<String>,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send {
        let tx = self.0.clone();
        let sequence = epoch.cursor.sequence.0;
        async move { tx.send(sequence).map_err(|e| e.to_string()) }
    }
}

fn chain() -> ChainIdentity {
    ChainIdentity {
        chain_id: "octra-test".into(),
        genesis_root: StateRoot([1; 32]),
    }
}

fn cursor(sequence: u64, epoch: u64, root: u8) -> Cursor {
    Cursor {
        sequence: Sequence(sequence),
        epoch: EpochId(epoch),
        state_root: StateRoot([root; 32]),
    }
}

fn epoch(sequence: u64, number: u64, parent: u8, root: u8) -> CommittedEpoch<String> {
    CommittedEpoch {
        chain: chain(),
        cursor: cursor(sequence, number, root),
        parent_root: StateRoot([parent; 32]),
        events: vec![format!("committed-{number}")],
    }
}

async fn pool(path: &Path) -> sqlx::SqlitePool {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(5));
    SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .unwrap()
}

#[tokio::test]
async fn outbox_rolls_back_with_host_state_and_survives_restart() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("chain.sqlite");
    let db = pool(&path).await;
    sqlx::query("CREATE TABLE chain_state (value INTEGER NOT NULL)")
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO chain_state(value) VALUES(0)")
        .execute(&db)
        .await
        .unwrap();
    let anchor = cursor(0, 0, 1);
    let source = SqliteEpochSource::<String>::open(db.clone(), chain(), anchor)
        .await
        .unwrap();

    let mut tx = db.begin().await.unwrap();
    sqlx::query("UPDATE chain_state SET value=1")
        .execute(&mut *tx)
        .await
        .unwrap();
    source.append(&mut tx, &epoch(1, 1, 1, 2)).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(source.head().await.unwrap(), anchor);
    assert!(source.load(Sequence(1)).await.unwrap().is_none());
    let value: i64 = sqlx::query("SELECT value FROM chain_state")
        .fetch_one(&db)
        .await
        .unwrap()
        .get("value");
    assert_eq!(value, 0);

    let mut tx = db.begin().await.unwrap();
    sqlx::query("UPDATE chain_state SET value=1")
        .execute(&mut *tx)
        .await
        .unwrap();
    source.append(&mut tx, &epoch(1, 1, 1, 2)).await.unwrap();
    tx.commit().await.unwrap();
    db.close().await;

    let reopened_pool = pool(&path).await;
    let reopened = SqliteEpochSource::<String>::open(reopened_pool.clone(), chain(), anchor)
        .await
        .unwrap();
    assert_eq!(reopened.head().await.unwrap(), cursor(1, 1, 2));
    assert_eq!(
        *reopened.load(Sequence(1)).await.unwrap().unwrap(),
        epoch(1, 1, 1, 2)
    );
    let value: i64 = sqlx::query("SELECT value FROM chain_state")
        .fetch_one(&reopened_pool)
        .await
        .unwrap()
        .get("value");
    assert_eq!(value, 1);
}

#[tokio::test]
async fn rejects_noncanonical_history_and_anchor_changes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("chain.sqlite");
    let pool = pool(&path).await;
    let anchor = cursor(u64::MAX - 1, 99, 3);
    let source = SqliteEpochSource::<String>::open(pool.clone(), chain(), anchor)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    for invalid in [
        epoch(u64::MAX - 1, 100, 3, 4),
        epoch(u64::MAX, 99, 3, 4),
        epoch(u64::MAX, 100, 9, 4),
    ] {
        assert!(source.append(&mut tx, &invalid).await.is_err());
    }
    let mut other_chain = epoch(u64::MAX, 100, 3, 4);
    other_chain.chain.genesis_root = StateRoot([8; 32]);
    assert!(source.append(&mut tx, &other_chain).await.is_err());
    source
        .append(&mut tx, &epoch(u64::MAX, 100, 3, 4))
        .await
        .unwrap();
    assert!(source
        .append(&mut tx, &epoch(u64::MAX, 101, 4, 5))
        .await
        .is_err());
    tx.commit().await.unwrap();
    assert_eq!(source.head().await.unwrap(), cursor(u64::MAX, 100, 4));
    assert!(
        SqliteEpochSource::<String>::open(pool, chain(), cursor(0, 0, 3))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn committed_sqlite_epoch_reaches_extension_and_checkpoints() {
    let temp = tempfile::tempdir().unwrap();
    let db = pool(&temp.path().join("chain.sqlite")).await;
    let source = Arc::new(
        SqliteEpochSource::<String>::open(db.clone(), chain(), cursor(0, 0, 1))
            .await
            .unwrap(),
    );
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&temp.path().join("checkpoints.sqlite"))
            .await
            .unwrap(),
    );
    let mut manager = ExExManager::new(source.clone(), checkpoints.clone()).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager.register(Recorder(tx)).await.unwrap();

    let mut transaction = db.begin().await.unwrap();
    source
        .append(&mut transaction, &epoch(1, 1, 1, 2))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    manager.notify_commit();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap(),
        Some(1)
    );
    assert_eq!(manager.stop("vpn").await.unwrap(), cursor(1, 1, 2));
    assert_eq!(
        checkpoints.load(&chain(), "vpn").await.unwrap(),
        Some(cursor(1, 1, 2))
    );
}
