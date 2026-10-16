use octra_exex::{
    sqlite::SqliteCheckpoints, ChainIdentity, CheckpointStore, Cursor, EpochId, Sequence, StateRoot,
};
fn chain(root: u8) -> ChainIdentity {
    ChainIdentity::genesis("pilot", StateRoot([root; 32]))
}
fn cursor(n: u64) -> Cursor {
    Cursor {
        sequence: Sequence(n),
        epoch: EpochId(n),
        state_root: StateRoot([7; 32]),
    }
}
#[tokio::test]
async fn checkpoint_survives_close_and_reopen_with_full_u64_range() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("checkpoints.sqlite");
    let store = SqliteCheckpoints::open(&path).await.unwrap();
    store
        .compare_and_save(&chain(1), "vpn", None, cursor(u64::MAX))
        .await
        .unwrap();
    store.close().await;
    let reopened = SqliteCheckpoints::open(&path).await.unwrap();
    assert_eq!(
        reopened.load(&chain(1), "vpn").await.unwrap(),
        Some(cursor(u64::MAX))
    );
    assert_eq!(reopened.load(&chain(2), "vpn").await.unwrap(), None);
    assert_eq!(reopened.load(&chain(1), "metrics").await.unwrap(), None);
}
#[tokio::test]
async fn competing_connections_cannot_overwrite_progress() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("checkpoints.sqlite");
    let a = SqliteCheckpoints::open(&path).await.unwrap();
    let b = SqliteCheckpoints::open(&path).await.unwrap();
    a.compare_and_save(&chain(1), "vpn", None, cursor(1))
        .await
        .unwrap();
    let identity = chain(1);
    let (first, second) = tokio::join!(
        a.compare_and_save(&identity, "vpn", Some(cursor(1)), cursor(2)),
        b.compare_and_save(&identity, "vpn", Some(cursor(1)), cursor(3))
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let winner = if first.is_ok() { 2 } else { 3 };
    assert_eq!(
        a.load(&chain(1), "vpn").await.unwrap(),
        Some(cursor(winner))
    );
    assert!(b
        .compare_and_save(&chain(1), "vpn", None, cursor(0))
        .await
        .is_err());
}

#[tokio::test]
async fn legacy_checkpoint_rows_are_retained_and_checkpoint_origins_are_isolated() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("legacy.sqlite");
    let store = SqliteCheckpoints::open(&path).await.unwrap();
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    // Insert using the old physical schema/key, bypassing the new identity API.
    sqlx::query("INSERT INTO exex_checkpoint(chain_id,genesis,extension,sequence,epoch,root) VALUES(?,?,?,?,?,?)")
        .bind("pilot").bind([1_u8;32].as_slice()).bind("vpn").bind("7").bind("7").bind([7_u8;32].as_slice()).execute(&pool).await.unwrap();
    assert_eq!(store.load(&chain(1), "vpn").await.unwrap(), Some(cursor(7)));
    let origin = ChainIdentity::checkpoint("pilot", 7, StateRoot([1; 32]));
    assert!(store.load(&origin, "vpn").await.unwrap().is_none());
    store
        .compare_and_save(&origin, "vpn", None, cursor(99))
        .await
        .unwrap();
    pool.close().await;
    store.close().await;
    let reopened = SqliteCheckpoints::open(&path).await.unwrap();
    assert_eq!(
        reopened.load(&chain(1), "vpn").await.unwrap(),
        Some(cursor(7))
    );
    assert_eq!(
        reopened.load(&origin, "vpn").await.unwrap(),
        Some(cursor(99))
    );
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    sqlx::query("DELETE FROM exex_origin WHERE chain_id=? AND namespace=?")
        .bind(&origin.chain_id)
        .bind(origin.namespace_key().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        reopened.load(&origin, "vpn").await.is_err(),
        "a retained checkpoint cursor cannot lose its typed origin"
    );
    assert_eq!(
        reopened.load(&chain(1), "vpn").await.unwrap(),
        Some(cursor(7))
    );
}

#[tokio::test]
async fn checkpoint_namespace_rejects_pre_origin_or_conflicting_floor_cursors() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("checkpoint-floor.sqlite");
    let store = SqliteCheckpoints::open(&path).await.unwrap();
    let origin = ChainIdentity::checkpoint("pilot", 7, StateRoot([1; 32]));
    for invalid in [cursor(6), cursor(7)] {
        assert!(store
            .compare_and_save(&origin, "vpn", None, invalid)
            .await
            .is_err());
        assert!(store.load(&origin, "vpn").await.unwrap().is_none());
    }
    let floor = Cursor {
        sequence: Sequence(0),
        epoch: EpochId(7),
        state_root: StateRoot([1; 32]),
    };
    store
        .compare_and_save(&origin, "vpn", None, floor)
        .await
        .unwrap();
    assert_eq!(store.load(&origin, "vpn").await.unwrap(), Some(floor));
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    sqlx::query("UPDATE exex_checkpoint SET epoch='6' WHERE chain_id=? AND genesis=?")
        .bind(&origin.chain_id)
        .bind(origin.namespace_key().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        store.load(&origin, "vpn").await.is_err(),
        "a persisted cursor cannot move below its configured origin"
    );
}
