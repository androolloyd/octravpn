use octra_exex::{
    sqlite::SqliteCheckpoints, ChainIdentity, CheckpointStore, Cursor, EpochId, Sequence, StateRoot,
};
fn chain(root: u8) -> ChainIdentity {
    ChainIdentity {
        chain_id: "pilot".into(),
        genesis_root: StateRoot([root; 32]),
    }
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
