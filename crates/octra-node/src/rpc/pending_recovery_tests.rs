//! A genuine newer QC/admission followed by an older canonical cleanup,
//! against the real durable queue and RPC intake. No cursor or receipt mock.
use super::*;

async fn closed(pending: Arc<executor::Pending>, rpc: Rpc) {
    let weak = Arc::downgrade(&pending);
    rpc.close().await;
    drop(pending);
    tokio::time::timeout(Duration::from_secs(10), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn historical_queue_cleanup_preserves_newer_admission_and_reopens() {
    let mut fixture = Box::pin(Fixture::with_application(None, Application::Circle)).await;
    let path = fixture.directory.path().join("ordered-pending.log");
    let pending = Arc::new(
        executor::Pending::open(path.clone(), &fixture.node.store)
            .await
            .unwrap(),
    );
    let rpc = Box::pin(Rpc::with_pending(
        &fixture,
        fixture.native.clone(),
        pending.clone(),
    ))
    .await;
    let old = fixture.node.head().await.unwrap();
    let old_record = fixture
        .node
        .publisher
        .record(old.cursor.sequence)
        .await
        .unwrap();
    let stale = draft(&fixture).await;
    let first = spawn(&fixture);
    assert_accepted(&rpc.submit(&first).await, &first);
    fixture.publish(vec![first.clone()]).await;
    let first_head = fixture.node.head().await.unwrap();
    assert!(first_head.cursor.sequence > old.cursor.sequence);
    let first_record = fixture
        .node
        .publisher
        .record(first_head.cursor.sequence)
        .await
        .unwrap();

    // Admission has already journaled the new head while the preceding
    // canonical callback is still waiting. Both candidates remain queued.
    let next = spawn(&fixture);
    assert_accepted(&rpc.submit(&next).await, &next);
    fixture.publish(vec![]).await;
    let current = fixture.node.head().await.unwrap();
    assert!(current.cursor.sequence > first_head.cursor.sequence);
    let current_record = fixture
        .node
        .publisher
        .record(current.cursor.sequence)
        .await
        .unwrap();
    // Proposal capture journals the newer authenticated head without committing
    // the next transaction or completing the delayed first cleanup.
    Box::pin(fixture.native.build_pending(
        draft(&fixture).await,
        pending.clone(),
        100_000.into(),
        8,
    ))
    .await
    .unwrap();
    let queued = pending.transactions().unwrap();
    assert_eq!(queued.len(), 2);
    assert!(queued.contains(&first) && queued.contains(&next));
    let before = std::fs::read(&path).unwrap();
    assert!(Box::pin(
        fixture
            .native
            .build_pending(stale, pending.clone(), 100_000.into(), 8)
    )
    .await
    .is_err());
    assert_eq!(pending.transactions().unwrap(), queued);
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let mut wrong = old.cursor;
    wrong.state_root.0[0] ^= 1;
    assert!(pending.committed(&old_record, wrong).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(pending.transactions().unwrap(), queued);

    // The old callback is idempotent and cannot regress the persisted cursor
    // or poison subsequent admission. Its unchanged pool needs no WAL frame.
    pending.committed(&old_record, old.cursor).unwrap();
    assert_eq!(pending.transactions().unwrap(), queued);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    pending.committed(&first_record, first_head.cursor).unwrap();
    assert_eq!(pending.transactions().unwrap(), vec![next.clone()]);
    pending.committed(&current_record, current.cursor).unwrap();
    closed(pending, rpc).await;

    let pending = Arc::new(
        executor::Pending::open(path.clone(), &fixture.node.store)
            .await
            .unwrap(),
    );
    let rpc = Box::pin(Rpc::with_pending(
        &fixture,
        fixture.native.clone(),
        pending.clone(),
    ))
    .await;
    assert_eq!(pending.transactions().unwrap(), vec![next.clone()]);
    // A still older callback after actual reopen must remain harmless too.
    pending.committed(&old_record, old.cursor).unwrap();
    assert_eq!(pending.transactions().unwrap(), vec![next.clone()]);
    fixture.publish(vec![next]).await;
    let final_head = fixture.node.head().await.unwrap();
    let final_record = fixture
        .node
        .publisher
        .record(final_head.cursor.sequence)
        .await
        .unwrap();
    pending.committed(&final_record, final_head.cursor).unwrap();
    assert!(pending.transactions().unwrap().is_empty());
    closed(pending, rpc).await;

    let pending = Arc::new(
        executor::Pending::open(path, &fixture.node.store)
            .await
            .unwrap(),
    );
    let rpc = Box::pin(Rpc::with_pending(
        &fixture,
        fixture.native.clone(),
        pending.clone(),
    ))
    .await;
    assert!(pending.transactions().unwrap().is_empty());
    assert_eq!(fixture.node.head().await.unwrap(), final_head);
    closed(pending, rpc).await;
    fixture.node.shutdown().await.unwrap();
}
