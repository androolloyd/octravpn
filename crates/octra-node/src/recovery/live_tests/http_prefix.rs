//! The real Service consumes one native HTTP chunk before its single resume.
use super::*;
use octra_node_protocol::{consensus::codec::Wire, state_sync::http};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn first_successor_target_imports_sixteen_native_epochs_before_one_service_resume() {
    let mut source = Box::pin(Fixture::new(false)).await;
    source.tasks.stop().await;
    // The trusted source host is now offline: stopping its recovery service
    // intentionally revoked reads. Reaudit/resume before constructing QCs.
    assert!(source.node.resume().await.unwrap());
    let mut records = Vec::new();
    for epoch in 2..=17 {
        let parent = source.node.head().await.unwrap();
        let (certificate, mut executed) = source.successor_at(f64::from(epoch) * 10.).await;
        assert_eq!(
            octra_node_protocol::consensus::Finalize::decode(&certificate)
                .unwrap()
                .epoch_id,
            i64::from(epoch)
        );
        executed.message = b"finalized epoch".to_vec();
        source
            .node
            .publish(&parent, &certificate, executed)
            .await
            .unwrap();
        records.push(
            source
                .node
                .publisher
                .record(Sequence(epoch as u64))
                .await
                .unwrap(),
        );
    }
    let expected = source.node.head().await.unwrap();
    assert_eq!(records.len(), 16);
    let available = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn({
        let available = available.clone();
        let requests = requests.clone();
        async move {
            let router = axum::Router::new().route(
                "/state-sync/range",
                axum::routing::get(
                    move |axum::extract::Query(query): axum::extract::Query<
                        std::collections::HashMap<String, String>,
                    >| {
                        let records = records.clone();
                        let available = available.clone();
                        let requests = requests.clone();
                        async move {
                            let from: i64 = query["from_epoch"].parse().unwrap();
                            let max: i64 = query["max_epochs"].parse().unwrap();
                            requests.lock().unwrap().push((from, max));
                            if !available.load(Ordering::SeqCst) {
                                return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Vec::new());
                            }
                            let query = http::RangeQuery {
                                from_epoch: from,
                                max_epochs: max,
                                part: None,
                                hash: None,
                            };
                            let body = http::range_response(
                                None,
                                &query,
                                &http::RangeResult::Records {
                                    records: records
                                        .into_iter()
                                        .filter(|r| r.epoch_id >= from)
                                        .take(max as usize)
                                        .collect(),
                                    next_epoch: None,
                                },
                            )
                            .unwrap();
                            (axum::http::StatusCode::OK, body)
                        }
                    },
                ),
            );
            axum::serve(listener, router).await.unwrap();
        }
    });
    let join = crate::consensus_join::Client::capture(|name| {
        (name == "OCTRA_JOIN_RPC").then(|| endpoint.as_bytes().to_vec())
    })
    .unwrap();
    let mut target = Box::pin(Fixture::with_http(join)).await;
    target
        .wait(|| {
            target.initial.wake().is_err()
                && matches!(target.node.status(), crate::Status::Suspended(_))
        })
        .await;
    let initial = target.node.head().await.unwrap();
    assert_eq!(initial.cursor.epoch.0, 1);
    let before_views = target.view_checks.load(Ordering::SeqCst);
    let before_votes = target.vote_journal();
    assert_eq!(before_votes.len(), 1);
    assert!(target.node.snapshot().is_err());
    // Every actual TCP root peer has only epoch1; neither the target nor its
    // desired obligation can be derived from a fake future root advertisement.
    for peer in &target.peers {
        assert!(peer
            .authority
            .ranges
            .lock()
            .unwrap()
            .keys()
            .all(|epoch| *epoch == 1));
    }
    available.store(true, Ordering::SeqCst);
    target.wait(|| matches!(target.node.status(), crate::Status::Serving(ref h) if h.cursor.epoch.0 == 17)).await;
    let committed = target.node.head().await.unwrap();
    assert_eq!(committed, expected);
    // Node constructs the admitted view only after its complete prefix audit.
    // No view/resume is constructed at any intermediate imported epoch.
    assert_eq!(target.view_checks.load(Ordering::SeqCst), before_views + 1);
    target.wait_checkpoint(committed.cursor).await;
    target
        .wait(|| target.epochs.lock().unwrap().len() == 17)
        .await;
    assert_eq!(target.journal.floor().unwrap(), Some(17));
    // Reconciliation advances the durable signing floor through the imported
    // head. That is journal maintenance, not a local vote: no other file may
    // appear or change while this observer catches up.
    let floor = before_votes
        .keys()
        .find(|path| path.ends_with("floor"))
        .unwrap()
        .clone();
    let mut expected_votes = before_votes;
    assert_eq!(
        expected_votes.insert(floor, b"17\n".to_vec()),
        Some(b"1\n".to_vec())
    );
    assert_eq!(target.vote_journal(), expected_votes);
    let seen = requests.lock().unwrap().clone();
    assert!(seen.contains(&(2, 16)));
    assert!(seen.iter().all(|(_, max)| *max == 16));
    assert_eq!(
        target.node.publisher.record(Sequence(1)).await.unwrap(),
        target.baseline
    );
    for epoch in 2..=17 {
        assert_eq!(
            target.node.publisher.record(Sequence(epoch)).await.unwrap(),
            source.node.publisher.record(Sequence(epoch)).await.unwrap()
        );
    }
    target.tasks.stop().await;
    target.node.shutdown().await.unwrap();
    source.node.shutdown().await.unwrap();
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}
