use super::*;

/// Cancel around the real SQL publication boundary. Either complete canonical
/// prefix is valid; the in-memory head, durable prefix, writer lease and restart
/// audit must agree after the coordinator's shutdown barrier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canceled_publication_drains_before_writer_release_and_reopens_one_atomic_prefix() {
    for delayed_polls in [0, 1, 16] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("chain.db");
        let state = genesis(format!("oct{}", "1".repeat(44)).as_bytes());
        let chain = ChainIdentity::genesis(
            format!("publication-cancel-{delayed_polls}"),
            StateRoot(finality_host::root(None, &state, &[])),
        );
        CanonicalStore::create(&path, chain.clone(), state.snapshot(), 0)
            .await
            .unwrap()
            .close()
            .await;
        let checkpoints = Arc::new(
            SqliteCheckpoints::open(&directory.path().join("exex.db"))
                .await
                .unwrap(),
        );
        let node = Arc::new(open(&path, checkpoints.clone(), chain.clone(), Arc::default()).await);
        assert!(node.resume().await.unwrap());
        let parent = node.head().await.unwrap();
        let authority = finality_host::Authority {
            seed: 1,
            chain: chain.clone(),
        };
        let executed = execute_received(
            &parent,
            StateBatch::from_snapshot(state.snapshot()),
            &[],
            &authority,
            None,
            None,
        )
        .unwrap();
        let certificate = finality_host::certificate(&parent, &executed, &authority)
            .encode()
            .unwrap();
        let publisher = node.clone();
        let publish =
            tokio::spawn(async move { publisher.publish(&parent, &certificate, executed).await });
        tokio::time::timeout(Duration::from_secs(10), async {
            while !publish.is_finished() && matches!(node.status(), Status::Serving(_)) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("publication must reach its durable boundary");
        for _ in 0..delayed_polls {
            tokio::task::yield_now().await;
        }
        publish.abort();
        match publish.await {
            Ok(result) => {
                result.unwrap();
            }
            Err(error) => assert!(error.is_cancelled()),
        }
        node.shutdown().await.unwrap();
        assert!(matches!(node.status(), Status::Suspended(_)));
        let before = node.head().await.unwrap();
        assert!(before.cursor.epoch.0 <= 1);
        let durable = CanonicalStore::open(&path, &chain).await.unwrap();
        assert_eq!(
            durable.head().await.unwrap(),
            before,
            "coordinator cache must match an independent durable reader"
        );
        durable.close().await;
        drop(node);
        let reopened = open(&path, checkpoints, chain, Arc::default()).await;
        assert_eq!(reopened.head().await.unwrap(), before);
        assert!(
            reopened.resume().await.unwrap(),
            "retained certificate/state/outbox must reauthenticate"
        );
        reopened.shutdown().await.unwrap();
    }
}
