use super::*;
use octra_node_protocol::network::swarm::TransportScope;

#[tokio::test]
async fn scope_barrier_closes_authenticated_sessions_and_restarts_same_identity() {
    let listener = listener().await;
    let address = listener.local_addr().unwrap();
    let swarm = Swarm::new(
        config(address.port(), vec![public(1), public(2)], vec![], false),
        key(1),
    )
    .unwrap();
    let identity = swarm.node_id().to_vec();
    let (task, mut received) = start(&swarm, listener);
    let mut original = client(2, address, b"swarm-test").await.unwrap();
    until(|| swarm.peers().len() == 1).await;
    let frame = Frame {
        message: 0x20,
        payload: b"before owned pause".to_vec(),
    };
    original.send(&frame).await.unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, received.recv())
            .await
            .unwrap()
            .unwrap()
            .1,
        frame
    );
    let paused = swarm.change_scope(TransportScope::Paused).await.unwrap();
    paused.check().unwrap();
    assert!(swarm.peers().is_empty());
    tokio::time::timeout(WAIT, async { while original.receive().await.is_ok() {} })
        .await
        .unwrap();
    assert!(tokio::time::timeout(
        Duration::from_millis(100),
        client(2, address, b"swarm-test")
    )
    .await
    .is_err());
    let active = swarm.change_scope(TransportScope::Public).await.unwrap();
    assert!(paused.check().is_err());
    active.check().unwrap();
    assert_eq!(swarm.node_id(), identity);
    let mut fresh = client(2, address, b"swarm-test").await.unwrap();
    until(|| swarm.peers().len() == 1).await;
    let frame = Frame {
        message: 0x20,
        payload: b"after owned pause".to_vec(),
    };
    fresh.send(&frame).await.unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, received.recv())
            .await
            .unwrap()
            .unwrap()
            .1,
        frame
    );
    swarm.stop();
    task.await.unwrap();
    assert!(active.check().is_err());
    assert!(swarm.change_scope(TransportScope::Public).await.is_err());
}

#[tokio::test]
async fn configured_pause_starts_without_dialing_and_can_be_explicitly_released() {
    let listener = listener().await;
    let address = listener.local_addr().unwrap();
    let swarm = Swarm::new(
        config(address.port(), vec![public(1), public(2)], vec![], false),
        key(1),
    )
    .unwrap();
    swarm.configure_scope(TransportScope::Paused).unwrap();
    let (task, _) = start(&swarm, listener);
    until(|| swarm.connection_diagnostics().running).await;
    assert!(swarm.peers().is_empty());
    assert!(swarm.configure_scope(TransportScope::Public).is_err());
    assert!(tokio::time::timeout(
        Duration::from_millis(100),
        client(2, address, b"swarm-test")
    )
    .await
    .is_err());
    swarm
        .change_scope(TransportScope::Public)
        .await
        .unwrap()
        .check()
        .unwrap();
    let _fresh = client(2, address, b"swarm-test").await.unwrap();
    until(|| swarm.peers().len() == 1).await;
    swarm.stop();
    task.await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "Requires isolated Linux NET_RAW; explicit network-scope qualification"]
async fn device_scope_reconnects_authenticated_native_frames_without_physical_fallback() {
    let al = listener().await;
    let bl = listener().await;
    let ap = al.local_addr().unwrap().port();
    let bp = bl.local_addr().unwrap().port();
    let keys = vec![public(1), public(2)];
    let swarm = Swarm::new(config(ap, keys.clone(), vec![endpoint(bp)], false), key(1)).unwrap();
    let other = Swarm::new(config(bp, keys, vec![], false), key(2)).unwrap();
    swarm.configure_scope(TransportScope::Paused).unwrap();
    let (task, mut back) = start(&swarm, al);
    let (remote, mut received) = start(&other, bl);
    until(|| swarm.connection_diagnostics().running && other.connection_diagnostics().running)
        .await;
    let scope = TransportScope::Interface {
        name: "lo".into(),
        pins: Default::default(),
        mark: 0x4f43_544e,
    };
    let bound = swarm.change_scope(scope).await.unwrap();
    bound.check().unwrap();
    until(|| swarm.peers().len() == 1 && other.peers().len() == 1).await;
    let frame = Frame {
        message: 0x20,
        payload: b"real device-bound native frame".to_vec(),
    };
    swarm.broadcast(frame.clone(), None, true).await.unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, received.recv())
            .await
            .unwrap()
            .unwrap()
            .1,
        frame
    );
    other.broadcast(frame.clone(), None, true).await.unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, back.recv())
            .await
            .unwrap()
            .unwrap()
            .1,
        frame
    );
    swarm.stop();
    other.stop();
    task.await.unwrap();
    remote.await.unwrap();
    assert!(bound.check().is_err());
}
