use super::*;
use octra_node_protocol::network::{
    frame,
    swarm::{Outcome, Phase},
};

fn count(swarm: &Swarm, direction: &str, phase: Phase, outcome: Outcome) -> u64 {
    swarm
        .connection_diagnostics()
        .outcomes
        .iter()
        .filter(|row| row.direction == direction && row.phase == phase && row.outcome == outcome)
        .map(|row| row.count)
        .sum()
}

async fn until_outcome(swarm: &Swarm, phase: Phase, outcome: Outcome) {
    let result = tokio::time::timeout(WAIT, async {
        while count(swarm, "outbound", phase, outcome) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "missing outbound {phase:?}/{outcome:?}: {:?}",
        swarm.connection_diagnostics()
    );
}

#[tokio::test]
async fn refused_tcp_and_graceful_early_close_have_distinct_outcomes() {
    // Select a currently unused local port, then close it immediately before
    // starting the dial. Keeping an unlistening socket bound can absorb SYNs
    // on macOS instead of producing the connection refusal exercised here.
    let dead = listener().await;
    let port = dead.local_addr().unwrap().port();
    let local = listener().await;
    let swarm = Swarm::new(
        config(
            local.local_addr().unwrap().port(),
            vec![],
            vec![endpoint(port)],
            false,
        ),
        key(1),
    )
    .unwrap();
    drop(dead);
    let (task, _) = start(&swarm, local);
    until_outcome(&swarm, Phase::Transport, Outcome::Refused).await;
    assert_eq!(
        count(&swarm, "outbound", Phase::Handshake, Outcome::Accepted),
        0
    );
    swarm.stop();
    task.await.unwrap();

    let peer = listener().await;
    let port = peer.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = peer.accept().await.unwrap();
        let hello = frame::read_frame(&mut stream, WAIT, frame::HANDSHAKE_PAYLOAD_MAX)
            .await
            .unwrap();
        assert_eq!(hello.message, 0x01);
        stream.shutdown().await.unwrap();
    });
    let local = listener().await;
    let swarm = Swarm::new(
        config(
            local.local_addr().unwrap().port(),
            vec![],
            vec![endpoint(port)],
            false,
        ),
        key(1),
    )
    .unwrap();
    let (task, _) = start(&swarm, local);
    until_outcome(&swarm, Phase::Handshake, Outcome::RemoteClose).await;
    assert!(count(&swarm, "outbound", Phase::Transport, Outcome::Accepted) > 0);
    assert_eq!(
        count(&swarm, "outbound", Phase::Handshake, Outcome::Frame),
        0
    );
    assert!(swarm.peers().is_empty());
    swarm.stop();
    task.await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn socks_refusal_keeps_its_fixed_reply_category_without_direct_fallback() {
    let target = listener().await;
    let target_port = target.local_addr().unwrap().port();
    let proxy = listener().await;
    let proxy_address = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        let mut header = [0; 5];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..4], &[5, 1, 0, 3]);
        let mut host = vec![0; usize::from(header[4])];
        stream.read_exact(&mut host).await.unwrap();
        assert_eq!(stream.read_u16().await.unwrap(), target_port);
        stream
            .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });
    let local = listener().await;
    let swarm = Swarm::new(
        config(
            local.local_addr().unwrap().port(),
            vec![],
            vec![endpoint(target_port)],
            false,
        ),
        key(1),
    )
    .unwrap();
    swarm.set_proxy(proxy_address).unwrap();
    let (task, _) = start(&swarm, local);
    until(|| count(&swarm, "outbound", Phase::Transport, Outcome::ProxyRefused) > 0).await;
    assert!(swarm.connection_diagnostics().proxy);
    assert_eq!(
        count(&swarm, "outbound", Phase::Transport, Outcome::Accepted),
        0
    );
    assert_eq!(
        count(&swarm, "outbound", Phase::Handshake, Outcome::Accepted),
        0
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), target.accept())
            .await
            .is_err()
    );
    swarm.stop();
    task.await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn rejected_handshakes_do_not_leak_peer_text_or_admit_connections() {
    let local = listener().await;
    let address = local.local_addr().unwrap();
    // Local key1 is an observer: its native closed handshake filter permits
    // key2 only, so the unknown-key case must fail before install.
    let swarm = Swarm::new(
        config(address.port(), vec![public(2)], vec![], false),
        key(1),
    )
    .unwrap();
    let (task, _) = start(&swarm, local);
    let hostile = b"handshake timeout connection_closed invalid Ed25519 signature";
    assert!(client(2, address, hostile).await.is_err());
    until(|| count(&swarm, "inbound", Phase::Handshake, Outcome::Chain) == 1).await;
    assert!(client(3, address, b"swarm-test").await.is_err());
    until(|| count(&swarm, "inbound", Phase::Handshake, Outcome::UnknownKey) == 1).await;
    let stream = TcpStream::connect(address).await.unwrap();
    let result = session::dial(
        stream,
        &LocalNode {
            chain_id: b"swarm-test".to_vec(),
            node_address: b"client".to_vec(),
            config_hash: [9; 32],
            listen_port: 9001,
            best_epoch: 0,
            best_root: [0; 32],
        },
        &key(2),
        &[],
        &mut OsRng,
        Timeouts {
            handshake_read: WAIT,
            read_idle: WAIT,
            write_idle: WAIT,
        },
    )
    .await;
    assert!(result.is_err());
    until(|| count(&swarm, "inbound", Phase::Handshake, Outcome::Config) == 1).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    frame::write_frame(
        &mut stream,
        &Frame {
            message: 0x01,
            payload: vec![],
        },
        WAIT,
    )
    .await
    .unwrap();
    until(|| count(&swarm, "inbound", Phase::Handshake, Outcome::Frame) == 1).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut forged = LocalNode {
        chain_id: b"swarm-test".to_vec(),
        node_address: b"client".to_vec(),
        config_hash: [1; 32],
        listen_port: 9001,
        best_epoch: 0,
        best_root: [0; 32],
    }
    .fresh_hello(&key(2), &mut OsRng)
    .unwrap();
    forged.signature[0] ^= 1;
    frame::write_frame(
        &mut stream,
        &Frame {
            message: 0x01,
            payload: forged.encode().unwrap(),
        },
        WAIT,
    )
    .await
    .unwrap();
    until(|| count(&swarm, "inbound", Phase::Handshake, Outcome::Signature) == 1).await;
    assert!(swarm.peers().is_empty());
    let encoded = serde_json::to_string(&swarm.connection_diagnostics()).unwrap();
    assert!(!encoded.contains(std::str::from_utf8(hostile).unwrap()));
    assert!(!encoded.contains("public_key"));
    assert!(!encoded.contains("payload"));
    // Refusals must leave ordinary authenticated reconnection intact.
    let mut good = client(2, address, b"swarm-test").await.unwrap();
    until(|| swarm.peers().len() == 1).await;
    for _ in 0..2 {
        good.receive().await.unwrap();
    }
    good.close().await;
    until(|| count(&swarm, "inbound", Phase::Session, Outcome::RemoteClose) == 1).await;
    let mut replacement = client(2, address, b"swarm-test").await.unwrap();
    until(|| count(&swarm, "inbound", Phase::Admission, Outcome::Accepted) == 2).await;
    assert_eq!(swarm.peers().len(), 1);
    for _ in 0..2 {
        replacement.receive().await.unwrap();
    }
    replacement.close().await;
    until(|| count(&swarm, "inbound", Phase::Session, Outcome::RemoteClose) == 2).await;
    swarm.stop();
    task.await.unwrap();
}

#[tokio::test]
async fn established_tcp_read_timeout_is_distinct_from_handshake_failure() {
    let local = listener().await;
    let address = local.local_addr().unwrap();
    let mut cfg = config(address.port(), vec![], vec![], false);
    cfg.timeouts.read_idle = Duration::from_millis(100);
    let swarm = Swarm::new(cfg, key(1)).unwrap();
    let (task, _) = start(&swarm, local);
    let _client = client(2, address, b"swarm-test").await.unwrap();
    until(|| count(&swarm, "inbound", Phase::Session, Outcome::ReadTimeout) == 1).await;
    assert_eq!(
        count(&swarm, "inbound", Phase::Handshake, Outcome::Accepted),
        1
    );
    assert_eq!(
        count(&swarm, "inbound", Phase::Handshake, Outcome::Timeout),
        0
    );
    assert_eq!(
        count(&swarm, "inbound", Phase::Session, Outcome::Cancelled),
        0
    );
    swarm.stop();
    task.await.unwrap();
}
