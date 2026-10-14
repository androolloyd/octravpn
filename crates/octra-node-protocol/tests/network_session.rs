use ed25519_dalek::SigningKey;
use octra_node_protocol::network::{
    frame::{self, Frame},
    handshake::{Ack, Finish, Hello},
    session::{self, Connection, LocalNode, Timeouts},
};
use rand::{rngs::StdRng, SeedableRng};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, DuplexStream};
fn local() -> LocalNode {
    LocalNode {
        chain_id: b"native-test-chain".to_vec(),
        node_address: b"node-address".to_vec(),
        config_hash: [7; 32],
        listen_port: 9000,
        best_epoch: 123,
        best_root: [8; 32],
    }
}
fn timeouts() -> Timeouts {
    Timeouts {
        handshake_read: Duration::from_millis(100),
        read_idle: Duration::from_millis(100),
        write_idle: Duration::from_millis(100),
    }
}
async fn pair() -> (Connection<DuplexStream>, Connection<DuplexStream>) {
    let (dial_stream, accept_stream) = tokio::io::duplex(64);
    let local = local();
    let dial_key = SigningKey::from_bytes(&[1; 32]);
    let accept_key = SigningKey::from_bytes(&[2; 32]);
    let mut dial_rng = StdRng::seed_from_u64(1);
    let mut accept_rng = StdRng::seed_from_u64(2);
    let (dial, accept) = tokio::join!(
        session::dial(
            dial_stream,
            &local,
            &dial_key,
            &[],
            &mut dial_rng,
            timeouts()
        ),
        session::accept(
            accept_stream,
            &local,
            &accept_key,
            &[],
            &mut accept_rng,
            timeouts()
        )
    );
    (dial.unwrap(), accept.unwrap())
}
#[tokio::test]
async fn authenticated_fragmented_exchange_and_independent_reconnect() {
    let (mut dial, mut accept) = pair().await;
    assert_eq!(
        dial.peer().public_key,
        SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes()
    );
    assert_eq!(
        accept.peer().public_key,
        SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes()
    );
    for message in [3, 49, 55] {
        let sent = Frame {
            message,
            payload: vec![message; 1500],
        };
        let (sent_result, received) = tokio::join!(dial.send(&sent), accept.receive());
        sent_result.unwrap();
        assert_eq!(received.unwrap(), sent);
    }
    dial.close().await;
    assert_eq!(
        accept.receive().await.unwrap_err().as_bytes(),
        b"connection_closed"
    );
    assert!(accept.is_closed());
    assert_eq!(
        accept.receive().await.unwrap_err().as_bytes(),
        b"connection_closed"
    );
    let (mut again, mut remote) = pair().await;
    let ping = Frame {
        message: 3,
        payload: vec![],
    };
    let (sent, received) = tokio::join!(again.send(&ping), remote.receive());
    sent.unwrap();
    assert_eq!(received.unwrap(), ping);
}
#[tokio::test]
async fn reconnect_replay_of_ack_fails_with_fresh_challenge() {
    let node = local();
    let key = SigningKey::from_bytes(&[1; 32]);
    let remote_key = SigningKey::from_bytes(&[2; 32]);
    let mut rng = StdRng::seed_from_u64(17);
    let mut remote_rng = StdRng::seed_from_u64(31);
    let previous = node.fresh_hello(&key, &mut rng).unwrap();
    let remote = node.fresh_hello(&remote_key, &mut remote_rng).unwrap();
    let replay = Ack::new(remote, previous.nonce.clone(), &remote_key).unwrap();
    let (stream, mut attacker) = tokio::io::duplex(1024);
    let attack = async {
        let received = frame::read_frame(&mut attacker, Duration::from_secs(1), 65536)
            .await
            .unwrap();
        let current = Hello::decode(&received.payload).unwrap();
        assert_ne!(current.nonce, previous.nonce);
        frame::write_frame(
            &mut attacker,
            &Frame {
                message: 2,
                payload: replay.encode().unwrap(),
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    };
    let (result, ()) = tokio::join!(
        session::dial(stream, &node, &key, &[], &mut rng, timeouts()),
        attack
    );
    assert_eq!(
        result.err().unwrap().as_bytes(),
        b"HELLO_ACK challenge mismatch"
    );
}
#[tokio::test]
async fn reconnect_replay_of_finish_cannot_authenticate_a_peer() {
    let node = local();
    let key = SigningKey::from_bytes(&[1; 32]);
    let remote_key = SigningKey::from_bytes(&[2; 32]);
    let mut rng = StdRng::seed_from_u64(11);
    let mut remote_rng = StdRng::seed_from_u64(13);
    let initiator = node.fresh_hello(&key, &mut rng).unwrap();
    let prior_responder = node.fresh_hello(&remote_key, &mut remote_rng).unwrap();
    let replay = Finish::new(&initiator, &prior_responder, &key).unwrap();
    let (stream, mut attacker) = tokio::io::duplex(1024);
    let attack = async {
        frame::write_frame(
            &mut attacker,
            &Frame {
                message: 1,
                payload: initiator.encode().unwrap(),
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let response = frame::read_frame(&mut attacker, Duration::from_secs(1), 65536)
            .await
            .unwrap();
        let ack = Ack::decode(&response.payload).unwrap();
        assert_ne!(ack.hello.nonce, prior_responder.nonce);
        frame::write_frame(
            &mut attacker,
            &Frame {
                message: 5,
                payload: replay.encode().unwrap(),
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    };
    let (result, ()) = tokio::join!(
        session::accept(stream, &node, &remote_key, &[], &mut remote_rng, timeouts()),
        attack
    );
    assert_eq!(
        result.err().unwrap().as_bytes(),
        b"HELLO_FINISH challenge mismatch"
    );
}
#[tokio::test]
async fn invalid_allowlist_and_chain_never_create_authenticated_receiver() {
    let node = local();
    let key = SigningKey::from_bytes(&[1; 32]);
    let remote_key = SigningKey::from_bytes(&[2; 32]);
    for wrong_chain in [false, true] {
        let mut remote_node = node.clone();
        if wrong_chain {
            remote_node.chain_id = b"other".to_vec();
        }
        let mut rng = StdRng::seed_from_u64(5);
        let mut remote_rng = StdRng::seed_from_u64(6);
        let (stream, remote) = tokio::io::duplex(1024);
        let allowed = vec![vec![0; 32]];
        let (dial, accept) = tokio::join!(
            session::dial(stream, &node, &key, &[], &mut rng, timeouts()),
            session::accept(
                remote,
                &remote_node,
                &remote_key,
                &allowed,
                &mut remote_rng,
                timeouts()
            )
        );
        assert!(dial.is_err());
        let error = accept.err().unwrap();
        assert!(error.as_bytes().starts_with(if wrong_chain {
            b"chain_id mismatch"
        } else {
            b"unknown validator pubkey"
        }));
    }
}
#[tokio::test]
async fn timeouts_and_partial_read_cancellation_poison_connection() {
    let (stream, _silent) = tokio::io::duplex(1024);
    let node = local();
    let key = SigningKey::from_bytes(&[1; 32]);
    let mut rng = StdRng::seed_from_u64(9);
    let result = session::accept(stream, &node, &key, &[], &mut rng, timeouts()).await;
    assert_eq!(result.err().unwrap().as_bytes(), b"handshake timeout");
    let (mut local, _remote) = pair().await;
    assert_eq!(
        local.receive().await.unwrap_err().as_bytes(),
        b"read timeout"
    );
    assert!(local.is_closed());
    let (mut local, _remote) = pair().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(2), local.receive())
            .await
            .is_err()
    );
    assert!(local.is_closed());
    assert_eq!(
        local.receive().await.unwrap_err().as_bytes(),
        b"connection_closed"
    );
}
#[tokio::test]
async fn write_idle_and_cancelled_partial_frame_fail_closed() {
    let (mut local, _remote) = pair().await;
    let message = Frame {
        message: 3,
        payload: vec![0; 4096],
    };
    assert_eq!(
        local.send(&message).await.unwrap_err().as_bytes(),
        b"write timeout"
    );
    assert!(local.is_closed());
    let (mut local, _remote) = pair().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(2), local.send(&message))
            .await
            .is_err()
    );
    assert!(local.is_closed());
    assert_eq!(
        local.send(&message).await.unwrap_err().as_bytes(),
        b"connection_closed"
    );
}
#[tokio::test]
async fn malformed_or_oversized_handshake_fails_before_payload_is_read() {
    let node = local();
    let key = SigningKey::from_bytes(&[1; 32]);
    for (wire, expected) in [
        (
            vec![0, 1, 0, 2, 55],
            b"handshake failed: Failure(\"frame_payload_limit size = 65537 max = 65536\")".to_vec(),
        ),
        (vec![0, 0, 0, 1, 3], b"expected HELLO, got 0x03".to_vec()),
    ] {
        let (stream, mut remote) = tokio::io::duplex(32);
        remote.write_all(&wire).await.unwrap();
        let mut rng = StdRng::seed_from_u64(10);
        let result = session::accept(stream, &node, &key, &[], &mut rng, timeouts()).await;
        assert_eq!(result.err().unwrap().as_bytes(), expected);
    }
}
