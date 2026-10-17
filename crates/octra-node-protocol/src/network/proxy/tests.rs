use super::*;
use crate::network::{frame::Frame, session};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::Duration;
use tokio::net::TcpListener;

async fn request(stream: &mut TcpStream) -> (String, u16) {
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).await.unwrap();
    let mut header = [0; 5];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(&header[..4], &[5, 1, 0, 3]);
    let mut name = vec![0; usize::from(header[4])];
    stream.read_exact(&mut name).await.unwrap();
    let port = stream.read_u16().await.unwrap();
    (String::from_utf8(name).unwrap(), port)
}

fn local(key: &SigningKey) -> session::LocalNode {
    session::LocalNode {
        chain_id: b"proxy-test".to_vec(),
        node_address: key.verifying_key().to_bytes().to_vec(),
        config_hash: [3; 32],
        listen_port: 19000,
        best_epoch: 2,
        best_root: [4; 32],
    }
}

#[tokio::test]
async fn remote_dns_transport_preserves_native_peer_authentication() {
    let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = peer.local_addr().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let relay = tokio::spawn(async move {
        let (mut incoming, _) = proxy.accept().await.unwrap();
        assert_eq!(request(&mut incoming).await, ("peer.invalid".into(), 19000));
        let mut outgoing = TcpStream::connect(target).await.unwrap();
        incoming
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
    });
    let server = tokio::spawn(async move {
        let key = SigningKey::from_bytes(&[2; 32]);
        let (stream, _) = peer.accept().await.unwrap();
        let mut connection = session::accept(
            stream,
            &local(&key),
            &key,
            &[],
            &mut OsRng,
            session::Timeouts::default(),
        )
        .await
        .unwrap();
        connection
            .send(&Frame {
                message: 0x10,
                payload: vec![],
            })
            .await
            .unwrap();
    });
    let stream = connect(
        &Endpoint {
            host: b"peer.invalid".to_vec(),
            port: 19000,
        },
        Some(proxy_addr),
    )
    .await
    .unwrap();
    let key = SigningKey::from_bytes(&[1; 32]);
    let remote = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
    let mut connection = session::dial(
        stream,
        &local(&key),
        &key,
        &[remote.to_vec()],
        &mut OsRng,
        session::Timeouts::default(),
    )
    .await
    .unwrap();
    assert_eq!(connection.peer().public_key, remote);
    assert_eq!(connection.receive().await.unwrap().message, 0x10);
    connection.close().await;
    server.await.unwrap();
    relay.await.unwrap();
}

#[tokio::test]
async fn rejected_proxy_never_falls_back_to_reachable_direct_target() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        request(&mut stream).await;
        stream
            .write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });
    let endpoint = Endpoint {
        host: b"127.0.0.1".to_vec(),
        port: target.local_addr().unwrap().port(),
    };
    assert!(connect(&endpoint, Some(proxy_addr)).await.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(30), target.accept())
            .await
            .is_err()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn fixed_socks_failure_reply_is_available_without_changing_public_errors() {
    for reply in [2, 3, 4, 5, 6, 7, 8, 255] {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            request(&mut stream).await;
            stream
                .write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let failure = connect_diagnosed(
            &Endpoint {
                host: b"peer.invalid".to_vec(),
                port: 19000,
            },
            Some(address),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(failure.socks_reply, Some(reply));
        assert_eq!(failure.error.as_bytes(), b"SOCKS5 CONNECT refused");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn malformed_proxy_negotiation_is_refused() {
    for reply in [vec![4, 0], vec![5, 2], vec![5, 0, 5, 0, 0, 9]] {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&reply).await.unwrap();
        });
        assert!(connect(
            &Endpoint {
                host: b"peer.invalid".to_vec(),
                port: 19000
            },
            Some(address)
        )
        .await
        .is_err());
        server.await.unwrap();
    }
    assert!(validate("192.0.2.1:1080".parse().unwrap()).is_err());
    assert!(validate("127.0.0.1:0".parse().unwrap()).is_err());
}

#[tokio::test]
async fn ordinary_direct_transport_is_retained() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint {
        host: b"127.0.0.1".to_vec(),
        port: listener.local_addr().unwrap().port(),
    };
    let _stream = connect(&endpoint, None).await.unwrap();
    listener.accept().await.unwrap();
}

#[tokio::test]
async fn stalled_proxy_has_a_bounded_connection_lifetime() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        let mut byte = [0; 1];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    });
    let started = std::time::Instant::now();
    let error = connect(
        &Endpoint {
            host: b"peer.invalid".to_vec(),
            port: 19000,
        },
        Some(address),
    )
    .await
    .unwrap_err();
    assert_eq!(error.as_bytes(), b"P2P transport connect timeout");
    assert!(started.elapsed() < Duration::from_secs(12));
    server.await.unwrap();
}
