use ed25519_dalek::SigningKey;
use octra_node_protocol::network::{
    endpoint::Endpoint,
    frame::Frame,
    handshake,
    session::{Peer, Timeouts},
    swarm::{Activation, Config, Handler, MessageFuture, Swarm},
    transaction_gossip::Message,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::mpsc};
struct Inbox(mpsc::UnboundedSender<(Vec<u8>, Frame)>);
impl Handler for Inbox {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        self.0.send((peer.hello().node_id.clone(), frame)).unwrap();
        Box::pin(async { Ok(()) })
    }
}
async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
#[ignore = "run with scripts/node-port/test-native-peer.py and its isolated native peer"]
async fn rust_swarm_interoperates_with_pinned_ocaml_swarm() {
    let remote: SocketAddr = std::env::var("OCTRA_NATIVE_PEER")
        .expect("native peer address")
        .parse()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let key = SigningKey::from_bytes(&[42; 32]);
    let native = SigningKey::from_bytes(&[77; 32])
        .verifying_key()
        .to_bytes()
        .to_vec();
    let native_id = handshake::node_id(&native);
    let s = Swarm::new(
        Config {
            chain_id: b"native-swarm-interop".to_vec(),
            node_address: b"rust-native".to_vec(),
            config_hash: vec![1; 32],
            binary_hash: vec![2; 32],
            require_binary_hash: false,
            upgrade: None,
            profiles: vec![Activation {
                epoch: 5,
                config_hash: vec![3; 32],
                profile_hash: b"profile-five".to_vec(),
            }],
            allowed_public_keys: vec![native.clone(), key.verifying_key().to_bytes().to_vec()],
            bootstrap: vec![Endpoint {
                host: remote.ip().to_string().into_bytes(),
                port: remote.port(),
            }],
            maximum_validators: 4,
            advertised: Endpoint {
                host: b"127.0.0.1".to_vec(),
                port,
            },
            timeouts: Timeouts::default(),
            head: Arc::new(|| (0, [0; 32])),
        },
        key,
    )
    .unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let owner = s.clone();
    let task = tokio::spawn(async move {
        owner.run(listener, Arc::new(Inbox(tx))).await.unwrap();
    });
    until(|| {
        s.peers().len() == 1
            && s.records().iter().any(|r| r.node_id == native_id)
            && s.profile_offer(&native_id, 5) == Some(vec![3; 32])
    })
    .await;
    assert_eq!(s.peers()[0].hello().public_key, native);
    let record = s
        .records()
        .into_iter()
        .find(|r| r.node_id == native_id)
        .unwrap();
    record
        .validate(b"native-swarm-interop", &[1; 32], Some(&[2; 32]), &[])
        .unwrap();
    assert_eq!(record.features, [b"bft".to_vec(), b"pex".to_vec()]);
    let payload = b"byte-exact Rust to OCaml echo".to_vec();
    assert!(
        s.send_to(
            &native_id,
            Frame {
                message: 3,
                payload: payload.clone()
            }
        )
        .await
    );
    let (from, reply) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, native_id);
    assert_eq!(
        reply,
        Frame {
            message: 4,
            payload
        }
    );
    let hashes = vec![b"AB".repeat(32), b"01".repeat(32)];
    let inventory = Message::Inventory(hashes.clone()).encode().unwrap();
    assert!(
        s.send_to(
            &native_id,
            Frame {
                message: 0x20,
                payload: inventory
            }
        )
        .await
    );
    let (from, reply) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, native_id);
    assert_eq!(reply.message, 0x20);
    assert_eq!(
        Message::decode(&reply.payload).unwrap(),
        Message::Get(hashes.iter().map(|h| h.to_ascii_lowercase()).collect())
    );
    s.stop();
    task.await.unwrap();
    assert!(s.peers().is_empty());
}
