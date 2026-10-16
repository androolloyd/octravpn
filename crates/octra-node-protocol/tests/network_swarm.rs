use ed25519_dalek::SigningKey;
use octra_node_protocol::network::{
    budget::PeerClass,
    endpoint::Endpoint,
    frame::Frame,
    handshake,
    session::{self, Connection, LocalNode, Peer, Timeouts},
    swarm::{Activation, Config, Handler, MessageFuture, Swarm},
    swarm_policy,
};
use rand::rngs::OsRng;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
};
const WAIT: Duration = Duration::from_secs(5);
struct Inbox(mpsc::UnboundedSender<(Vec<u8>, Frame)>);
impl Handler for Inbox {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        let _ = self.0.send((peer.hello().node_id.clone(), frame));
        Box::pin(async { Ok(()) })
    }
}
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn public(n: u8) -> Vec<u8> {
    key(n).verifying_key().to_bytes().to_vec()
}
fn config(port: u16, allowed: Vec<Vec<u8>>, bootstrap: Vec<Endpoint>, profiles: bool) -> Config {
    Config {
        chain_id: b"swarm-test".to_vec(),
        node_address: b"node".to_vec(),
        config_hash: vec![1; 32],
        binary_hash: vec![2; 32],
        require_binary_hash: false,
        upgrade: None,
        profiles: if profiles {
            vec![Activation {
                epoch: 5,
                config_hash: vec![3; 32],
                profile_hash: b"profile-five".to_vec(),
            }]
        } else {
            vec![]
        },
        allowed_public_keys: allowed,
        bootstrap,
        maximum_validators: 16,
        advertised: endpoint(port),
        timeouts: Timeouts {
            handshake_read: WAIT,
            read_idle: Duration::from_secs(60),
            write_idle: WAIT,
        },
        head: Arc::new(|| (0, [0; 32])),
    }
}
fn endpoint(port: u16) -> Endpoint {
    Endpoint {
        host: b"127.0.0.1".to_vec(),
        port,
    }
}
async fn listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}
fn start(s: &Swarm, l: TcpListener) -> (JoinHandle<()>, mpsc::UnboundedReceiver<(Vec<u8>, Frame)>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let s = s.clone();
    (
        tokio::spawn(async move {
            s.run(l, Arc::new(Inbox(tx))).await.unwrap();
        }),
        rx,
    )
}
async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("swarm condition timed out");
}
async fn client(
    n: u8,
    address: SocketAddr,
    chain: &[u8],
) -> Result<Connection<TcpStream>, octra_node_protocol::network::Error> {
    let stream = TcpStream::connect(address).await.unwrap();
    session::dial(
        stream,
        &LocalNode {
            chain_id: chain.to_vec(),
            node_address: b"client".to_vec(),
            config_hash: [1; 32],
            listen_port: 9001,
            best_epoch: 0,
            best_root: [0; 32],
        },
        &key(n),
        &[],
        &mut OsRng,
        Timeouts {
            handshake_read: WAIT,
            read_idle: WAIT,
            write_idle: WAIT,
        },
    )
    .await
}
#[tokio::test]
async fn handshake_keys_do_not_select_scheduled_or_unknown_validators() {
    // Cover native dynamic admission and a scheduled key already allowed by a
    // closed handshake filter. Both remain observers until actual selection.
    for (peer_key, handshake_keys) in [
        (3, vec![]),
        // Native bound active/scheduled admission lists can repeat keys. Only
        // the separately installed selected validator set requires uniqueness.
        (2, vec![public(1), public(2), public(1)]),
    ] {
        let al = listener().await;
        let bl = listener().await;
        let original = vec![public(1)];
        let a = Swarm::new(
            config(
                al.local_addr().unwrap().port(),
                handshake_keys.clone(),
                vec![endpoint(bl.local_addr().unwrap().port())],
                false,
            ),
            key(1),
        )
        .unwrap();
        let b = Swarm::new(
            config(
                bl.local_addr().unwrap().port(),
                handshake_keys,
                vec![],
                false,
            ),
            key(peer_key),
        )
        .unwrap();
        // The native startup installs independently authenticated membership after
        // choosing its open handshake policy. A connection cannot add a voter.
        a.set_validators(original.clone()).unwrap();
        b.set_validators(original.clone()).unwrap();
        let (bt, _) = start(&b, bl);
        let (at, _) = start(&a, al);
        until(|| a.peers().len() == 1 && b.peers().len() == 1).await;
        assert_eq!(
            a.direction(b.node_id()),
            Some(swarm_policy::Direction::Outbound)
        );
        assert_eq!(a.peers()[0].peer_class(), PeerClass::Observer);
        assert_eq!(b.peers()[0].peer_class(), PeerClass::Validator);
        let selected = vec![public(1), public(peer_key)];
        a.set_validators(selected.clone()).unwrap();
        b.set_validators(selected).unwrap();
        assert_eq!(a.peers()[0].peer_class(), PeerClass::Validator);
        a.set_validators(original).unwrap();
        assert_eq!(a.peers()[0].peer_class(), PeerClass::Observer);
        a.stop();
        b.stop();
        at.await.unwrap();
        bt.await.unwrap();
    }
}

#[tokio::test]
async fn signed_discovery_builds_mesh_and_delivers_native_frames() {
    let al = listener().await;
    let bl = listener().await;
    let cl = listener().await;
    let bp = bl.local_addr().unwrap().port();
    let keys = vec![public(1), public(2), public(3)];
    let a = Swarm::new(
        config(
            al.local_addr().unwrap().port(),
            keys.clone(),
            vec![endpoint(bp)],
            true,
        ),
        key(1),
    )
    .unwrap();
    let b = Swarm::new(config(bp, keys.clone(), vec![], true), key(2)).unwrap();
    let c = Swarm::new(
        config(
            cl.local_addr().unwrap().port(),
            keys,
            vec![endpoint(bp)],
            false,
        ),
        key(3),
    )
    .unwrap();
    assert!(a
        .broadcast(
            Frame {
                message: 3,
                payload: vec![]
            },
            None,
            true
        )
        .await
        .is_err());
    let (bt, mut br) = start(&b, bl);
    let (at, _ar) = start(&a, al);
    until(|| b.records().iter().any(|r| r.node_id == a.node_id())).await;
    let (ct, mut cr) = start(&c, cl);
    until(|| a.peers().len() == 2 && b.peers().len() == 2 && c.peers().len() == 2).await;
    let frame = Frame {
        message: 0x20,
        payload: b"opaque native transaction bytes".to_vec(),
    };
    a.broadcast(frame.clone(), None, true).await.unwrap();
    let (sender, received) = tokio::time::timeout(WAIT, cr.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sender, a.node_id());
    assert_eq!(received, frame);
    let (sender, received) = tokio::time::timeout(WAIT, br.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sender, a.node_id());
    assert_eq!(received, frame);
    assert!(a
        .peers()
        .iter()
        .all(|p| p.peer_class() == PeerClass::Validator));
    // PROFILE is authenticated independently of record discovery. Only the peer
    // which offered the target profile is retained at activation.
    until(|| b.profile_offer(a.node_id(), 5) == Some(vec![3; 32])).await;
    assert_eq!(b.switch_profile(5).unwrap(), b"profile-five");
    assert_eq!(b.peers().len(), 1);
    assert_eq!(b.peers()[0].hello().node_id, a.node_id());
    a.switch_profile(5).unwrap();
    assert!(
        b.send_to(
            a.node_id(),
            Frame {
                message: 3,
                payload: vec![]
            }
        )
        .await
    );
    a.stop();
    b.stop();
    c.stop();
    at.await.unwrap();
    bt.await.unwrap();
    ct.await.unwrap();
    assert!(a.peers().is_empty());
    assert!(b.peers().is_empty());
    assert!(c.peers().is_empty());
}
#[tokio::test]
async fn simultaneous_dials_converge_and_stale_shutdown_cannot_install_peers() {
    let al = listener().await;
    let bl = listener().await;
    let ap = al.local_addr().unwrap().port();
    let bp = bl.local_addr().unwrap().port();
    let keys = vec![public(1), public(2)];
    let a = Swarm::new(config(ap, keys.clone(), vec![endpoint(bp)], false), key(1)).unwrap();
    let b = Swarm::new(config(bp, keys, vec![endpoint(ap)], false), key(2)).unwrap();
    let (at, _) = start(&a, al);
    let (bt, _) = start(&b, bl);
    until(|| {
        a.peers().len() == 1
            && b.peers().len() == 1
            && a.direction(b.node_id())
                == Some(swarm_policy::preferred_direction(a.node_id(), b.node_id()))
            && b.direction(a.node_id())
                == Some(swarm_policy::preferred_direction(b.node_id(), a.node_id()))
    })
    .await;
    let old = a.peers()[0].clone();
    let mut silent = TcpStream::connect(("127.0.0.1", ap)).await.unwrap();
    a.stop();
    at.await.unwrap();
    assert!(!old.is_connected());
    assert!(a.peers().is_empty());
    let mut byte = [0; 1];
    match tokio::time::timeout(WAIT, silent.read(&mut byte))
        .await
        .unwrap()
    {
        Ok(n) => assert_eq!(n, 0),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
    }
    let renewed = TcpListener::bind(("127.0.0.1", ap)).await.unwrap();
    let (at, _) = start(&a, renewed);
    until(|| a.peers().len() == 1 && b.peers().len() == 1).await;
    assert!(!old.is_connected());
    assert!(
        !old.enqueue(
            Frame {
                message: 3,
                payload: vec![]
            },
            WAIT
        )
        .await
    );
    a.stop();
    b.stop();
    at.await.unwrap();
    bt.await.unwrap();
}
#[tokio::test]
async fn observers_are_bounded_and_identity_bans_survive_reconnect() {
    let l = listener().await;
    let address = l.local_addr().unwrap();
    let server = Swarm::new(
        config(address.port(), vec![public(1)], vec![], false),
        key(1),
    )
    .unwrap();
    let (task, _) = start(&server, l);
    assert!(client(2, address, b"foreign-chain").await.is_err());
    assert!(server.peers().is_empty());
    let mut clients = vec![];
    for n in 2..10 {
        clients.push(client(n, address, b"swarm-test").await.unwrap());
    }
    until(|| server.peers().len() == 8).await;
    assert!(server
        .peers()
        .iter()
        .all(|p| p.peer_class() == PeerClass::Observer));
    let mut excess = client(10, address, b"swarm-test").await.unwrap();
    assert!(excess.receive().await.is_err());
    assert_eq!(server.peers().len(), 8);
    for _ in 0..3 {
        clients[0]
            .send(&Frame {
                message: 0x11,
                payload: vec![0xff],
            })
            .await
            .unwrap();
    }
    let id = handshake::node_id(&public(2));
    until(|| {
        server
            .scores()
            .iter()
            .any(|(k, s)| k == &[b"node:".as_slice(), &id].concat() && s.bad_count == 3)
    })
    .await;
    until(|| server.peers().len() == 7).await;
    let mut replay = client(2, address, b"swarm-test").await.unwrap();
    assert!(replay.receive().await.is_err());
    assert_eq!(server.peers().len(), 7);
    server.stop();
    task.await.unwrap();
}
