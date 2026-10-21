use ed25519_dalek::SigningKey;
use octra_node_protocol::network::{
    budget::PeerClass,
    endpoint::Endpoint,
    frame::Frame,
    handshake,
    peer_record::{self, Added, Record, Registry},
    session::{self, Connection, LocalNode, Peer, Timeouts},
    swarm::{Activation, Config, Handler, MessageFuture, Outcome, Phase, Swarm},
    swarm_policy,
};
use rand::rngs::OsRng;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
};
const WAIT: Duration = Duration::from_secs(5);
#[path = "network_swarm/diagnostics.rs"]
mod diagnostics;
#[path = "network_swarm/scope.rs"]
mod scope;
struct Inbox(mpsc::UnboundedSender<(Vec<u8>, Frame)>);
impl Handler for Inbox {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        let _ = self.0.send((peer.hello().node_id.clone(), frame));
        Box::pin(async { Ok(()) })
    }
}
struct Connections(mpsc::UnboundedSender<Vec<u8>>);
impl Handler for Connections {
    fn connected(&self, peer: Peer) {
        let _ = self.0.send(peer.hello().node_id.clone());
    }
    fn message(&self, _peer: Peer, _frame: Frame) -> MessageFuture {
        Box::pin(async { Ok(()) })
    }
}
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn public(n: u8) -> Vec<u8> {
    key(n).verifying_key().to_bytes().to_vec()
}
fn signed_record(n: u8, timestamp: i64) -> Record {
    let mut record = Record {
        chain_id: b"swarm-test".to_vec(),
        node_id: vec![],
        node_address: b"record-peer".to_vec(),
        public_key: vec![],
        binary_hash: vec![2; 32],
        config_hash: vec![1; 32],
        host: b"127.0.0.1".to_vec(),
        port: 9000,
        features: vec![],
        timestamp,
        signature: vec![],
    };
    record.sign(&key(n)).unwrap();
    record
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
async fn proxy_selection_is_local_and_immutable_after_startup() {
    let listener = listener().await;
    let address = listener.local_addr().unwrap();
    let swarm = Swarm::new(
        config(address.port(), vec![public(1), public(2)], vec![], false),
        key(1),
    )
    .unwrap();
    assert!(swarm.set_proxy("192.0.2.1:1080".parse().unwrap()).is_err());
    swarm.set_proxy("127.0.0.1:1080".parse().unwrap()).unwrap();
    let (task, _) = start(&swarm, listener);
    let _peer = client(2, address, b"swarm-test").await.unwrap();
    until(|| swarm.peers().len() == 1).await;
    assert!(swarm.set_proxy("127.0.0.1:1081".parse().unwrap()).is_err());
    swarm.stop();
    task.await.unwrap();
}
#[tokio::test]
async fn bootstrap_and_native_frames_use_the_selected_proxy() {
    let al = listener().await;
    let bl = listener().await;
    let target = bl.local_addr().unwrap();
    let proxy = listener().await;
    let proxy_address = proxy.local_addr().unwrap();
    let relay = tokio::spawn(async move {
        let (mut incoming, _) = proxy.accept().await.unwrap();
        let mut greeting = [0; 3];
        incoming.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        incoming.write_all(&[5, 0]).await.unwrap();
        let mut header = [0; 5];
        incoming.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..4], &[5, 1, 0, 3]);
        let mut name = vec![0; usize::from(header[4])];
        incoming.read_exact(&mut name).await.unwrap();
        assert_eq!(name, b"peer.invalid");
        assert_eq!(incoming.read_u16().await.unwrap(), 19000);
        let mut outgoing = TcpStream::connect(target).await.unwrap();
        incoming
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
    });
    let keys = vec![public(1), public(2)];
    let a = Swarm::new(
        config(
            al.local_addr().unwrap().port(),
            keys.clone(),
            vec![Endpoint {
                host: b"peer.invalid".to_vec(),
                port: 19000,
            }],
            false,
        ),
        key(1),
    )
    .unwrap();
    let b = Swarm::new(config(target.port(), keys, vec![], false), key(2)).unwrap();
    a.set_proxy(proxy_address).unwrap();
    let (at, _) = start(&a, al);
    let (bt, mut inbox) = start(&b, bl);
    until(|| a.peers().len() == 1 && b.peers().len() == 1).await;
    let frame = Frame {
        message: 0x20,
        payload: b"authenticated relay transport".to_vec(),
    };
    a.broadcast(frame.clone(), None, true).await.unwrap();
    let (_, delivered) = tokio::time::timeout(WAIT, inbox.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivered, frame);
    a.stop();
    b.stop();
    at.await.unwrap();
    bt.await.unwrap();
    relay.await.unwrap();
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
async fn membership_cutover_closes_retired_peers_when_local_becomes_observer() {
    let listener = listener().await;
    let address = listener.local_addr().unwrap();
    let swarm = Swarm::new(config(address.port(), vec![], vec![], false), key(1)).unwrap();
    swarm.set_validators(vec![public(1), public(2)]).unwrap();
    let (task, _) = start(&swarm, listener);
    let _client = client(2, address, b"swarm-test").await.unwrap();
    until(|| swarm.peers().len() == 1).await;
    let retired = swarm.peers()[0].clone();

    swarm.set_validators(vec![public(3)]).unwrap();
    assert!(swarm.peers().is_empty());
    assert!(!retired.is_connected());
    assert!(
        !swarm
            .send_to(
                &retired.hello().node_id,
                Frame {
                    message: 3,
                    payload: vec![],
                },
            )
            .await
    );
    swarm.stop();
    task.await.unwrap();
}

#[tokio::test]
async fn dead_peer_slot_cannot_bypass_observer_capacity() {
    let listener = listener().await;
    let address = listener.local_addr().unwrap();
    let swarm = Swarm::new(config(address.port(), vec![], vec![], false), key(1)).unwrap();
    swarm.set_validators(vec![public(1)]).unwrap();
    let (connected_tx, mut connected_rx) = mpsc::unbounded_channel();
    let running = swarm.clone();
    let task = tokio::spawn(async move {
        running
            .run(listener, Arc::new(Connections(connected_tx)))
            .await
            .unwrap();
    });
    let mut clients = Vec::new();
    for n in 2..10 {
        clients.push(client(n, address, b"swarm-test").await.unwrap());
        tokio::time::timeout(WAIT, connected_rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    let retired_id = handshake::node_id(&public(2));
    let retired = swarm
        .peers()
        .into_iter()
        .find(|peer| peer.hello().node_id == retired_id)
        .unwrap();
    retired.close();
    clients.push(client(10, address, b"swarm-test").await.unwrap());
    tokio::time::timeout(WAIT, connected_rx.recv())
        .await
        .unwrap()
        .unwrap();
    clients.push(client(2, address, b"swarm-test").await.unwrap());
    until(|| {
        swarm
            .connection_diagnostics()
            .outcomes
            .iter()
            .filter(|row| row.phase == Phase::Admission && row.outcome == Outcome::Capacity)
            .map(|row| row.count)
            .sum::<u64>()
            > 0
    })
    .await;
    assert_eq!(clients.len(), 10);
    assert_eq!(swarm.peers().len(), 8);
    swarm.stop();
    task.await.unwrap();
}

#[test]
fn peer_registry_caps_new_records_but_allows_refresh_and_expiry() {
    let mut registry = Registry::with_capacity(300.0, 4, 2);
    let first = signed_record(1, 1000);
    let second = signed_record(2, 1000);
    let third = signed_record(3, 1000);
    assert_eq!(registry.add(1000.0, first.clone()).unwrap(), Added::New);
    assert_eq!(registry.add(1000.0, second).unwrap(), Added::New);
    assert_eq!(
        registry.add(1000.0, third).unwrap_err().as_bytes(),
        b"registry_capacity"
    );
    assert_eq!(registry.add(1000.0, first).unwrap(), Added::Refreshed);
    assert_eq!(
        registry.add(1301.0, signed_record(3, 1301)).unwrap(),
        Added::New
    );
    assert_eq!(registry.values(1301.0).count(), 1);
}

#[tokio::test]
async fn relayed_peer_records_follow_active_validators() {
    let al = listener().await;
    let bl = listener().await;
    let a = Swarm::new(
        config(al.local_addr().unwrap().port(), vec![], vec![], false),
        key(1),
    )
    .unwrap();
    let b = Swarm::new(
        config(
            bl.local_addr().unwrap().port(),
            vec![],
            vec![endpoint(al.local_addr().unwrap().port())],
            false,
        ),
        key(2),
    )
    .unwrap();
    a.set_validators(vec![public(1), public(2)]).unwrap();
    b.set_validators(vec![public(1), public(2)]).unwrap();
    let (at, _) = start(&a, al);
    let (bt, _) = start(&b, bl);
    until(|| a.peers().len() == 1 && b.peers().len() == 1).await;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let outsider = signed_record(3, timestamp);
    let prior_rejections = a.diagnostics().relayed_records.rejected;
    assert!(
        b.send_to(
            a.node_id(),
            Frame {
                message: 0x11,
                payload: peer_record::encode_list(std::slice::from_ref(&outsider)).unwrap(),
            }
        )
        .await
    );
    until(|| a.diagnostics().relayed_records.rejected > prior_rejections).await;
    assert!(!a.records().iter().any(|r| r.node_id == outsider.node_id));

    let active = signed_record(2, timestamp);
    let prior_admissions = {
        let relayed = a.diagnostics().relayed_records;
        relayed.accepted + relayed.unchanged
    };
    assert!(
        b.send_to(
            a.node_id(),
            Frame {
                message: 0x11,
                payload: peer_record::encode_list(std::slice::from_ref(&active)).unwrap(),
            }
        )
        .await
    );
    until(|| {
        let relayed = a.diagnostics().relayed_records;
        relayed.accepted + relayed.unchanged > prior_admissions
    })
    .await;
    assert!(a.records().iter().any(|r| r.node_id == active.node_id));

    a.set_validators(vec![public(1)]).unwrap();
    assert!(a.records().is_empty());
    let retired = signed_record(2, timestamp);
    let prior_rejections = a.diagnostics().relayed_records.rejected;
    assert!(
        b.send_to(
            a.node_id(),
            Frame {
                message: 0x11,
                payload: peer_record::encode_list(std::slice::from_ref(&retired)).unwrap(),
            }
        )
        .await
    );
    until(|| a.diagnostics().relayed_records.rejected > prior_rejections).await;
    assert!(!a.records().iter().any(|r| r.node_id == retired.node_id));
    a.stop();
    b.stop();
    at.await.unwrap();
    bt.await.unwrap();
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
