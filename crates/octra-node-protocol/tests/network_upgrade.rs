use ed25519_dalek::SigningKey;
use octra_node_protocol::network::{
    endpoint::Endpoint,
    frame::Frame,
    handshake,
    session::{self, Connection, LocalNode, Peer, Timeouts},
    swarm::{Activation, Config, Handler, MessageFuture, Swarm},
    upgrade::{self, Plan},
    Error,
};
use rand::rngs::OsRng;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
};

const WAIT: Duration = Duration::from_secs(5);
const BASE_CONSENSUS: [u8; 32] = [0x11; 32];
const TARGET_CONSENSUS: [u8; 32] = [0x12; 32];
const ROLLBACK_CONSENSUS: [u8; 32] = [0x13; 32];
const BASE_TRANSPORT: [u8; 32] = [0x21; 32];
const TARGET_TRANSPORT: [u8; 32] = [0x22; 32];
const ROLLBACK_TRANSPORT: [u8; 32] = [0x23; 32];
const OLD_BINARY: [u8; 32] = [0x31; 32];
const NEW_BINARY: [u8; 32] = [0x32; 32];
const UPGRADE_EPOCH: &str = "OCTRA_P2P_UPGRADE_ACTIVATE_EPOCH";
const UPGRADE_BINARY: &str = "OCTRA_P2P_UPGRADE_BINARY_HASH";
const UPGRADE_CONFIG: &str = "OCTRA_P2P_UPGRADE_CONFIG_HASH";
const ROLLBACK_EPOCH: &str = "OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH";
const ROLLBACK_BINARY: &str = "OCTRA_P2P_ROLLBACK_BINARY_HASH";
const ROLLBACK_CONFIG: &str = "OCTRA_P2P_ROLLBACK_CONFIG_HASH";

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn public(n: u8) -> Vec<u8> {
    key(n).verifying_key().to_bytes().to_vec()
}
fn plan(overrides: &[(&'static str, Vec<u8>)]) -> Plan {
    // Capture trusted launcher inputs without mutating the process environment.
    let mut inputs = BTreeMap::from([
        (UPGRADE_EPOCH, b"10".to_vec()),
        (UPGRADE_BINARY, hex::encode(NEW_BINARY).into_bytes()),
        (UPGRADE_CONFIG, hex::encode(TARGET_CONSENSUS).into_bytes()),
        (ROLLBACK_EPOCH, b"20".to_vec()),
        (ROLLBACK_BINARY, hex::encode(OLD_BINARY).into_bytes()),
        (
            ROLLBACK_CONFIG,
            hex::encode(ROLLBACK_CONSENSUS).into_bytes(),
        ),
    ]);
    inputs.extend(overrides.iter().cloned());
    upgrade::from_inputs(&BASE_CONSENSUS, true, |name| {
        inputs.get(name).map(Vec::as_slice)
    })
    .unwrap()
    .unwrap()
}
fn timeouts() -> Timeouts {
    Timeouts {
        handshake_read: WAIT,
        read_idle: WAIT,
        write_idle: WAIT,
    }
}
fn config(
    port: u16,
    epoch: i64,
    transport: [u8; 32],
    binary: [u8; 32],
    plan: &Plan,
    profiles: Vec<Activation>,
) -> Config {
    Config {
        chain_id: b"upgrade-tcp-test".to_vec(),
        node_address: b"server".to_vec(),
        config_hash: transport.to_vec(),
        binary_hash: binary.to_vec(),
        require_binary_hash: true,
        upgrade: Some(plan.clone()),
        profiles,
        allowed_public_keys: vec![public(1), public(2)],
        bootstrap: vec![],
        maximum_validators: 16,
        advertised: Endpoint {
            host: b"127.0.0.1".to_vec(),
            port,
        },
        timeouts: timeouts(),
        head: Arc::new(move || (epoch, [0; 32])),
    }
}
struct Inbox(mpsc::UnboundedSender<(Vec<u8>, Frame)>);
impl Handler for Inbox {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        let _ = self.0.send((peer.hello().node_id.clone(), frame));
        Box::pin(async { Ok(()) })
    }
}
struct Node {
    swarm: Swarm,
    address: SocketAddr,
    inbox: mpsc::UnboundedReceiver<(Vec<u8>, Frame)>,
    task: Option<JoinHandle<Result<(), Error>>>,
}
impl Drop for Node {
    fn drop(&mut self) {
        self.swarm.stop();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl Node {
    async fn start(
        epoch: i64,
        transport: [u8; 32],
        binary: [u8; 32],
        plan: &Plan,
        profiles: Vec<Activation>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let swarm = Swarm::new(
            config(address.port(), epoch, transport, binary, plan, profiles),
            key(1),
        )
        .unwrap();
        let (tx, inbox) = mpsc::unbounded_channel();
        let owner = swarm.clone();
        let task = tokio::spawn(async move { owner.run(listener, Arc::new(Inbox(tx))).await });
        Self {
            swarm,
            address,
            inbox,
            task: Some(task),
        }
    }
    async fn dial(
        &self,
        epoch: i64,
        transport: [u8; 32],
        binary: [u8; 32],
        plan: &Plan,
    ) -> Result<Connection<TcpStream>, Error> {
        // A refused TCP connection or a hung handshake is a test failure, never
        // evidence that incompatible upgrade schedules were rejected.
        let stream = tokio::time::timeout(WAIT, TcpStream::connect(self.address))
            .await
            .expect("upgrade listener was unreachable")
            .expect("upgrade TCP connection failed");
        let hello = LocalNode {
            chain_id: b"upgrade-tcp-test".to_vec(),
            node_address: b"client".to_vec(),
            config_hash: upgrade::handshake_hash(epoch, &transport, &binary, true, Some(plan))
                .unwrap()
                .try_into()
                .unwrap(),
            listen_port: 9001,
            best_epoch: epoch,
            best_root: [0; 32],
        };
        tokio::time::timeout(
            WAIT,
            session::dial(
                stream,
                &hello,
                &key(2),
                &[public(1)],
                &mut OsRng,
                timeouts(),
            ),
        )
        .await
        .expect("upgrade handshake hung")
    }
    async fn rejected(&self, epoch: i64, transport: [u8; 32], binary: [u8; 32], plan: &Plan) {
        let Err(error) = self.dial(epoch, transport, binary, plan).await else {
            panic!("incompatible upgrade transport authenticated");
        };
        assert_eq!(
            error.as_bytes(),
            b"handshake failed: Failure(\"connection_closed\")"
        );
        assert!(self.swarm.peers().is_empty());
        assert!(!self.task.as_ref().unwrap().is_finished());
    }
    async fn exchange(&mut self, connection: &mut Connection<TcpStream>) {
        assert_eq!(connection.peer().node_id, self.swarm.node_id());
        assert_eq!(connection.peer().public_key, public(1));
        let request = Frame {
            message: 0x20,
            payload: b"authenticated upgrade request".to_vec(),
        };
        tokio::time::timeout(WAIT, connection.send(&request))
            .await
            .unwrap()
            .unwrap();
        let (sender, received) = tokio::time::timeout(WAIT, self.inbox.recv())
            .await
            .expect("authenticated peer was not installed")
            .unwrap();
        assert_eq!(sender, handshake::node_id(&public(2)));
        assert_eq!(received, request);
        let reply = Frame {
            message: 0x21,
            payload: b"authenticated upgrade reply".to_vec(),
        };
        assert!(
            tokio::time::timeout(WAIT, self.swarm.send_to(&sender, reply.clone()))
                .await
                .unwrap()
        );
        tokio::time::timeout(WAIT, async {
            loop {
                let frame = connection.receive().await.unwrap();
                if matches!(frame.message, 0x10..=0x12) {
                    continue;
                }
                assert_eq!(frame, reply);
                break;
            }
        })
        .await
        .expect("authenticated return traffic was not delivered");
    }
    async fn accepted(&mut self, epoch: i64, transport: [u8; 32], binary: [u8; 32], plan: &Plan) {
        let mut connection = self.dial(epoch, transport, binary, plan).await.unwrap();
        self.exchange(&mut connection).await;
        connection.close().await;
        tokio::time::timeout(WAIT, async {
            while !self.swarm.peers().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("closed upgrade peer remained installed");
    }
    async fn stop(mut self) {
        self.swarm.stop();
        tokio::time::timeout(WAIT, self.task.as_mut().unwrap())
            .await
            .expect("upgrade listener did not stop")
            .unwrap()
            .unwrap();
        let _ = self.task.take();
    }
}

#[tokio::test]
async fn trusted_schedule_allows_mixed_binaries_before_activation() {
    let plan = plan(&[]);
    for epoch in [0, 9] {
        for (server, client) in [(OLD_BINARY, NEW_BINARY), (NEW_BINARY, OLD_BINARY)] {
            let mut node = Node::start(epoch, BASE_TRANSPORT, server, &plan, vec![]).await;
            node.accepted(epoch, BASE_TRANSPORT, client, &plan).await;
            node.stop().await;
        }
    }
}

#[tokio::test]
async fn every_trusted_schedule_field_is_bound_before_activation() {
    let trusted = plan(&[]);
    for change in [
        (UPGRADE_EPOCH, b"11".to_vec()),
        (UPGRADE_BINARY, vec![0x40; 32]),
        (UPGRADE_CONFIG, vec![0x41; 32]),
        (ROLLBACK_EPOCH, b"21".to_vec()),
        (ROLLBACK_BINARY, vec![0x42; 32]),
        (ROLLBACK_CONFIG, vec![0x43; 32]),
    ] {
        let remote = plan(&[change]);
        let mut node = Node::start(9, BASE_TRANSPORT, OLD_BINARY, &trusted, vec![]).await;
        node.rejected(9, BASE_TRANSPORT, NEW_BINARY, &remote).await;
        // Positive control on the same listener excludes dead listener/guard
        // failure as the negative compatibility oracle.
        node.accepted(9, BASE_TRANSPORT, NEW_BINARY, &trusted).await;
        node.stop().await;
    }
    let mut node = Node::start(9, BASE_TRANSPORT, OLD_BINARY, &trusted, vec![]).await;
    node.rejected(9, TARGET_TRANSPORT, NEW_BINARY, &trusted)
        .await;
    node.accepted(9, BASE_TRANSPORT, NEW_BINARY, &trusted).await;
    node.stop().await;
}

#[tokio::test]
async fn activation_requires_matching_running_binary_and_transport() {
    let plan = plan(&[]);
    for epoch in [10, 19] {
        let mut node = Node::start(epoch, TARGET_TRANSPORT, NEW_BINARY, &plan, vec![]).await;
        node.rejected(epoch, TARGET_TRANSPORT, OLD_BINARY, &plan)
            .await;
        node.rejected(epoch, BASE_TRANSPORT, NEW_BINARY, &plan)
            .await;
        node.rejected(9, BASE_TRANSPORT, OLD_BINARY, &plan).await;
        node.accepted(epoch, TARGET_TRANSPORT, NEW_BINARY, &plan)
            .await;
        node.stop().await;
    }
}

#[tokio::test]
async fn rollback_requires_matching_running_binary_and_transport() {
    let plan = plan(&[]);
    for epoch in [20, 21] {
        let mut node = Node::start(epoch, ROLLBACK_TRANSPORT, OLD_BINARY, &plan, vec![]).await;
        node.rejected(epoch, ROLLBACK_TRANSPORT, NEW_BINARY, &plan)
            .await;
        node.rejected(epoch, TARGET_TRANSPORT, OLD_BINARY, &plan)
            .await;
        node.accepted(epoch, ROLLBACK_TRANSPORT, OLD_BINARY, &plan)
            .await;
        node.stop().await;
    }
}

#[tokio::test]
async fn profile_activation_replaces_transport_without_replacing_running_binary() {
    let plan = plan(&[]);
    let profile = Activation {
        epoch: 10,
        config_hash: TARGET_TRANSPORT.to_vec(),
        profile_hash: b"target-profile".to_vec(),
    };
    let mut node = Node::start(9, BASE_TRANSPORT, NEW_BINARY, &plan, vec![profile]).await;
    let mut old = node
        .dial(9, BASE_TRANSPORT, OLD_BINARY, &plan)
        .await
        .unwrap();
    node.exchange(&mut old).await;
    assert!(node.swarm.advance_profile(9).unwrap().is_none());
    assert_eq!(
        node.swarm.advance_profile(10).unwrap(),
        Some(b"target-profile".to_vec())
    );
    // This client never offered the next profile, so its old session is retired.
    assert!(node.swarm.peers().is_empty());
    tokio::time::timeout(WAIT, async {
        loop {
            match old.receive().await {
                Ok(frame) => assert!(matches!(frame.message, 0x10..=0x12)),
                Err(error) => {
                    assert_eq!(error.as_bytes(), b"connection_closed");
                    break;
                }
            }
        }
    })
    .await
    .expect("old profile session was not closed");
    node.rejected(10, TARGET_TRANSPORT, OLD_BINARY, &plan).await;
    node.rejected(10, BASE_TRANSPORT, NEW_BINARY, &plan).await;
    node.accepted(10, TARGET_TRANSPORT, NEW_BINARY, &plan).await;
    node.stop().await;
}

#[test]
fn voting_readiness_uses_canonical_consensus_hash_and_running_binary() {
    let plan = plan(&[]);
    let staged = Swarm::new(
        config(9001, 9, BASE_TRANSPORT, NEW_BINARY, &plan, vec![]),
        key(1),
    )
    .unwrap();
    assert!(staged.upgrade_ready(9, &BASE_CONSENSUS).is_ok());
    for epoch in [10, 19] {
        assert!(staged.upgrade_ready(epoch, &TARGET_CONSENSUS).is_ok());
        for wrong in [BASE_CONSENSUS, BASE_TRANSPORT, TARGET_TRANSPORT] {
            assert_eq!(
                staged.upgrade_ready(epoch, &wrong).unwrap_err().as_bytes(),
                b"config_hash"
            );
        }
    }
    let old = Swarm::new(
        config(9002, 9, ROLLBACK_TRANSPORT, OLD_BINARY, &plan, vec![]),
        key(2),
    )
    .unwrap();
    assert!(old.upgrade_ready(9, &BASE_CONSENSUS).is_ok());
    assert_eq!(
        old.upgrade_ready(10, &TARGET_CONSENSUS)
            .unwrap_err()
            .as_bytes(),
        b"binary_hash"
    );
    for epoch in [20, 21] {
        assert!(old.upgrade_ready(epoch, &ROLLBACK_CONSENSUS).is_ok());
        assert_eq!(
            old.upgrade_ready(epoch, &ROLLBACK_TRANSPORT)
                .unwrap_err()
                .as_bytes(),
            b"config_hash"
        );
        assert_eq!(
            staged
                .upgrade_ready(epoch, &ROLLBACK_CONSENSUS)
                .unwrap_err()
                .as_bytes(),
            b"binary_hash"
        );
    }
}
