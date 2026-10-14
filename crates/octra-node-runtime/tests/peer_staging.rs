//! Real authenticated TCP peers sharing the production RPC/gossip staging path.
//! This test stops at block selection; it does not claim peer consensus execution.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer as _, SigningKey};
use octra_node_protocol::{
    network::{
        endpoint::Endpoint,
        frame::Frame,
        session::{Peer, Timeouts},
        swarm::{Config, Handler, MessageFuture, Swarm},
        transaction_gossip::Message,
    },
    resource_lanes::Lane,
    state::{Account, Ledger},
    transaction::{address_from_public_key, Nonce, OpType, RuleMode, Transaction},
    transaction_policy::Profile,
};
use octra_node_runtime::{
    p2p_transaction::{self, Ingress, Staging},
    staging::{
        intake::{self, Host, Rpc, Rules},
        DropRecord, Pool, QueueState,
    },
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinHandle};
const WAIT: Duration = Duration::from_secs(10);
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(seed: u8) -> Vec<u8> {
    STANDARD
        .encode(key(seed).verifying_key().to_bytes())
        .into_bytes()
}
fn hash(tx: &Transaction) -> Vec<u8> {
    hex::encode(tx.hash().unwrap()).into_bytes()
}
fn signed(nonce: i64, fee: i64, amount: i64) -> Transaction {
    let mut tx = Transaction {
        from: address_from_public_key(&public(42)),
        to: address_from_public_key(&public(43)),
        amount: amount.into(),
        nonce: Nonce::new(nonce).unwrap(),
        ou: fee.into(),
        timestamp: 1000.,
        signature: vec![],
        public_key: Some(public(42)),
        message: None,
        encrypted_data: None,
        op_type: OpType::Standard,
    };
    tx.signature = STANDARD
        .encode(key(42).sign(&tx.signing_bytes().unwrap()).to_bytes())
        .into_bytes();
    tx
}
struct StandardWorker;
impl Host for StandardWorker {
    fn preverify(&mut self, tx: &Transaction, _: &Pool) -> Result<(), String> {
        if Lane::of(tx.op_type).preverify_queue() == 0 {
            Ok(())
        } else {
            Err("pre_verify_unavailable fixture has no proof worker".into())
        }
    }
    fn save_drops(&mut self, _: &[DropRecord]) {}
    fn invalidate(&mut self, _: &[u8]) {}
    fn changed(&mut self, _: &Pool) {}
    fn accepted(&mut self, _: &Transaction, _: &Pool) {}
}
struct State {
    pool: Pool,
    ingress: Ingress,
    ledger: Ledger,
    rules: Rules,
    frames: usize,
}
impl State {
    fn new() -> Self {
        Self {
            pool: Pool::default(),
            ingress: Ingress::default(),
            frames: 0,
            ledger: Ledger::from_accounts(BTreeMap::from([(
                address_from_public_key(&public(42)),
                Account {
                    balance: 5000.into(),
                    public_key: Some(public(42)),
                    ..Account::default()
                },
            )]))
            .unwrap(),
            rules: Rules {
                bft: true,
                profile: Profile::default(),
                compute: RuleMode::Prior,
                settle: RuleMode::Prior,
                proof: RuleMode::Active,
                duty: None,
                queue_head: Some(0),
                stealth_minimum: 5000.into(),
            },
        }
    }
    fn submit(&mut self, tx: &Transaction) -> Result<Vec<u8>, String> {
        intake::submit(
            &mut self.pool,
            tx,
            &self.ledger,
            &self.rules,
            &Rpc {
                now: 1000.,
                max_drift: 300.,
                observer: false,
                preverify_capacity: true,
                preverify_pending: Nonce::default(),
                preverify_maximum: Nonce::new(6).unwrap(),
                nonce_window: Nonce::new(32).unwrap(),
            },
            &mut StandardWorker,
            &|| 1000.,
        )
        .map_err(|e| e.to_string())
    }
    fn selected(&self) -> Vec<Vec<u8>> {
        self.pool
            .ready_epoch(
                &10000.into(),
                &|a| self.ledger.account(a).map(|a| a.nonce),
                &|_| true,
            )
            .iter()
            .map(|e| e.hash.clone())
            .collect()
    }
}
struct Dispatch {
    state: Arc<Mutex<State>>,
    swarm: Swarm,
}
impl Handler for Dispatch {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        let state = self.state.clone();
        let swarm = self.swarm.clone();
        Box::pin(async move {
            if frame.message != 0x20 {
                return Ok(());
            }
            let effects = {
                let mut state = state.lock().unwrap();
                let State {
                    pool,
                    ingress,
                    ledger,
                    rules,
                    frames,
                } = &mut *state;
                let mut effects = Vec::new();
                ingress
                    .stage(
                        &peer.hello().node_id,
                        &frame.payload,
                        300.,
                        &mut Staging {
                            pool,
                            ledger,
                            rules,
                            host: &mut StandardWorker,
                            shared: &|_| None,
                            clock: &|| 1000.,
                            effects: &mut |e| effects.push(e),
                        },
                    )
                    .map_err(|e| octra_node_protocol::network::Error::new(e.to_string()))?;
                *frames += 1;
                effects
            };
            for effect in effects {
                p2p_transaction::deliver(&swarm, &peer, effect).await?;
            }
            Ok(())
        })
    }
}
struct Node {
    port: u16,
    swarm: Swarm,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}
fn endpoint(port: u16) -> Endpoint {
    Endpoint {
        host: b"127.0.0.1".to_vec(),
        port,
    }
}
async fn start(seed: u8, bootstrap: Vec<Endpoint>) -> Node {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let swarm = Swarm::new(
        Config {
            chain_id: b"staging-peer-test".to_vec(),
            node_address: format!("peer-{seed}").into_bytes(),
            config_hash: vec![1; 32],
            binary_hash: vec![2; 32],
            require_binary_hash: false,
            upgrade: None,
            profiles: vec![],
            allowed_public_keys: vec![],
            bootstrap,
            maximum_validators: 16,
            advertised: endpoint(port),
            timeouts: Timeouts {
                handshake_read: WAIT,
                read_idle: Duration::from_secs(60),
                write_idle: WAIT,
            },
            head: Arc::new(|| (0, [0; 32])),
        },
        key(seed),
    )
    .unwrap();
    let state = Arc::new(Mutex::new(State::new()));
    let handler = Arc::new(Dispatch {
        state: state.clone(),
        swarm: swarm.clone(),
    });
    let runner = swarm.clone();
    let task = tokio::spawn(async move {
        runner.run(listener, handler).await.unwrap();
    });
    Node {
        port,
        swarm,
        state,
        task,
    }
}
async fn until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("peer staging condition timed out");
}
async fn broadcast(node: &Node, message: Message) {
    node.swarm
        .broadcast(
            Frame {
                message: 0x20,
                payload: message.encode().unwrap(),
            },
            None,
            true,
        )
        .await
        .unwrap();
}
async fn submit(node: &Node, tx: &Transaction) {
    let hash = node.state.lock().unwrap().submit(tx).unwrap();
    broadcast(node, Message::Inventory(vec![hash])).await;
}
async fn direct(a: &Node, b: &Node, tx: &Transaction) {
    let before = b.state.lock().unwrap().frames;
    broadcast(
        a,
        Message::Transaction {
            hash: hash(tx),
            json: tx.to_json_bytes().unwrap(),
        },
    )
    .await;
    until(|| b.state.lock().unwrap().frames > before).await;
}
#[tokio::test]
async fn rpc_and_authenticated_peers_share_nonce_balance_replacement_and_selection_rules() {
    let b = start(2, vec![]).await;
    let a = start(1, vec![endpoint(b.port)]).await;
    until(|| a.swarm.peers().len() == 1 && b.swarm.peers().len() == 1).await;
    let second = signed(2, 1000, 1);
    submit(&a, &second).await;
    until(|| b.state.lock().unwrap().pool.find(&hash(&second)).is_some()).await;
    assert!(b.state.lock().unwrap().selected().is_empty());
    assert!(
        matches!(b.state.lock().unwrap().pool.queue_state(&hash(&second),Nonce::default()),Some(QueueState::WaitNonce {expected,..}) if expected.get()==1)
    );
    let first = signed(1, 1000, 1);
    submit(&a, &first).await;
    until(|| b.state.lock().unwrap().selected() == vec![hash(&first), hash(&second)]).await;
    let mut forged = signed(1, 2000, 1);
    forged.signature = STANDARD.encode([0; 64]).into_bytes();
    direct(&a, &b, &forged).await;
    assert_eq!(
        b.state.lock().unwrap().selected(),
        vec![hash(&first), hash(&second)]
    );
    let replacement = signed(1, 1100, 1);
    submit(&a, &replacement).await;
    until(|| b.state.lock().unwrap().selected() == vec![hash(&replacement), hash(&second)]).await;
    let unaffordable = signed(3, 1000, 5000);
    assert!(a
        .state
        .lock()
        .unwrap()
        .submit(&unaffordable)
        .unwrap_err()
        .contains("insufficient balance"));
    direct(&a, &b, &unaffordable).await;
    assert!(b
        .state
        .lock()
        .unwrap()
        .pool
        .find(&hash(&unaffordable))
        .is_none());
    {
        let state = b.state.lock().unwrap();
        assert_eq!(
            state.pool.virtual_balance(&replacement.from),
            Some(&2898.into())
        );
        assert_eq!(
            state.pool.dropped(&hash(&first)).unwrap().detail,
            "replaced by higher fee-rate"
        );
    }
    a.swarm.stop();
    b.swarm.stop();
    tokio::time::timeout(WAIT, a.task).await.unwrap().unwrap();
    tokio::time::timeout(WAIT, b.task).await.unwrap().unwrap();
}
