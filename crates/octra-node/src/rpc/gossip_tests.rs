//! Actual gossip parser/guard and authenticated TCP transport. These checks
//! qualify the read path, not transaction execution or queue acceptance.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{
    network::{
        endpoint::Endpoint,
        session::Timeouts,
        swarm::{self, Handler, MessageFuture},
    },
    state::Account,
    transaction::{self, Nonce, OpType, RuleMode},
};
use octra_node_runtime::{consensus_preverify_cache::Shared, staging::Pool};
use std::{
    sync::{mpsc as channel, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinHandle};

fn tx() -> Transaction {
    let key = SigningKey::from_bytes(&[1; 32]);
    let public = STANDARD.encode(key.verifying_key().as_bytes()).into_bytes();
    let mut tx = Transaction {
        from: transaction::address_from_public_key(&public),
        to: transaction::address_from_public_key(
            STANDARD
                .encode(SigningKey::from_bytes(&[2; 32]).verifying_key().as_bytes())
                .as_bytes(),
        ),
        amount: 1.into(),
        nonce: Nonce::new(1).unwrap(),
        ou: 1000.into(),
        timestamp: 10.,
        signature: vec![],
        public_key: Some(public),
        message: None,
        encrypted_data: None,
        op_type: OpType::Standard,
    };
    tx.signature = STANDARD
        .encode(key.sign(&tx.signing_bytes().unwrap()).to_bytes())
        .into_bytes();
    tx
}
fn hash(tx: &Transaction) -> Vec<u8> {
    hex::encode(tx.hash().unwrap()).into_bytes()
}
fn rules() -> p2p_transaction::Rules {
    p2p_transaction::Rules {
        max_drift: 300.,
        duty: None,
        bft: true,
    }
}
fn state(tx: &Transaction) -> StateBatch {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    let account = Account {
        balance: 100_000.into(),
        nonce: Nonce::new(0).unwrap(),
        public_key: tx.public_key.clone(),
        ..Account::default()
    };
    account_store::set(&mut state, &tx.from, &account, RuleMode::Prior).unwrap();
    // A full ledger fold would parse this unrelated malformed account.
    state
        .set(&[b"accounts", b"unrelated", b"data"], b"broken".to_vec())
        .unwrap();
    state
}
fn captured(tx: &Transaction) -> Captured {
    let shared = Shared::default();
    shared.share(std::slice::from_ref(tx)).unwrap();
    Captured::capture(
        shared,
        10.,
        Arc::new(Pending::new(Pool::default())),
        Some(state(tx)),
    )
    .unwrap()
}
#[test]
fn inventory_and_get_do_not_fold_accounts_and_sender_lookup_is_lazy() {
    let tx = tx();
    let mut host = captured(&tx);
    let mut ingress = p2p_transaction::Ingress::default();
    assert!(account_store::ledger(host.state.as_ref().unwrap()).is_err());
    let inventory = Message::Inventory(vec![hash(&tx), vec![b'a'; 64]])
        .encode()
        .unwrap();
    assert!(host
        .receive(&mut ingress, b"peer", &inventory, rules())
        .unwrap());
    assert_eq!(
        host.effects,
        vec![Effect::Send(
            Message::Get(vec![vec![b'a'; 64]]).encode().unwrap()
        )]
    );
    host.effects.clear();
    let get = Message::Get(vec![hash(&tx)]).encode().unwrap();
    assert!(host.receive(&mut ingress, b"peer", &get, rules()).unwrap());
    assert_eq!(
        host.effects,
        vec![Effect::Send(
            Message::Transaction {
                hash: hash(&tx),
                json: tx.to_json_bytes().unwrap()
            }
            .encode()
            .unwrap()
        )]
    );
    host.effects.clear();
    // A fresh transaction reaches only its sender account and remains subject
    // to the separate complete submit_peer admission after this parser returns.
    let mut unseen = tx;
    unseen.nonce = Nonce::new(2).unwrap();
    unseen.signature = STANDARD
        .encode(
            SigningKey::from_bytes(&[1; 32])
                .sign(&unseen.signing_bytes().unwrap())
                .to_bytes(),
        )
        .into_bytes();
    let payload = Message::Transaction {
        hash: hash(&unseen),
        json: unseen.to_json_bytes().unwrap(),
    }
    .encode()
    .unwrap();
    assert!(host
        .receive(&mut ingress, b"peer", &payload, rules())
        .unwrap());
    assert_eq!(host.transactions, vec![unseen]);
    assert!(host.effects.is_empty());
}
#[test]
fn native_gossip_guard_precedes_sender_read_and_corrupt_sender_is_fatal() {
    let tx = tx();
    let mut host = captured(&tx);
    host.shared = Shared::default();
    host.state
        .as_mut()
        .unwrap()
        .set(&[b"accounts", &tx.from, b"data"], b"broken".to_vec())
        .unwrap();
    let payload = Message::Transaction {
        hash: hash(&tx),
        json: tx.to_json_bytes().unwrap(),
    }
    .encode()
    .unwrap();
    let mut ingress = p2p_transaction::Ingress::default();
    // Consume the exact native peer message budget. The rejected frame must
    // close the peer without examining its otherwise corrupt sender account.
    for _ in 0..4096 {
        ingress
            .guard
            .admit(
                octra_node_protocol::network::gossip_guard::Config::default(),
                10.,
                b"limited",
                0,
            )
            .unwrap();
    }
    assert!(host
        .receive(&mut ingress, b"limited", &payload, rules())
        .unwrap());
    assert!(matches!(
        host.effects.as_slice(),
        [Effect::ReportBad(_), Effect::Close]
    ));
    assert!(host.transactions.is_empty());
    host.effects.clear();
    assert!(host
        .receive(&mut ingress, b"fresh", &payload, rules())
        .unwrap_err()
        .to_string()
        .contains("account data rejected"));
    assert!(host.effects.is_empty() && host.transactions.is_empty());
}
#[test]
fn a_poisoned_pending_owner_does_not_turn_into_a_cache_only_success() {
    let tx = tx();
    let mut host = captured(&tx);
    let pending = host.pending.clone();
    let _ = std::thread::spawn(move || {
        let _ = pending.ingress_read::<()>(|_| panic!("deliberate queue owner poison"));
    })
    .join();
    let payload = Message::Get(vec![hash(&tx)]).encode().unwrap();
    assert!(host
        .receive(
            &mut p2p_transaction::Ingress::default(),
            b"peer",
            &payload,
            rules()
        )
        .unwrap_err()
        .to_string()
        .contains("poisoned"));
    assert!(host.effects.is_empty() && host.transactions.is_empty());
}

struct Reader {
    state: Arc<Mutex<(Captured, p2p_transaction::Ingress)>>,
    swarm: Swarm,
}
impl Handler for Reader {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        let state = self.state.clone();
        let swarm = self.swarm.clone();
        Box::pin(async move {
            if frame.message != 0x20 {
                return Ok(());
            }
            let effects = {
                let mut state = state.lock().unwrap();
                let (host, ingress) = &mut *state;
                host.receive(ingress, &peer.hello().node_id, &frame.payload, rules())
                    .unwrap();
                std::mem::take(&mut host.effects)
            };
            for effect in effects {
                p2p_transaction::deliver(&swarm, &peer, effect).await?;
            }
            Ok(())
        })
    }
}
struct Replies(tokio::sync::mpsc::UnboundedSender<Frame>);
impl Handler for Replies {
    fn message(&self, _: Peer, frame: Frame) -> MessageFuture {
        let replies = self.0.clone();
        Box::pin(async move {
            let _ = replies.send(frame);
            Ok(())
        })
    }
}
struct Running {
    swarm: Swarm,
    task: JoinHandle<std::result::Result<(), octra_node_protocol::network::Error>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.swarm.stop();
        self.task.abort();
    }
}
async fn swarm(seed: u8, bootstrap: Vec<Endpoint>) -> (Swarm, TcpListener, Endpoint) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint {
        host: b"127.0.0.1".to_vec(),
        port: listener.local_addr().unwrap().port(),
    };
    let swarm = Swarm::new(
        swarm::Config {
            chain_id: b"rpc-gossip-read-fixture".to_vec(),
            node_address: vec![seed; 47],
            config_hash: vec![1; 32],
            binary_hash: vec![0; 32],
            require_binary_hash: false,
            upgrade: None,
            profiles: vec![],
            allowed_public_keys: (1..=2)
                .map(|n| {
                    SigningKey::from_bytes(&[n; 32])
                        .verifying_key()
                        .as_bytes()
                        .to_vec()
                })
                .collect(),
            bootstrap,
            maximum_validators: 4,
            advertised: endpoint.clone(),
            timeouts: Timeouts::default(),
            head: Arc::new(|| (0, [0; 32])),
        },
        SigningKey::from_bytes(&[seed; 32]),
    )
    .unwrap();
    (swarm, listener, endpoint)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_tcp_get_serves_shared_bytes_during_queue_write_and_suspension() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let tx = tx();
        let host = captured(&tx);
        let pending = host.pending.clone();
        let (entered, started) = channel::channel();
        let (release, wait) = channel::channel();
        let holder = std::thread::spawn(move || {
            pending
                .ingress_read(|_| {
                    entered.send(()).unwrap();
                    wait.recv().unwrap();
                })
                .unwrap()
        });
        tokio::task::spawn_blocking(move || started.recv().unwrap())
            .await
            .unwrap();
        // Always release a held queue on an assertion/unwind, before joining.
        struct Hold(
            Option<channel::Sender<()>>,
            Option<std::thread::JoinHandle<Option<()>>>,
        );
        impl Drop for Hold {
            fn drop(&mut self) {
                if let Some(release) = self.0.take() {
                    let _ = release.send(());
                }
                if let Some(holder) = self.1.take() {
                    let _ = holder.join();
                }
            }
        }
        let _held = Hold(Some(release), Some(holder));
        let host = Captured::capture(host.shared, host.now, host.pending, host.state).unwrap();
        assert!(!host.admitting, "busy Pending must disable new admission");
        let state = Arc::new(Mutex::new((host, p2p_transaction::Ingress::default())));
        let (server, listener, endpoint) = swarm(1, vec![]).await;
        let handler = Arc::new(Reader {
            state: state.clone(),
            swarm: server.clone(),
        });
        let running = server.clone();
        let _server = Running {
            swarm: server,
            task: tokio::spawn(async move { running.run(listener, handler).await }),
        };
        let (client, listener, _) = swarm(2, vec![endpoint]).await;
        let (send, mut replies) = tokio::sync::mpsc::unbounded_channel();
        let running = client.clone();
        let _client = Running {
            swarm: client.clone(),
            task: tokio::spawn(async move { running.run(listener, Arc::new(Replies(send))).await }),
        };
        while client.peers().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let peer = client.peers().pop().unwrap();
        peer.enqueue_wait(Frame {
            message: 0x20,
            payload: Message::Get(vec![hash(&tx)]).encode().unwrap(),
        })
        .await;
        let reply = loop {
            let frame = replies.recv().await.unwrap();
            if frame.message == 0x20 {
                break frame;
            }
        };
        assert_eq!(
            Message::decode(&reply.payload).unwrap(),
            Message::Transaction {
                hash: hash(&tx),
                json: tx.to_json_bytes().unwrap()
            }
        );
        assert!(
            state
                .lock()
                .unwrap()
                .0
                .pending
                .ingress_read(|_| ())
                .unwrap()
                .is_none(),
            "positive Get control must still hold the actual queue writer"
        );
        assert!(state.lock().unwrap().0.transactions.is_empty());
        // Canonical suspension also leaves immutable verified bytes readable.
        state.lock().unwrap().0.state = None;
        let mut unseen = tx.clone();
        unseen.nonce = Nonce::new(2).unwrap();
        unseen.signature = STANDARD
            .encode(
                SigningKey::from_bytes(&[1; 32])
                    .sign(&unseen.signing_bytes().unwrap())
                    .to_bytes(),
            )
            .into_bytes();
        peer.enqueue_wait(Frame {
            message: 0x20,
            payload: Message::Transaction {
                hash: hash(&unseen),
                json: unseen.to_json_bytes().unwrap(),
            }
            .encode()
            .unwrap(),
        })
        .await;
        peer.enqueue_wait(Frame {
            message: 0x20,
            payload: Message::Get(vec![hash(&tx)]).encode().unwrap(),
        })
        .await;
        // The ordered Get is a positive transport control after the actual
        // unknown transaction frame was handled; no intake is inferred from it.
        let reply = loop {
            let frame = replies.recv().await.unwrap();
            if frame.message == 0x20 {
                break frame;
            }
        };
        assert_eq!(
            Message::decode(&reply.payload).unwrap(),
            Message::Transaction {
                hash: hash(&tx),
                json: tx.to_json_bytes().unwrap()
            }
        );
        assert!(state.lock().unwrap().0.transactions.is_empty());
        assert!(state.lock().unwrap().0.state.is_none());
    })
    .await
    .expect("bounded authenticated TCP read exchange");
}
