//! Relay transport qualification; opaque payloads are not consensus execution.
use ed25519_dalek::SigningKey;
use octra_node_protocol::network::{
    endpoint::Endpoint,
    frame::Frame,
    session::{Peer, Timeouts},
    swarm::{Config, Handler, MessageFuture, Swarm},
};
use octra_node_runtime::proposal_relay::{Broadcast, ProposalRelay};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, sync::mpsc, task::JoinHandle};
const WAIT: Duration = Duration::from_secs(10);
struct Inbox(mpsc::UnboundedSender<(Vec<u8>, Frame)>);
impl Handler for Inbox {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        self.0.send((peer.hello().node_id.clone(), frame)).unwrap();
        Box::pin(async { Ok(()) })
    }
}
struct Node {
    endpoint: Endpoint,
    swarm: Swarm,
    inbox: mpsc::UnboundedReceiver<(Vec<u8>, Frame)>,
    task: JoinHandle<()>,
}
impl Drop for Node {
    fn drop(&mut self) {
        self.swarm.stop();
        self.task.abort();
    }
}
async fn node(seed: u8, bootstrap: Vec<Endpoint>) -> Node {
    node_on_chain(seed, bootstrap, b"vote-guard-fixture").await
}
async fn node_on_chain(seed: u8, bootstrap: Vec<Endpoint>, chain: &[u8]) -> Node {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint {
        host: b"127.0.0.1".to_vec(),
        port: listener.local_addr().unwrap().port(),
    };
    let swarm = Swarm::new(
        Config {
            chain_id: chain.to_vec(),
            node_address: format!("node-{seed}").into_bytes(),
            config_hash: vec![1; 32],
            binary_hash: vec![2; 32],
            require_binary_hash: false,
            upgrade: None,
            profiles: vec![],
            allowed_public_keys: (1..=3)
                .map(|seed| {
                    SigningKey::from_bytes(&[seed; 32])
                        .verifying_key()
                        .to_bytes()
                        .to_vec()
                })
                .collect(),
            bootstrap,
            maximum_validators: 16,
            advertised: endpoint.clone(),
            timeouts: Timeouts {
                handshake_read: WAIT,
                read_idle: Duration::from_secs(60),
                write_idle: WAIT,
            },
            head: Arc::new(|| (0, [0; 32])),
        },
        SigningKey::from_bytes(&[seed; 32]),
    )
    .unwrap();
    let (tx, inbox) = mpsc::unbounded_channel();
    let runner = swarm.clone();
    let task = tokio::spawn(async move {
        runner.run(listener, Arc::new(Inbox(tx))).await.unwrap();
    });
    Node {
        endpoint,
        swarm,
        inbox,
        task,
    }
}

#[tokio::test]
async fn vote_guard_requires_durable_local_vote_before_peer_publication() {
    use octra_node_protocol::consensus::{
        codec::Wire,
        engine::{Engine, TimeoutConfig},
        hash,
        journal::JournalOwner,
        policy::Protocol,
        Proposal, Validator, ValidatorSet, Vote,
    };
    use octra_node_protocol::{
        consensus::pending_log::PendingCommit, transaction::RuleMode, transaction_outcome,
    };
    use octra_node_runtime::consensus_votes::VoteGuard;
    use octra_node_runtime::{
        consensus_bundle::{RawBundle, Rules},
        consensus_recovery::{self, Context},
    };
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/pending-recovery.json")).unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["input"]["mutate"] == "none" && c["input"]["ops"].as_array().unwrap().len() == 1
        })
        .unwrap();
    let call = &case["expected"];
    let record =
        PendingCommit::decode(&hex::decode(call["record"].as_str().unwrap()).unwrap()).unwrap();
    let raw = RawBundle {
        tx_hashes: record.tx_hashes,
        txs_json: record.txs_json,
        receipts_json: record.receipts_json,
    };
    let mode = |name: &str| {
        if call["rules"][name] == true {
            RuleMode::Active
        } else {
            RuleMode::Prior
        }
    };
    let rules = Rules {
        payload: octra_node_protocol::transaction_payload::Limits::default(),
        crypto_active: false,
        stealth_minimum: 5000.into(),
        envelope: transaction_outcome::Rules {
            envelope: mode("envelope"),
            compute: mode("compute"),
            settle: mode("settle"),
        },
    };
    let proposal =
        Proposal::decode(&hex::decode(call["proposal"].as_str().unwrap()).unwrap()).unwrap();
    let vote = Vote::decode(&hex::decode(call["vote"].as_str().unwrap()).unwrap()).unwrap();
    assert!(hash::verify_vote(
        &SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
        &vote
    )
    .unwrap());
    let mut a = node_on_chain(1, vec![], &vote.chain_id).await;
    let mut b = node_on_chain(2, vec![a.endpoint.clone()], &vote.chain_id).await;
    tokio::time::timeout(WAIT, async {
        while a.swarm.peers().is_empty() || b.swarm.peers().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let set = ValidatorSet::unweighted(
        (1..=4)
            .map(|n| Validator {
                address: format!("v{n}").into_bytes(),
                pubkey: SigningKey::from_bytes(&[n; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            })
            .collect(),
    );
    let mut engine = Engine::new(
        vote.chain_id.clone(),
        vote.validator.clone(),
        set.clone(),
        vote.epoch_id,
        Protocol::default(),
        TimeoutConfig::default(),
    );
    let context = Context {
        chain_id: &vote.chain_id,
        validator_set: &set,
        protocol: Protocol::default(),
        rules: &rules,
    };
    let dir = tempfile::tempdir().unwrap();
    let owner = JournalOwner::open(dir.path()).unwrap();
    let mut guard = VoteGuard::new(vote.chain_id.clone(), vote.validator.clone(), owner.clone());
    guard.prepare(false, &mut engine, Ok(vec![])).unwrap();
    assert!(!guard
        .broadcast(
            &engine,
            &a.swarm,
            &vote,
            Some(&proposal),
            false,
            |pending| {
                std::future::ready(
                    consensus_recovery::before_precommit(
                        &context,
                        &owner,
                        &vote.validator,
                        &pending,
                        &raw,
                        &[],
                        3.,
                        |_| Err("execution unavailable".into()),
                    )
                    .is_ok(),
                )
            }
        )
        .await
        .unwrap());
    assert!(owner.find_vote(&vote).unwrap().is_none());
    assert!(owner.pending().unwrap().is_empty());
    // Ordered peer barrier proves the refused precommit was not enqueued.
    a.swarm.broadcast(frame(9), None, true).await.unwrap();
    receive(&mut b, a.swarm.node_id(), 9).await;
    let mut persisted = false;
    assert!(guard
        .broadcast(
            &engine,
            &a.swarm,
            &vote,
            Some(&proposal),
            false,
            |pending| {
                assert!(owner.find_vote(&vote).unwrap().is_none());
                assert_eq!(pending.vote_wire, vote.encode().unwrap());
                assert_eq!(pending.proposal_wire, proposal.encode().unwrap());
                let result = consensus_recovery::before_precommit(
                    &context,
                    &owner,
                    &vote.validator,
                    &pending,
                    &raw,
                    &[],
                    3.,
                    |_| {
                        assert!(owner.pending().unwrap().is_empty());
                        persisted = true;
                        Ok(())
                    },
                );
                std::future::ready(result.is_ok())
            }
        )
        .await
        .unwrap());
    let (peer, received) = tokio::time::timeout(WAIT, b.inbox.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer, a.swarm.node_id());
    assert_eq!(received.message, 0x31);
    assert_eq!(received.payload, vote.encode().unwrap());
    assert!(persisted);
    let stored = owner.pending().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(
        consensus_recovery::recover(&context, &stored[0])
            .unwrap()
            .vote,
        vote
    );
    assert_eq!(owner.find_vote(&vote).unwrap(), Some(vote.clone()));
    let mut conflict = vote.clone();
    conflict.proposal_id[0] ^= 1;
    assert!(!guard
        .broadcast(&engine, &a.swarm, &conflict, None, false, |_| async {
            panic!("conflict must precede persistence")
        })
        .await
        .unwrap());
    a.swarm.broadcast(frame(10), None, true).await.unwrap();
    receive(&mut b, a.swarm.node_id(), 10).await;
    drop(guard);
    drop(owner);
    let owner = JournalOwner::open(dir.path()).unwrap();
    let stored = owner.pending().unwrap();
    let recovered = consensus_recovery::recover(&context, &stored[0]).unwrap();
    let mut restored = VoteGuard::new(vote.chain_id.clone(), vote.validator.clone(), owner.clone());
    restored
        .prepare(
            false,
            &mut engine,
            Ok(vec![recovered.vote.encode().unwrap()]),
        )
        .unwrap();
    assert_eq!(engine.state().round, vote.round + 1);
    assert_eq!(owner.find_vote(&vote).unwrap(), Some(vote));
    a.swarm.stop();
    b.swarm.stop();
    tokio::time::timeout(WAIT, &mut a.task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(WAIT, &mut b.task)
        .await
        .unwrap()
        .unwrap();
}
fn frame(n: u8) -> Frame {
    Frame {
        message: 0x30,
        payload: vec![n; 128],
    }
}
fn offer(
    relay: &ProposalRelay<Broadcast>,
    generation: i64,
    key: u8,
    value: u8,
    except: Option<Vec<u8>>,
) {
    relay.offer(
        generation,
        vec![key],
        Broadcast {
            frame: frame(value),
            except,
        },
    );
}
async fn receive(node: &mut Node, sender: &[u8], value: u8) {
    let (peer, frame) = tokio::time::timeout(WAIT, node.inbox.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer, sender);
    assert_eq!(frame, self::frame(value));
}
#[tokio::test]
async fn relay_swarm_preserves_bytes_exclusion_deduplication_and_generation() {
    let a = node(1, vec![]).await;
    let mut b = node(2, vec![a.endpoint.clone()]).await;
    let mut c = node(3, vec![a.endpoint.clone()]).await;
    tokio::time::timeout(WAIT, async {
        while a.swarm.peers().len() != 2 || b.swarm.peers().len() != 2 || c.swarm.peers().len() != 2
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let warnings = Arc::new(Mutex::new(Vec::new()));
    let log = warnings.clone();
    let relay = ProposalRelay::for_swarm(a.swarm.clone(), move |reason| {
        log.lock().unwrap().push(reason.to_vec());
    });
    offer(&relay, 0, 1, 1, Some(b.swarm.node_id().to_vec()));
    receive(&mut c, a.swarm.node_id(), 1).await;
    // The next broadcast is also an ordered barrier: excluded or duplicate
    // traffic would be received before it and fail the assertions.
    offer(&relay, 0, 1, 99, None);
    offer(&relay, 0, 2, 2, None);
    receive(&mut b, a.swarm.node_id(), 2).await;
    receive(&mut c, a.swarm.node_id(), 2).await;
    relay.progress(1);
    offer(&relay, 0, 3, 99, None);
    offer(&relay, 1, 1, 3, None);
    receive(&mut b, a.swarm.node_id(), 3).await;
    receive(&mut c, a.swarm.node_id(), 3).await;
    relay.close();
    offer(&relay, 2, 4, 99, None);
    relay.open(2);
    offer(&relay, 2, 1, 4, None);
    receive(&mut b, a.swarm.node_id(), 4).await;
    receive(&mut c, a.swarm.node_id(), 4).await;
    assert!(warnings.lock().unwrap().is_empty());
    relay.close();
    for node in [&a, &b, &c] {
        node.swarm.stop();
    }
    for node in [&mut b, &mut c] {
        tokio::time::timeout(WAIT, &mut node.task)
            .await
            .unwrap()
            .unwrap();
    }
    let mut a = a;
    tokio::time::timeout(WAIT, &mut a.task)
        .await
        .unwrap()
        .unwrap();
}
