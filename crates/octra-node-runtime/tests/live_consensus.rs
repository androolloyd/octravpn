//! Real engine votes over authenticated loopback peers. Execution and canonical
//! publication are controlled host fixtures; these tests do not qualify mainnet.
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{
    consensus::{
        codec::Wire,
        engine::{self, Engine, TimeoutConfig},
        evidence::VoteConflict,
        hash,
        journal::JournalOwner,
        policy::Protocol,
        qc, Bytes, EpochHeader, Error, Finalize, ParentCommit, Proposal, Validator, ValidatorSet,
        Vote, VoteType,
    },
    network::{
        endpoint::Endpoint,
        frame::Frame,
        session::{Peer, Timeouts},
        swarm::{Config, Handler, MessageFuture, Swarm},
    },
};
use octra_node_runtime::{
    consensus_bundle,
    consensus_driver::{Driver, Handle, Host, ProposalPlan, Publication, Verdict},
    consensus_recovery,
    consensus_votes::{Precommit, Readiness},
};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};
const CHAIN: &[u8] = b"live-consensus-fixture";
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn address(n: u8) -> Bytes {
    format!("validator-{n}").into_bytes()
}
fn validators(n: u8) -> ValidatorSet {
    ValidatorSet::unweighted(
        (1..=n)
            .map(|n| Validator {
                address: address(n),
                pubkey: key(n).verifying_key().to_bytes().to_vec(),
            })
            .collect(),
    )
}
fn rules() -> consensus_bundle::Rules {
    use octra_node_protocol::{transaction::RuleMode, transaction_outcome};
    consensus_bundle::Rules {
        payload: octra_node_protocol::transaction_payload::Limits::default(),
        crypto_active: false,
        stealth_minimum: 5000.into(),
        envelope: transaction_outcome::Rules {
            envelope: RuleMode::Prior,
            compute: RuleMode::Prior,
            settle: RuleMode::Prior,
        },
    }
}
fn header(epoch: i64, creator: Bytes) -> EpochHeader {
    EpochHeader {
        proto_version: 4,
        chain_id: CHAIN.to_vec(),
        epoch_id: epoch,
        prev_state_root: vec![0; 32],
        tx_list_hash: engine::tx_list_hash_for_header(&[]).to_vec(),
        receipt_root: hash::receipt_root(&[]).unwrap().to_vec(),
        proposed_state_root: vec![3; 32],
        parent_commit_hash: vec![0; 32],
        creator_addr: creator,
        txid_hi: 0,
        ts: 10.,
    }
}
#[derive(Clone)]
struct Authority {
    id: u8,
    set: ValidatorSet,
    journal: JournalOwner,
    ready: Arc<AtomicBool>,
    commits: Arc<Mutex<Vec<Finalize>>>,
    attempts: Arc<AtomicUsize>,
    builds: Arc<AtomicUsize>,
    checks: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
    reject_publish: Arc<AtomicBool>,
    reject_precommit: Arc<AtomicBool>,
    fail_build: Arc<AtomicBool>,
    wait_verify: Arc<AtomicBool>,
    readiness_checks: Arc<AtomicUsize>,
    verify_gate: watch::Receiver<bool>,
    warnings: Arc<Mutex<Vec<String>>>,
    evidence: Arc<Mutex<Vec<VoteConflict>>>,
}
#[async_trait::async_trait]
impl Host for Authority {
    fn sign(&self, bytes: &[u8]) -> Result<Bytes, Error> {
        Ok(key(self.id).sign(bytes).to_bytes().to_vec())
    }
    fn readiness(&self) -> Readiness {
        self.readiness_checks.fetch_add(1, Ordering::SeqCst);
        Readiness {
            role_can_vote: true,
            can_vote: self.ready.load(Ordering::SeqCst) && self.head_epoch() == 0,
            finality_proof_needed: false,
        }
    }
    fn verify_parent(&self, epoch: i64, parent: Option<&ParentCommit>) -> Result<(), Error> {
        if epoch != 1 || parent.is_some() {
            return Err("fixture only executes genesis child".into());
        }
        Ok(())
    }
    async fn build(&self, epoch: i64) -> Result<Option<ProposalPlan>, Error> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        if self.fail_build.swap(false, Ordering::SeqCst) {
            return Err("injected builder failure".into());
        }
        Ok(Some(ProposalPlan {
            header: header(epoch, address(self.id)),
            tx_hashes: vec![],
            parent_commit: None,
        }))
    }
    async fn verify(&self, p: &Proposal) -> Result<Verdict, Error> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        let mut gate = self.verify_gate.clone();
        while !*gate.borrow_and_update() {
            gate.changed()
                .await
                .map_err(|e| Error::from(e.to_string()))?;
        }
        if self.wait_verify.load(Ordering::SeqCst) {
            return Ok(Verdict::Wait);
        }
        Ok(if p.header == header(1, p.header.creator_addr.clone()) {
            Verdict::Accept
        } else {
            Verdict::Reject
        })
    }
    async fn before_precommit(&self, record: Precommit) -> bool {
        if self.reject_precommit.load(Ordering::SeqCst) {
            return false;
        }
        consensus_recovery::before_precommit(
            &consensus_recovery::Context {
                chain_id: CHAIN,
                validator_set: &self.set,
                protocol: Protocol::default(),
                rules: &rules(),
            },
            &self.journal,
            &address(self.id),
            &record,
            &consensus_bundle::RawBundle {
                tx_hashes: vec![],
                txs_json: vec![],
                receipts_json: vec![],
            },
            &[],
            10.,
            |_| Ok(()),
        )
        .is_ok()
    }
    async fn activate(&self, _: i64) -> Result<ValidatorSet, Error> {
        Ok(self.set.clone())
    }
    async fn validators(&self, _: i64) -> Result<ValidatorSet, Error> {
        Ok(self.set.clone())
    }
    async fn evidence(&self, conflict: VoteConflict) -> Result<(), Error> {
        self.evidence.lock().unwrap().push(conflict);
        Ok(())
    }
    fn warning(&self, s: &str) {
        self.warnings.lock().unwrap().push(s.into());
    }
}
#[async_trait::async_trait]
impl Publication for Authority {
    fn head_epoch(&self) -> i64 {
        self.commits
            .lock()
            .unwrap()
            .last()
            .map_or(0, |f| f.epoch_id)
    }
    async fn finalized(&self, set: &ValidatorSet, f: &Finalize) -> Result<(), Error> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if self.reject_publish.load(Ordering::SeqCst) {
            return Err("injected publication failure".into());
        }
        qc::validate_finalize(CHAIN, set, f, qc::FinalityMode::Live(Protocol::default()))?;
        let mut commits = self.commits.lock().unwrap();
        if !commits.contains(f) {
            commits.push(f.clone());
        }
        Ok(())
    }
    fn stopped(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }
}

struct Dispatch {
    handle: Handle,
    seen: Arc<Mutex<Vec<Frame>>>,
}
impl Handler for Dispatch {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        let result = self
            .handle
            .enqueue(&peer, &frame)
            .map_err(|e| octra_node_protocol::network::Error::from(e.to_string()));
        self.seen.lock().unwrap().push(frame);
        Box::pin(async move { result.map(|_| ()) })
    }
}
struct Node {
    authority: Authority,
    handle: Handle,
    swarm: Swarm,
    endpoint: Endpoint,
    seen: Arc<Mutex<Vec<Frame>>>,
    gate: watch::Sender<bool>,
    stop: watch::Sender<bool>,
    driver: JoinHandle<Result<(), Error>>,
    network: JoinHandle<()>,
    _dir: tempfile::TempDir,
}
impl Drop for Node {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        self.swarm.stop();
        self.driver.abort();
        self.network.abort();
    }
}
async fn node(id: u8, n: u8, bootstrap: Vec<Endpoint>, restored: Option<Proposal>) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let journal = JournalOwner::open(dir.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint {
        host: b"127.0.0.1".to_vec(),
        port: listener.local_addr().unwrap().port(),
    };
    let set = validators(n);
    let swarm = Swarm::new(
        Config {
            chain_id: CHAIN.to_vec(),
            node_address: address(id),
            config_hash: vec![1; 32],
            binary_hash: vec![2; 32],
            require_binary_hash: false,
            upgrade: None,
            profiles: vec![],
            allowed_public_keys: set.validators.iter().map(|v| v.pubkey.clone()).collect(),
            bootstrap,
            maximum_validators: 16,
            advertised: endpoint.clone(),
            timeouts: Timeouts {
                handshake_read: Duration::from_secs(10),
                read_idle: Duration::from_secs(60),
                write_idle: Duration::from_secs(10),
            },
            head: Arc::new(|| (0, [0; 32])),
        },
        key(id),
    )
    .unwrap();
    let (gate, verify_gate) = watch::channel(true);
    let authority = Authority {
        id,
        set: set.clone(),
        journal: journal.clone(),
        ready: Arc::default(),
        commits: Arc::default(),
        attempts: Arc::default(),
        builds: Arc::default(),
        checks: Arc::default(),
        stopped: Arc::default(),
        reject_publish: Arc::default(),
        reject_precommit: Arc::default(),
        fail_build: Arc::default(),
        wait_verify: Arc::default(),
        readiness_checks: Arc::default(),
        verify_gate,
        warnings: Arc::default(),
        evidence: Arc::default(),
    };
    let mut engine = Engine::new(
        CHAIN.to_vec(),
        address(id),
        set,
        1,
        Protocol::default(),
        TimeoutConfig::default(),
    );
    if let Some(proposal) = restored {
        engine.restore_precommit_lock(proposal).unwrap();
    }
    let (handle, driver) = Driver::new(
        engine,
        journal,
        swarm.clone(),
        authority.clone(),
        authority.clone(),
        Ok(vec![]),
    )
    .unwrap();
    let (stop, shutdown) = watch::channel(false);
    let seen = Arc::default();
    let dispatch = Arc::new(Dispatch {
        handle: handle.clone(),
        seen: Arc::clone(&seen),
    });
    let network = swarm.clone();
    let network = tokio::spawn(async move {
        network.run(listener, dispatch).await.unwrap();
    });
    let driver = tokio::spawn(driver.run(shutdown));
    Node {
        authority,
        handle,
        swarm,
        endpoint,
        seen,
        gate,
        stop,
        driver,
        network,
        _dir: dir,
    }
}
async fn wait(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(12), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("condition timed out");
}
fn enable(nodes: &[Node]) {
    for node in nodes {
        node.authority.ready.store(true, Ordering::SeqCst);
        node.handle.wake().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authentic_quorum_retries_publication_without_advancing_vote_floor() {
    let mut nodes = vec![node(1, 4, vec![], None).await];
    for id in 2..=4 {
        nodes.push(
            node(
                id,
                4,
                nodes.iter().map(|n| n.endpoint.clone()).collect(),
                None,
            )
            .await,
        );
    }
    wait(|| nodes.iter().all(|n| n.swarm.peers().len() == 3)).await;
    nodes[0]
        .authority
        .reject_publish
        .store(true, Ordering::SeqCst);
    nodes[0].gate.send_replace(false);
    nodes[0].authority.wait_verify.store(true, Ordering::SeqCst);
    let leader = validators(4).leader(1, 0).unwrap().address.clone();
    nodes
        .iter()
        .find(|n| address(n.authority.id) == leader)
        .unwrap()
        .authority
        .fail_build
        .store(true, Ordering::SeqCst);
    enable(&nodes);
    wait(|| {
        nodes[0].authority.attempts.load(Ordering::SeqCst) >= 2
            && nodes[1..].iter().all(|n| n.authority.head_epoch() == 1)
    })
    .await;
    assert_eq!(nodes[0].authority.journal.floor().unwrap(), Some(0));
    assert_eq!(nodes[0].handle.status().borrow().height, 1);
    assert!(!nodes[0].driver.is_finished());
    nodes[0].gate.send_replace(true);
    let checks = nodes[0].authority.readiness_checks.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        nodes[0].authority.readiness_checks.load(Ordering::SeqCst) - checks < 500,
        "expired proposal retry caused a busy loop during failed publication"
    );
    nodes[0]
        .authority
        .wait_verify
        .store(false, Ordering::SeqCst);

    nodes[0]
        .authority
        .reject_publish
        .store(false, Ordering::SeqCst);
    wait(|| nodes.iter().all(|n| n.handle.status().borrow().height == 2)).await;
    let expected = nodes[0].authority.commits.lock().unwrap()[0]
        .proposal_id
        .clone();
    for node in &nodes {
        assert_eq!(node.authority.journal.floor().unwrap(), Some(1));
        let commits = node.authority.commits.lock().unwrap();
        assert_eq!(commits.len(), 1);
        qc::validate_finalize(
            CHAIN,
            &validators(4),
            &commits[0],
            qc::FinalityMode::Persisted,
        )
        .unwrap();
        assert_eq!(commits[0].proposal_id, expected);
    }
    // Every emitted local non-nil precommit has recoverable WAL before sending.
    for receiver in &nodes {
        for frame in receiver
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.message == 0x31)
        {
            let vote = Vote::decode(&frame.payload).unwrap();
            if vote.vote_type == VoteType::Precommit && vote.proposal_id != vec![0; 32] {
                let sender = nodes
                    .iter()
                    .find(|n| address(n.authority.id) == vote.validator)
                    .unwrap();
                assert!(sender.authority.journal.find_vote(&vote).unwrap().is_some());
                assert!(!sender.authority.journal.pending().unwrap().is_empty());
            }
        }
    }
    for node in &nodes {
        node.stop.send_replace(true);
    }
    wait(|| {
        nodes
            .iter()
            .all(|n| n.driver.is_finished() && n.authority.stopped.load(Ordering::SeqCst))
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_verification_leaves_peer_reader_live_and_cancellation_stops_worker() {
    let nodes = vec![node(1, 2, vec![], None).await];
    let mut nodes = nodes;
    nodes.push(node(2, 2, vec![nodes[0].endpoint.clone()], None).await);
    wait(|| nodes.iter().all(|n| n.swarm.peers().len() == 1)).await;
    let leader = validators(2).leader(1, 0).unwrap().address.clone();
    let follower = nodes
        .iter()
        .position(|n| address(n.authority.id) != leader)
        .unwrap();
    nodes[follower].gate.send_replace(false);
    enable(&nodes);
    wait(|| nodes[follower].authority.checks.load(Ordering::SeqCst) > 0).await;
    // A malformed vote is handled while the proposal verifier is still waiting.
    let remote = nodes
        .iter()
        .find(|n| address(n.authority.id) == leader)
        .unwrap();
    remote
        .swarm
        .broadcast(
            Frame {
                message: 0x31,
                payload: vec![0],
            },
            None,
            true,
        )
        .await
        .unwrap();
    wait(|| {
        nodes[follower]
            .authority
            .warnings
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.contains("frame 49 rejected"))
    })
    .await;
    assert_eq!(nodes[follower].authority.head_epoch(), 0);
    nodes[follower].stop.send_replace(true);
    wait(|| nodes[follower].driver.is_finished()).await;
    nodes[follower].gate.send_replace(true);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(nodes[follower].authority.head_epoch(), 0);
    assert!(nodes[follower]
        .authority
        .journal
        .pending()
        .unwrap()
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restored_lock_survives_driver_start() {
    let mut p = Proposal {
        chain_id: CHAIN.to_vec(),
        epoch_id: 1,
        round: 4,
        valid_round: None,
        header: header(1, address(1)),
        tx_hashes: vec![],
        parent_commit: None,
        proposer: address(1),
        signature: vec![],
    };
    p.signature = key(1)
        .sign(&hash::propose_sign_bytes(&p).unwrap())
        .to_bytes()
        .to_vec();
    let restored = node(1, 1, vec![], Some(p)).await;
    wait(|| restored.handle.status().borrow().started).await;
    assert_eq!(restored.handle.status().borrow().locked_round, 4);
    assert!(
        restored.handle.status().borrow().round >= 4,
        "startup reset recovered round"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_precommit_durability_never_reaches_peers() {
    let first = node(1, 2, vec![], None).await;
    let second = node(2, 2, vec![first.endpoint.clone()], None).await;
    let nodes = [first, second];
    wait(|| nodes.iter().all(|n| n.swarm.peers().len() == 1)).await;
    for node in &nodes {
        node.authority
            .reject_precommit
            .store(true, Ordering::SeqCst);
    }
    enable(&nodes);
    wait(|| {
        nodes
            .iter()
            .all(|n| n.handle.status().borrow().issue.as_deref() == Some("precommit_not_durable"))
    })
    .await;
    for node in &nodes {
        assert_eq!(node.authority.head_epoch(), 0);
        assert_eq!(node.authority.journal.floor().unwrap(), Some(0));
        assert!(node.authority.journal.pending().unwrap().is_empty());
        for frame in node
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.message == 0x31)
        {
            assert_ne!(
                Vote::decode(&frame.payload).unwrap().vote_type,
                VoteType::Precommit
            );
        }
    }
}
