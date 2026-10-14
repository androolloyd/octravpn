use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::consensus::{journal::JournalOwner, pending_log::PendingCommit};
use octra_node_protocol::{
    consensus::{Error, Validator, ValidatorSet},
    network::{
        endpoint::Endpoint,
        frame::Frame,
        session::{Peer, Timeouts},
        swarm::{Config, Handler, MessageFuture, Swarm},
    },
};
use octra_node_runtime::epoch_roots::{reached, EpochRoots, Host, Response, State, WaitFor};
use octra_node_runtime::{consensus_recovery::Restored, pending_reconciliation};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};
const CHAIN: &[u8] = b"root-fixture";
const WAIT: Duration = Duration::from_secs(10);
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn validators(weights: &[i64], weighted: bool) -> ValidatorSet {
    let entries = weights
        .iter()
        .enumerate()
        .map(|(i, w)| {
            (
                Validator {
                    address: format!("v{}", i + 1).into_bytes(),
                    pubkey: key((i + 1) as u8).verifying_key().to_bytes().to_vec(),
                },
                (*w).into(),
            )
        })
        .collect::<Vec<_>>();
    if weighted {
        ValidatorSet::weighted(entries).unwrap()
    } else {
        ValidatorSet::unweighted(entries.into_iter().map(|(v, _)| v).collect())
    }
}
#[test]
fn native_root_query_agreement_and_weighted_quorum() {
    let f: Value = serde_json::from_str(include_str!("fixtures/epoch-roots.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(f["upstream_commit"], source["upstream_commit"]);
    assert_eq!(f["source_sha256"], source["files"]);
    assert_eq!(f["instrumentation"], json!({}));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (field, path) in [
        ("oracle_sha256", "scripts/node-port/epoch-roots-oracle.ml"),
        ("runner_sha256", "scripts/node-port/native-oracle.py"),
    ] {
        assert_eq!(
            f[field],
            hex::encode(Sha256::digest(fs::read(root.join(path)).unwrap()))
        );
    }
    for (i, case) in f["cases"].as_array().unwrap().iter().enumerate() {
        let j = &case["input"];
        let set = validators(
            &j["weights"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().parse().unwrap())
                .collect::<Vec<_>>(),
            j["weighted"].as_bool().unwrap(),
        );
        let records = j["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| Response {
                responder_addr: r["addr"].as_str().unwrap().as_bytes().to_vec(),
                responder_head_epoch: 0,
                state_root: r["root"].as_str().map(|s| s.as_bytes().to_vec()),
            })
            .collect::<Vec<_>>();
        let check = |wait| {
            reached(
                j["chain"].as_str().unwrap().as_bytes(),
                j["epoch"].as_str().unwrap().parse().unwrap(),
                &set,
                wait,
                &records,
            )
            .unwrap()
        };
        assert_eq!(
            json!({"source":check(WaitFor::SourceAgreement),"quorum":check(WaitFor::ConsensusQuorum)}),
            case["expected"],
            "root policy {i}"
        );
    }
}
#[derive(Clone)]
struct Authority {
    seed: u8,
    requests: Arc<AtomicUsize>,
    corrupt: Arc<AtomicBool>,
    remembered: Arc<Mutex<Vec<Response>>>,
    next: Arc<Mutex<Vec<i64>>>,
}
#[async_trait::async_trait]
impl Host for Authority {
    async fn state(&self) -> Result<State, Error> {
        Ok(State {
            active: validators(&[1; 4], false),
            stake: validators(&[1; 4], false),
            height: 8,
            head: 7,
        })
    }
    async fn root(&self, epoch: i64) -> Result<Option<Vec<u8>>, Error> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        Ok((epoch == 7).then(|| vec![7; 32]))
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(if self.corrupt.load(Ordering::SeqCst) {
            vec![0; 64]
        } else {
            key(self.seed).sign(bytes).to_bytes().to_vec()
        })
    }
    fn remember(&self, _epoch: i64, response: &Response) {
        self.remembered.lock().unwrap().push(response.clone());
    }
    async fn request_missing_finalize(
        &self,
        epoch: i64,
        _responses: &[Response],
    ) -> Result<(), Error> {
        self.next.lock().unwrap().push(epoch);
        Ok(())
    }
}
struct Dispatch {
    roots: EpochRoots<Authority>,
    gate: watch::Receiver<bool>,
}
impl Handler for Dispatch {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        let roots = self.roots.clone();
        let mut gate = self.gate.clone();
        Box::pin(async move {
            if frame.message == 0x35 {
                while !*gate.borrow_and_update() {
                    if gate.changed().await.is_err() {
                        return Ok(());
                    }
                }
            }
            roots
                .handle(&peer, &frame)
                .await
                .map_err(|e| octra_node_protocol::network::Error::from(e.to_string()))?;
            Ok(())
        })
    }
}
struct Node {
    swarm: Swarm,
    endpoint: Endpoint,
    roots: EpochRoots<Authority>,
    authority: Authority,
    gate: watch::Sender<bool>,
    task: JoinHandle<()>,
}
impl Drop for Node {
    fn drop(&mut self) {
        self.swarm.stop();
        self.task.abort();
    }
}
async fn node(seed: u8, bootstrap: Vec<Endpoint>) -> Node {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint {
        host: b"127.0.0.1".to_vec(),
        port: listener.local_addr().unwrap().port(),
    };
    let swarm = Swarm::new(
        Config {
            chain_id: CHAIN.to_vec(),
            node_address: format!("v{seed}").into_bytes(),
            config_hash: vec![1; 32],
            binary_hash: vec![2; 32],
            require_binary_hash: false,
            upgrade: None,
            profiles: vec![],
            allowed_public_keys: (1..=4)
                .map(|n| key(n).verifying_key().to_bytes().to_vec())
                .collect(),
            bootstrap,
            maximum_validators: 16,
            advertised: endpoint.clone(),
            timeouts: Timeouts {
                handshake_read: WAIT,
                read_idle: Duration::from_secs(60),
                write_idle: WAIT,
            },
            head: Arc::new(|| (7, [7; 32])),
        },
        key(seed),
    )
    .unwrap();
    let authority = Authority {
        seed,
        requests: Arc::new(AtomicUsize::new(0)),
        corrupt: Arc::new(AtomicBool::new(false)),
        remembered: Arc::new(Mutex::new(vec![])),
        next: Arc::new(Mutex::new(vec![])),
    };
    let roots = EpochRoots::new(
        CHAIN.to_vec(),
        format!("v{seed}").into_bytes(),
        authority.clone(),
        swarm.clone(),
    );
    let (gate, receive) = watch::channel(true);
    let dispatch = Arc::new(Dispatch {
        roots: roots.clone(),
        gate: receive,
    });
    let runner = swarm.clone();
    let task = tokio::spawn(async move {
        runner.run(listener, dispatch).await.unwrap();
    });
    Node {
        swarm,
        endpoint,
        roots,
        authority,
        gate,
        task,
    }
}
async fn wait_for(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

// Real network queries and disk journals; canonical catch-up remains a
// controlled host callback in this transport/recovery qualification.
struct Startup {
    roots: EpochRoots<Authority>,
    journal: JournalOwner,
    head: i64,
    advance: bool,
}
#[async_trait::async_trait]
impl pending_reconciliation::Host for Startup {
    fn head_epoch(&self) -> Result<i64, Error> {
        Ok(self.head)
    }
    fn pending(&self) -> Result<Vec<PendingCommit>, Error> {
        self.journal.pending()
    }
    fn restore(&mut self, pending: &PendingCommit) -> Restored {
        assert!(pending.proposal_b64.is_none());
        Restored::Legacy
    }
    async fn query(&mut self, epoch: i64) -> Result<Vec<Option<Vec<u8>>>, Error> {
        Ok(self
            .roots
            .query(epoch, 1., WaitFor::SourceAgreement, false)
            .await?
            .into_iter()
            .map(|r| r.state_root)
            .collect())
    }
    async fn catchup(&mut self, epoch: i64) -> Result<(), Error> {
        assert_eq!(epoch, 7);
        assert_eq!(self.journal.pending()?.len(), 1);
        if self.advance {
            self.head = epoch;
        }
        Ok(())
    }
    fn delete(&mut self, epoch: i64, round: i64) -> Result<(), Error> {
        assert!(self.head >= epoch);
        self.journal.delete_pending(epoch, round)
    }
}
#[tokio::test]
async fn authenticated_epoch_roots_keep_other_readers_alive_after_cancellation() {
    let a = node(1, vec![]).await;
    let b = node(2, vec![a.endpoint.clone()]).await;
    let c = node(3, vec![a.endpoint.clone()]).await;
    let d = node(4, vec![a.endpoint.clone()]).await;
    wait_for(|| [&a, &b, &c, &d].iter().all(|n| n.swarm.peers().len() == 3)).await;
    a.gate.send_replace(false);
    let roots = a.roots.clone();
    let first =
        tokio::spawn(async move { roots.query(7, 10., WaitFor::SourceAgreement, false).await });
    let roots = a.roots.clone();
    let second =
        tokio::spawn(async move { roots.query(7, 10., WaitFor::ConsensusQuorum, true).await });
    wait_for(|| {
        [&b, &c, &d]
            .iter()
            .all(|n| n.authority.requests.load(Ordering::SeqCst) >= 2)
    })
    .await;
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    a.gate.send_replace(true);
    let replies = tokio::time::timeout(WAIT, second)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(replies.len(), 3);
    assert!(replies
        .iter()
        .all(|r| r.state_root == Some(vec![7; 32]) && r.responder_head_epoch == 7));
    let signers: std::collections::BTreeSet<_> =
        replies.iter().map(|r| r.responder_addr.clone()).collect();
    assert_eq!(signers.len(), 3);
    assert_eq!(*a.authority.next.lock().unwrap(), vec![8]);
    // Missing roots are authenticated replies but cannot meet root agreement.
    let missing = a
        .roots
        .query(9, 0.15, WaitFor::SourceAgreement, true)
        .await
        .unwrap();
    assert_eq!(missing.len(), 3);
    assert!(missing.iter().all(|r| r.state_root.is_none()));
    assert_eq!(*a.authority.next.lock().unwrap(), vec![8]);
    // Forged validator signatures cannot enter the next reader's reply set.
    b.authority.corrupt.store(true, Ordering::SeqCst);
    a.authority.remembered.lock().unwrap().clear();
    let checked = a
        .roots
        .query(7, 0.25, WaitFor::ConsensusQuorum, false)
        .await
        .unwrap();
    assert_eq!(checked.len(), 2);
    assert!(checked
        .iter()
        .all(|r| r.responder_addr != b"v2" && r.state_root == Some(vec![7; 32])));
    assert!(a
        .authority
        .remembered
        .lock()
        .unwrap()
        .iter()
        .all(|r| r.responder_addr != b"v2"));
    let dir = tempfile::tempdir().unwrap();
    let journal = JournalOwner::open(dir.path()).unwrap();
    journal
        .keep_pending(&PendingCommit {
            epoch_id: 7,
            round: 0,
            proposal_id: b"legacy".to_vec(),
            proposed_state_root: hex::encode([7; 32]).into_bytes(),
            txid_hi: 0,
            ts: 1.,
            validator_addr: b"v1".to_vec(),
            proposal_b64: None,
            vote_b64: None,
            tx_hashes: vec![],
            txs_json: vec![],
            receipts_json: vec![],
        })
        .unwrap();
    drop(journal);
    let mut startup = Startup {
        roots: a.roots.clone(),
        journal: JournalOwner::open(dir.path()).unwrap(),
        head: 6,
        advance: false,
    };
    assert!(!pending_reconciliation::run_once(&mut startup, 4, 2)
        .await
        .unwrap());
    assert_eq!(startup.journal.pending().unwrap().len(), 1);
    startup.advance = true;
    assert!(pending_reconciliation::run_once(&mut startup, 4, 2)
        .await
        .unwrap());
    assert!(startup.journal.pending().unwrap().is_empty());
    for n in [&a, &b, &c, &d] {
        n.swarm.stop();
    }
}
