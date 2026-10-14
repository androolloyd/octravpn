//! This composes the real live engines, peer bundle requests, canonical SQL,
//! Circle WASM views, VPN revocation and ExEx. Genesis escrow is still a fixture.
use super::{
    announce, bundle_peer, counter, execute, finality_host, genesis, network_bundle, open, reached,
    vpn_config, Authority, ImportExecutor, Recorder,
};
use ed25519_dalek::{Signer, SigningKey};
use octra_exex::{sqlite::SqliteCheckpoints, ChainIdentity, StateRoot};
use octra_node::{consensus::Canonical, Node, Status};
use octra_node_protocol::consensus::{
    codec::Wire,
    engine::{Engine, TimeoutConfig},
    evidence::VoteConflict,
    hash,
    journal::JournalOwner,
    policy::Protocol,
    Bytes, EpochHeader, Error, Finalize, ParentCommit, Proposal, ValidatorSet,
};
use octra_node_runtime::{
    canonical::CanonicalStore,
    consensus_bundle,
    consensus_driver::{Driver, Host, ProposalPlan, Publication, Verdict},
    consensus_recovery,
    consensus_votes::{Precommit, Readiness},
};
use octravpn_node::admission::SessionAuthority;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tokio::sync::watch;

// Development activation and staging remain explicit inputs. Construction,
// verification and finalized publication use the reusable Native executor.
fn protocol() -> Protocol {
    // The first retained epoch has no parent QC. Use the native legacy startup
    // interval explicitly, then require a parent certificate from epoch two.
    Protocol::new(2).unwrap()
}

fn proposal_rules(header: &EpochHeader) -> consensus_bundle::Rules {
    use octra_node_protocol::{
        rules::{self, Rule},
        transaction_outcome,
    };
    let mode = |rule| rules::at(&header.chain_id, rule, header.epoch_id);
    consensus_bundle::Rules {
        payload: octra_node_protocol::transaction_payload::Limits::default(),
        crypto_active: false,
        stealth_minimum: 5000.into(),
        envelope: transaction_outcome::Rules {
            envelope: mode(Rule::TxEnvelope),
            compute: mode(Rule::VmBytes),
            settle: mode(Rule::Settle),
        },
    }
}

struct LiveHost {
    node: Arc<Node<Authority>>,
    id: u8,
    set: ValidatorSet,
    journal: JournalOwner,
    peer: bundle_peer::Authority,
    bundles: octra_node_runtime::bundle_queries::Bundles<bundle_peer::Authority>,
    authority: finality_host::Authority,
    executor: octra_node::executor::Native,
    prepared: Mutex<Option<octra_node::executor::Prepared>>,
    built: Mutex<Option<octra_node::executor::Built>>,
    pending: Arc<octra_node::executor::Pending>,
    refused: Arc<Mutex<Vec<Vec<u8>>>>,
    ready: Arc<AtomicBool>,
    warnings: Arc<Mutex<Vec<String>>>,
}
#[async_trait::async_trait]
impl Host for LiveHost {
    fn sign(&self, bytes: &[u8]) -> Result<Bytes, Error> {
        Ok(SigningKey::from_bytes(&[self.id + 1; 32])
            .sign(bytes)
            .to_bytes()
            .to_vec())
    }
    fn readiness(&self) -> Readiness {
        Readiness {
            role_can_vote: true,
            can_vote: self.ready.load(Ordering::SeqCst)
                && self
                    .node
                    .snapshot()
                    .is_ok_and(|v| v.head().cursor.epoch.0 == 0),
            finality_proof_needed: false,
        }
    }
    fn verify_parent(&self, epoch: i64, parent: Option<&ParentCommit>) -> Result<(), Error> {
        if epoch != 1 || parent.is_some() {
            return Err("fixture only executes first live epoch".into());
        }
        Ok(())
    }
    async fn build(&self, epoch: i64) -> Result<Option<ProposalPlan>, Error> {
        let graph = octra_node_protocol::rules::Graph::new(
            self.authority.chain.chain_id.as_bytes().to_vec(),
            None,
        );
        let draft = Arc::new(
            self.node
                .proposal_draft(
                    &graph,
                    octra_node_runtime::finality::proposal::Policy {
                        protocol: protocol(),
                        genesis_time: Some(0.),
                    },
                    format!("validator-{}", self.id).as_bytes(),
                    10.,
                )
                .await
                .map_err(|e| Error::from(e.to_string()))?,
        );
        if draft.context().header().epoch_id != epoch {
            return Ok(None);
        }
        let built = self
            .executor
            .build_pending(draft, self.pending.clone(), 10_000_000_000_u64.into(), 4)
            .await
            .map_err(|e| Error::from(e.to_string()))?;
        if !self.node.draft_current(built.draft()) {
            return Ok(None);
        }
        self.refused
            .lock()
            .unwrap()
            .extend(built.refused().iter().map(|tx| tx.hash().unwrap().to_vec()));
        assert!(built.held().is_empty());
        self.peer.cached.lock().unwrap().insert(
            hash::proposal_id(&built.plan().header)?,
            built.bundle().clone(),
        );
        let plan = ProposalPlan {
            header: built.plan().header.clone(),
            tx_hashes: built.plan().tx_hashes.clone(),
            parent_commit: built.plan().parent_commit.clone(),
        };
        *self.built.lock().unwrap() = Some(built);
        Ok(Some(plan))
    }
    async fn verify(&self, p: &Proposal) -> Result<Verdict, Error> {
        let candidate = match self
            .node
            .proposal_candidate(
                p,
                &octra_node_protocol::rules::Graph::new(
                    self.authority.chain.chain_id.as_bytes().to_vec(),
                    None,
                ),
                octra_node_runtime::finality::proposal::Policy {
                    protocol: protocol(),
                    genesis_time: Some(0.),
                },
                10.,
            )
            .await
        {
            Ok(candidate) => Arc::new(candidate),
            Err(octra_node_runtime::finality::Error::Invalid(_)) => return Ok(Verdict::Reject),
            Err(e) => {
                self.warning(&e.to_string());
                return Ok(Verdict::Wait);
            }
        };
        let rules = self
            .executor
            .proposal_rules(&candidate)
            .map_err(|e| Error::from(e.to_string()))?;
        // This fetch shares the connection that delivered the proposal. It
        // would deadlock if the peer reader awaited the consensus actor.
        let Some((_, bundle)) = self
            .bundles
            .query(p.epoch_id, hash::proposal_id(&p.header)?, 3., |r| {
                Ok(consensus_bundle::proposal_wire(p, &r.bundle, &rules).ok())
            })
            .await?
        else {
            return Ok(Verdict::Wait);
        };
        let prepared = match self
            .executor
            .verify_proposal(candidate.clone(), &bundle.to_raw()?)
            .await
        {
            Ok(prepared) => prepared,
            Err(error @ octra_node::executor::ProposalError::Invalid(_)) => {
                self.warning(&error.to_string());
                return Ok(Verdict::Reject);
            }
            Err(error) => {
                self.warning(&error.to_string());
                return Ok(Verdict::Wait);
            }
        };
        if !self.node.proposal_current(&candidate) {
            return Ok(Verdict::Wait);
        }
        self.peer
            .cached
            .lock()
            .unwrap()
            .insert(hash::proposal_id(&p.header)?, prepared.bundle().clone());
        *self.prepared.lock().unwrap() = Some(prepared);
        Ok(Verdict::Accept)
    }
    async fn before_precommit(&self, record: Precommit) -> bool {
        let result = (|| {
            self.node
                .snapshot()
                .map_err(|e| Error::from(e.to_string()))?;
            let proposal = Proposal::decode(&record.proposal_wire)?;
            // Native leaders prevote their own execution without first
            // receiving their proposal back through a peer. Both local builds
            // and verified peer candidates must retain their canonical lease.
            let local = self.built.lock().unwrap();
            let received = self.prepared.lock().unwrap();
            let current = local.as_ref().is_some_and(|built| {
                self.node.draft_current(built.draft()) && built.plan().header == proposal.header
            }) || received.as_ref().is_some_and(|prepared| {
                self.node.proposal_current(prepared.candidate())
                    && prepared.candidate().context().proposal().header == proposal.header
            });
            if !current {
                return Err("local proposal execution expired".into());
            }
            let rules = proposal_rules(&proposal.header);
            let raw = self
                .peer
                .cached
                .lock()
                .unwrap()
                .get(&hash::proposal_id(&proposal.header)?)
                .cloned()
                .ok_or("precommit bundle unavailable")?;
            consensus_recovery::before_precommit(
                &consensus_recovery::Context {
                    chain_id: self.authority.chain.chain_id.as_bytes(),
                    validator_set: &self.set,
                    protocol: protocol(),
                    rules: &rules,
                },
                &self.journal,
                format!("validator-{}", self.id).as_bytes(),
                &record,
                &raw,
                &[],
                10.,
                |_| Ok(()),
            )
        })();
        if let Err(e) = &result {
            self.warning(&e.to_string());
        }
        result.is_ok()
    }
    async fn activate(&self, _: i64) -> Result<ValidatorSet, Error> {
        Ok(self.set.clone())
    }
    async fn validators(&self, _: i64) -> Result<ValidatorSet, Error> {
        Ok(self.set.clone())
    }
    async fn evidence(&self, _: VoteConflict) -> Result<(), Error> {
        Ok(())
    }
    fn warning(&self, s: &str) {
        self.warnings.lock().unwrap().push(s.into());
    }
}

async fn open_circle(http: &reqwest::Client, base: &str, circle: &str, scope: &str) -> String {
    let response = http
        .get(format!("{base}/open"))
        .query(&[("u", format!("oct://{circle}/index.html"))])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(
        response.url().path(),
        format!("/view/{scope}/{circle}/index.html")
    );
    let html = response.text().await.unwrap();
    html.split("data-token=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_quorum_publishes_circle_vpn_and_exex_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let circle = format!("oct{}", "1".repeat(44));
    let state = genesis(circle.as_bytes());
    let chain = ChainIdentity {
        chain_id: "live-node-services-fixture".into(),
        genesis_root: StateRoot(finality_host::root(None, &state, &[])),
    };
    let authority = finality_host::Authority {
        seed: 1,
        chain: chain.clone(),
    };
    let mut nodes = vec![];
    let mut peers = vec![];
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&dir.path().join("exex.db"))
            .await
            .unwrap(),
    );
    for id in 0..4 {
        let db = dir.path().join(format!("node-{id}.db"));
        drop(
            CanonicalStore::create(&db, chain.clone(), state.snapshot(), 0)
                .await
                .unwrap(),
        );
        let node = Arc::new(open(&db, checkpoints.clone(), chain.clone(), Arc::default()).await);
        assert!(node.resume().await.unwrap());
        let set = authority
            .validators(node.snapshot().unwrap().head(), 1)
            .unwrap();
        let peer = bundle_peer::node(
            chain.chain_id.as_bytes(),
            format!("validator-{id}").into_bytes(),
            SigningKey::from_bytes(&[id + 1; 32]),
            set,
            peers
                .iter()
                .map(|p: &bundle_peer::Node| p.endpoint.clone())
                .collect(),
        )
        .await;
        *peer.authority.history.lock().unwrap() = Some(node.history());
        peers.push(peer);
        nodes.push(node);
    }
    bundle_peer::wait_for(|| peers.iter().all(|p| p.swarm.peers().len() == 3)).await;
    let committed = nodes[0].snapshot().unwrap();
    let (wire, executed) = execute(&committed, circle.as_bytes(), &authority);
    let mut planned = Finalize::decode(&wire).unwrap();
    planned.header.proto_version = protocol().version_at(1);
    let set = authority.validators(committed.head(), 1).unwrap();
    // Keep the fixture's creator/reward attribution and let the real engines
    // produce the certificate. No fixture certificate enters publication.
    let round = (0..32)
        .find(|&r| set.leader(1, r).unwrap().address == b"validator-0")
        .unwrap();
    let mut proposal = Proposal {
        chain_id: planned.chain_id.clone(),
        epoch_id: 1,
        round,
        valid_round: None,
        header: planned.header.clone(),
        tx_hashes: network_bundle(&executed).tx_hashes,
        parent_commit: None,
        proposer: b"validator-0".to_vec(),
        signature: vec![],
    };
    proposal.signature = SigningKey::from_bytes(&[1; 32])
        .sign(&hash::propose_sign_bytes(&proposal).unwrap())
        .to_bytes()
        .to_vec();
    let graph = octra_node_protocol::rules::Graph::new(chain.chain_id.as_bytes().to_vec(), None);
    let policy = octra_node_runtime::finality::proposal::Policy {
        protocol: protocol(),
        genesis_time: Some(0.),
    };
    let candidate = nodes[0]
        .proposal_candidate(&proposal, &graph, policy, 10.)
        .await
        .unwrap();
    assert!(nodes[0].proposal_current(&candidate));
    assert!(candidate.context().rules().authority().is_err());
    nodes[0].suspend("candidate freshness test");
    assert!(!nodes[0].proposal_current(&candidate));
    assert!(nodes[0]
        .proposal_candidate(&proposal, &graph, policy, 10.)
        .await
        .is_err());
    nodes[0].resume().await.unwrap();
    assert!(
        !nodes[0].proposal_current(&candidate),
        "resume revived a revoked candidate"
    );
    let candidate = nodes[0]
        .proposal_candidate(&proposal, &graph, policy, 10.)
        .await
        .unwrap();
    assert!(nodes[0].proposal_current(&candidate));
    // Uncommitted bundles must be served by the proposal cache, while durable
    // history supplies committed range/root queries after publication.
    *peers[0].authority.history.lock().unwrap() = None;
    let records = Arc::new(Mutex::new(vec![]));
    nodes[0].register(Recorder(records.clone())).await.unwrap();
    let (request, settlement) = announce();
    let domain = &settlement.session.domain;
    let admission = nodes[0].vpn_authority(settlement.clone());
    let permit = admission
        .authorize(&request, domain)
        .await
        .unwrap()
        .unwrap();
    let services = nodes[0]
        .bind(
            "127.0.0.1:0".parse().unwrap(),
            vpn_config(&dir.path().join("vpn"), domain),
            settlement.clone(),
        )
        .await
        .unwrap();
    let base = format!("http://{}", services.browser_addr().unwrap());
    let (service_stop, service_shutdown) = watch::channel(false);
    let serving = tokio::spawn(services.run(service_shutdown));
    let http = reqwest::Client::new();
    let token = open_circle(
        &http,
        &base,
        &circle,
        &nodes[0].snapshot().unwrap().provenance().id(),
    )
    .await;
    assert_eq!(
        counter(&http, &base, &token)
            .await
            .json::<serde_json::Value>()
            .await
            .unwrap()["result"]["result"],
        "4"
    );
    // An admitted exit from an unbonded validator and its successor force sender cutoffs before
    // this leader can publish the independently expected Circle transition.
    use base64::Engine as _;
    use octra_node_protocol::transaction::{Nonce, OpType};
    let call = super::circle_call(1, circle.as_bytes());
    let mut rejected = call.clone();
    rejected.op_type = OpType::ValidatorExit;
    rejected.nonce = Nonce::new(2).unwrap();
    rejected.amount = 0.into();
    rejected.to = rejected.from.clone();
    rejected.encrypted_data = None;
    rejected.message = None;
    let mut successor = rejected.clone();
    successor.op_type = OpType::Standard;
    successor.to = circle.as_bytes().to_vec();
    successor.nonce = Nonce::new(3).unwrap();
    successor.amount = 1.into();
    successor.encrypted_data = None;
    successor.message = None;
    for tx in [&mut rejected, &mut successor] {
        tx.signature = base64::engine::general_purpose::STANDARD
            .encode(
                SigningKey::from_bytes(&[42; 32])
                    .sign(&tx.signing_bytes().unwrap())
                    .to_bytes(),
            )
            .into_bytes();
    }
    let refused_hash = rejected.hash().unwrap().to_vec();
    let inputs = vec![call.clone(), rejected.clone(), successor.clone()];
    let refused = Arc::new(Mutex::new(vec![]));
    let ready = Arc::new(AtomicBool::new(false));
    let warnings = Arc::new(Mutex::new(vec![]));
    let mut tasks = vec![];
    let mut handles = vec![];
    let mut stops = vec![];
    let mut queues = vec![];
    for id in 0..4usize {
        let journal = JournalOwner::open(dir.path().join(format!("journal-{id}"))).unwrap();
        let mut engine = Engine::new(
            chain.chain_id.as_bytes().to_vec(),
            format!("validator-{id}").into_bytes(),
            set.clone(),
            1,
            protocol(),
            TimeoutConfig::default(),
        );
        engine.realign_round(round).unwrap();
        let executor = ImportExecutor::with_protocol(&authority, &nodes[id], protocol());
        let pending = super::pending::admitted(nodes[id].snapshot().unwrap().state(), &inputs);
        queues.push(pending.clone());
        let host = LiveHost {
            node: nodes[id].clone(),
            id: id as u8,
            set: set.clone(),
            journal: journal.clone(),
            peer: peers[id].authority.clone(),
            bundles: peers[id].bundles.clone(),
            authority: authority.clone(),
            executor: executor.native.clone(),
            prepared: Mutex::new(None),
            built: Mutex::new(None),
            pending,
            refused: refused.clone(),
            ready: ready.clone(),
            warnings: warnings.clone(),
        };
        let publication =
            Canonical::new(nodes[id].clone(), peers[id].bundles.clone(), executor, 3.)
                .await
                .unwrap()
                .with_pending(queues[id].clone());
        let (handle, driver) = Driver::new(
            engine,
            journal,
            peers[id].swarm.clone(),
            host,
            publication,
            Ok(vec![]),
        )
        .unwrap();
        *peers[id].consensus.lock().unwrap() = Some(handle.clone());
        let (stop, shutdown) = watch::channel(false);
        stops.push(stop);
        handles.push(handle);
        tasks.push(tokio::spawn(driver.run(shutdown)));
    }
    ready.store(true, Ordering::SeqCst);
    for handle in &handles {
        handle.wake().unwrap();
    }
    bundle_peer::wait_for(|| handles.iter().all(|h| h.status().borrow().height == 2)).await;
    reached(&nodes[0], 1).await;
    assert!(
        !nodes[0].proposal_current(&candidate),
        "commit retained a stale voting candidate"
    );
    assert!(
        !permit.live(),
        "prior VPN admission survived a canonical commit"
    );
    assert!(admission
        .authorize(&request, domain)
        .await
        .unwrap()
        .unwrap()
        .live());
    let token = open_circle(
        &http,
        &base,
        &circle,
        &nodes[0].snapshot().unwrap().provenance().id(),
    )
    .await;
    assert_eq!(
        counter(&http, &base, &token)
            .await
            .json::<serde_json::Value>()
            .await
            .unwrap()["result"]["result"],
        "5"
    );
    assert_eq!(records.lock().unwrap().len(), 1);
    assert!(!refused.lock().unwrap().is_empty());
    assert!(refused
        .lock()
        .unwrap()
        .iter()
        .all(|hash| hash == &refused_hash));
    for queue in &queues {
        assert_eq!(queue.transactions().unwrap(), vec![successor.clone()],
            "canonical cleanup must retire confirmations and refusals, retaining the dependent successor");
    }
    let committed_root = nodes[0].head().await.unwrap().cursor.state_root;
    assert_eq!(
        committed_root.0.as_slice(),
        planned.header.proposed_state_root
    );
    assert_eq!(
        nodes[0].snapshot().unwrap().state().root().unwrap(),
        executed.state.root().unwrap()
    );
    for node in &nodes {
        assert_eq!(node.head().await.unwrap().cursor.state_root, committed_root);
    }
    for peer in &peers[1..] {
        assert!(!peer.authority.requests.lock().unwrap().is_empty());
    }
    // Retry after a durable commit must not execute twice, re-emit ExEx or
    // invalidate a fresh VPN admission. A conflicting certificate is rejected.
    let octra_node_runtime::finality_queries::Range::Found {
        records: history, ..
    } = nodes[0].history().range(1, 1).await.unwrap()
    else {
        panic!("missing history");
    };
    let finalized = &history[0].finality.as_ref().unwrap().finalize;
    let executor = ImportExecutor::with_protocol(&authority, &nodes[0], protocol());
    executor.fail.store(true, Ordering::SeqCst);
    let publication = Canonical::new(nodes[0].clone(), peers[0].bundles.clone(), executor, 1.)
        .await
        .unwrap();
    let fresh = admission
        .authorize(&request, domain)
        .await
        .unwrap()
        .unwrap();
    publication.finalized(&set, finalized).await.unwrap();
    assert!(fresh.live());
    assert_eq!(records.lock().unwrap().len(), 1);
    let mut conflicting = finalized.clone();
    conflicting.header.proposed_state_root[0] ^= 1;
    finality_host::sign(&mut conflicting, 1);
    assert!(publication.finalized(&set, &conflicting).await.is_err());
    assert!(!fresh.live());
    assert_eq!(
        nodes[0].head().await.unwrap().cursor.state_root,
        committed_root
    );
    assert_eq!(http.get(&base).send().await.unwrap().status(), 503);
    publication.finalized(&set, finalized).await.unwrap();
    assert!(matches!(nodes[0].status(), Status::Serving(_)));
    assert_eq!(records.lock().unwrap().len(), 1);
    let fresh = admission
        .authorize(&request, domain)
        .await
        .unwrap()
        .unwrap();
    for stop in stops {
        stop.send_replace(true);
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert!(!fresh.live());
    assert!(matches!(nodes[0].status(), Status::Suspended(_)));
    service_stop.send_replace(true);
    serving.await.unwrap().unwrap();
    for node in &nodes {
        node.shutdown().await.unwrap();
    }
    drop(publication);
    drop(admission);
    drop(peers);
    drop(nodes);
    let restarted = open(
        &dir.path().join("node-0.db"),
        checkpoints,
        chain,
        Arc::default(),
    )
    .await;
    assert!(matches!(restarted.status(), Status::Suspended(_)));
    assert_eq!(
        restarted.head().await.unwrap().cursor.state_root,
        committed_root
    );
    assert!(restarted.resume().await.unwrap());
    restarted.shutdown().await.unwrap();
}
