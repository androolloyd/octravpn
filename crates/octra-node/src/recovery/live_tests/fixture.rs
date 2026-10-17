use super::vpn::Vpn;
use crate::recovery::test_peer as peer;
use crate::{
    consensus::Canonical,
    consensus_join, driver,
    executor::{self, Native, Pending},
    import::Executor as _,
    peers::Network,
    recovery::Service,
    rpc::Submission,
    Node,
};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use octra_browser::application::UnavailableHost;
use octra_exex::{
    native_history::NativeTransaction, sqlite::SqliteCheckpoints, ChainIdentity, CheckpointStore,
    CommittedEpoch, Cursor, ExEx, ExtensionStatus, StateRoot,
};
use octra_node_protocol::{
    circles::{self, AssetMeta, LocatorMode, MetadataMode, ResourceMode},
    consensus::{
        codec::Wire,
        engine::{Engine, TimeoutConfig},
        hash,
        health::Config as HealthConfig,
        journal::JournalOwner,
        policy::Protocol,
        CatchupEpochRecord, Finalize, Validator, Vote, VoteType,
    },
    epoch_index,
    network::{endpoint::Endpoint, session::Timeouts, swarm},
    rules::Graph,
    transaction::address_from_public_key,
    transaction_policy::Profile,
};
use octra_node_runtime::{
    canonical::CanonicalStore,
    consensus_driver::{Driver, Handle},
    epoch_footer,
    finality::proposal::Policy,
    state_batch::StateBatch,
    validator_history::{Authority, CanonicalValidators, Environment, ReceiptPolicy},
};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};

#[path = "../../../../octra-node-runtime/tests/common/circle_host.rs"]
// Recovery fixtures stay independent of the payment harness's private helpers.
#[allow(clippy::duplicate_mod)]
mod circle;

pub(super) const WAIT: Duration = Duration::from_secs(40);
pub(super) const EXTENSION: &str = "live-root-health";
const CIRCLE: &str = "oct11111111111111111111111111111111111111111111";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn member(seed: u8) -> Validator {
    let pubkey = key(seed).verifying_key().to_bytes().to_vec();
    Validator {
        address: address_from_public_key(STANDARD.encode(&pubkey).as_bytes()),
        pubkey,
    }
}
fn genesis() -> StateBatch {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    for (name, value) in [
        (b"last_epoch".as_slice(), b"0".as_slice()),
        (b"emission_remaining", b"0"),
        (b"total_supply", b"0"),
    ] {
        state.set(&[b"meta", name], value.to_vec()).unwrap();
    }
    circle::install_counter(&mut state, CIRCLE.as_bytes(), b"4");
    let body = b"<!doctype html><html><body>Recovery Circle</body></html>";
    let path = circles::path_key(b"/index.html");
    let meta = AssetMeta {
        path_key: path.as_bytes().to_vec(),
        canonical_path: b"/index.html".to_vec(),
        content_type: b"text/html".to_vec(),
        encoding: b"identity".to_vec(),
        size_bytes: body.len() as i64,
        blob_hash: hex::encode(Sha256::digest(body)).into_bytes(),
        body_mode: ResourceMode::Public,
        plaintext_hash: None,
        key_id: None,
        padding_class: None,
        resource_key: path.as_bytes().to_vec(),
        locator_mode: LocatorMode::Path,
        slot_ref: None,
        activate_after_epoch: None,
        expire_after_epoch: None,
        metadata_mode: MetadataMode::Reveal,
    };
    let base = [
        b"circles".as_slice(),
        CIRCLE.as_bytes(),
        b"assets",
        b"by_hash",
        path.as_bytes(),
    ];
    let mut location = base.to_vec();
    location.push(b"meta");
    state.set(&location, meta.to_json_bytes()).unwrap();
    location.pop();
    location.push(b"body_b64");
    state
        .set(&location, STANDARD.encode(body).into_bytes())
        .unwrap();
    state
}
fn chain(state: &StateBatch, voting: bool) -> ChainIdentity {
    let (_, index) =
        epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
            .unwrap();
    let root = epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap();
    ChainIdentity::genesis(format!("live-root-supervisor-{voting}"), StateRoot(root))
}
fn config(
    chain: &ChainIdentity,
    data: &Path,
    protocol: Protocol,
    profile: Profile,
) -> executor::Config {
    executor::Config {
        graph: Graph::new(chain.chain_id.as_bytes().to_vec(), None),
        protocol,
        profile,
        payload: octra_node_protocol::transaction_payload::Limits::default(),
        bundle: executor::Limits::new(100_000, 50_000_000, 10_000_000_000_u64.into()),
        validators: octra_node_protocol::validator::policy::Policy::Inactive,
        emission: epoch_footer::Policy {
            emission_guard: true,
            schedule: octra_node_protocol::emission::Schedule::Inactive,
            legacy_total: None,
        },
        sender_key_activation: Some(0),
        private_result_activation: 0,
        max_fhe: 32,
        max_stealth: 32,
        max_multi_exec_calls: 8,
        ready_max_lag: 10,
        pvac_dir: data.join("pvac"),
        migration: None,
    }
}
struct Record(Arc<Mutex<Vec<CommittedEpoch<NativeTransaction>>>>);
impl ExEx<NativeTransaction> for Record {
    fn name(&self) -> &'static str {
        EXTENSION
    }
    async fn on_epoch(&mut self, epoch: &CommittedEpoch<NativeTransaction>) -> Result<(), String> {
        assert!(epoch.events.is_empty());
        self.0.lock().unwrap().push(epoch.clone());
        Ok(())
    }
}
pub(super) struct Tasks {
    stop: watch::Sender<bool>,
    handles: Vec<JoinHandle<Result<()>>>,
}
impl Drop for Tasks {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        for task in &self.handles {
            task.abort();
        }
    }
}
impl Tasks {
    fn new() -> Self {
        Self {
            stop: watch::channel(false).0,
            handles: vec![],
        }
    }
    fn spawn<F: Future<Output = Result<()>> + Send + 'static>(
        &mut self,
        start: impl FnOnce(watch::Receiver<bool>) -> F,
    ) {
        self.handles
            .push(tokio::spawn(start(self.stop.subscribe())));
    }
    pub(super) fn healthy(&self) {
        assert!(
            self.handles.iter().all(|task| !task.is_finished()),
            "live recovery service exited early"
        );
    }
    pub(super) async fn stop(&mut self) {
        self.stop.send_replace(true);
        for task in &mut self.handles {
            tokio::time::timeout(WAIT, task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        self.handles.clear();
    }
}
pub(super) struct Fixture {
    pub(super) directory: tempfile::TempDir,
    pub(super) node: Arc<Node<Authority>>,
    executor: Native,
    pub(super) authority: crate::peers::Authority,
    pub(super) swarm: swarm::Swarm,
    pub(super) peers: Vec<peer::Node>,
    pub(super) journal: JournalOwner,
    pub(super) checkpoints: Arc<SqliteCheckpoints>,
    pub(super) epochs: Arc<Mutex<Vec<CommittedEpoch<NativeTransaction>>>>,
    pub(super) initial: Handle,
    pub(super) baseline: CatchupEpochRecord,
    pub(super) head: octra_node_runtime::canonical::Head,
    pub(super) address: Vec<u8>,
    pub(super) browser: String,
    pub(super) page: String,
    pub(super) vpn: Vpn,
    pub(super) tasks: Tasks,
}
impl Fixture {
    pub(super) async fn new(voting: bool) -> Self {
        Box::pin(Self::with_health(voting, HealthConfig::default())).await
    }
    pub(super) async fn with_health(voting: bool, health: HealthConfig) -> Self {
        Box::pin(Self::start(voting, health, false, None)).await
    }
    pub(super) async fn soft_lag(voting: bool) -> Self {
        Box::pin(Self::start(voting, HealthConfig::default(), true, Some(2))).await
    }
    async fn start(
        voting: bool,
        health: HealthConfig,
        initial_matching: bool,
        advertised_head: Option<i64>,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let state = genesis();
        let chain = chain(&state, voting);
        let store = CanonicalStore::create(
            &directory.path().join("canonical.db"),
            chain.clone(),
            state.snapshot(),
            0,
        )
        .await
        .unwrap();
        let journal = JournalOwner::open(directory.path()).unwrap();
        journal.set_floor(0).unwrap();
        let environment = Environment {
            current: Some(
                (1..=4)
                    .map(|seed| {
                        let member = member(seed);
                        format!(
                            "{}:{}",
                            String::from_utf8(member.address).unwrap(),
                            STANDARD.encode(member.pubkey)
                        )
                        .into_bytes()
                    })
                    .collect::<Vec<_>>()
                    .join(&b','),
            ),
            ..Environment::default()
        };
        let reader = store.reader();
        let membership = CanonicalValidators::new(reader.clone(), environment.clone());
        let checkpoints = Arc::new(
            SqliteCheckpoints::open(&directory.path().join("exex.db"))
                .await
                .unwrap(),
        );
        let protocol = Protocol::new(2).unwrap();
        let policy = Policy {
            protocol,
            genesis_time: Some(0.),
        };
        let profile = Profile::from_values(Some(b"devnet_full_v1"), None, None);
        let runtime = circle::runtime();
        let node = Arc::new(
            Node::open(
                store,
                Authority::new(
                    reader.clone(),
                    environment,
                    ReceiptPolicy::new(Some(b"0"), &profile, None),
                    journal.clone(),
                ),
                runtime.clone(),
                Arc::new(UnavailableHost),
                checkpoints.clone(),
            )
            .await
            .unwrap(),
        );
        let executor = Native::new(
            config(&chain, directory.path(), protocol, profile),
            runtime,
            node.history(),
        )
        .unwrap();
        assert!(node.resume().await.unwrap());
        let epochs = Arc::new(Mutex::new(vec![]));
        node.register(Record(epochs.clone())).await.unwrap();
        // Build effects with the production Native executor. Only the fixed
        // local signing keys stand in for a peer-produced quorum certificate.
        let parent = node.head().await.unwrap();
        let draft = Arc::new(
            node.proposal_draft(&executor.graph(), policy, &member(1).address, 10.)
                .await
                .unwrap(),
        );
        let built = executor.build_proposal(draft, vec![]).await.unwrap();
        let mut finalized = Finalize {
            chain_id: chain.chain_id.as_bytes().to_vec(),
            epoch_id: 1,
            commit_round: 0,
            header: built.plan().header.clone(),
            proposal_id: hash::proposal_id(&built.plan().header).unwrap().to_vec(),
            precommits: vec![],
            parent_commit: built.plan().parent_commit.clone(),
        };
        finalized.precommits = (1..=3)
            .map(|seed| {
                let mut vote = Vote {
                    chain_id: finalized.chain_id.clone(),
                    epoch_id: 1,
                    round: 0,
                    vote_type: VoteType::Precommit,
                    proposal_id: finalized.proposal_id.clone(),
                    validator: member(seed).address,
                    signature: vec![],
                };
                vote.signature = key(seed)
                    .sign(&hash::vote_sign_bytes(&vote).unwrap())
                    .to_bytes()
                    .to_vec();
                vote
            })
            .collect();
        let head = node
            .publish(
                &parent,
                &finalized.encode().unwrap(),
                built.execution().clone(),
            )
            .await
            .unwrap()
            .head;
        checkpoint(&node, head.cursor).await;
        journal.set_floor(1).unwrap();
        let baseline = node.publisher.record(head.cursor.sequence).await.unwrap();
        let scope = node.snapshot().unwrap().provenance().id();
        let validators = membership.stake_set(&head, 2).await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Endpoint {
            host: b"127.0.0.1".to_vec(),
            port: listener.local_addr().unwrap().port(),
        };
        let mut peers = vec![];
        for seed in 2..=4 {
            let peer = peer::node(
                chain.chain_id.as_bytes(),
                member(seed).address,
                key(seed),
                validators.clone(),
                vec![endpoint.clone()],
            )
            .await;
            peer.authority
                .ranges
                .lock()
                .unwrap()
                .insert(1, baseline.clone());
            peer.authority
                .roots_unavailable
                .store(!initial_matching, std::sync::atomic::Ordering::SeqCst);
            *peer.authority.advertised_head.lock().unwrap() = advertised_head;
            peers.push(peer);
        }
        let capture = node.clone();
        let network = Network::new(
            listener,
            swarm::Config {
                chain_id: chain.chain_id.as_bytes().to_vec(),
                node_address: member(1).address,
                config_hash: vec![1; 32],
                binary_hash: vec![2; 32],
                require_binary_hash: false,
                upgrade: None,
                profiles: vec![],
                allowed_public_keys: (1..=4).map(|seed| member(seed).pubkey).collect(),
                bootstrap: vec![],
                maximum_validators: 16,
                advertised: endpoint,
                timeouts: Timeouts::default(),
                head: Arc::new(move || {
                    let head = capture.store.cached_head().unwrap();
                    (head.cursor.epoch.0 as i64, head.cursor.state_root.0)
                }),
            },
            key(1),
            node.history(),
            reader,
            membership.clone(),
            validators,
            journal.clone(),
        )
        .unwrap();
        let authority = network.authority.clone();
        let swarm = network.swarm.clone();
        let pending = Arc::new(
            Pending::open(directory.path().join("pending.log"), &node.store)
                .await
                .unwrap(),
        );
        let settings = octra_node_protocol::consensus::profile::Settings::from_values(
            std::collections::BTreeMap::new(),
        )
        .unwrap();
        let submission = Arc::new(Submission {
            node: node.clone(),
            executor: executor.clone(),
            pending: pending.clone(),
            swarm: swarm.clone(),
            policy,
            address: member(1).address,
            compute: None,
            vpn_program: None,
            status: None,
            tokens: None,
            staging_notify: Arc::new(|| {}),
            history_epoch_limit: 100,
            fees: octra_node_protocol::submit_rpc::Fees::default(),
            http: Arc::new(crate::rpc::http::Service::new(
                directory.path().to_owned(),
                Some(&settings),
                chain.chain_id.as_bytes().to_vec(),
                member(1).pubkey,
            )),
        });
        pending.recover(&submission).await.unwrap();
        let config = driver::Config {
            key: key(1),
            address: member(1).address,
            policy,
            journal: journal.clone(),
            epoch_capacity: 10_000_000_000_u64.into(),
            stealth_slots: 4,
            evidence_dir: directory.path().join("evidence"),
            release: None,
        };
        let timeouts = TimeoutConfig::default();
        let validator = driver::Validator::new(
            node.clone(),
            executor.clone(),
            pending.clone(),
            &network,
            config.clone(),
        )
        .unwrap();
        node.suspend("awaiting authenticated current-head root evidence");
        let set = validator.activate_retained(2).await.unwrap();
        validator.set_enabled(false);
        let engine = Engine::new(
            chain.chain_id.as_bytes().to_vec(),
            member(1).address,
            set,
            2,
            protocol,
            timeouts,
        );
        let publication =
            Canonical::new(node.clone(), network.bundles.clone(), executor.clone(), 1.)
                .await
                .unwrap()
                .with_pending(pending.clone());
        let (initial, driver) = Driver::new(
            engine,
            journal.clone(),
            swarm.clone(),
            validator,
            publication,
            Ok(vec![]),
        )
        .unwrap();
        authority.attach(initial.clone()).unwrap();
        let service = Service {
            node: node.clone(),
            submission,
            executor: executor.clone(),
            pending,
            authority: authority.clone(),
            swarm: swarm.clone(),
            bundles: network.bundles.clone(),
            roots: network.roots.clone(),
            finality: network.finality.clone(),
            membership,
            join: consensus_join::Client::capture(|_| None).unwrap(),
            config,
            timeouts,
            voting,
            minimum_peers: 2,
            health,
            budget: Duration::from_secs(5),
            duty: None,
        };
        let vpn = Vpn::new();
        let services = node
            .bind(
                "127.0.0.1:0".parse().unwrap(),
                vpn.config(&directory.path().join("vpn")),
                vpn.settlement.clone(),
            )
            .await
            .unwrap();
        let browser = format!("http://{}", services.browser_addr().unwrap());
        let page = format!("{browser}/view/{scope}/{CIRCLE}/index.html");
        let mut tasks = Tasks::new();
        tasks
            .spawn(move |stop| async move { network.run(stop).await.map_err(anyhow::Error::from) });
        tasks.spawn(move |stop| services.run(stop));
        peer::wait_for(|| {
            swarm.peers().len() == 3 && peers.iter().all(|peer| peer.swarm.peers().len() == 3)
        })
        .await;
        tasks.spawn(move |stop| service.run(driver, stop));
        Self {
            directory,
            node,
            executor,
            authority,
            swarm,
            peers,
            journal,
            checkpoints,
            epochs,
            initial,
            baseline,
            head,
            address: member(1).address,
            browser,
            page,
            vpn,
            tasks,
        }
    }
    pub(super) fn roots(&self, root: Option<[u8; 32]>) {
        for peer in &self.peers {
            let mut records = peer.authority.ranges.lock().unwrap();
            records.clear();
            let mut record = self.baseline.clone();
            if let Some(root) = root {
                record.state_root = root.to_vec();
            }
            records.insert(1, record);
            peer.authority
                .roots_unavailable
                .store(root.is_none(), std::sync::atomic::Ordering::SeqCst);
        }
    }
    pub(super) async fn successor(&self) -> (Vec<u8>, octra_node_runtime::finality::ExecutedEpoch) {
        let draft = self
            .node
            .proposal_draft(
                &self.executor.graph(),
                Policy {
                    protocol: Protocol::new(2).unwrap(),
                    genesis_time: Some(0.),
                },
                &self.address,
                20.,
            )
            .await
            .unwrap();
        let built = self
            .executor
            .build_proposal(Arc::new(draft), vec![])
            .await
            .unwrap();
        let mut finalized = Finalize {
            chain_id: self.node.store.chain().chain_id.as_bytes().to_vec(),
            epoch_id: built.plan().header.epoch_id,
            commit_round: 0,
            header: built.plan().header.clone(),
            proposal_id: hash::proposal_id(&built.plan().header).unwrap().to_vec(),
            precommits: vec![],
            parent_commit: built.plan().parent_commit.clone(),
        };
        finalized.precommits = (1..=3)
            .map(|seed| {
                let mut vote = Vote {
                    chain_id: finalized.chain_id.clone(),
                    epoch_id: finalized.epoch_id,
                    round: 0,
                    vote_type: VoteType::Precommit,
                    proposal_id: finalized.proposal_id.clone(),
                    validator: member(seed).address,
                    signature: vec![],
                };
                vote.signature = key(seed)
                    .sign(&hash::vote_sign_bytes(&vote).unwrap())
                    .to_bytes()
                    .to_vec();
                vote
            })
            .collect();
        (finalized.encode().unwrap(), built.execution().clone())
    }
    pub(super) async fn successor_record(&self) -> CatchupEpochRecord {
        let (certificate, executed) = self.successor().await;
        assert!(executed.transactions.is_empty());
        let finalized = Finalize::decode(&certificate).unwrap();
        let header = &finalized.header;
        CatchupEpochRecord {
            epoch_id: finalized.epoch_id,
            prev_state_root: header.prev_state_root.clone(),
            state_root: header.proposed_state_root.clone(),
            tx_list_hash: header.tx_list_hash.clone(),
            tx_hashes: vec![],
            txs_json: vec![],
            receipt_root: header.receipt_root.clone(),
            receipts_json: executed.consensus_receipts,
            epoch_ts: header.ts,
            creator_addr: header.creator_addr.clone(),
            commit_round: finalized.commit_round,
            reward_source: Some(executed.reward_source),
            finality: Some(octra_node_protocol::consensus::CatchupFinality {
                finalize: finalized,
                validator_set: self.peers[0].authority.validators.clone(),
            }),
        }
    }
    pub(super) fn matching_roots(&self, count: usize) {
        assert!(count <= self.peers.len());
        // Disable first so a partial update cannot transiently expose a quorum.
        for peer in &self.peers {
            peer.authority
                .roots_unavailable
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        for peer in self.peers.iter().take(count) {
            peer.authority
                .roots_unavailable
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    pub(super) fn query_counts(&self) -> Vec<usize> {
        self.peers
            .iter()
            .map(|peer| {
                peer.seen
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|frame| frame.message == 0x34)
                    .count()
            })
            .collect()
    }
    pub(super) fn lie_about_head(&self) {
        let mut record = self.baseline.clone();
        record.epoch_id = 999;
        self.peers[0]
            .authority
            .ranges
            .lock()
            .unwrap()
            .insert(999, record);
    }
    pub(super) fn vote_journal(&self) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
        fn read(
            path: &Path,
            records: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>,
        ) {
            if !path.exists() {
                return;
            }
            for entry in std::fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let kind = entry.file_type().unwrap();
                if kind.is_dir() {
                    read(&entry.path(), records);
                } else {
                    assert!(kind.is_file());
                    records.insert(entry.path(), std::fs::read(entry.path()).unwrap());
                }
            }
        }
        let mut records = std::collections::BTreeMap::new();
        read(&self.directory.path().join("vote_log"), &mut records);
        records
    }
    pub(super) async fn wait(&self, mut predicate: impl FnMut() -> bool) {
        tokio::time::timeout(WAIT, async {
            loop {
                self.tasks.healthy();
                if predicate() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("recovery supervisor condition timed out");
    }
    pub(super) async fn wait_checkpoint(&self, expected: Cursor) {
        tokio::time::timeout(WAIT, async {
            loop {
                self.tasks.healthy();
                if self
                    .checkpoints
                    .load(self.node.store.chain(), EXTENSION)
                    .await
                    .unwrap()
                    == Some(expected)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("recovery ExEx checkpoint did not become durable");
    }
}
async fn checkpoint(node: &Node<Authority>, cursor: Cursor) {
    let mut status = node.extension_status(EXTENSION).await.unwrap();
    tokio::time::timeout(WAIT, async { loop { if matches!(*status.borrow_and_update(), ExtensionStatus::Running { checkpoint } if checkpoint == cursor) { break; } status.changed().await.unwrap(); } }).await.unwrap();
}
