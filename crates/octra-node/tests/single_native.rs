//! Direct comparison to pristine native Single modules, not a public chain or
//! a claim that the pristine CLI accepts these explicit private-prior fixtures.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use octra_exex::{Cursor, EpochId, Sequence, StateRoot};
use octra_node::{
    executor::{self, single::Request, Native},
    single,
};
use octra_node_protocol::{
    consensus::policy::Protocol,
    epoch_index, irmin,
    native_json::Document,
    rules::Graph,
    state::Account,
    transaction::{self, RuleMode, Transaction},
    transaction_policy::Profile,
};
use octra_node_runtime::{
    account_store,
    canonical::Head,
    circle::CircleRuntime,
    epoch_footer,
    execution::{Completion, Outcome},
    finality::{self, history::History},
    single_private,
    state_batch::{Snapshot, StateBatch},
};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};
struct LocalHistory(Head);
#[async_trait::async_trait]
impl History for LocalHistory {
    async fn head(&self) -> Result<Head, finality::Error> {
        Ok(self.0.clone())
    }
    async fn root(&self, epoch: i64) -> Result<Option<Vec<u8>>, finality::Error> {
        Ok((epoch >= 0 && epoch as u64 == self.0.cursor.epoch.0)
            .then(|| self.0.cursor.state_root.0.to_vec()))
    }
    async fn range(
        &self,
        _: i64,
        _: i64,
    ) -> Result<octra_node_runtime::finality_queries::Range, finality::Error> {
        Err(finality::Error::Unavailable(
            "fixture supplies no BFT history".into(),
        ))
    }
    async fn bundle(
        &self,
        _: &[u8; 32],
    ) -> Result<Option<octra_node_runtime::consensus_bundle::RawBundle>, finality::Error> {
        Err(finality::Error::Unavailable(
            "fixture supplies no BFT bundle".into(),
        ))
    }
}
fn public(id: u8) -> Vec<u8> {
    STANDARD
        .encode(SigningKey::from_bytes(&[id; 32]).verifying_key().as_bytes())
        .into_bytes()
}
fn address(id: u8) -> Vec<u8> {
    transaction::address_from_public_key(&public(id))
}
fn config(dir: &std::path::Path) -> executor::Config {
    executor::Config {
        graph: Graph::new(b"octra-single-local-native-oracle".to_vec(), None),
        protocol: Protocol::default(),
        profile: Profile::default(),
        payload: octra_node_protocol::transaction_payload::Limits::default(),
        bundle: executor::Limits::new(100_000, 50_000_000, 10_000_000_000_u64.into()),
        validators: octra_node_protocol::validator::policy::Policy::Inactive,
        emission: epoch_footer::Policy {
            emission_guard: false,
            schedule: octra_node_protocol::emission::Schedule::Inactive,
            legacy_total: None,
        },
        sender_key_activation: Some(0),
        private_result_activation: 0,
        max_fhe: 32,
        max_stealth: 32,
        max_multi_exec_calls: 8,
        ready_max_lag: 10,
        pvac_dir: dir.join("pvac"),
        migration: None,
    }
}
fn initial(case: &Value) -> StateBatch {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    for row in case["metadata"].as_array().unwrap() {
        state
            .set(
                &[b"meta", row[0].as_str().unwrap().as_bytes()],
                row[1].as_str().unwrap().as_bytes().to_vec(),
            )
            .unwrap();
    }
    for id in [1, 2, 4, 5] {
        account_store::set(
            &mut state,
            &address(id),
            &Account {
                balance: if id == 4 || id == 5 {
                    0.into()
                } else {
                    1_000_000.into()
                },
                public_key: Some(public(id)),
                encrypted_balance: if id == 1 {
                    case["input"]
                        .get("private")
                        .map(|data| STANDARD.decode(data["current"].as_str().unwrap()).unwrap())
                } else {
                    None
                },
                ..Default::default()
            },
            RuleMode::Prior,
        )
        .unwrap();
    }
    if let Some(data) = case["input"].get("private") {
        use sha2::{Digest, Sha256};
        let key = STANDARD.decode(data["public"].as_str().unwrap()).unwrap();
        state
            .set(
                &[b"pvac_hashes", &address(1)],
                hex::encode(Sha256::digest(key)).into_bytes(),
            )
            .unwrap();
    }
    state.acknowledge_commit().unwrap();
    state
}
fn parent(case: &Value, state: &Snapshot) -> Head {
    let ledger_root = hex::encode(state.root().unwrap());
    assert_eq!(ledger_root, case["before"].as_str().unwrap());
    let (hash, index) =
        epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
            .unwrap();
    let index_root = hex::encode(index);
    Head {
        cursor: Cursor {
            sequence: Sequence(0),
            epoch: EpochId(case["input"]["epoch"].as_u64().unwrap() - 1),
            state_root: StateRoot(
                epoch_index::folded_state_root(ledger_root.as_bytes(), index_root.as_bytes())
                    .unwrap(),
            ),
        },
        ledger_root,
        index_root,
        index_hash: Some(hex::encode(hash)),
        irmin_commit: case["before_commit"]["hash"].as_str().unwrap().into(),
        parent_commit: None,
        txid_hi: -1,
        date: case["before_commit"]["date"].as_i64().unwrap(),
        message: b"genesis".to_vec(),
    }
}
#[tokio::test]
async fn pristine_single_sender_footer_tree_and_commit_bytes() {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/single-native.json")).unwrap();
    assert_eq!(
        fixture["upstream_commit"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    assert_eq!(fixture["instrumentation"], serde_json::json!({}));
    use sha2::{Digest as _, Sha256};
    let source_map: Value =
        serde_json::from_slice(include_bytes!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["source_sha256"], source_map["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/single-oracle.ml"
        )))
    );
    assert_eq!(
        fixture["runner_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/resource-native-oracle.py"
        )))
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 31);
    for case in cases {
        let name = case["input"]["name"].as_str().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let state = initial(case);
        let parent = parent(case, &state.snapshot());
        let mut cfg = config(tmp.path());
        cfg.max_fhe = case["input"]["fhe"].as_u64().unwrap() as usize;
        cfg.max_stealth = case["input"]["stealth"].as_u64().unwrap() as usize;
        let native = Native::new(
            cfg,
            CircleRuntime::new(Arc::new(octra_node_runtime::circle_hfhe::Backend)),
            Arc::new(LocalHistory(parent.clone())),
        )
        .unwrap();
        let members = vec![(address(4), public(4)), (address(5), public(5))];
        let context = native.single_context(&parent, &members).await.unwrap();
        let envelope = native.single_source_rules(&parent).await.unwrap();
        let transactions = case["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                Transaction::from_document(
                    &Document::parse(&STANDARD.decode(v.as_str().unwrap()).unwrap()).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let proposer = STANDARD.decode(case["proposer"].as_str().unwrap()).unwrap();
        let mut deferred = single_private::Deferred::default();
        for row in case["input"]["defer_counts"].as_array().unwrap() {
            deferred.counts.insert(
                hex::encode(
                    transactions[row[0].as_u64().unwrap() as usize]
                        .hash()
                        .unwrap(),
                ),
                row[1].as_i64().unwrap(),
            );
        }
        let mut preverify = BTreeMap::new();
        let mut ready = BTreeMap::new();
        if let Some(data) = case["input"].get("private") {
            let key = STANDARD.decode(data["public"].as_str().unwrap()).unwrap();
            octra_node_runtime::pvac::Files(tmp.path().join("pvac"))
                .persist(&key)
                .unwrap();
            let ledger = account_store::ledger(&state).unwrap();
            let profile = octra_node_runtime::private_balance::Profile {
                fields: context.private_payload,
                strict: false,
                math: octra_hfhe::scalar::ScalarRule::Prior,
                result: octra_node_runtime::private_crypto::ResultPolicy::Recoverable,
            };
            let hash = hex::encode(transactions[0].hash().unwrap());
            let binding =
                single_private::CacheBinding::preverify(&ledger, &transactions[0], profile, &key)
                    .unwrap();
            preverify.insert(hash.clone(), octra_node_protocol::single::Preverify::Ready);
            ready.insert(hash, binding);
        }
        let roots = BTreeMap::new();
        let executed = native.execute_single(Request {
            parent: &parent,
            state: state.snapshot(),
            context: &context,
            envelope,
            validators: &members,
            proposer: &proposer,
            transactions: &transactions,
            deferred,
            preverify,
            ready,
            maximum_defer: case["input"]["max_defer"].as_i64().unwrap(),
            inline: false,
            ready_roots: &roots,
        });
        let expected = &case["result"];
        if let Some(error) = expected.get("error") {
            assert_eq!(
                executed.err().unwrap().to_string(),
                error.as_str().unwrap(),
                "{name}"
            );
            continue;
        }
        let output = executed.unwrap_or_else(|e| panic!("{name}: {e:#}"));
        assert_eq!(
            hex::encode(output.epoch.state.root().unwrap()),
            expected["ledger_root"].as_str().unwrap(),
            "ledger/{name}"
        );
        assert_eq!(
            output.epoch.fees.to_string(),
            expected["fees"].as_str().unwrap(),
            "fees/{name}"
        );
        assert_eq!(
            std::str::from_utf8(&output.epoch.tree_state_root).unwrap(),
            expected["tree_state_hash"].as_str().unwrap(),
            "tree state/{name}"
        );
        let confirmed = output
            .epoch
            .confirmed
            .iter()
            .map(|&index| hex::encode(transactions[index].hash().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            serde_json::json!(confirmed),
            expected["confirmed"],
            "confirmed/{name}"
        );
        let processed = output
            .epoch
            .processed
            .iter()
            .map(|h| std::str::from_utf8(h).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            serde_json::json!(processed),
            expected["processed"],
            "processed/{name}"
        );
        let mut tree = octra_node_protocol::legacy_tree::Tree::create(
            transaction::Nonce::new(case["input"]["epoch"].as_i64().unwrap()).unwrap(),
            b"GENESIS".to_vec(),
        );
        let digest = tree
            .finalize_epoch(
                tree.epoch_id,
                &proposer,
                output.epoch.tree_state_root.clone(),
                0.,
                &output
                    .epoch
                    .confirmed
                    .iter()
                    .map(|&i| transactions[i].clone())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&digest).unwrap(),
            expected["legacy_digest"].as_str().unwrap(),
            "legacy/{name}"
        );
        let ledger =
            account_store::ledger(&StateBatch::from_snapshot(output.epoch.state.clone())).unwrap();
        for row in expected["accounts"].as_array().unwrap() {
            let address = STANDARD.decode(row[0].as_str().unwrap()).unwrap();
            let actual = ledger.account(&address).unwrap().to_json_bytes();
            assert_eq!(
                actual,
                STANDARD.decode(row[1].as_str().unwrap()).unwrap(),
                "account/{name}/{}",
                String::from_utf8_lossy(&address)
            );
        }
        let commit = irmin::commit_hash(
            &output.epoch.state.root().unwrap(),
            &[hex::decode(&parent.irmin_commit)
                .unwrap()
                .try_into()
                .unwrap()],
            expected["commit"]["date"].as_i64().unwrap(),
            b"octra",
            expected["commit"]["message"].as_str().unwrap().as_bytes(),
        );
        assert_eq!(
            hex::encode(commit),
            expected["commit"]["hash"].as_str().unwrap(),
            "Irmin commit/{name}"
        );
        for value in expected["rejected"].as_array().unwrap() {
            let hash = value["hash"].as_str().unwrap();
            let event = output
                .epoch
                .events
                .iter()
                .find(|e| hex::encode(transactions[e.input_index].hash().unwrap()) == hash)
                .unwrap();
            let (kind, reason) = match &event.outcome {
                Outcome::Completed(Completion::Rejected(r)) => {
                    (r.tag.as_bytes().to_vec(), r.reason.clone())
                }
                Outcome::NonceMismatch { expected, got } => (
                    b"nonce_mismatch".to_vec(),
                    format!(
                        "expected_nonce = {} got_nonce = {}",
                        expected.get(),
                        got.get()
                    )
                    .into_bytes(),
                ),
                other @ Outcome::Completed(_) => panic!("unexpected {other:?}"),
            };
            assert_eq!(
                kind,
                STANDARD.decode(value["type"].as_str().unwrap()).unwrap(),
                "rejection type/{name}"
            );
            assert_eq!(
                reason,
                STANDARD.decode(value["reason"].as_str().unwrap()).unwrap(),
                "rejection reason/{name}"
            );
        }
    }
}
fn settings() -> single::Settings {
    single::Settings {
        mode: "single".into(),
        private_prior_fixture: true,
        wallet_address: address(4),
        wallet_public: public(4),
        validators: None,
        next_validators: None,
        activation: None,
        fee_recipient: None,
        epoch_capacity: "10000000000".into(),
        stealth_minimum: "5000".into(),
        maximum_defer: 3,
        inline_ranges: false,
        maximum_timestamp_drift: 300.,
        preverify_ttl: 45.,
        preverify_maximum: 64,
    }
}
async fn open_node(path: &std::path::Path, now: f64) -> Arc<single::Node> {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/single-native.json")).unwrap();
    let case = &fixture["cases"][0];
    let initial = initial(case);
    let parent = parent(case, &initial.snapshot());
    let chain = octra_exex::ChainIdentity::genesis(
        "octra-single-local-native-oracle",
        parent.cursor.state_root,
    );
    let settings = settings();
    let policy = Native::single_policy_for(&config(path), &settings).unwrap();
    let authority = octra_node_runtime::canonical::single::Authority::new(
        chain,
        SigningKey::from_bytes(&[4; 32]),
        policy,
    )
    .unwrap();
    let database = path.join("canonical.db");
    let store = if database.exists() {
        octra_node_runtime::canonical::single::Store::open(&database, authority)
            .await
            .unwrap()
    } else {
        octra_node_runtime::canonical::single::Store::create(&database,authority,initial.snapshot(),parent.date,serde_json::to_vec(&serde_json::json!({"entries":[],"preview":octra_node_runtime::staging::Pool::default().preview_state(),"deferred":{"counts":{}},"kats":[]})).unwrap()).await.unwrap()
    };
    let store = Arc::new(store);
    let native = Native::new(
        config(path),
        CircleRuntime::new(Arc::new(octra_node_runtime::circle_hfhe::Backend)),
        Arc::new(single::History(store.clone())),
    )
    .unwrap();
    let checkpoints = Arc::new(
        octra_exex::sqlite::SqliteCheckpoints::open(&path.join("checkpoints.db"))
            .await
            .unwrap(),
    );
    single::Node::open(store, native, settings, checkpoints, now)
        .await
        .unwrap()
}
fn signed_transfer() -> Transaction {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/single-native.json")).unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["input"]["name"] == "one-sender")
        .unwrap();
    Transaction::from_document(
        &Document::parse(
            &STANDARD
                .decode(case["transactions"][0].as_str().unwrap())
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}
struct Collect(Arc<std::sync::Mutex<Vec<u64>>>);
impl octra_exex::ExEx<octra_exex::native_history::NativeTransaction> for Collect {
    fn name(&self) -> &'static str {
        "single-test-exex"
    }
    async fn on_epoch(
        &mut self,
        epoch: &octra_exex::CommittedEpoch<octra_exex::native_history::NativeTransaction>,
    ) -> Result<(), String> {
        self.0.lock().unwrap().push(epoch.cursor.sequence.0);
        Ok(())
    }
}
async fn wait_checkpoint(node: &single::Node, expected: u64) {
    let mut status = node.extension_status("single-test-exex").await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10),async{loop{if matches!(&*status.borrow(),octra_exex::ExtensionStatus::Running{checkpoint}if checkpoint.sequence.0>=expected){break}status.changed().await.unwrap();}}).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timer_durable_queue_empty_epochs_restart_and_exex() {
    let tmp = tempfile::tempdir().unwrap();
    let node = open_node(tmp.path(), 0.).await;
    let epochs = Arc::new(std::sync::Mutex::new(Vec::new()));
    node.register(Collect(epochs.clone())).await.unwrap();
    let tx = signed_transfer();
    let hash = node.submit(tx.clone(), 10.).await.unwrap();
    assert_eq!(hash, hex::encode(tx.hash().unwrap()).as_bytes());
    assert_eq!(node.queued().unwrap().len(), 1);
    assert!(node.tick(9.999, 10).await.unwrap().is_none());
    let first = node.tick(10., 10).await.unwrap().unwrap();
    assert_eq!(first.cursor.epoch, EpochId(1));
    assert!(node.queued().unwrap().is_empty());
    wait_checkpoint(&node, 1).await;
    assert_eq!(*epochs.lock().unwrap(), vec![1]);
    let record = node.store().record(Sequence(1)).await.unwrap();
    assert_eq!(record.tree_state_root, record.parent.ledger_root.as_bytes());
    node.shutdown().await.unwrap();
    drop(node);
    let resumed = open_node(tmp.path(), 10.).await;
    assert_eq!(resumed.head().await.unwrap(), first);
    resumed.register(Collect(epochs.clone())).await.unwrap();
    assert!(resumed.tick(19.999, 20).await.unwrap().is_none());
    assert_eq!(
        resumed.tick(20., 20).await.unwrap().unwrap().cursor.epoch,
        EpochId(2)
    );
    wait_checkpoint(&resumed, 2).await;
    assert_eq!(*epochs.lock().unwrap(), vec![1, 2]);
    resumed.shutdown().await.unwrap();
}
#[tokio::test]
async fn single_and_bft_store_authorities_are_not_interchangeable() {
    use octra_node_runtime::{
        canonical::{
            single::{Authority, Store},
            CanonicalStore,
        },
        finality::{EpochRules, Publisher, ValidatorHistory},
    };
    struct NoAuthority;
    #[async_trait::async_trait]
    impl ValidatorHistory for NoAuthority {
        async fn resolve(
            &self,
            _: &Head,
            _: u64,
            _: octra_node_runtime::canonical::ReliefSource,
        ) -> Result<EpochRules, String> {
            panic!("Single must be refused before any BFT authority resolution")
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let live = open_node(tmp.path(), 0.).await;
    let head = live.head().await.unwrap();
    let identity = live.store().identity().clone();
    live.shutdown().await.unwrap();
    drop(live);
    let raw = CanonicalStore::open(&tmp.path().join("canonical.db"), &identity.chain)
        .await
        .unwrap();
    let error = Publisher::open(Arc::new(raw), NoAuthority)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("local Single store cannot provide BFT finality"),
        "{error}"
    );
    let wrong = Authority::new(
        identity.chain.clone(),
        SigningKey::from_bytes(&[9; 32]),
        identity.policy,
    )
    .unwrap();
    assert!(Store::open(&tmp.path().join("canonical.db"), wrong)
        .await
        .is_err());
    let other = tempfile::tempdir().unwrap();
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/single-native.json")).unwrap();
    let state = initial(&fixture["cases"][0]);
    let chain = octra_exex::ChainIdentity::genesis(
        "octra-single-local-native-oracle",
        head.cursor.state_root,
    );
    let raw = CanonicalStore::create(
        &other.path().join("bft.db"),
        chain.clone(),
        state.snapshot(),
        0,
    )
    .await
    .unwrap();
    drop(raw);
    let authority =
        Authority::new(chain, SigningKey::from_bytes(&[4; 32]), identity.policy).unwrap();
    assert!(Store::open(&other.path().join("bft.db"), authority)
        .await
        .is_err());
    for chain in [
        octra_exex::ChainIdentity::genesis("octra-devnet-9871-cluster", head.cursor.state_root),
        octra_exex::ChainIdentity::checkpoint(
            "octra-single-local-native-oracle",
            1,
            head.cursor.state_root,
        ),
    ] {
        assert!(Authority::new(chain, SigningKey::from_bytes(&[4; 32]), [0; 32]).is_err());
    }
}
#[tokio::test]
async fn malformed_local_epoch_is_refused_before_any_canonical_write() {
    use octra_node_runtime::canonical::single::Publication;
    let tmp = tempfile::tempdir().unwrap();
    let node = open_node(tmp.path(), 0.).await;
    let (base, state) = node.store().snapshot().await.unwrap();
    let queue = node.store().queue().await.unwrap();
    for mutation in 0..6 {
        let mut tree = octra_node_protocol::legacy_tree::Tree::create(
            transaction::Nonce::new(1).unwrap(),
            b"GENESIS".to_vec(),
        );
        let digest = tree
            .finalize_epoch(
                tree.epoch_id,
                &address(4),
                base.ledger_root.as_bytes().to_vec(),
                0.,
                &[],
            )
            .unwrap();
        let mut publication = Publication {
            epoch: 1,
            state: state.snapshot(),
            transactions: vec![],
            legacy_parent: b"GENESIS".to_vec(),
            legacy_digest: digest,
            observation: octra_node_protocol::epoch_journal::Observation {
                finalized_at: 0.,
                fees_total: "0".into(),
                fees_burned: "0".into(),
                base_reward: "0".into(),
                total_reward: "0".into(),
                proposer_reward: "0".into(),
                validator_reward_each: "0".into(),
                reward_recipients: vec![],
            },
            processed: vec![],
            deferred: vec![],
            wall_time: 10.,
            date: 10,
            proposer: address(4),
            tree_state_root: base.ledger_root.as_bytes().to_vec(),
            outcomes: vec![],
            vm_receipts: BTreeMap::new(),
            queue: queue.payload.clone(),
            queue_revision: queue.revision,
        };
        match mutation {
            0 => publication.wall_time = f64::NAN,
            1 => publication.wall_time = f64::INFINITY,
            2 => publication.wall_time = -1.,
            3 => publication.observation.finalized_at = 1.,
            4 => publication.tree_state_root = vec![b'0'; 128],
            5 => publication.legacy_parent = b"wrong".to_vec(),
            _ => unreachable!(),
        }
        assert!(node.store().prepare(&base, publication).await.is_err());
        assert_eq!(node.head().await.unwrap(), base);
        assert_eq!(node.store().queue().await.unwrap().revision, queue.revision);
    }
    node.shutdown().await.unwrap();
}
async fn sqlite_blocker(
    path: &std::path::Path,
    label: &str,
) -> (tokio::process::Child, std::path::PathBuf) {
    let ready = path.join(format!("{label}.ready"));
    let release = path.join(format!("{label}.release"));
    let script="import sqlite3,sys,time,pathlib\nc=sqlite3.connect(sys.argv[1]);c.execute('BEGIN IMMEDIATE');pathlib.Path(sys.argv[2]).write_text('locked')\nfor _ in range(6000):\n if pathlib.Path(sys.argv[3]).exists():break\n time.sleep(.01)\nc.rollback()\n";
    let mut command = tokio::process::Command::new("python3");
    command
        .arg("-c")
        .arg(script)
        .arg(path.join("canonical.db"))
        .arg(&ready)
        .arg(&release)
        .kill_on_drop(true);
    let child = command.spawn().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !ready.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (child, release)
}
async fn wait_queue_publication(node: &single::Node) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while node.queued().is_ok() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
// A bounded test-only barrier at the real prepare→COMMIT boundary. It does
// not publish speculative Tree state or depend on task/reference-count timing.
#[derive(Default)]
struct CommitBarrier {
    entered: std::sync::atomic::AtomicBool,
    released: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
}
impl single::PublicationHook for CommitBarrier {
    fn revoke(&self) {
        self.entered
            .store(true, std::sync::atomic::Ordering::Release);
        let (released, _) = self
            .wake
            .wait_timeout_while(
                self.released.lock().unwrap(),
                std::time::Duration::from_secs(30),
                |released| !*released,
            )
            .unwrap();
        assert!(*released, "controlled pre-COMMIT barrier expired");
    }
    fn committed(&self, _: &Head) {}
}
impl CommitBarrier {
    async fn wait(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !self.entered.load(std::sync::atomic::Ordering::Acquire) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_cancellation_does_not_drop_owned_queue_or_epoch_publication() {
    let tmp = tempfile::tempdir().unwrap();
    let node = open_node(tmp.path(), 0.).await;
    let (mut blocker, release) = sqlite_blocker(tmp.path(), "intake").await;
    let pending = {
        let node = node.clone();
        tokio::spawn(async move { node.submit(signed_transfer(), 10.).await })
    };
    wait_queue_publication(&node).await;
    assert!(
        blocker.try_wait().unwrap().is_none(),
        "actual SQLite writer barrier expired"
    );
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    std::fs::write(release, b"release").unwrap();
    assert!(blocker.wait().await.unwrap().success());
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if node.queued().is_ok_and(|txs| txs.len() == 1) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let barrier = Arc::new(CommitBarrier::default());
    node.set_publication_hook(barrier.clone()).await.unwrap();
    let pending = {
        let node = node.clone();
        tokio::spawn(async move { node.tick(10., 10).await })
    };
    barrier.wait().await;
    assert_eq!(node.head().await.unwrap().cursor.epoch, EpochId(0));
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    barrier.release();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if node.head().await.unwrap().cursor.epoch == EpochId(1)
                && node.queued().is_ok_and(|q| q.is_empty())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    node.shutdown().await.unwrap();
    drop(node);
    let resumed = open_node(tmp.path(), 10.).await;
    assert_eq!(resumed.head().await.unwrap().cursor.epoch, EpochId(1));
    assert!(resumed.queued().unwrap().is_empty());
    resumed.shutdown().await.unwrap();
}
#[tokio::test]
#[ignore = "controlled subprocess crash helper, executed by crash_recovery test"]
async fn single_crash_child() {
    let path = std::path::PathBuf::from(std::env::var_os("OCTRA_SINGLE_CRASH_DIRECTORY").unwrap());
    let node = open_node(&path, 0.).await;
    let phase = std::env::var("OCTRA_SINGLE_CRASH_PHASE").unwrap();
    if phase == "after" {
        node.submit(signed_transfer(), 10.).await.unwrap();
        node.tick(10., 10).await.unwrap();
        std::fs::write(path.join("crash.ready"), b"committed").unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    } else {
        use octra_node_runtime::canonical::single::Publication;
        let (base, mut state) = node.store().snapshot().await.unwrap();
        state.begin().unwrap();
        state.set(&[b"meta", b"last_epoch"], b"1".to_vec()).unwrap();
        state
            .set(&[b"meta", b"current_epoch"], b"2".to_vec())
            .unwrap();
        let queue = node.store().queue().await.unwrap();
        let mut tree = octra_node_protocol::legacy_tree::Tree::create(
            transaction::Nonce::new(1).unwrap(),
            b"GENESIS".to_vec(),
        );
        let digest = tree
            .finalize_epoch(
                tree.epoch_id,
                &address(4),
                base.ledger_root.as_bytes().to_vec(),
                0.,
                &[],
            )
            .unwrap();
        let prepared = node
            .store()
            .prepare(
                &base,
                Publication {
                    epoch: 1,
                    state: state.snapshot(),
                    transactions: vec![],
                    legacy_parent: b"GENESIS".to_vec(),
                    legacy_digest: digest,
                    observation: octra_node_protocol::epoch_journal::Observation {
                        finalized_at: 0.,
                        fees_total: "0".into(),
                        fees_burned: "0".into(),
                        base_reward: "0".into(),
                        total_reward: "0".into(),
                        proposer_reward: "0".into(),
                        validator_reward_each: "0".into(),
                        reward_recipients: vec![],
                    },
                    processed: vec![],
                    deferred: vec![],
                    wall_time: 10.,
                    date: 10,
                    proposer: address(4),
                    tree_state_root: base.ledger_root.as_bytes().to_vec(),
                    outcomes: vec![],
                    vm_receipts: BTreeMap::new(),
                    queue: queue.payload,
                    queue_revision: queue.revision,
                },
            )
            .await
            .unwrap();
        std::fs::write(path.join("crash.ready"), b"prepared").unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        drop(prepared);
    }
    panic!("parent did not kill controlled crash helper")
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigkill_before_and_after_commit_recovers_exact_prefix_and_exex() {
    for phase in ["before", "after"] {
        let tmp = tempfile::tempdir().unwrap();
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "single_crash_child", "--ignored", "--nocapture"])
            .env("OCTRA_SINGLE_CRASH_DIRECTORY", tmp.path())
            .env("OCTRA_SINGLE_CRASH_PHASE", phase)
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        // Cold CI runners may need more than ten seconds to start the helper.
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            while !tmp.path().join("crash.ready").exists() {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "crash helper exited early"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        child.start_kill().unwrap();
        assert!(!child.wait().await.unwrap().success());
        let resumed = open_node(tmp.path(), 10.).await;
        let expected = u64::from(phase == "after");
        assert_eq!(
            resumed.head().await.unwrap().cursor.epoch,
            EpochId(expected)
        );
        let epochs = Arc::new(std::sync::Mutex::new(Vec::new()));
        resumed.register(Collect(epochs.clone())).await.unwrap();
        wait_checkpoint(&resumed, expected).await;
        if phase == "after" {
            assert_eq!(*epochs.lock().unwrap(), vec![1]);
        } else {
            assert!(epochs.lock().unwrap().is_empty());
        }
        resumed.shutdown().await.unwrap();
    }
}

struct AnchorHistory {
    head: Head,
    roots: BTreeMap<i64, Vec<u8>>,
    faults: Value,
    default: String,
}
#[async_trait::async_trait]
impl History for AnchorHistory {
    async fn head(&self) -> Result<Head, finality::Error> {
        Ok(self.head.clone())
    }
    async fn root(&self, epoch: i64) -> Result<Option<Vec<u8>>, finality::Error> {
        match self.faults[epoch.to_string()]
            .as_str()
            .unwrap_or(&self.default)
        {
            "missing" => Ok(None),
            "bad" => Ok(Some(vec![0; 32])),
            "unreadable" => Err(finality::Error::Unavailable("disk unavailable".into())),
            "good" => Ok(self.roots.get(&epoch).cloned()),
            _ => panic!("unrecognized native fixture root status"),
        }
    }
    async fn range(
        &self,
        _: i64,
        _: i64,
    ) -> Result<octra_node_runtime::finality_queries::Range, finality::Error> {
        Err(finality::Error::Unavailable(
            "no BFT fixture history".into(),
        ))
    }
    async fn bundle(
        &self,
        _: &[u8; 32],
    ) -> Result<Option<octra_node_runtime::consensus_bundle::RawBundle>, finality::Error> {
        Err(finality::Error::Unavailable("no BFT fixture bundle".into()))
    }
}
#[tokio::test]
async fn activated_public_single_preserves_native_missing_parent_refusal() {
    let fixture: Value = serde_json::from_slice(include_bytes!(
        "../../octra-node-runtime/tests/fixtures/execution-rules.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["upstream_commit"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    assert_eq!(fixture["instrumentation"], serde_json::json!({}));
    let inputs = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["expected"]["error"] == "validator set fold parent commit missing")
        .collect::<Vec<_>>();
    assert_eq!(inputs.len(), 8);
    let base_fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/single-native.json")).unwrap();
    let initial = initial(&base_fixture["cases"][0]);
    for case in inputs {
        let input = &case["input"];
        assert!(input["parent"].is_null());
        assert_eq!(input["default"], "good");
        let epoch = input["epoch"].as_u64().unwrap();
        let mut head = parent(&base_fixture["cases"][0], &initial.snapshot());
        head.cursor.epoch = EpochId(epoch - 1);
        let roots = input["plans"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| !p.is_null())
            .map(|p| {
                (
                    p[0].as_i64().unwrap(),
                    hex::decode(STANDARD.decode(p[1].as_str().unwrap()).unwrap()).unwrap(),
                )
            })
            .collect();
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = config(tmp.path());
        cfg.graph = Graph::new(
            STANDARD.decode(input["chain"].as_str().unwrap()).unwrap(),
            (!input["config"].is_null())
                .then(|| STANDARD.decode(input["config"].as_str().unwrap()).unwrap()),
        );
        let native = Native::new(
            cfg,
            CircleRuntime::new(Arc::new(octra_node_runtime::circle_hfhe::Backend)),
            Arc::new(AnchorHistory {
                head: head.clone(),
                roots,
                faults: input["roots"].clone(),
                default: input["default"].as_str().unwrap().into(),
            }),
        )
        .unwrap();
        let error = native
            .single_context(&head, &[(address(4), public(4))])
            .await
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            case["expected"]["error"].as_str().unwrap()
        );
    }
}

fn start_single_fixture(
    command: &str,
    path: &std::path::Path,
    log: &std::path::Path,
) -> tokio::process::Child {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_octra-node"))
        .args([command, "--config"])
        .arg(path)
        .stderr(std::fs::File::create(log).unwrap())
        .stdout(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}
async fn single_rpc(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Value,
) -> Result<Value, reqwest::Error> {
    client
        .post(url)
        .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await?
        .json()
        .await
}
async fn wait_single_head(
    child: &mut tokio::process::Child,
    client: &reqwest::Client,
    url: &str,
    epoch: u64,
    log: &std::path::Path,
) -> Value {
    let mut last_response = String::new();
    // A cold CI workspace can spend longer initializing the private ledger
    // while other test binaries share the runner. Keep the process and exact
    // head checks, but give startup the same bounded window as the live gate.
    let result = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "private Single CLI stopped early: {}",
                std::fs::read_to_string(log).unwrap_or_default()
            );
            if let Ok(response) = single_rpc(client, url, "octra_head", Value::Null).await {
                if response["result"]["cursor"]["epoch"].as_u64() == Some(epoch) {
                    return response["result"].clone();
                }
                // A concurrent local commit temporarily suspends publication.
                // The exact head must still become available before the deadline.
                assert!(
                    response.get("error").is_none()
                        || response["error"]["code"].as_i64() == Some(110),
                    "{response}"
                );
                last_response = response.to_string();
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await;
    result.unwrap_or_else(|_| {
        panic!(
            "private Single head {epoch} unavailable; last response: {last_response}; log: {}",
            std::fs::read_to_string(log).unwrap_or_default()
        )
    })
}
async fn stop_single_fixture(child: &mut tokio::process::Child) {
    assert!(tokio::process::Command::new("kill")
        .args(["-TERM", &child.id().unwrap().to_string()])
        .status()
        .await
        .unwrap()
        .success());
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_private_single_cli_seed_clock_rpc_sigterm_and_restart() {
    use ed25519_dalek::Signer as _;
    use octra_node::single::launch::{Config, Execution, Seed};
    use octra_node_runtime::ledger_image;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/single-native.json")).unwrap();
    let state = initial(&fixture["cases"][0]);
    let initial_head = parent(&fixture["cases"][0], &state.snapshot());
    let mut image = Vec::new();
    let written = ledger_image::write(
        &state.snapshot(),
        &mut image,
        ledger_image::Limits::default(),
    )
    .unwrap();
    let image_path = tmp.path().join("genesis.image");
    std::fs::write(&image_path, &image).unwrap();
    let key = tmp.path().join("fixture.key");
    std::fs::write(&key, [4; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let rpc = listener.local_addr().unwrap();
    drop(listener);
    let config = Config {
        services: None,
        chain: octra_exex::ChainIdentity::genesis(
            "octra-single-local-native-oracle",
            initial_head.cursor.state_root,
        ),
        data: tmp.path().join("data"),
        key,
        seed: Seed {
            path: image_path,
            bytes: written.bytes,
            sha256: hex::encode(Sha256::digest(&image)),
            ledger_root: written.root,
            maximum_records: written.records,
            maximum_string_bytes: 1_048_576,
            date: initial_head.date,
        },
        settings: settings(),
        execution: Execution {
            activated_applications: false,
            release: None,
            crypto_profile: None,
            admit_ops: None,
            emission_guard: false,
            emission_activation: None,
            legacy_total: None,
            sender_key_activation: Some(0),
            private_result_activation: 0,
            maximum_fhe: 32,
            maximum_stealth: 32,
            maximum_multi_exec: 8,
            ready_max_lag: 10,
        },
        rpc,
        maximum_http_body: 1_048_576,
    };
    let config_path = tmp.path().join("single.json");
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let network_path = tmp.path().join("single-network.json");
    std::fs::write(
        &network_path,
        serde_json::to_vec(&serde_json::json!({"role":"single","single":&config})).unwrap(),
    )
    .unwrap();
    let url = format!("http://{rpc}/rpc");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let started = std::time::Instant::now();
    let mut child = start_single_fixture("run-single", &config_path, &tmp.path().join("first.log"));
    let genesis =
        wait_single_head(&mut child, &client, &url, 0, &tmp.path().join("first.log")).await;
    assert_eq!(genesis["ledger_root"], config.seed.ledger_root);
    let mut tx = signed_transfer();
    tx.timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    tx.signature = STANDARD
        .encode(
            SigningKey::from_bytes(&[1; 32])
                .sign(&tx.signing_bytes().unwrap())
                .to_bytes(),
        )
        .into_bytes();
    let response = single_rpc(
        &client,
        &url,
        "octra_submit",
        serde_json::json!([serde_json::from_slice::<Value>(&tx.to_json_bytes().unwrap()).unwrap()]),
    )
    .await
    .unwrap();
    assert_eq!(
        response["result"]["tx_hash"],
        hex::encode(tx.hash().unwrap()),
        "{response}"
    );
    let first = wait_single_head(&mut child, &client, &url, 1, &tmp.path().join("first.log")).await;
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(9),
        "native ten-second timer fired early"
    );
    let balance = single_rpc(
        &client,
        &url,
        "octra_balance",
        serde_json::json!([String::from_utf8(address(1)).unwrap()]),
    )
    .await
    .unwrap();
    assert_eq!(
        balance["result"],
        serde_json::json!({"address":String::from_utf8(address(1)).unwrap(),"balance":"0.998999","balance_raw":"998999","nonce":1,"pending_nonce":1,"has_public_key":true})
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !config.data.join("single-archive/1.json").exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let archive: Value =
        serde_json::from_slice(&std::fs::read(config.data.join("single-archive/1.json")).unwrap())
            .unwrap();
    assert_eq!(archive["cursor"]["sequence"], 1);
    stop_single_fixture(&mut child).await;
    let mut resumed =
        start_single_fixture("run-network", &network_path, &tmp.path().join("second.log"));
    assert_eq!(
        wait_single_head(
            &mut resumed,
            &client,
            &url,
            1,
            &tmp.path().join("second.log")
        )
        .await,
        first
    );
    assert_eq!(
        single_rpc(
            &client,
            &url,
            "octra_balance",
            serde_json::json!([String::from_utf8(address(1)).unwrap()])
        )
        .await
        .unwrap()["result"],
        balance["result"]
    );
    stop_single_fixture(&mut resumed).await;
}

#[cfg(unix)]
#[tokio::test]
async fn single_writer_lease_resolves_database_symlink_aliases() {
    let tmp = tempfile::tempdir().unwrap();
    let node = open_node(tmp.path(), 0.).await;
    let database = node.store().database_path();
    let alias = tmp.path().join("alias.db");
    std::os::unix::fs::symlink(&database, &alias).unwrap();
    assert!(single::writer_lock(&alias).is_err());
    assert!(single::writer_lock(&database).is_err());
    node.shutdown().await.unwrap();
    let aliased_lease = single::writer_lock(&alias).unwrap();
    drop(node);
    assert!(single::writer_lock(&database).is_err());
    drop(aliased_lease);
    // A concurrently spawned test subprocess may briefly inherit an open file
    // description before exec closes it. Require the lease to become available
    // promptly, while retaining the exact error if it does not.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match single::writer_lock(&database) {
            Ok(_) => break,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(error) => panic!("released canonical writer lease unavailable: {error:#}"),
        }
    }
}

#[test]
fn local_policy_binds_the_actual_migration_admission_payload() {
    use octra_node_protocol::state_sync::migration::Admission;
    use sha2::{Digest as _, Sha256};
    let tmp = tempfile::tempdir().unwrap();
    let mut config = config(tmp.path());
    let settings = settings();
    let absent = Native::single_policy_for(&config, &settings).unwrap();
    let mut previous = absent;
    for activation in [1, 2] {
        let chain = std::str::from_utf8(config.graph.chain_id()).unwrap();
        let state_root = "0".repeat(64);
        let activation = activation.to_string();
        let mut payload = Vec::new();
        for field in [
            "octra_pvac_migration_entitlements_v2",
            chain,
            "0",
            &state_root,
            &activation,
            "0",
        ] {
            payload.extend_from_slice(field.len().to_string().as_bytes());
            payload.push(b':');
            payload.extend_from_slice(field.as_bytes());
        }
        let root = hex::encode(Sha256::digest(payload));
        let raw=serde_json::to_vec(&serde_json::json!({"schema":"octra_pvac_migration_entitlements_v2","chain_id":chain,"snapshot_epoch":0,"state_root":state_root,"activation_epoch":activation.parse::<i64>().unwrap(),"root":root,"entries":[]})).unwrap();
        config.migration = Some(Arc::new(
            Admission::parse(&raw, config.graph.chain_id(), root.as_bytes(), |_| false).unwrap(),
        ));
        let bound = Native::single_policy_for(&config, &settings).unwrap();
        assert_ne!(bound, absent);
        assert_ne!(bound, previous);
        previous = bound;
    }
}

#[cfg(unix)]
#[path = "single_native/services.rs"]
mod services;

#[cfg(unix)]
#[path = "single_native/facade.rs"]
mod facade;
