use base64::{engine::general_purpose::STANDARD, Engine};
use octra_exex::{Cursor, EpochId, Sequence, StateRoot};
use octra_node_protocol::{
    consensus::{codec::Wire, EpochHeader, Finalize, ParentCommit},
    rules::{Graph, RootRead},
    transaction::RuleMode,
};
use octra_node_runtime::{
    canonical::Head,
    consensus_bundle::RawBundle,
    execution_rules::Bound,
    finality::{self, history::History},
    finality_queries::Range,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};

#[path = "common/finality_host.rs"]
mod finality_host;

fn raw(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/execution-rules.json")).unwrap()
}
fn graph(v: &Value) -> Graph {
    Graph::new(
        raw(&v["chain"]),
        (!v["config"].is_null()).then(|| raw(&v["config"])),
    )
}
fn parent(v: &Value) -> Option<ParentCommit> {
    (!v["parent"].is_null()).then(|| ParentCommit::decode(&raw(&v["parent"])).unwrap())
}
fn candidate_rules() -> &'static Value {
    static FIXTURE: OnceLock<Value> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../octra-node-protocol/tests/fixtures/consensus-staged-c49.json"
        ))
        .unwrap();
        let candidate: Value = serde_json::from_str(include_str!(
            "../../../docs/rust-node/source-map-candidate.json"
        ))
        .unwrap();
        assert_eq!(fixture["upstream_commit"], candidate["upstream_commit"]);
        for (path, hash) in fixture["source_sha256"].as_object().unwrap() {
            assert_eq!(hash, &candidate["files"][path], "{path}");
        }
        assert_eq!(
            fixture["oracle_sha256"],
            hex::encode(Sha256::digest(include_bytes!(
                "../../../scripts/node-port/candidate-consensus-oracle.ml"
            )))
        );
        fixture
    })
}
fn plans(v: &Value) -> BTreeMap<i64, Vec<u8>> {
    let mut plans: BTreeMap<_, _> = v["plans"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| !p.is_null())
        .map(|p| (p[0].as_i64().unwrap(), raw(&p[1])))
        .collect();
    // The historical oracle's 'good' source predates five candidate rules.
    // Supply only native-derived anchor inputs; candidate outcomes are separately captured.
    if let Some(native) = candidate_rules()["graph"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["input"]["chain"] == v["chain"])
    {
        for plan in native["expected"]["plans"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|plan| !plan.is_null())
        {
            let (epoch, root) = (plan[0].as_i64().unwrap(), raw(&plan[1]));
            if let Some(old) = plans.insert(epoch, root.clone()) {
                assert_eq!(old, root, "native anchor drift {epoch}");
            }
        }
    }
    plans
}
fn preview(input: &Value) -> Value {
    let plans = plans(input);
    Bound::resolve(
        &graph(input),
        input["epoch"].as_i64().unwrap(),
        parent(input),
        &[],
        &|epoch| match input["roots"][epoch.to_string()]
            .as_str()
            .unwrap_or(input["default"].as_str().unwrap())
        {
            "missing" => RootRead::Missing,
            "bad" => RootRead::Root(b"wrong-root".to_vec()),
            "unreadable" => RootRead::Unreadable(b"disk unavailable".to_vec()),
            "good" => plans
                .get(&epoch)
                .cloned()
                .map_or(RootRead::Missing, RootRead::Root),
            _ => panic!("unknown root mode"),
        },
    )
    .map_or_else(|error| json!({"error":error.0}), |bound| summary(&bound))
}

fn summary(bound: &Bound) -> Value {
    let active = |mode| mode == RuleMode::Active;
    json!({"manifest":bound.circle.manifest.name(),"update_policy":bound.circle.update_policy,"object_cost":bound.object_cost,
        "owner_migration":active(bound.owner_migration),"cipher_migration":active(bound.cipher_migration),"private_payload":active(bound.private_payload),
        "math":bound.circle.wasm.math,"proof_exec":bound.circle.wasm.proof_exec,"float":bound.circle.wasm.wasm_float,"inspect":bound.circle.inspect,"storage_proof":bound.circle.storage_proof})
}

#[test]
fn native_preview_rule_selection_and_fault_precedence() {
    let fixture = fixture();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], sources["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], sources["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (key, bytes) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/execution-rules-oracle.ml").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
        (
            "input_fixture_sha256",
            include_bytes!("fixtures/rule-activation.json").as_slice(),
        ),
    ] {
        assert_eq!(fixture[key], hex::encode(Sha256::digest(bytes)), "{key}");
    }
    let current: Value =
        serde_json::from_str(include_str!("fixtures/execution-rules-c49.json")).unwrap();
    let candidate: Value = serde_json::from_str(include_str!(
        "../../../docs/rust-node/source-map-candidate.json"
    ))
    .unwrap();
    assert_eq!(current["upstream_commit"], candidate["upstream_commit"]);
    for (path, hash) in current["source_sha256"].as_object().unwrap() {
        assert_eq!(hash, &candidate["files"][path], "{path}");
    }
    for (key, bytes) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/candidate-execution-rules-oracle.ml")
                .as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/candidate-execution-rules-oracle.py")
                .as_slice(),
        ),
        (
            "dependency_runner_sha256",
            include_bytes!("../../../scripts/node-port/candidate-rule-activation-oracle.py")
                .as_slice(),
        ),
        (
            "historical_fixture_sha256",
            include_bytes!("fixtures/execution-rules.json").as_slice(),
        ),
    ] {
        assert_eq!(current[key], hex::encode(Sha256::digest(bytes)), "{key}");
    }
    let old_cases = fixture["cases"].as_array().unwrap();
    let cases = current["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 978);
    assert_eq!(cases.len(), old_cases.len());
    let mut reauthenticated = 0;
    for (index, (old, case)) in old_cases.iter().zip(cases).enumerate() {
        assert_eq!(old["input"], case["input"], "historical input {index}");
        if old["expected"] != case["expected"] {
            // Current native quorum policy rejects three historical high-epoch
            // parent certificates. All earlier fault controls remain identical.
            assert!(old["expected"]["error"].is_null());
            assert_eq!(
                case["expected"],
                json!({"error":"validator duty commit is invalid: quorum"})
            );
            reauthenticated += 1;
        }
        assert_eq!(
            preview(&case["input"]),
            case["expected"],
            "native preview rules {index}"
        );
    }
    assert_eq!(reauthenticated, 3);
}

#[test]
fn new_anchor_faults_match_candidate_native_rules_and_keep_earlier_fault_priority() {
    let historical = fixture();
    let basis = &historical["cases"][155]["input"];
    assert_eq!(basis["default"], "good");
    assert_eq!(basis["roots"], json!({}));
    for kind in ["missing", "bad", "unreadable"] {
        let native = candidate_rules()["graph"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| {
                case["input"]["chain"] == basis["chain"]
                    && case["input"]["epoch"] == 1_737_333
                    && case["input"]["root"] == kind
                    && case["input"]["floor"] == 0
            })
            .unwrap();
        // Native oracle lists ProofKey at slot31, after the original28 rules.
        let plan = &native["expected"]["plans"][31];
        let anchor = plan[0].as_i64().unwrap().to_string();
        let mut input = basis.clone();
        input["roots"][&anchor] = json!(kind);
        let fault = String::from_utf8(raw(&native["expected"]["modes"][31]["error"])).unwrap();
        assert_eq!(preview(&input), json!({"error":fault}));
        let mut earlier = historical["cases"][156]["input"].clone();
        earlier["roots"][&anchor] = json!(kind);
        assert_eq!(preview(&earlier), historical["cases"][156]["expected"]);
    }
}

struct Roots {
    values: BTreeMap<i64, Vec<u8>>,
    fault: Option<(i64, &'static str)>,
    reads: Mutex<Vec<i64>>,
}
#[async_trait::async_trait]
impl History for Roots {
    async fn head(&self) -> Result<Head, finality::Error> {
        unreachable!()
    }
    async fn range(&self, _: i64, _: i64) -> Result<Range, finality::Error> {
        unreachable!()
    }
    async fn bundle(&self, _: &[u8; 32]) -> Result<Option<RawBundle>, finality::Error> {
        unreachable!()
    }
    async fn root(&self, epoch: i64) -> Result<Option<Vec<u8>>, finality::Error> {
        self.reads.lock().unwrap().push(epoch);
        match self.fault.filter(|(e, _)| *e == epoch).map(|(_, f)| f) {
            Some("missing") => Ok(None),
            Some("bad") => Ok(Some(vec![0; 32])),
            Some("hex") => Ok(self.values.get(&epoch).map(|v| hex::encode(v).into_bytes())),
            Some(_) => Err(finality::Error::Unavailable("disk unavailable".into())),
            None => Ok(self.values.get(&epoch).cloned()),
        }
    }
}

#[tokio::test]
async fn historical_rules_bind_the_captured_parent_and_cache_faults() {
    // Parent certificates are native-signed fixtures. This test exercises the
    // context's retained-history contract; finality authenticates the child QC
    // before entering it in the real import path.
    let fixture = fixture();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["input"]["epoch"] == 1_688_734
                && c["expected"]["update_policy"] == true
                && c["input"]["roots"] == json!({})
        })
        .unwrap();
    let input = &case["input"];
    let epoch = input["epoch"].as_i64().unwrap();
    let parent_root = [4; 32];
    let head = Head {
        cursor: Cursor {
            sequence: Sequence((epoch - 1) as u64),
            epoch: EpochId((epoch - 1) as u64),
            state_root: StateRoot(parent_root),
        },
        ledger_root: "unused".into(),
        irmin_commit: "unused".into(),
        parent_commit: None,
        index_root: "unused".into(),
        index_hash: None,
        txid_hi: 0,
        date: 0,
        message: vec![],
    };
    let chain = raw(&input["chain"]);
    let finalized = Finalize {
        chain_id: chain.clone(),
        epoch_id: epoch,
        commit_round: 0,
        proposal_id: vec![],
        precommits: vec![],
        parent_commit: parent(input),
        header: EpochHeader {
            proto_version: 4,
            chain_id: chain,
            epoch_id: epoch,
            prev_state_root: parent_root.to_vec(),
            tx_list_hash: vec![],
            receipt_root: vec![],
            proposed_state_root: vec![],
            parent_commit_hash: vec![],
            creator_addr: vec![],
            txid_hi: 0,
            ts: 0.,
        },
    };
    let graph = graph(input);
    let mut roots = Roots {
        values: plans(input)
            .into_iter()
            .map(|(e, root)| (e, hex::decode(root).unwrap()))
            .collect(),
        fault: None,
        reads: Mutex::new(vec![]),
    };
    roots.values.insert(epoch - 1, parent_root.to_vec());
    let bound = Bound::canonical(&graph, &head, &finalized, &[], &roots)
        .await
        .unwrap();
    assert_eq!(summary(&bound), case["expected"]);
    let reads = roots.reads.lock().unwrap().clone();
    assert!(reads.iter().all(|e| *e < epoch));
    assert_eq!(
        reads
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        reads.len()
    );
    assert_eq!(reads[0], epoch - 1);
    for fault in ["missing", "bad", "hex", "unreadable"] {
        roots.fault = Some((reads[1], fault));
        roots.reads.lock().unwrap().clear();
        let error = Bound::canonical(&graph, &head, &finalized, &[], &roots)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains(&reads[1].to_string()), "{error}");
        assert_eq!(*roots.reads.lock().unwrap(), reads[..2]);
    }
    roots.fault = Some((epoch - 1, "bad"));
    roots.reads.lock().unwrap().clear();
    assert!(Bound::canonical(&graph, &head, &finalized, &[], &roots)
        .await
        .err()
        .unwrap()
        .0
        .contains("history differs"));
    assert_eq!(*roots.reads.lock().unwrap(), [epoch - 1]);
    roots.fault = None;
    for field in ["chain", "epoch", "root"] {
        let mut wrong = finalized.clone();
        match field {
            "chain" => wrong.header.chain_id = b"different".to_vec(),
            "epoch" => wrong.header.epoch_id += 1,
            _ => wrong.header.prev_state_root[0] ^= 1,
        }
        roots.reads.lock().unwrap().clear();
        assert!(Bound::canonical(&graph, &head, &wrong, &[], &roots)
            .await
            .is_err());
        assert!(roots.reads.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn execution_and_catchup_keep_the_authority_that_verified_the_certificate() {
    use octra_exex::{ChainIdentity, StateRoot};
    use octra_node_protocol::consensus::{CatchupEpochRecord, CatchupFinality};
    use octra_node_runtime::{
        canonical::{CanonicalStore, ReliefSource},
        finality::{EpochRules, ExecutedEpoch, Publisher, ValidatorHistory},
        state_batch::StateBatch,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct ChangingAuthority {
        fixed: finality_host::Authority,
        reads: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl ValidatorHistory for ChangingAuthority {
        async fn resolve(
            &self,
            parent: &Head,
            epoch: u64,
            relief: ReliefSource,
        ) -> Result<EpochRules, String> {
            if self.reads.fetch_add(1, Ordering::SeqCst) != 0 {
                return Err("live authority changed during execution binding".into());
            }
            self.fixed.resolve(parent, epoch, relief).await
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let state = StateBatch::default();
    let chain = ChainIdentity::genesis(
        "execution-authority-fixture",
        StateRoot(finality_host::root(None, &state, &[])),
    );
    let store = Arc::new(
        CanonicalStore::create(
            &dir.path().join("node.db"),
            chain.clone(),
            state.snapshot(),
            0,
        )
        .await
        .unwrap(),
    );
    let fixed = finality_host::Authority { seed: 1, chain };
    let reads = Arc::new(AtomicUsize::new(0));
    let publisher = Publisher::open(
        store.clone(),
        ChangingAuthority {
            fixed: fixed.clone(),
            reads: reads.clone(),
        },
    )
    .await
    .unwrap();
    let parent = store.head().await.unwrap();
    let executed = ExecutedEpoch {
        epoch_observation: None,
        metrics: octra_node_protocol::metrics::Epoch::default(),
        vm_receipts: std::collections::BTreeMap::default(),
        state: state.snapshot(),
        transactions: vec![],
        consensus_receipts: vec![],
        reward_source: finality_host::reward_source(1),
        date: 10,
        message: vec![],
    };
    let finalized = finality_host::certificate(&parent, &executed, &fixed);
    let graph = Graph::new(finalized.chain_id.clone(), None);
    let validators = fixed.validators(&parent, 1).unwrap();
    let expected = validators
        .validators
        .iter()
        .map(|v| v.address.clone())
        .collect::<Vec<_>>();
    let (checked, bound) = publisher
        .verify_execution(&parent, &finalized.encode().unwrap(), &graph)
        .await
        .unwrap();
    assert_eq!(checked, finalized);
    assert_eq!(bound.fold.context().active_addresses, expected);
    assert_eq!(bound.authority().unwrap().validators, validators);
    assert!(!bound.authority().unwrap().receipts.required);
    assert!(!bound.authority().unwrap().receipts.crypto_active);
    assert_eq!(
        bound.authority().unwrap().receipts.stealth_minimum,
        5000.into()
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);

    let record = CatchupEpochRecord {
        epoch_id: 1,
        prev_state_root: finalized.header.prev_state_root.clone(),
        state_root: finalized.header.proposed_state_root.clone(),
        tx_list_hash: finalized.header.tx_list_hash.clone(),
        tx_hashes: vec![],
        txs_json: vec![],
        receipt_root: finalized.header.receipt_root.clone(),
        receipts_json: vec![],
        epoch_ts: finalized.header.ts,
        creator_addr: finalized.header.creator_addr.clone(),
        commit_round: finalized.commit_round,
        reward_source: Some(executed.reward_source),
        finality: Some(CatchupFinality {
            finalize: finalized.clone(),
            validator_set: validators,
        }),
    };
    reads.store(0, Ordering::SeqCst);
    let (checked, bound) = publisher
        .verify_record(&parent, &record, &graph)
        .await
        .unwrap();
    assert_eq!(checked, finalized);
    assert_eq!(bound.fold.context().active_addresses, expected);
    assert_eq!(
        bound.authority().unwrap().validators,
        fixed.validators(&parent, 1).unwrap()
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);

    reads.store(0, Ordering::SeqCst);
    let wrong_graph = Graph::new(b"wrong-chain".to_vec(), None);
    assert!(publisher
        .verify_execution(&parent, &finalized.encode().unwrap(), &wrong_graph)
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("graph differs"));
    reads.store(0, Ordering::SeqCst);
    let mut forged = finalized;
    forged.precommits[0].signature[0] ^= 1;
    assert!(publisher
        .verify_execution(&parent, &forged.encode().unwrap(), &graph)
        .await
        .is_err());
    assert_eq!(store.head().await.unwrap(), parent);
}
