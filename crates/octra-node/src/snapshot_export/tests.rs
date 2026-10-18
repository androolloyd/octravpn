use super::*;
use ed25519_dalek::Signer;
use octra_browser::application::UnavailableHost;
use octra_exex::{
    native_history::{ArchiveProof, NativeTransaction},
    sqlite::SqliteCheckpoints,
    ChainIdentity, StateRoot,
};
use octra_node_protocol::{
    consensus::{
        codec::Wire, engine, hash, EpochHeader, Finalize, ParentCommit, Validator, ValidatorSet,
        Vote, VoteType,
    },
    epoch_index,
};
use octra_node_runtime::{
    canonical::{CanonicalStore, Head, ReliefSource},
    circle::CircleRuntime,
    finality::{EpochRules, ExecutedEpoch, ReceiptRules, ValidatorHistory},
    state_batch::StateBatch,
};
use std::{collections::BTreeMap, fs, time::SystemTime};
mod bootstrap_recovery;
fn key(id: u8) -> SigningKey {
    SigningKey::from_bytes(&[id; 32])
}
fn set() -> ValidatorSet {
    ValidatorSet::unweighted(
        (1..=4)
            .map(|id| {
                let pubkey = key(id).verifying_key().to_bytes().to_vec();
                Validator {
                    address: octra_node_protocol::transaction::address_from_public_key(
                        STANDARD.encode(&pubkey).as_bytes(),
                    ),
                    pubkey,
                }
            })
            .collect(),
    )
}
#[derive(Clone)]
struct TestAuthority {
    transition: Option<ValidatorSet>,
}
#[async_trait::async_trait]
impl ValidatorHistory for TestAuthority {
    async fn resolve(
        &self,
        _: &Head,
        epoch: u64,
        _: ReliefSource,
    ) -> std::result::Result<EpochRules, String> {
        Ok(EpochRules {
            validators: if epoch >= 66 {
                self.transition.clone().unwrap_or_else(set)
            } else {
                set()
            },
            receipts: ReceiptRules {
                required: false,
                crypto_active: false,
                stealth_minimum: 5000.into(),
            },
            relief: None,
        })
    }
}
impl Host for TestAuthority {}
fn folded(base: Option<&Head>, state: &StateBatch, transactions: &[NativeTransaction]) -> [u8; 32] {
    let prior = base.map_or_else(
        || hex::encode(epoch_index::genesis_root()),
        |head| head.index_root.clone(),
    );
    let (_, index) = epoch_index::next_root(
        prior.as_bytes(),
        base.map_or(0, |head| head.cursor.epoch.0 as i64 + 1),
        &transactions
            .iter()
            .map(|transaction| epoch_index::Item {
                txid: transaction.txid,
                hash: transaction.hash.as_bytes().to_vec(),
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap()
}
async fn fixture(path: &Path, epochs: u64) -> (Arc<Node<TestAuthority>>, Config, SigningKey) {
    fixture_inner(path, epochs, false).await
}
async fn fixture_inner(
    path: &Path,
    epochs: u64,
    transition: bool,
) -> (Arc<Node<TestAuthority>>, Config, SigningKey) {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    state.set(&[b"meta", b"last_epoch"], b"0".to_vec()).unwrap();
    state.acknowledge_commit().unwrap();
    let blob = b"public fixture PVAC artifact";
    let digest = hex::encode(Sha256::digest(blob));
    state.begin().unwrap();
    state
        .set(&[b"pvac_hashes", b"fixture"], digest.as_bytes().to_vec())
        .unwrap();
    state.acknowledge_commit().unwrap();
    fs::create_dir_all(path.join("pvac/blobs")).unwrap();
    fs::write(path.join(format!("pvac/blobs/{digest}.pk")), blob).unwrap();
    let identity = ChainIdentity::genesis(
        "snapshot-export-local",
        StateRoot(folded(None, &state, &[])),
    );
    let update = octra_node_protocol::control_payload::ValidatorUpdate::make_weighted(
        0,
        66,
        &(2..=5)
            .map(|id| {
                let pubkey = key(id).verifying_key().as_bytes().to_vec();
                octra_node_protocol::validator::admission::Member {
                    address: octra_node_protocol::transaction::address_from_public_key(
                        STANDARD.encode(&pubkey).as_bytes(),
                    ),
                    pubkey,
                    weight: 1.into(),
                }
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let next_set = update
        .validator_set()
        .unwrap()
        .for_epoch(identity.chain_id.as_bytes(), 66)
        .unwrap();
    let exporter = key(7);
    let public = STANDARD.encode(exporter.verifying_key().as_bytes());
    let address = octra_node_protocol::transaction::address_from_public_key(public.as_bytes());
    let network = bootstrap::Network {
        identity: identity.clone(),
        config_hash: "ad".repeat(32),
        minimum_epoch: 0,
        migration_root: None,
        validators: set()
            .validators
            .iter()
            .map(|member| {
                format!(
                    "{}:{}",
                    String::from_utf8(member.address.clone()).unwrap(),
                    STANDARD.encode(&member.pubkey)
                )
            })
            .collect(),
        exporters: vec![format!(
            "{}:{}",
            String::from_utf8(address).unwrap(),
            public
        )],
    };
    let store = CanonicalStore::create(
        &path.join("canonical.sqlite"),
        identity,
        state.snapshot(),
        0,
    )
    .await
    .unwrap();
    let node = Arc::new(
        Node::open(
            store,
            TestAuthority {
                transition: transition.then_some(next_set.clone()),
            },
            CircleRuntime::new(Arc::new(octra_node_runtime::circle_hfhe::Backend)),
            Arc::new(UnavailableHost),
            Arc::new(
                SqliteCheckpoints::open(&path.join("exex.db"))
                    .await
                    .unwrap(),
            ),
        )
        .await
        .unwrap(),
    );
    let timestamp = now().unwrap() - i64::try_from(epochs).unwrap();
    let mut parent = None;
    let mut previous_set = set();
    for epoch in 1..=epochs {
        let (base, mut state) = node.store.snapshot().await.unwrap();
        state.begin().unwrap();
        state
            .set(&[b"meta", b"last_epoch"], epoch.to_string().into_bytes())
            .unwrap();
        if transition && epoch == 65 {
            state
                .set(
                    &[b"meta", octra_node_protocol::validator::update::PENDING_KEY],
                    update.to_bytes(),
                )
                .unwrap();
        }
        if transition && epoch == 66 {
            state
                .set(
                    &[b"meta", octra_node_protocol::validator::update::ACTIVE_KEY],
                    update.to_bytes(),
                )
                .unwrap();
            state
                .remove(&[b"meta", octra_node_protocol::validator::update::PENDING_KEY])
                .unwrap();
        }
        state.acknowledge_commit().unwrap();
        let validators = if transition && epoch >= 66 {
            next_set.clone()
        } else {
            set()
        };
        let proposer = validators.validators[0].address.clone();
        let rewards = validators
            .validators
            .iter()
            .map(|member| {
                (
                    member.address.clone(),
                    STANDARD.encode(&member.pubkey).into_bytes(),
                )
            })
            .collect::<Vec<_>>();
        // One genuine signed archived transfer advances the transaction high
        // water from genesis -1; empty later epochs retain it. Effects are an
        // explicit export fixture, not a transaction-execution qualification.
        let transactions = if epoch == 1 {
            use octra_node_protocol::transaction::{
                address_from_public_key, Nonce, OpType, Transaction,
            };
            let signer = key(9);
            let public = STANDARD.encode(signer.verifying_key().as_bytes());
            let address = address_from_public_key(public.as_bytes());
            let mut transaction = Transaction {
                from: address.clone(),
                to: address,
                amount: 0.into(),
                nonce: Nonce::new(1).unwrap(),
                ou: 0.into(),
                timestamp: f64::from(u32::try_from(timestamp).unwrap()),
                signature: Vec::new(),
                public_key: Some(public.into_bytes()),
                message: None,
                encrypted_data: None,
                op_type: OpType::Standard,
            };
            transaction.signature = STANDARD
                .encode(
                    signer
                        .sign(&transaction.signing_bytes().unwrap())
                        .to_bytes(),
                )
                .into_bytes();
            let identity = transaction.identity_bytes().unwrap();
            vec![NativeTransaction {
                txid: 0,
                hash: hex::encode(transaction.hash().unwrap()),
                proof: ArchiveProof::Exact,
                transaction: identity.clone(),
                identity,
                receipt: None,
            }]
        } else {
            Vec::new()
        };
        let parent_commit = parent.map(|certificate| ParentCommit {
            certificate,
            validator_set: previous_set.clone(),
        });
        let executed = ExecutedEpoch {
            epoch_observation: None,
            metrics: octra_node_protocol::metrics::Epoch::default(),
            vm_receipts: BTreeMap::default(),
            state: state.snapshot(),
            transactions,
            consensus_receipts: vec![],
            reward_source: octra_node_protocol::consensus::reward_attribution::to_source(
                &match &parent_commit {
                    Some(parent) => {
                        octra_node_protocol::consensus::reward_attribution::of_parent(parent)
                            .unwrap()
                    }
                    None => octra_node_protocol::consensus::reward_attribution::full_set(
                        &proposer, &rewards,
                    ),
                },
            )
            .unwrap(),
            date: epoch as i64,
            message: b"snapshot fixture".to_vec(),
        };
        let mut finalize = Finalize {
            chain_id: network.identity.chain_id.as_bytes().to_vec(),
            epoch_id: epoch as i64,
            commit_round: 0,
            header: EpochHeader {
                proto_version: 4,
                chain_id: network.identity.chain_id.as_bytes().to_vec(),
                epoch_id: epoch as i64,
                prev_state_root: base.cursor.state_root.0.to_vec(),
                proposed_state_root: folded(Some(&base), &state, &executed.transactions).to_vec(),
                tx_list_hash: engine::tx_list_hash_for_header(
                    &executed
                        .transactions
                        .iter()
                        .map(|transaction| transaction.hash.as_bytes().to_vec())
                        .collect::<Vec<_>>(),
                )
                .to_vec(),
                receipt_root: hash::receipt_root(&[]).unwrap().to_vec(),
                parent_commit_hash: hash::parent_commit_hash_opt(parent_commit.as_ref())
                    .unwrap()
                    .to_vec(),
                creator_addr: proposer,
                txid_hi: base.txid_hi + executed.transactions.len() as i64,
                ts: f64::from(u32::try_from(timestamp + epoch as i64).unwrap()),
            },
            proposal_id: vec![],
            precommits: vec![],
            parent_commit,
        };
        finalize.proposal_id = hash::proposal_id(&finalize.header).unwrap().to_vec();
        let first = if transition && epoch >= 66 { 2 } else { 1 };
        finalize.precommits = (first..first + 3)
            .map(|id| {
                let mut vote = Vote {
                    chain_id: finalize.chain_id.clone(),
                    epoch_id: epoch as i64,
                    round: 0,
                    vote_type: VoteType::Precommit,
                    proposal_id: finalize.proposal_id.clone(),
                    validator: octra_node_protocol::transaction::address_from_public_key(
                        STANDARD
                            .encode(key(id).verifying_key().as_bytes())
                            .as_bytes(),
                    ),
                    signature: vec![],
                };
                vote.signature = key(id)
                    .sign(&hash::vote_sign_bytes(&vote).unwrap())
                    .to_bytes()
                    .to_vec();
                vote
            })
            .collect();
        parent = Some(finalize.certificate());
        previous_set = validators;
        node.publish(&base, &finalize.encode().unwrap(), executed)
            .await
            .unwrap();
    }
    assert!(node.resume().await.unwrap());
    let config = Config {
        network,
        source: path.to_owned(),
        root: path.join("archive"),
        certificate: path.join("state_sync/certificate.json"),
        force: false,
        limits: Limits {
            bytes: 1024 * 1024,
            records: 1000,
            string_bytes: 1024 * 1024,
        },
    };
    (node, config, exporter)
}
async fn publish_at(
    node: &Node<TestAuthority>,
    config: &Config,
    archive: &archive::Archive,
    key: &SigningKey,
    epoch: u64,
) -> String {
    let authority = bootstrap::Authority::new(config.network.clone()).unwrap();
    let head = node.store.reader().head_for_epoch(epoch).await.unwrap();
    let anchor = chain::build(node, config, &head).await.unwrap();
    let capture = package::capture(&authority, &node.store, &config.source, head, anchor)
        .await
        .unwrap();
    let id = capture.snapshot_id().unwrap();
    let stage = archive.stage(&id).unwrap();
    package::prepare_capture(
        &config.source,
        &stage,
        capture,
        16 * 1024 * 1024,
        config.limits,
    )
    .unwrap();
    let raw = package::sign_capture(&authority, &stage, key, config.limits).unwrap();
    archive.complete(&id, &raw).unwrap();
    archive.publish(config, &id, &raw).unwrap();
    id
}
#[tokio::test]
async fn publication_restart_reauthenticates_files_and_failed_capture_preserves_pointer() {
    let directory = tempfile::tempdir().unwrap();
    let (node, config, key) = fixture(directory.path(), 66).await;
    let archive = archive::Archive::open(&config).unwrap();
    let id = publish_at(&node, &config, &archive, &key, 65).await;
    let pointer = archive.current().unwrap().unwrap();
    let certificate = bootstrap::Authority::new(config.network.clone())
        .unwrap()
        .trust()
        .verify(&pointer, now().unwrap())
        .unwrap();
    let source = chain::finality(
        &node,
        &bootstrap::Authority::new(config.network.clone()).unwrap(),
        65,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        certificate.draft().checkpoint.created_at,
        source.finalize.header.ts as i64
    );
    assert_eq!(
        certificate.draft().checkpoint.valid_until - certificate.draft().checkpoint.created_at,
        cycle::VALID_FOR_SECONDS
    );
    assert_eq!(
        fs::read(archive.path(&id).unwrap().join(".certificate.json")).unwrap(),
        pointer
    );
    assert_eq!(archive.load(&config).unwrap(), Some(65));
    assert!(
        archive::Archive::open(&config).is_err(),
        "physical archive lease survives until owner drops"
    );
    node.suspend("fixture disconnected");
    assert!(capture(
        node.clone(),
        config.clone(),
        Arc::new(
            archive::Archive::open(&Config {
                root: directory.path().join("other"),
                ..config.clone()
            })
            .unwrap()
        ),
        key.clone(),
        66,
        Arc::new(AtomicBool::new(false))
    )
    .await
    .is_err());
    assert_eq!(archive.current().unwrap().unwrap(), pointer);
    drop(archive);
    let restarted = archive::Archive::open(&config).unwrap();
    assert_eq!(restarted.load(&config).unwrap(), Some(65));
    fs::write(restarted.path(&id).unwrap().join("ledger.dat"), b"corrupt").unwrap();
    assert!(
        restarted.load(&config).is_err(),
        "signed manifest cannot bless changed files"
    );
    assert_eq!(restarted.current().unwrap().unwrap(), pointer);
    node.shutdown().await.unwrap();
}
#[cfg(unix)]
#[tokio::test]
async fn retention_honors_fresh_bounded_leases_and_preserves_unknown_or_foreign_paths() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let (node, config, key) = fixture(directory.path(), 69).await;
    let archive = archive::Archive::open(&config).unwrap();
    let mut ids = Vec::new();
    for epoch in 65..=69 {
        ids.push(publish_at(&node, &config, &archive, &key, epoch).await);
    }
    let leased = archive.path(&ids[0]).unwrap();
    fs::write(leased.join("download.lease"), b"").unwrap();
    let foreign = "f".repeat(64);
    fs::create_dir(archive.path(&foreign).unwrap()).unwrap();
    fs::write(archive.path(&foreign).unwrap().join("keep"), b"foreign").unwrap();
    let external = directory.path().join("external");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("keep"), b"external").unwrap();
    let linked = "e".repeat(64);
    symlink(&external, archive.path(&linked).unwrap()).unwrap();
    let unknown = format!("{}.next", "d".repeat(64));
    fs::create_dir(config.root.join(&unknown)).unwrap();
    fs::write(config.root.join(&unknown).join(".writer"), b"unowned").unwrap();
    let errors = archive.retain(&config, 2).unwrap();
    assert!(!errors.is_empty());
    assert!(leased.exists());
    assert!(!archive.path(&ids[1]).unwrap().exists());
    assert!(!archive.path(&ids[2]).unwrap().exists());
    assert!(archive.path(&ids[3]).unwrap().exists());
    assert!(archive.path(&ids[4]).unwrap().exists());
    assert!(external.join("keep").exists());
    assert!(archive.path(&foreign).unwrap().join("keep").exists());
    assert!(config.root.join(&unknown).exists());
    let file = fs::OpenOptions::new()
        .write(true)
        .open(leased.join("download.lease"))
        .unwrap();
    file.set_times(fs::FileTimes::new().set_modified(SystemTime::now() + Duration::from_secs(61)))
        .unwrap();
    archive.retain(&config, 2).unwrap();
    assert!(!leased.exists(), "future lease is rejected");
    node.shutdown().await.unwrap();
}
#[test]
fn archive_rejects_authority_changes_and_linked_ownership_markers() {
    let directory = tempfile::tempdir().unwrap();
    let mut values = BTreeMap::new();
    values.insert("OCTRA_CHAIN_ID".into(), b"fixture".to_vec());
    let members = set()
        .validators
        .into_iter()
        .map(|member| {
            format!(
                "{}:{}",
                String::from_utf8(member.address).unwrap(),
                STANDARD.encode(member.pubkey)
            )
        })
        .collect::<Vec<_>>();
    let network = bootstrap::Network {
        identity: ChainIdentity::genesis("fixture", StateRoot([0; 32])),
        config_hash: "ab".repeat(32),
        validators: members.clone(),
        exporters: members,
        minimum_epoch: 0,
        migration_root: None,
    };
    let settings = Settings::from_values(values).unwrap();
    let mut config = Config::capture(
        network,
        directory.path().to_owned(),
        &settings,
        false,
        LimitsConfig::default(),
    )
    .unwrap();
    let archive = archive::Archive::open(&config).unwrap();
    drop(archive);
    config.network.config_hash = "bc".repeat(32);
    assert!(archive::Archive::open(&config).is_err());
    #[cfg(unix)]
    {
        config.network.config_hash = "ab".repeat(32);
        let external = directory.path().join("external");
        fs::write(&external, b"unchanged").unwrap();
        fs::remove_file(config.root.join(".octra-owner.json")).unwrap();
        std::os::unix::fs::symlink(&external, config.root.join(".octra-owner.json")).unwrap();
        assert!(archive::Archive::open(&config).is_err());
        assert_eq!(fs::read(&external).unwrap(), b"unchanged");
    }
}

#[tokio::test]
async fn failed_payload_capture_is_owned_before_write_and_retries_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let (node, config, key) = fixture(directory.path(), 66).await;
    let archive = Arc::new(archive::Archive::open(&config).unwrap());
    publish_at(&node, &config, &archive, &key, 65).await;
    let previous = archive.current().unwrap().unwrap();
    let blob = b"public fixture PVAC artifact";
    let blob_path = config.source.join(format!(
        "pvac/blobs/{}.pk",
        hex::encode(Sha256::digest(blob))
    ));
    fs::remove_file(&blob_path).unwrap();
    assert!(capture(
        node.clone(),
        config.clone(),
        archive.clone(),
        key.clone(),
        66,
        Arc::new(AtomicBool::new(false))
    )
    .await
    .is_err());
    assert_eq!(archive.current().unwrap().unwrap(), previous);
    let stages = fs::read_dir(&config.root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "next"))
        .collect::<Vec<_>>();
    assert_eq!(stages.len(), 1);
    assert!(stages[0].join(".octra-owner.json").is_file());
    assert!(stages[0].join("ledger.dat").is_file());
    drop(archive);
    let restarted = Arc::new(archive::Archive::open(&config).unwrap());
    fs::write(&blob_path, blob).unwrap();
    assert_eq!(
        capture(
            node.clone(),
            config.clone(),
            restarted.clone(),
            key,
            66,
            Arc::new(AtomicBool::new(false))
        )
        .await
        .unwrap(),
        66
    );
    assert_ne!(restarted.current().unwrap().unwrap(), previous);
    assert_eq!(restarted.load(&config).unwrap(), Some(66));
    assert!(stages.into_iter().all(|stage| !stage.exists()));
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn snapshot_anchor_reconstructs_actual_pending_set_transition_and_rejects_foreign_trust() {
    let directory = tempfile::tempdir().unwrap();
    let (node, config, exporter) = fixture_inner(directory.path(), 70, true).await;
    let head = node.head().await.unwrap();
    let anchor = chain::build(&node, &config, &head).await.unwrap();
    assert_eq!(anchor.steps.len(), 1);
    assert_eq!(
        anchor.steps[0].source,
        octra_node_protocol::state_sync::anchor::Source::Pending
    );
    assert_eq!(anchor.steps[0].finalize.epoch_id, 65);
    assert!(anchor.validator_set.weighted);
    let archive = archive::Archive::open(&config).unwrap();
    publish_at(&node, &config, &archive, &exporter, 70).await;
    assert_eq!(archive.load(&config).unwrap(), Some(70));
    let mut foreign = config.clone();
    foreign.network.validators = (9..=12)
        .map(|id| {
            let public = STANDARD.encode(key(id).verifying_key().as_bytes());
            let address =
                octra_node_protocol::transaction::address_from_public_key(public.as_bytes());
            format!("{}:{public}", String::from_utf8(address).unwrap())
        })
        .collect();
    assert!(chain::build(&node, &foreign, &head).await.is_err());
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn corrupted_same_head_package_is_replaced_atomically_and_foreign_pointer_preserved() {
    let directory = tempfile::tempdir().unwrap();
    let (node, config, key) = fixture(directory.path(), 65).await;
    let archive = Arc::new(archive::Archive::open(&config).unwrap());
    let id = publish_at(&node, &config, &archive, &key, 65).await;
    let pointer = archive.current().unwrap().unwrap();
    fs::remove_file(archive.path(&id).unwrap().join("ledger.dat")).unwrap();
    drop(archive);
    let restarted = Arc::new(archive::Archive::open(&config).unwrap());
    assert_eq!(load_published(&restarted, &config).unwrap(), None);
    assert_eq!(
        capture(
            node.clone(),
            config.clone(),
            restarted.clone(),
            key.clone(),
            65,
            Arc::new(AtomicBool::new(false))
        )
        .await
        .unwrap(),
        65
    );
    assert_eq!(restarted.current().unwrap().unwrap(), pointer);
    assert_eq!(restarted.load(&config).unwrap(), Some(65));
    assert!(restarted.path(&id).unwrap().join("ledger.dat").is_file());
    // A syntactically valid foreign authority/unsigned pointer cannot be
    // treated as a damaged cache entry or overwritten by a fresh local export.
    fs::write(
        &config.certificate,
        b"{}
",
    )
    .unwrap();
    assert!(load_published(&restarted, &config).is_err());
    assert!(capture(
        node.clone(),
        config.clone(),
        restarted.clone(),
        key,
        65,
        Arc::new(AtomicBool::new(false))
    )
    .await
    .is_err());
    assert_eq!(
        fs::read(&config.certificate).unwrap(),
        b"{}
"
    );
    node.shutdown().await.unwrap();
}

#[cfg(unix)]
#[path = "../bootstrap/export/offline_tests.rs"]
mod offline_commands;
