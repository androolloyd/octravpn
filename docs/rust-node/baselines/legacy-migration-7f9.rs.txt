//! Trusted PRIVATE legacy genesis, explicit core policy inputs and real proofs.
//! This qualifies neither public activation selection nor entitlement provenance.
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_exex::{
    native_history::{ArchiveProof, NativeTransaction},
    ChainIdentity, CommittedEpochSource, Sequence, StateRoot,
};
use octra_hfhe::scalar::ScalarRule;
use octra_node_protocol::{
    consensus::{
        codec::Wire, policy::Protocol, reward_attribution, Finalize, Validator, ValidatorSet,
    },
    epoch_index,
    native_json::Document,
    preverify_commit::Gate,
    preverify_receipt::{self, Binding, Receipt},
    state_sync::migration::Admission,
    transaction::{OpType, RuleMode, Transaction},
    transaction_outcome,
    validator::policy::Policy,
};
use octra_node_runtime::{
    account_store, admission,
    canonical::{CanonicalStore, Head, ReliefSource},
    epoch_execution::{self, Preverification, Request},
    epoch_footer,
    finality::{EpochRules, ExecutedEpoch, Publisher, ReceiptRules, ValidatorHistory},
    private_balance::Profile,
    private_crypto::ResultPolicy,
    private_epoch::Epoch,
    private_key,
    state_batch::StateBatch,
    validator_epoch,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write, path::Path, sync::Arc};
#[path = "common/crypto_worker.rs"]
mod worker;

fn raw(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn hash(v: &[u8]) -> Vec<u8> {
    hex::encode(Sha256::digest(v)).into_bytes()
}
fn snapshot(v: &Value) -> StateBatch {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    for row in v["entries"].as_array().unwrap() {
        let path = row[0]
            .as_array()
            .unwrap()
            .iter()
            .map(raw)
            .collect::<Vec<_>>();
        state
            .set(
                &path.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                raw(&row[1]),
            )
            .unwrap();
    }
    assert_eq!(hex::encode(state.root().unwrap()), v["root"]);
    state.acknowledge_commit().unwrap();
    state
}
fn matches_snapshot(state: &StateBatch, v: &Value) {
    assert_eq!(hex::encode(state.root().unwrap()), v["root"]);
    for row in v["entries"].as_array().unwrap() {
        let path = row[0]
            .as_array()
            .unwrap()
            .iter()
            .map(raw)
            .collect::<Vec<_>>();
        assert_eq!(
            state.get(&path.iter().map(Vec::as_slice).collect::<Vec<_>>()),
            Some(raw(&row[1])).as_deref()
        );
    }
}
fn transaction(v: &Value) -> Transaction {
    let bytes = raw(v);
    let tx = Transaction::from_document(&Document::parse(&bytes).unwrap()).unwrap();
    assert_eq!(tx.to_json_bytes().unwrap(), bytes);
    admission::signature(&tx, tx.public_key.as_deref()).unwrap();
    tx
}
fn valid_point(encoded: &[u8]) -> bool {
    STANDARD
        .decode(encoded)
        .ok()
        .and_then(|p| <[u8; 32]>::try_from(p).ok())
        .is_some_and(|p| octra_hfhe::proof::generators::point_valid(&p))
}
#[derive(Clone)]
struct Authority {
    chain: ChainIdentity,
    validators: ValidatorSet,
}
#[async_trait::async_trait]
impl ValidatorHistory for Authority {
    async fn resolve(
        &self,
        parent: &Head,
        epoch: u64,
        relief: ReliefSource,
    ) -> Result<EpochRules, String> {
        if epoch != parent.cursor.epoch.0 + 1
            || (parent.cursor.sequence.0 == 0
                && self.chain.genesis_root() != Some(parent.cursor.state_root))
            || matches!(relief, ReliefSource::Committed(Some(_)))
        {
            return Err("fixture authority mismatch".into());
        }
        Ok(EpochRules {
            validators: self.validators.clone(),
            relief: None,
            receipts: ReceiptRules {
                required: true,
                crypto_active: true,
                stealth_minimum: 5000.into(),
            },
        })
    }
}
#[derive(Clone, Copy)]
struct Execution<'a> {
    owner: bool,
    cipher: bool,
    admitted: Option<&'a Admission>,
    keys: &'a [(Vec<u8>, Vec<u8>)],
    finalized: &'a Finalize,
    blob_dir: &'a Path,
}
fn execute(
    parent: &Head,
    state: &mut StateBatch,
    txs: &[Transaction],
    gate: Option<&Gate>,
    context: Execution<'_>,
    blobs: &mut BTreeMap<Vec<u8>, Vec<u8>>,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let Execution {
        owner,
        cipher,
        admitted,
        keys,
        finalized,
        blob_dir,
    } = context;
    let before = state.snapshot();
    let mut ledger = account_store::ledger(state).unwrap();
    state.begin().unwrap();
    let reward = reward_attribution::resolve(
        finalized.chain_id.as_slice(),
        finalized.epoch_id,
        Protocol::new(2).unwrap(),
        &finalized.header.creator_addr,
        keys,
        finalized.parent_commit.as_ref(),
    )
    .unwrap();
    let policy = Policy::Inactive;
    let emission = epoch_footer::Policy {
        emission_guard: true,
        schedule: octra_node_protocol::emission::Schedule::Inactive,
        legacy_total: None,
    };
    let minimum = 5000.into();
    let previous = hex::encode(parent.cursor.state_root.0);
    let request = Request {
        validators: validator_epoch::Request {
            chain: &finalized.chain_id,
            epoch: finalized.epoch_id,
            policy: &policy,
            legacy_members: &[],
            previous_root: previous.as_bytes(),
            committed_head: Some(&before),
        },
        envelope: transaction_outcome::Rules {
            envelope: RuleMode::Prior,
            compute: RuleMode::Prior,
            settle: RuleMode::Prior,
        },
        sender_key_activation: Some(0),
        preverification: gate.map(|gate| Preverification {
            gate,
            crypto_active: true,
            minimum: &minimum,
        }),
        emission: &emission,
        reward: &reward,
        validator_keys: keys,
    };
    let fold = |_: i64, _: &StateBatch| {
        Ok(validator_epoch::Fold {
            account_mode: RuleMode::Active,
            ..validator_epoch::Fold::prior()
        })
    };
    let mut host = Epoch::new(
        private_key::Policy {
            balance: Profile {
                fields: RuleMode::Active,
                strict: true,
                math: ScalarRule::Prior,
                result: ResultPolicy::Recoverable,
            },
            owner: if owner {
                RuleMode::Active
            } else {
                RuleMode::Prior
            },
            cipher: if cipher {
                RuleMode::Active
            } else {
                RuleMode::Prior
            },
        },
        octra_node_runtime::private_epoch::Limits {
            max_fhe: 4,
            max_stealth: 1,
        },
        finalized.epoch_id,
        gate,
        admitted,
    );
    let mut persisted = Vec::new();
    let executed = epoch_execution::execute(
        &request,
        &fold,
        txs,
        &mut ledger,
        state,
        |tx, ledger, state| {
            if tx.op_type == OpType::Standard {
                ledger
                    .transfer(&tx.from, &tx.to, &tx.amount, &tx.ou, tx.nonce)
                    .map_err(|error| {
                        octra_node_runtime::execution::Error(format!(
                            "valid public fixture transfer failed: {error:?}"
                        ))
                    })?;
                return Ok(epoch_execution::Effect::Confirmed(tx.ou.clone()));
            }
            host.process(
                tx,
                ledger,
                state,
                |requested| {
                    let path =
                        blob_dir.join(format!("{}.pk", std::str::from_utf8(requested).unwrap()));
                    let raw = match std::fs::read(path) {
                        Ok(v) => Some(v),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                        Err(e) => return Err(octra_node_runtime::execution::Error(e.to_string())),
                    };
                    if let Some(ref raw) = raw {
                        assert_eq!(hash(raw), requested);
                    }
                    Ok(raw)
                },
                |public| {
                    let h = hash(public);
                    let path = blob_dir.join(format!("{}.pk", std::str::from_utf8(&h).unwrap()));
                    if path.exists() {
                        assert_eq!(std::fs::read(&path).unwrap(), public);
                    } else {
                        let mut file = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&path)
                            .unwrap();
                        file.write_all(public).unwrap();
                        file.sync_all().unwrap();
                    }
                    persisted.push((h, public.to_vec()));
                    Ok(())
                },
            )
        },
    )
    .unwrap();
    for (h, p) in persisted {
        blobs.insert(h, p);
    }
    executed
        .artifacts
        .rejected
        .iter()
        .map(|r| (r.refusal.error_type.clone(), r.refusal.reason.clone()))
        .collect()
}
#[tokio::test(flavor = "current_thread")]
async fn genuine_legacy_migration_proofs_receipts_qcs_and_restart() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/legacy-migration-native.json")).unwrap();
    let native_map: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], native_map["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], native_map["files"]);
    assert_eq!(
        fixture["rust_test_sha256"],
        hex::encode(Sha256::digest(include_bytes!("legacy_migration.rs")))
    );
    assert_eq!(fixture["instrumentation"], json!({}));
    let capture = &fixture["capture"];
    assert_eq!(capture["material_self_verified"], true);
    let _scope = worker::scope(false);
    let chain_name = capture["chain_id"].as_str().unwrap();
    let payer = capture["payer"].as_str().unwrap().as_bytes();
    let old = raw(&capture["old_public"]);
    let new = raw(&capture["new_public"]);
    let keys = capture["validators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["address"].as_str().unwrap().as_bytes().to_vec(),
                v["public"].as_str().unwrap().as_bytes().to_vec(),
            )
        })
        .collect::<Vec<_>>();
    let validators = ValidatorSet::unweighted(
        keys.iter()
            .map(|(address, public)| Validator {
                address: address.clone(),
                pubkey: STANDARD.decode(public).unwrap(),
            })
            .collect(),
    );
    let mut positives = 0;
    for case in capture["cases"].as_array().unwrap() {
        assert_eq!(
            case["admission_origin"],
            "explicit independently root-bound trusted private legacy genesis entitlement"
        );
        assert_eq!(
            case["current_claim_chain_refusal"],
            "history initial encrypted balance is not empty"
        );
        assert!(case["current_legacy_deposit_refusal"]
            .as_str()
            .unwrap()
            .ends_with("pvac pubkey proof circuit lacks alias rejection"));
        let state = snapshot(&case["initial"]);
        let (_, index0) =
            epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
                .unwrap();
        let root = epoch_index::folded_state_root(
            hex::encode(state.root().unwrap()).as_bytes(),
            hex::encode(index0).as_bytes(),
        )
        .unwrap();
        assert_eq!(hex::encode(root), case["genesis_root"]);
        let chain = ChainIdentity::genesis(chain_name, StateRoot(root));
        let authority = Authority {
            chain: chain.clone(),
            validators: validators.clone(),
        };
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("canonical.sqlite");
        let blob_dir = directory.path().join("blobs");
        std::fs::create_dir(&blob_dir).unwrap();
        std::fs::write(
            blob_dir.join(format!("{}.pk", std::str::from_utf8(&hash(&old)).unwrap())),
            &old,
        )
        .unwrap();
        let store = Arc::new(
            CanonicalStore::create(&path, chain.clone(), state.snapshot(), 0)
                .await
                .unwrap(),
        );
        let publisher = Publisher::open(store.clone(), authority.clone())
            .await
            .unwrap();
        let mut blobs = BTreeMap::from([(hash(&old), old.clone())]);
        let admission = (!case["admission"].is_null()).then(|| {
            let bytes = serde_json::to_vec(&case["admission"]).unwrap();
            let trusted = case["trusted_admission_root"].as_str().unwrap().as_bytes();
            assert!(
                Admission::parse(&bytes, chain_name.as_bytes(), &[b'0'; 64], valid_point).is_err()
            );
            let admission =
                Admission::parse(&bytes, chain_name.as_bytes(), trusted, valid_point).unwrap();
            assert!(admission.bind_snapshot(&[b'0'; 64]).is_err());
            admission
                .bind_snapshot(
                    case["epochs"][1]["head"]["state_root"]
                        .as_str()
                        .unwrap()
                        .as_bytes(),
                )
                .unwrap();
            admission
        });
        let mut rows = case["epochs"]
            .as_array()
            .unwrap()
            .iter()
            .collect::<Vec<_>>();
        if !case["published"].is_null() {
            rows.push(&case["published"]);
            positives += 1;
        }
        for row in rows {
            let (parent, mut state) = store.snapshot().await.unwrap();
            let finalized = Finalize::decode(&raw(&row["finality"])).unwrap();
            let txs = row["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .map(transaction)
                .collect::<Vec<_>>();
            let raws = row["receipts"]
                .as_array()
                .unwrap()
                .iter()
                .map(raw)
                .collect::<Vec<_>>();
            let gate = Gate::parse(&raws).unwrap();
            if finalized.epoch_id == 3 {
                let tx = &txs[0];
                let receipt = Receipt::parse(&raws[0]).unwrap();
                let plan = private_key::verify(
                    &account_store::ledger(&state).unwrap(),
                    tx,
                    private_key::Policy {
                        balance: Profile {
                            fields: RuleMode::Active,
                            strict: true,
                            math: ScalarRule::Prior,
                            result: ResultPolicy::Recoverable,
                        },
                        owner: RuleMode::Active,
                        cipher: if case["policy"]["cipher"] == true {
                            RuleMode::Active
                        } else {
                            RuleMode::Prior
                        },
                    },
                    3,
                    admission.as_ref(),
                    || Ok(Some(old.clone())),
                )
                .unwrap();
                let Binding::Private(binding) = receipt.binding else {
                    panic!("native migration receipt lacks private binding")
                };
                assert_eq!(
                    binding.pre_state_hash,
                    preverify_receipt::state_hash(parent.ledger_root.as_bytes())
                );
                assert_eq!(binding.source_cipher_hash, hash(plan.current_cipher()));
                assert_eq!(binding.pvac_key_hash, hash(&old));
                assert_eq!(
                    binding.transition_hash,
                    Some(plan.transition_hash().into_bytes())
                );
            }
            let rejected = execute(
                &parent,
                &mut state,
                &txs,
                Some(&gate),
                Execution {
                    owner: true,
                    cipher: case["policy"]["cipher"] == true,
                    admitted: admission.as_ref(),
                    keys: &keys,
                    finalized: &finalized,
                    blob_dir: &blob_dir,
                },
                &mut blobs,
            );
            assert!(rejected.is_empty());
            matches_snapshot(&state, &row["state"]);
            let transactions = txs
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    let identity = t.identity_bytes().unwrap();
                    NativeTransaction {
                        txid: parent.txid_hi + 1 + i64::try_from(i).unwrap(),
                        hash: hex::encode(t.hash().unwrap()),
                        identity: identity.clone(),
                        transaction: identity,
                        proof: ArchiveProof::Exact,
                        receipt: None,
                    }
                })
                .collect();
            let reward = reward_attribution::resolve(
                chain_name.as_bytes(),
                finalized.epoch_id,
                Protocol::new(2).unwrap(),
                &finalized.header.creator_addr,
                &keys,
                finalized.parent_commit.as_ref(),
            )
            .unwrap();
            let executed = ExecutedEpoch {
                epoch_observation: None,
                metrics: octra_node_protocol::metrics::Epoch::default(),
                vm_receipts: BTreeMap::default(),
                state: state.snapshot(),
                transactions,
                consensus_receipts: raws,
                reward_source: reward_attribution::to_source(&reward).unwrap(),
                date: finalized.epoch_id,
                message: b"actual native legacy migration fixture".to_vec(),
            };
            let mut bad = finalized.clone();
            bad.precommits[0].signature[0] ^= 1;
            assert!(publisher
                .prepare(&parent, &bad.encode().unwrap(), executed.clone())
                .await
                .is_err());
            assert_eq!(store.head().await.unwrap(), parent);
            let committed = publisher
                .prepare(&parent, &finalized.encode().unwrap(), executed)
                .await
                .unwrap()
                .commit()
                .await
                .unwrap();
            let event = store
                .source()
                .load(committed.cursor.sequence)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                event.cursor.epoch.0,
                u64::try_from(finalized.epoch_id).unwrap()
            );
            assert_eq!(
                committed.cursor.state_root.0,
                finalized.header.proposed_state_root.as_slice()
            );
        }
        let (parent, mut state) = store.snapshot().await.unwrap();
        if case["published"].is_null() {
            matches_snapshot(&state, &case["before"]);
            let tx = transaction(&case["transaction"]);
            let raws = case["receipt"]
                .as_str()
                .map(|_| raw(&case["receipt"]))
                .into_iter()
                .collect::<Vec<_>>();
            let gate = (!raws.is_empty()).then(|| Gate::parse(&raws).unwrap());
            let previous = Finalize::decode(&raw(&case["epochs"][1]["finality"])).unwrap();
            // Unpublished core execution context; its parent is the real retained QC.
            let mut candidate = previous.clone();
            candidate.epoch_id = 3;
            candidate.parent_commit = Some(octra_node_protocol::consensus::ParentCommit {
                certificate: previous.certificate(),
                validator_set: validators.clone(),
            });
            candidate.header.epoch_id = 3;
            candidate.header.prev_state_root = parent.cursor.state_root.0.to_vec();
            let rejected = execute(
                &parent,
                &mut state,
                &[tx],
                gate.as_ref(),
                Execution {
                    owner: case["policy"]["owner"] == true,
                    cipher: case["policy"]["cipher"] == true,
                    admitted: admission.as_ref(),
                    keys: &keys,
                    finalized: &candidate,
                    blob_dir: &blob_dir,
                },
                &mut blobs,
            );
            let expected = case["outcome"]["rejected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    (
                        v["tag"].as_str().unwrap().as_bytes().to_vec(),
                        raw(&v["reason"]),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(rejected, expected, "{}", case["name"]);
            matches_snapshot(&state, &case["after"]);
            assert_eq!(store.head().await.unwrap(), parent);
            assert!(store.source().load(Sequence(3)).await.unwrap().is_none());
        } else {
            assert_eq!(
                state.get(&[b"pvac_hashes", payer]),
                Some(hash(&new)).as_deref()
            );
            assert_eq!(blobs.get(&hash(&new)), Some(&new));
            let tx = transaction(&case["transaction"]);
            let before = account_store::load(&state, payer).unwrap().unwrap();
            let mut ledger = account_store::ledger(&state).unwrap();
            state.begin().unwrap();
            let mut host = Epoch::new(
                private_key::Policy {
                    balance: Profile {
                        fields: RuleMode::Active,
                        strict: true,
                        math: ScalarRule::Prior,
                        result: ResultPolicy::Recoverable,
                    },
                    owner: RuleMode::Active,
                    cipher: RuleMode::Active,
                },
                octra_node_runtime::private_epoch::Limits {
                    max_fhe: 4,
                    max_stealth: 1,
                },
                4,
                None,
                admission.as_ref(),
            );
            assert!(matches!(
                host.process(
                    &tx,
                    &mut ledger,
                    &mut state,
                    |h| Ok(blobs.get(h).cloned()),
                    |_| panic!("replay persisted key")
                )
                .unwrap(),
                epoch_execution::Effect::Rejected(_)
            ));
            assert_eq!(ledger.account(payer), Some(&before));
        }
        drop(publisher);
        drop(store);
        let cold = Arc::new(CanonicalStore::open(&path, &chain).await.unwrap());
        let audited = Publisher::open(cold.clone(), authority).await.unwrap();
        let (head, state) = cold.snapshot().await.unwrap();
        assert_eq!(
            head.cursor.sequence.0,
            if case["published"].is_null() { 2 } else { 3 }
        );
        let expected = if case["published"].is_null() {
            &case["before"]
        } else {
            &case["after"]
        };
        matches_snapshot(&state, expected);
        let key_hash = state.get(&[b"pvac_hashes", payer]).unwrap();
        let public =
            std::fs::read(blob_dir.join(format!("{}.pk", std::str::from_utf8(key_hash).unwrap())))
                .unwrap();
        assert_eq!(hash(&public), key_hash);
        assert_eq!(
            public,
            if case["published"].is_null() {
                old.clone()
            } else {
                new.clone()
            }
        );
        drop(audited);
        drop(cold);
    }
    assert_eq!(positives, 2);
}
