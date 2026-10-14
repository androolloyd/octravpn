use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    native_json::Document,
    transaction::{RuleMode, Transaction},
    transaction_outcome::{self as outcome, Rules},
};
use octra_node_runtime::{
    epoch_execution::{Artifacts, Refusal, Rejected},
    epoch_partition::Partition,
    execution::Error,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn mode(v: &Value) -> RuleMode {
    if v == true {
        RuleMode::Active
    } else {
        RuleMode::Prior
    }
}

#[test]
fn native_finalized_selection_and_candidate_partition_refusals() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/epoch-partition.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (name, data) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/epoch-partition-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/epoch-partition-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
        (
            "artifact_fixture_sha256",
            include_bytes!("fixtures/epoch-execution.json").as_slice(),
        ),
    ] {
        assert_eq!(fixture[name], hex::encode(Sha256::digest(data)), "{name}");
    }
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let expected = &case["expected"];
        let txs = input["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| {
                Transaction::from_document(
                    &Document::parse(&bytes(
                        &fixture["transaction_pool"][id.as_u64().unwrap() as usize],
                    ))
                    .unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let confirmed = input["confirmed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| txs[id.as_u64().unwrap() as usize].clone())
            .collect::<Vec<_>>();
        let rejected = input["rejected"].as_array().unwrap();
        let rejections = outcome::build(
            &txs,
            &rejected
                .iter()
                .map(|r| {
                    (
                        txs[r["index"].as_u64().unwrap() as usize].clone(),
                        bytes(&r["type"]),
                        bytes(&r["reason"]),
                    )
                })
                .collect::<Vec<_>>(),
            &rejected
                .iter()
                .filter(|r| r["charged"] == true)
                .map(|r| txs[r["index"].as_u64().unwrap() as usize].clone())
                .collect::<Vec<_>>(),
        );
        let partition = rejections
            .map_err(|e| Error(e.to_string()))
            .and_then(|rejections| {
                if input["finalized"] == true {
                    Partition::finalized(
                        &confirmed,
                        &rejections,
                        Rules {
                            envelope: mode(&input["envelope"]),
                            compute: mode(&input["compute"]),
                            settle: mode(&input["settle"]),
                        },
                    )
                } else {
                    Partition::candidates(&confirmed, &rejections)
                }
            });
        let partition = match partition {
            Err(e) => {
                assert_eq!(json!({"error":e.0}), *expected, "prepare {index}");
                continue;
            }
            Ok(p) => {
                assert!(expected["error"].is_null(), "prepare {index}");
                p
            }
        };
        assert_eq!(
            json!(partition
                .transactions()
                .iter()
                .map(|tx| hex::encode(tx.hash().unwrap()))
                .collect::<Vec<_>>()),
            expected["inputs"],
            "inputs {index}"
        );
        let artifacts = Artifacts {
            confirmed: expected["actual_confirmed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| {
                    (
                        r[0].as_u64().unwrap() as usize,
                        r[1].as_u64().unwrap() as usize,
                    )
                })
                .collect(),
            rejected: expected["actual_rejected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| Rejected {
                    input_index: r["index"].as_u64().unwrap() as usize,
                    refusal: Refusal {
                        error_type: bytes(&r["type"]),
                        reason: bytes(&r["reason"]),
                    },
                    charged: r["charged"].as_bool().unwrap(),
                })
                .collect(),
            ..Artifacts::default()
        };
        let error = Error("operation unavailable".into());
        let result = partition.verify(if input["mutation"] == "error" {
            Err(&error)
        } else {
            Ok(&artifacts)
        });
        assert_eq!(
            result.err().map_or("ok".into(), |e| e.0),
            expected["verify"].as_str().unwrap(),
            "verify {index}"
        );
    }
}

#[test]
fn finalized_replay_excludes_vm_fees_and_atomically_checks_charged_outcomes() {
    use ed25519_dalek::{Signer, SigningKey};
    use octra_node_protocol::{
        emission::Schedule,
        epoch_rewards::{Attribution, Validator},
        state::Account,
        transaction::{address_from_public_key, Nonce, OpType},
        validator::policy::Policy,
    };
    use octra_node_runtime::{
        account_store,
        epoch_execution::{self, Effect, Request},
        epoch_footer,
        state_batch::StateBatch,
        validator_epoch,
    };
    let key = SigningKey::from_bytes(&[42; 32]);
    let public = STANDARD.encode(key.verifying_key().to_bytes()).into_bytes();
    let sender = address_from_public_key(&public);
    let tx = |op_type, nonce, amount: i64| {
        let mut tx = Transaction {
            from: sender.clone(),
            to: b"receiver".to_vec(),
            amount: amount.into(),
            nonce: Nonce::new(nonce).unwrap(),
            ou: 7.into(),
            timestamp: 1.,
            signature: vec![],
            public_key: Some(public.clone()),
            message: None,
            encrypted_data: None,
            op_type,
        };
        tx.signature = STANDARD
            .encode(key.sign(&tx.signing_bytes().unwrap()).to_bytes())
            .into_bytes();
        tx
    };
    let mut ordinary = tx(OpType::CircleCall, 1, 0i64);
    let other = (0u8..=255)
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .find(|key| {
            address_from_public_key(STANDARD.encode(key.verifying_key().to_bytes()).as_bytes())
                < sender
        })
        .unwrap();
    let other_public = STANDARD
        .encode(other.verifying_key().to_bytes())
        .into_bytes();
    ordinary.from = address_from_public_key(&other_public);
    ordinary.public_key = Some(other_public);
    ordinary.signature = STANDARD
        .encode(other.sign(&ordinary.signing_bytes().unwrap()).to_bytes())
        .into_bytes();
    let charged = tx(OpType::ComputeFund, 1, 0);
    let confirmed = tx(OpType::Standard, 2, 100);
    let inputs = [ordinary.clone(), charged.clone(), confirmed.clone()];
    let rejections = outcome::build(
        &inputs,
        &[
            (
                ordinary.clone(),
                b"vm_failed".to_vec(),
                b"ignored preview fee".to_vec(),
            ),
            (
                charged.clone(),
                b"compute_failed".to_vec(),
                b"charged".to_vec(),
            ),
        ],
        std::slice::from_ref(&charged),
    )
    .unwrap();
    let envelope = Rules {
        envelope: RuleMode::Active,
        compute: RuleMode::Active,
        settle: RuleMode::Prior,
    };
    let partition =
        Partition::finalized(std::slice::from_ref(&confirmed), &rejections, envelope).unwrap();
    assert_eq!(partition.transactions(), &[charged, confirmed]);
    let mut original = StateBatch::default();
    original.begin().unwrap();
    account_store::set(
        &mut original,
        &sender,
        &Account {
            balance: 1000.into(),
            ..Account::default()
        },
        RuleMode::Prior,
    )
    .unwrap();
    original
        .set(&[b"meta", b"total_supply"], b"1000".to_vec())
        .unwrap();
    original
        .set(&[b"meta", b"emission_remaining"], b"0".to_vec())
        .unwrap();
    original.acknowledge_commit().unwrap();
    let before = original.snapshot();
    let previous = hex::encode(before.root().unwrap());
    let emission = epoch_footer::Policy {
        emission_guard: true,
        schedule: Schedule::Inactive,
        legacy_total: None,
    };
    let reward = Attribution {
        proposer: b"reward".to_vec(),
        proposer_public_key: None,
        validators: vec![Validator {
            address: b"reward".to_vec(),
            public_key: None,
            weight: 1.into(),
        }],
    };
    let request = Request {
        validators: validator_epoch::Request {
            chain: b"partition-fixture",
            epoch: 1,
            policy: &Policy::Inactive,
            legacy_members: &[],
            previous_root: previous.as_bytes(),
            committed_head: Some(&before),
        },
        envelope,
        sender_key_activation: Some(0),
        preverification: None,
        emission: &emission,
        reward: &reward,
        validator_keys: &[],
    };
    let fold = |_: i64, _: &StateBatch| {
        Ok(validator_epoch::Fold {
            vm_bytes: RuleMode::Active,
            account_mode: RuleMode::Active,
            ..validator_epoch::Fold::prior()
        })
    };
    // Charged operation effects below are deliberately controlled: this tests
    // the atomic replay boundary, not a compute-transfer implementation.
    for fault in ["none", "confirmation", "reason", "abort", "panic"] {
        let mut state = original.clone();
        state.begin().unwrap();
        let mut ledger = account_store::ledger(&state).unwrap();
        let accounts = ledger.accounts().clone();
        ledger.begin_journal();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            partition.execute(
                &request,
                &fold,
                &mut ledger,
                &mut state,
                |tx, ledger, state| {
                    assert_ne!(
                        tx.hash().unwrap(),
                        ordinary.hash().unwrap(),
                        "ordinary refusal must not execute or charge fees"
                    );
                    if tx.op_type == OpType::ComputeFund {
                        ledger.debit(&tx.from, &tx.ou, tx.nonce, None).unwrap();
                        state
                            .set(&[b"fixture", b"charged"], b"yes".to_vec())
                            .unwrap();
                        if fault == "confirmation" {
                            return Ok(Effect::Confirmed(tx.ou.clone()));
                        }
                        return Ok(Effect::RejectedAfterFee {
                            fee: tx.ou.clone(),
                            refusal: Refusal {
                                error_type: b"compute_failed".to_vec(),
                                reason: if fault == "reason" {
                                    b"wrong".to_vec()
                                } else {
                                    b"charged".to_vec()
                                },
                            },
                        });
                    }
                    let effect = epoch_execution::public(tx, ledger, state)?;
                    match fault {
                        "abort" => Err(Error("operation unavailable".into())),
                        "panic" => panic!("operation panic"),
                        _ => Ok(effect),
                    }
                },
            )
        }));
        if fault == "none" {
            let executed = result.unwrap().unwrap();
            assert_eq!(executed.artifacts.confirmed_fees, 14.into());
            assert_eq!(executed.artifacts.transaction_count, 2);
            assert_eq!(ledger.account(&sender).unwrap().balance, 886.into());
            assert_eq!(ledger.account(b"receiver").unwrap().balance, 100.into());
            assert_eq!(
                ledger.account(&sender).unwrap().public_key,
                Some(public.clone())
            );
            assert_eq!(
                state.get(&[b"fixture", b"charged"]),
                Some(b"yes".as_slice())
            );
            assert_ne!(state.root().unwrap(), before.root().unwrap());
        } else {
            let expected = match fault {
                "confirmation" => "preview_confirmed_mismatch",
                "reason" => "preview_rejection_mismatch",
                _ => "operation unavailable",
            };
            if fault == "panic" {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap().err().unwrap().0, expected);
            }
            assert_eq!(state.root().unwrap(), before.root().unwrap(), "{fault}");
            assert_eq!(*ledger.accounts(), accounts, "{fault}");
            assert_eq!(ledger.total_supply(), &1000.into());
            assert!(!ledger.is_dirty());
        }
        assert_eq!(state.published_root().unwrap(), before.root().unwrap());
        assert_eq!(ledger.journal_depth(), 1, "the caller's journal survives");
        assert!(ledger.spent_nonces().is_empty());
        ledger.abort_journal();
        assert_eq!(*ledger.accounts(), accounts);
    }
}
