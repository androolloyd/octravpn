use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use octra_node_protocol::{
    emission::Schedule,
    epoch_rewards::{Attribution, Validator},
    native_json::Document,
    rules::{self, Rule},
    transaction::{address_from_public_key, RuleMode, Transaction},
    transaction_outcome,
    validator::policy::{self, Active, Policy},
};
use octra_node_runtime::{
    account_store,
    epoch_execution::{self, Effect, Refusal, Request},
    epoch_footer,
    execution::{Error, OperationHost},
    state_batch::StateBatch,
    validator_epoch,
    validator_transaction::{self, Fold, ReadyEnvironment},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn raw(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn address(id: u8) -> Vec<u8> {
    address_from_public_key(
        STANDARD
            .encode(SigningKey::from_bytes(&[id; 32]).verifying_key().to_bytes())
            .as_bytes(),
    )
}
fn mode(active: &Value) -> RuleMode {
    if *active == true {
        RuleMode::Active
    } else {
        RuleMode::Prior
    }
}
fn transaction(raw: &[u8]) -> Transaction {
    // The native low-level oracle constructs negative money inputs, which both
    // network decoders reject. Preserve those direct-call probes here.
    let mut value: Value = serde_json::from_slice(raw).unwrap();
    let amount = value["amount"].as_str().unwrap().parse().unwrap();
    let ou = value["ou"].as_str().unwrap().parse().unwrap();
    value["amount"] = json!("0");
    value["ou"] = json!("0");
    let mut tx =
        Transaction::from_document(&Document::parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .unwrap();
    tx.amount = amount;
    tx.ou = ou;
    assert_eq!(tx.to_json_bytes().unwrap(), raw);
    tx
}
#[test]
fn native_bft_epoch_effects_roots_keys_rewards_and_atomic_failure() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/epoch-execution.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/epoch-execution-oracle.ml"
        )))
    );
    assert_eq!(
        fixture["runner_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/native-oracle.py"
        )))
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let expected = &case["expected"];
        let mut state = StateBatch::default();
        state.begin().unwrap();
        for row in expected["initial_accounts"].as_array().unwrap() {
            state
                .set(&[b"accounts", &raw(&row[0]), b"data"], raw(&row[1]))
                .unwrap();
        }
        for row in input["meta"].as_array().unwrap() {
            state
                .set(
                    &[b"meta", row[0].as_str().unwrap().as_bytes()],
                    row[1].as_str().unwrap().as_bytes().to_vec(),
                )
                .unwrap();
        }
        let before = hex::encode(state.root().unwrap());
        assert_eq!(before, expected["before"], "initial tree {index}");
        state.acknowledge_commit().unwrap();
        state.begin().unwrap();
        let committed = state.snapshot();
        let mut ledger = account_store::ledger(&state).unwrap();
        let txs = expected["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| transaction(&raw(v)))
            .collect::<Vec<_>>();
        let epoch = input["epoch"].as_i64().unwrap();
        let chain = input["chain"].as_str().unwrap().as_bytes();
        let fold = |_: i64, _: &StateBatch| {
            if input["fold_fail"] == true {
                return Err(Error("fixture anchor unavailable".into()));
            }
            Ok(Fold {
                account_mode: mode(&input["packed"]),
                vm_bytes: mode(&input["vm"]),
                ..Fold::prior()
            })
        };
        let policy = if input["bonded"] == true {
            Policy::Bonded(Active {
                activation_epoch: 64,
                parameters: policy::parameters(),
                snapshot_interval: 64,
                evidence_epochs: 86400,
            })
        } else {
            Policy::Inactive
        };
        let emission = epoch_footer::Policy {
            emission_guard: input["guard"] == true,
            schedule: Schedule::Inactive,
            legacy_total: None,
        };
        let reward = Attribution {
            proposer: address(4),
            proposer_public_key: None,
            validators: vec![Validator {
                address: address(4),
                public_key: None,
                weight: 1.into(),
            }],
        };
        let members = [address(4)];
        let request = Request {
            validators: validator_epoch::Request {
                chain,
                epoch,
                policy: &policy,
                legacy_members: &members,
                previous_root: before.as_bytes(),
                committed_head: Some(&committed),
            },
            envelope: transaction_outcome::Rules {
                envelope: rules::at(chain, Rule::TxEnvelope, epoch),
                compute: rules::at(chain, Rule::VmBytes, epoch),
                settle: rules::at(chain, Rule::Settle, epoch),
            },
            sender_key_activation: input["key_activation"].as_i64(),
            preverification: None,
            emission: &emission,
            reward: &reward,
            validator_keys: &[],
        };
        let mut validator = validator_transaction::Host {
            chain,
            epoch,
            policy: &policy,
            fold,
            ready: ReadyEnvironment {
                prev_state_root: before.as_bytes(),
                max_lag: 2,
                root_at: None,
            },
        };
        let result = epoch_execution::execute(
            &request,
            &fold,
            &txs,
            &mut ledger,
            &mut state,
            |tx, ledger, state| {
                let position = txs.iter().position(|t| t == tx).unwrap();
                if let Some(fault) = input["transactions"][position]["fault"].as_str() {
                    if let Err(e) = ledger.debit(&tx.from, &tx.ou, tx.nonce, None) {
                        return Ok(Effect::Rejected(Refusal {
                            error_type: b"insufficient_balance".to_vec(),
                            reason: e.0.into_bytes(),
                        }));
                    }
                    state
                        .set(
                            &[b"meta", b"fixture_effect"],
                            hex::encode(tx.hash().unwrap()).into_bytes(),
                        )
                        .unwrap();
                    return match fault {
                        "abort" => Err(Error("fixture operation unavailable".into())),
                        "reject" => Ok(Effect::Rejected(Refusal {
                            error_type: b"fixture_refusal".to_vec(),
                            reason: b"after write".to_vec(),
                        })),
                        "charged" => Ok(Effect::RejectedAfterFee {
                            fee: tx.ou.clone(),
                            refusal: Refusal {
                                error_type: b"fixture_charged".to_vec(),
                                reason: b"after fee".to_vec(),
                            },
                        }),
                        _ => panic!("unknown fault"),
                    };
                }
                let route = octra_node_runtime::execution::route(tx);
                if route == octra_node_runtime::execution::Route::Validator {
                    Effect::from_completion(tx, validator.execute(route, tx, ledger, state)?)
                } else {
                    epoch_execution::public(tx, ledger, state)
                }
            },
        );
        let result = match result {
            Ok(result) => {
                json!({"root":hex::encode(result.root),"fees":result.artifacts.confirmed_fees.to_string(),"count":result.artifacts.transaction_count,
                "confirmed":result.artifacts.confirmed,"rejected":result.artifacts.rejected.iter().map(|r| json!({"index":r.input_index,"type":STANDARD.encode(&r.refusal.error_type),"reason":STANDARD.encode(&r.refusal.reason),"charged":r.charged})).collect::<Vec<_>>()})
            }
            // Native wraps raised operational errors with Printexc.to_string;
            // envelope refusal is returned directly. No rejection data is normalized.
            Err(e) => {
                json!({"error": if e.0.starts_with("transaction envelope:") { e.0 } else { format!("Failure({:?})",e.0) }})
            }
        };
        assert_eq!(result, expected["result"], "epoch result {index}");
        assert_eq!(
            hex::encode(state.root().unwrap()),
            expected["root"],
            "state root {index}"
        );
        assert_eq!(
            ledger.total_supply().to_string(),
            expected["supply"],
            "supply {index}"
        );
        let accounts = ledger
            .accounts()
            .iter()
            .map(|(address, account)| {
                json!([
                    STANDARD.encode(address),
                    STANDARD.encode(account.to_json_bytes())
                ])
            })
            .collect::<Vec<_>>();
        assert_eq!(
            json!(accounts),
            expected["accounts"],
            "ledger accounts {index}"
        );
        assert_eq!(
            json!(ledger.spent_nonces().len()),
            expected["spent"],
            "spent nonces {index}"
        );
        assert_eq!(
            json!(ledger.journal_active()),
            expected["journal"],
            "journal {index}"
        );
    }
}
