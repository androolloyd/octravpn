#[path = "common/circle_host.rs"]
#[allow(dead_code)] // This suite uses the shared runtime/fixture without install_counter.
mod host;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    state::{Account, Ledger},
    transaction::{Nonce, OpType, RuleMode, Transaction},
};
use octra_node_runtime::{
    account_store,
    circle::WasmRules,
    circle_transaction::{self, Rules},
    execution::{Completion, Executed, Outcome},
    state_batch::StateBatch,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn encoded(bytes: &[u8]) -> Value {
    json!(STANDARD.encode(bytes))
}
fn optional(value: &Value) -> Option<Vec<u8>> {
    (!value.is_null()).then(|| bytes(value))
}
fn tx(index: usize, value: &Value) -> Transaction {
    Transaction {
        from: bytes(&value["from"]),
        to: bytes(&value["to"]),
        amount: value["amount"].as_str().unwrap().parse().unwrap(),
        nonce: Nonce::new(value["nonce"].as_i64().unwrap()).unwrap(),
        ou: value["ou"].as_str().unwrap().parse().unwrap(),
        timestamp: 1.,
        signature: index.to_string().into_bytes(),
        public_key: None,
        message: optional(&value["params"]),
        encrypted_data: optional(&value["method"]),
        op_type: OpType::CircleCall,
    }
}
fn event(event: &Executed) -> Value {
    let value = match &event.outcome {
        Outcome::NonceMismatch { expected, got } => json!({"mismatch":[expected.get(),got.get()]}),
        Outcome::Completed(Completion::Confirmed { .. }) => json!("confirmed"),
        Outcome::Completed(Completion::Rejected(r)) => {
            json!({"rejected":{"tag":r.tag,"reason":encoded(&r.reason),"notify":r.notify_reason.as_ref().map(|s|encoded(s)),"consume":r.consume_nonce,"persist":r.persist_state}})
        }
        Outcome::Completed(Completion::Deferred { .. }) => {
            panic!("unexpected deferred Circle transaction")
        }
    };
    json!({"index":event.input_index,"outcome":value})
}
fn setup(input: &Value, fixture: &Value) -> (StateBatch, Ledger, Vec<Transaction>) {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    for e in input["entries"].as_array().unwrap() {
        let path = e["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect::<Vec<_>>();
        state
            .set(
                &path.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                bytes(&e["value"]),
            )
            .unwrap();
    }
    let circle = input["circle"].as_str().unwrap().as_bytes();
    state
        .set(
            &[b"circles", circle, b"program", b"code_b64"],
            fixture["wasm_b64"].as_str().unwrap().as_bytes().to_vec(),
        )
        .unwrap();
    state
        .set(
            &[b"circles", circle, b"code_hash"],
            fixture["wasm_sha256"].as_str().unwrap().as_bytes().to_vec(),
        )
        .unwrap();
    let accounts: BTreeMap<_, _> = input["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                bytes(&v["address"]),
                Account {
                    balance: v["balance"].as_str().unwrap().parse().unwrap(),
                    nonce: Nonce::new(v["nonce"].as_i64().unwrap()).unwrap(),
                    ..Account::default()
                },
            )
        })
        .collect();
    for (address, account) in &accounts {
        account_store::set(&mut state, address, account, RuleMode::Prior).unwrap();
    }
    let ledger = Ledger::from_accounts(accounts).unwrap();
    let transactions = input["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, v)| tx(i, v))
        .collect();
    (state, ledger, transactions)
}
fn rules(input: &Value) -> Rules {
    Rules {
        manifest: if input["wasm_compute"] == false {
            octra_node_runtime::circle::WasmProfile::Compute
        } else {
            octra_node_runtime::circle::WasmProfile::Manifest
        },
        update_policy: input["circle_policy"] == true,
        wasm: WasmRules {
            proof_exec: input["proof"].as_bool().unwrap(),
            wasm_float: input["float"].as_bool().unwrap(),
            math: input["math"].as_bool().unwrap(),
        },
        inspect: input["inspect"].as_bool().unwrap(),
        storage_proof: input["storage_proof"].as_bool().unwrap(),
        fhe_work: input["fhe_work"] == true,
    }
}
#[test]
fn native_bft_circle_epochs_match_production_processor_roots_and_receipts() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/epoch-circle.json")).unwrap();
    assert_eq!(
        fixture["guest_source_sha256"],
        host::fixture()["guest_source_sha256"]
    );
    assert_bft_epochs(&fixture);
}

#[test]
fn native_circle_activation_refuses_nonpersistent_imports_in_updates() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/circle-policy.json")).unwrap();
    assert_eq!(
        fixture["guest_source_sha256"],
        json!({"scripts/node-port/circle-policy-guest.rs":hex::encode(Sha256::digest(include_bytes!("../../../scripts/node-port/circle-policy-guest.rs")))})
    );
    assert_bft_epochs(&fixture);
}

fn assert_bft_epochs(fixture: &Value) {
    use octra_node_protocol::{
        emission::Schedule,
        epoch_rewards::{Attribution, Validator},
        transaction_outcome,
        validator::policy::Policy,
    };
    use octra_node_runtime::{
        epoch_execution::{self, Request},
        epoch_footer, validator_epoch,
    };
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/epoch-circle-oracle.ml"
        )))
    );
    assert_eq!(
        fixture["runner_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/native-oracle.py"
        )))
    );
    assert_eq!(
        fixture["wasm_sha256"],
        hex::encode(Sha256::digest(bytes(&fixture["wasm_b64"])))
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let (mut state, mut ledger, transactions) = setup(input, fixture);
        state
            .set(
                &[b"meta", b"total_supply"],
                ledger.total_supply().to_string().into_bytes(),
            )
            .unwrap();
        state
            .set(&[b"meta", b"emission_remaining"], b"0".to_vec())
            .unwrap();
        let before = hex::encode(state.root().unwrap());
        state.acknowledge_commit().unwrap();
        state.begin().unwrap();
        let committed = state.snapshot();
        let runtime = host::runtime();
        let epoch = input["epoch"].as_i64().unwrap();
        let mut calls = circle_transaction::Calls::new(
            &runtime,
            rules(input),
            epoch,
            input["now"].as_f64().unwrap(),
            before.as_bytes(),
            circle_transaction::Verification::Direct,
        );
        let emission = epoch_footer::Policy {
            emission_guard: true,
            schedule: Schedule::Inactive,
            legacy_total: None,
        };
        let addr = format!("oct{}", "4".repeat(44)).into_bytes();
        let reward = Attribution {
            proposer: addr.clone(),
            proposer_public_key: None,
            validators: vec![Validator {
                address: addr.clone(),
                public_key: None,
                weight: 1.into(),
            }],
        };
        let fold = |_: i64, _: &StateBatch| {
            Ok(validator_epoch::Fold {
                vm_bytes: if input["inspect"] == true {
                    RuleMode::Active
                } else {
                    RuleMode::Prior
                },
                proof_exec: if input["proof"] == true {
                    RuleMode::Active
                } else {
                    RuleMode::Prior
                },
                ..validator_epoch::Fold::prior()
            })
        };
        let result = epoch_execution::execute(
            &Request {
                validators: validator_epoch::Request {
                    chain: b"epoch-circle-fixture",
                    epoch,
                    policy: &Policy::Inactive,
                    legacy_members: &[addr],
                    previous_root: before.as_bytes(),
                    committed_head: Some(&committed),
                },
                envelope: transaction_outcome::Rules {
                    envelope: RuleMode::Prior,
                    compute: RuleMode::Prior,
                    settle: RuleMode::Prior,
                },
                sender_key_activation: Some(0),
                preverification: None,
                emission: &emission,
                reward: &reward,
                validator_keys: &[],
            },
            &fold,
            &transactions,
            &mut ledger,
            &mut state,
            |tx, ledger, state| calls.process(tx, ledger, state),
        );
        let result = match result {
            Ok(result) => {
                json!({"fees":result.artifacts.confirmed_fees.to_string(),"confirmed":result.artifacts.confirmed,"rejected":result.artifacts.rejected.iter().map(|r|json!({"index":r.input_index,"type":encoded(&r.refusal.error_type),"reason":encoded(&r.refusal.reason),"charged":r.charged})).collect::<Vec<_>>() })
            }
            Err(e) => json!({"error":format!("Failure({:?})",e.0)}),
        };
        let actual = json!({"before":before,"result":result,"root":hex::encode(state.root().unwrap()),"receipts":calls.receipts().iter().map(|(k,v)|json!([k,encoded(v)])).collect::<Vec<_>>(),"accounts":ledger.accounts().iter().map(|(a,v)|json!([encoded(a),encoded(&v.to_json_bytes())])).collect::<Vec<_>>(),"supply":ledger.total_supply().to_string(),"spent":ledger.spent_nonces().len(),"journal":ledger.journal_active()});
        assert_eq!(actual, case["expected"], "native BFT Circle epoch {index}");
    }
}
#[test]
fn native_circle_transactions_match_fees_nonces_value_rollback_and_vm_receipts() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/circle-transaction.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/circle-transaction-oracle.ml"
        )))
    );
    assert_eq!(
        fixture["wasm_sha256"],
        hex::encode(Sha256::digest(bytes(&fixture["wasm_b64"])))
    );
    assert_eq!(
        fixture["guest_source_sha256"],
        host::fixture()["guest_source_sha256"]
    );
    for (i, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let (mut state, mut ledger, transactions) = setup(input, &fixture);
        let before = hex::encode(state.root().unwrap());
        let batch = circle_transaction::execute(
            &host::runtime(),
            rules(input),
            input["epoch"].as_i64().unwrap(),
            input["now"].as_f64().unwrap(),
            &transactions,
            &mut ledger,
            &mut state,
        )
        .unwrap_or_else(|e| panic!("case {i}: {e}"));
        let actual = json!({"before":before,"root":hex::encode(state.root().unwrap()),"events":batch.outcomes.iter().map(event).collect::<Vec<_>>(),"fees":batch.fees.to_string(),"receipts":batch.receipts.iter().map(|(k,v)|json!([k,encoded(v)])).collect::<Vec<_>>(),"accounts":ledger.accounts().iter().map(|(a,v)|json!([encoded(a),encoded(&v.to_json_bytes())])).collect::<Vec<_>>(),"supply":ledger.total_supply().to_string(),"active":ledger.active_accounts(),"spent":ledger.spent_nonces().iter().map(|(a,n)|json!([encoded(a),n.get()])).collect::<Vec<_>>(),"journal":ledger.journal_active()});
        assert_eq!(
            actual, case["expected"],
            "native Circle transaction case {i}"
        );
    }
}
#[test]
fn missing_operation_or_parameter_capability_rolls_back_the_entire_attempt() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/circle-transaction.json")).unwrap();
    let mut input = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["expected"]["events"][0]["outcome"] == "confirmed"
                && c["input"]["transactions"].as_array().unwrap().len() == 1
        })
        .unwrap()["input"]
        .clone();
    // Fund the whole attempt so a second fee debit cannot mask the deliberately
    // unavailable operation. The native parity cases above remain unmodified.
    for account in input["accounts"].as_array_mut().unwrap() {
        account["balance"] = json!("1000000000000");
    }
    for op in [OpType::CircleCall, OpType::ContractCall] {
        let (mut state, mut ledger, mut transactions) = setup(&input, &fixture);
        let before = state.root().unwrap();
        let accounts = ledger.accounts().clone();
        let supply = ledger.total_supply().clone();
        let mut unavailable = transactions[0].clone();
        unavailable.nonce = unavailable.nonce.successor();
        unavailable.op_type = op;
        unavailable.message = Some(b"{".to_vec());
        transactions.push(unavailable);
        assert!(circle_transaction::execute(
            &host::runtime(),
            rules(&input),
            3,
            123.5,
            &transactions,
            &mut ledger,
            &mut state
        )
        .is_err());
        assert_eq!(state.root().unwrap(), before);
        assert_eq!(*ledger.accounts(), accounts);
        assert_eq!(*ledger.total_supply(), supply);
        assert!(ledger.spent_nonces().is_empty());
        assert!(!ledger.journal_active());
    }
}

#[test]
fn receipt_replay_checks_snapshot_and_execution_binding_before_staging_effects() {
    use circle_transaction::Verification;
    use octra_node_protocol::{
        preverify_commit::Gate,
        preverify_receipt::{Binding, Receipt},
    };
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/circle-transaction.json")).unwrap();
    let input = &fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["expected"]["events"][0]["outcome"] == "confirmed"
                && c["input"]["transactions"].as_array().unwrap().len() == 1
        })
        .unwrap()["input"];
    let (mut captured, mut captured_ledger, txs) = setup(input, &fixture);
    let root = hex::encode(captured.root().unwrap());
    let batch = circle_transaction::execute_verified(
        &host::runtime(),
        rules(input),
        3,
        123.5,
        &txs,
        &mut captured_ledger,
        &mut captured,
        Verification::Capture,
    )
    .unwrap();
    let binding = batch.bindings[&hex::encode(txs[0].hash().unwrap())].at_snapshot(root.as_bytes());
    for mutation in [
        "none", "snapshot", "circle", "code", "stable", "reads", "context", "missing",
    ] {
        let (mut state, mut ledger, txs) = setup(input, &fixture);
        let before = state.root().unwrap();
        let accounts = ledger.accounts().clone();
        let supply = ledger.total_supply().clone();
        let mut changed = binding.clone();
        let wrong = vec![b'a'; 64];
        match mutation {
            "snapshot" => changed.snapshot_hash = wrong,
            "circle" => changed.circle_id = format!("oct{}", "9".repeat(44)).into_bytes(),
            "code" => changed.code_hash = wrong,
            "stable" => changed.stable_root = wrong,
            "reads" => changed.public_reads_hash = wrong,
            "context" => changed.context_hash = wrong,
            _ => (),
        }
        let bound = Binding::Circle(changed);
        let receipt = Receipt::for_tx(
            &txs[0],
            bound.clone(),
            bound.input_hash(&txs[0]).unwrap(),
            bound.output_hash(&txs[0], b"ok").unwrap(),
            true,
            vec![],
            &5000.into(),
        )
        .unwrap();
        let gate = Gate {
            receipts: if mutation == "missing" {
                vec![]
            } else {
                vec![receipt]
            },
        };
        if mutation != "missing" {
            gate.check(&txs, false, &5000.into()).unwrap();
        }
        let result = circle_transaction::execute_verified(
            &host::runtime(),
            rules(input),
            3,
            123.5,
            &txs,
            &mut ledger,
            &mut state,
            Verification::Consume {
                root: root.as_bytes(),
                gate: &gate,
            },
        );
        if mutation == "none" {
            assert_eq!(result.unwrap().bindings, batch.bindings);
            assert_eq!(state.root().unwrap(), captured.root().unwrap());
            assert_eq!(ledger.accounts(), captured_ledger.accounts());
        } else {
            assert!(result.is_err(), "accepted changed {mutation}");
            assert_eq!(state.root().unwrap(), before);
            assert_eq!(*ledger.accounts(), accounts);
            assert_eq!(*ledger.total_supply(), supply);
            assert!(ledger.spent_nonces().is_empty());
            assert!(!ledger.journal_active());
        }
    }
}
