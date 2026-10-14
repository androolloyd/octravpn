use base64::{engine::general_purpose::STANDARD, Engine};
use octra_hfhe::scalar::ScalarRule;
use octra_node_protocol::{
    state::{Account, Ledger},
    transaction::{Nonce, OpType, RuleMode, Transaction},
};
use octra_node_runtime::{
    account_store,
    private_balance::{self as balance, Error, Failure, Profile},
    private_crypto::ResultPolicy,
    state_batch::StateBatch,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn failure(e: Failure) -> Value {
    json!({"tag":e.tag,"reason":STANDARD.encode(e.reason),"user_reason":STANDARD.encode(e.user_reason)})
}
fn rejected(error: Error) -> Value {
    match error {
        Error::Rejected(e) => failure(e),
        other @ Error::Unavailable(_) => panic!("{other}"),
    }
}
fn state(ledger: &Ledger, nonce: Nonce) -> Value {
    json!({"account":ledger.accounts().get(b"alice".as_slice()).map(|a|STANDARD.encode(a.to_json_bytes())),"supply":ledger.total_supply().to_string(),"spent":ledger.spent_nonces().contains(&(b"alice".to_vec(),nonce))})
}
#[test]
fn native_verified_plans_account_roots_and_rollback() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/private-balance.json")).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inventory: Value = serde_json::from_slice(
        &std::fs::read(root.join("docs/rust-node/source-map.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (key, name) in [
        ("oracle_sha256", "private-balance-oracle.ml"),
        ("runner_sha256", "native-oracle.py"),
        ("generator_sha256", "private-balance-fixtures.py"),
    ] {
        assert_eq!(
            fixture[key],
            hex::encode(Sha256::digest(
                std::fs::read(root.join("scripts/node-port").join(name)).unwrap()
            ))
        );
    }
    let mut confirmed = 0;
    let mut rollback = 0;
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let current = bytes(&input["current"]);
        let account = Account {
            balance: input["balance"].as_str().unwrap().parse().unwrap(),
            encrypted_balance: (current != b"0").then_some(current),
            ..Account::default()
        };
        let mut store = StateBatch::default();
        store.begin().unwrap();
        account_store::set(&mut store, b"alice", &account, RuleMode::Prior).unwrap();
        let public = input["public"].as_str().map(|_| bytes(&input["public"]));
        if let Some(public) = &public {
            store
                .set(
                    &[b"pvac_hashes", b"alice"],
                    hex::encode(Sha256::digest(public)).into_bytes(),
                )
                .unwrap();
        }
        let mut ledger = Ledger::from_accounts([(b"alice".to_vec(), account)].into()).unwrap();
        let nonce = Nonce::new(input["nonce"].as_i64().unwrap()).unwrap();
        let tx = Transaction {
            from: b"alice".to_vec(),
            to: b"alice".to_vec(),
            amount: input["amount"].as_str().unwrap().parse().unwrap(),
            nonce,
            ou: input["fee"].as_str().unwrap().parse().unwrap(),
            timestamp: 1.,
            signature: b"fixture".to_vec(),
            public_key: None,
            message: None,
            op_type: if input["withdraw"] == true {
                OpType::Decrypt
            } else {
                OpType::Encrypt
            },
            encrypted_data: input["payload"].as_str().map(|_| bytes(&input["payload"])),
        };
        let profile = Profile {
            fields: if input["unique"] == true {
                RuleMode::Active
            } else {
                RuleMode::Prior
            },
            strict: input["strict"].as_bool().unwrap(),
            math: ScalarRule::Wide,
            result: if input["recoverable"] == true {
                ResultPolicy::Recoverable
            } else {
                ResultPolicy::Legacy
            },
        };
        let before = state(&ledger, nonce);
        let outcome = match balance::verify(&ledger, &tx, public.as_deref(), profile) {
            Err(e) => json!({"error":rejected(e)}),
            Ok(plan) => {
                let mut substitution = tx.clone();
                substitution.amount += 1;
                assert!(matches!(
                    plan.apply(&mut ledger, &substitution),
                    Err(Error::Unavailable(_))
                ));
                assert_eq!(state(&ledger, nonce), before);
                let prepared = json!({"current":STANDARD.encode(plan.current_cipher()),"next":STANDARD.encode(plan.next_cipher()),"hash":plan.transition_hash()});
                if input["stale"] == true {
                    ledger.update_encrypted_balance(b"alice", b"0".to_vec());
                }
                let checkpoint = state(&ledger, nonce);
                let applied = match plan.apply(&mut ledger, &tx) {
                    Ok(()) => {
                        confirmed += 1;
                        let committed = state(&ledger, nonce);
                        assert!(matches!(
                            plan.apply(&mut ledger, &tx),
                            Err(Error::Rejected(_))
                        ));
                        assert_eq!(state(&ledger, nonce), committed);
                        json!(true)
                    }
                    Err(e) => {
                        assert_eq!(state(&ledger, nonce), checkpoint);
                        rollback += 1;
                        rejected(e)
                    }
                };
                json!({"plan":prepared,"applied":applied})
            }
        };
        let after = state(&ledger, nonce);
        account_store::flush_dirty(&mut ledger, &mut store, RuleMode::Prior).unwrap();
        let actual = json!({"before":before,"outcome":outcome,"after":after,"root":hex::encode(store.root().unwrap()),"data":store.get(&[b"accounts",b"alice",b"data"]).map(|v|STANDARD.encode(v))});
        assert_eq!(actual, case["expected"], "case {index}: {}", input["name"]);
        assert!(!ledger.journal_active());
    }
    assert!(confirmed >= 6 && rollback >= 7);
}
