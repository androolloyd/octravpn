use base64::{engine::general_purpose::STANDARD, Engine};
use octra_hfhe::scalar::ScalarRule;
use octra_node_protocol::{
    preverify_commit::Gate,
    state::{Account, Ledger},
    transaction::{Nonce, OpType, RuleMode, Transaction},
};
use octra_node_runtime::{
    account_store, epoch_execution::Effect, private_balance::Profile, private_crypto::ResultPolicy,
    private_epoch::Epoch, state_batch::StateBatch,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
#[test]
fn native_epoch_admission_receipts_and_key_availability() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/private-epoch.json")).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inventory: Value = serde_json::from_slice(
        &std::fs::read(root.join("docs/rust-node/source-map.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (key, name) in [
        ("oracle_sha256", "private-epoch-oracle.ml"),
        ("runner_sha256", "native-oracle.py"),
        ("generator_sha256", "private-epoch-fixtures.py"),
    ] {
        assert_eq!(
            fixture[key],
            hex::encode(Sha256::digest(
                std::fs::read(root.join("scripts/node-port").join(name)).unwrap()
            ))
        );
    }
    let mut confirmed = 0;
    let mut unavailable = 0;
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let account = Account {
            balance: 100.into(),
            encrypted_balance: Some(bytes(&input["current"])),
            ..Account::default()
        };
        let mut store = StateBatch::default();
        store.begin().unwrap();
        account_store::set(&mut store, b"alice", &account, RuleMode::Prior).unwrap();
        let public = bytes(&input["public"]);
        let hash = hex::encode(Sha256::digest(&public));
        if input["bound"] == true {
            store
                .set(&[b"pvac_hashes", b"alice"], hash.as_bytes().to_vec())
                .unwrap();
        }
        let mut ledger = Ledger::from_accounts([(b"alice".to_vec(), account)].into()).unwrap();
        let warmup = input["warmup"].as_str().unwrap();
        let tx = Transaction {
            from: b"alice".to_vec(),
            to: if input["self"] == true {
                b"alice".to_vec()
            } else {
                b"elsewhere".to_vec()
            },
            amount: 7.into(),
            nonce: Nonce::new(if warmup == "none" { 1 } else { 2 }).unwrap(),
            ou: 2.into(),
            timestamp: 1.,
            signature: b"fixture".to_vec(),
            public_key: None,
            message: None,
            op_type: if input["operation"] == "private" {
                OpType::Private
            } else if input["operation"] == "recrypt" {
                OpType::Recrypt
            } else if input["withdraw"] == true {
                OpType::Decrypt
            } else {
                OpType::Encrypt
            },
            encrypted_data: Some(bytes(&input["payload"])),
        };
        let profile = Profile {
            fields: if input["unique"] == true {
                RuleMode::Active
            } else {
                RuleMode::Prior
            },
            strict: input["active"].as_bool().unwrap(),
            math: ScalarRule::Wide,
            result: ResultPolicy::Recoverable,
        };
        let raws = case["expected"]["receipt"]
            .as_str()
            .map(|_| bytes(&case["expected"]["receipt"]))
            .into_iter()
            .collect::<Vec<_>>();
        let gate = (input["gate"] != "none").then(|| Gate::parse(&raws).unwrap());
        let mut host = Epoch::new(
            profile,
            input["max_fhe"].as_u64().unwrap() as usize,
            gate.as_ref(),
        );
        if warmup != "none" {
            let mut first = tx.clone();
            first.nonce = Nonce::new(1).unwrap();
            first.to = b"alice".to_vec();
            first.op_type = if warmup == "decrypt" {
                OpType::Decrypt
            } else {
                OpType::Encrypt
            };
            assert!(matches!(
                host.process(&first, &mut ledger, &store, |_| Ok(Some(public.clone())))
                    .unwrap(),
                Effect::Confirmed(_)
            ));
        }
        let before = ledger.accounts().get(b"alice".as_slice()).unwrap().clone();
        let before_supply = ledger.total_supply().clone();
        let before_spent = ledger.spent_nonces().clone();
        let mut key_reads = 0;
        let result = host.process(&tx, &mut ledger, &store, |requested| {
            key_reads += 1;
            assert_eq!(requested, hash.as_bytes());
            Ok(match input["key_fault"].as_str() {
                Some("missing") => None,
                Some("corrupt") => Some(b"corrupt".to_vec()),
                _ => Some(public.clone()),
            })
        });
        let outcome = match result {
            Ok(Effect::Confirmed(fee)) => {
                confirmed += 1;
                json!({"fee":fee.to_string()})
            }
            Ok(Effect::Rejected(e)) => {
                json!({"tag":String::from_utf8(e.error_type).unwrap(),"reason":STANDARD.encode(e.reason)})
            }
            Ok(Effect::RejectedAfterFee { .. }) => {
                panic!("private transaction charged after rejection")
            }
            Err(e) => {
                unavailable += 1;
                json!({"exception":STANDARD.encode(format!("Failure({:?})", e.0))})
            }
        };
        if outcome.get("fee").is_none() {
            assert_eq!(ledger.accounts().get(b"alice".as_slice()).unwrap(), &before);
            assert_eq!(ledger.total_supply(), &before_supply);
            assert_eq!(ledger.spent_nonces(), &before_spent);
        }
        if input["name"].as_str().unwrap().contains("failure before") {
            assert_eq!(
                key_reads, 0,
                "payload/receipt rejection must precede blob lookup"
            );
        }
        account_store::flush_dirty(&mut ledger, &mut store, RuleMode::Prior).unwrap();
        let actual = json!({"receipt":case["expected"]["receipt"],"outcome":outcome,
            "account":STANDARD.encode(ledger.accounts().get(b"alice".as_slice()).unwrap().to_json_bytes()),
            "root":hex::encode(store.root().unwrap())});
        assert_eq!(actual, case["expected"], "case {index}: {}", input["name"]);
        assert!(!ledger.journal_active());
    }
    assert!(confirmed >= 4 && unavailable == 2);
}
