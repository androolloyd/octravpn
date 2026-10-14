//! Outputs come from pinned native modules, including rejection precedence and state after every step.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use num_bigint::BigInt;
use octra_node_protocol::{
    state::{Account, Ledger, TransferError},
    transaction::{self as tx, Nonce, OpType, Transaction},
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
fn bytes(value: &Value, field: &str) -> Vec<u8> {
    STANDARD.decode(value[field].as_str().unwrap()).unwrap()
}
fn optional(value: &Value, field: &str) -> Option<Vec<u8>> {
    value[field].as_str().map(|v| STANDARD.decode(v).unwrap())
}
fn integer(value: &Value, field: &str) -> BigInt {
    value[field].as_str().unwrap().parse().unwrap()
}
fn nonce(value: &Value, field: &str) -> Nonce {
    Nonce::new(value[field].as_str().unwrap().parse().unwrap()).unwrap()
}
fn blob(bytes: &[u8]) -> Value {
    json!(STANDARD.encode(bytes))
}
fn transaction(value: &Value) -> Transaction {
    Transaction {
        from: bytes(value, "from"),
        to: bytes(value, "to"),
        amount: integer(value, "amount"),
        nonce: nonce(value, "nonce"),
        ou: integer(value, "ou"),
        timestamp: f64::from_bits(
            u64::from_str_radix(value["timestamp_bits"].as_str().unwrap(), 16).unwrap(),
        ),
        signature: bytes(value, "signature"),
        public_key: optional(value, "public_key"),
        message: optional(value, "message"),
        op_type: OpType::parse(value["op_type"].as_str().unwrap().as_bytes()).unwrap(),
        encrypted_data: optional(value, "encrypted_data"),
    }
}
fn account(value: &Value) -> Account {
    Account {
        balance: integer(value, "balance"),
        nonce: nonce(value, "nonce"),
        public_key: optional(value, "public_key"),
        encrypted_balance: optional(value, "encrypted_balance"),
        decrypt_allowance: integer(value, "decrypt_allowance"),
    }
}
fn unit<E: std::fmt::Display>(result: Result<(), E>) -> Value {
    result.err().map_or(Value::Null, |e| json!(e.to_string()))
}
fn snapshot(ledger: &Ledger) -> Value {
    json!({"accounts":ledger.accounts().iter().map(|(address,account)|json!([blob(address),blob(&account.to_json_bytes())])).collect::<Vec<_>>(),
        "supply":ledger.total_supply().to_string(),"active":ledger.active_accounts(),"dirty":ledger.is_dirty(),
        "dirty_addresses":ledger.dirty_addresses().iter().map(|address|blob(address)).collect::<Vec<_>>(),
        "spent":ledger.spent_nonces().iter().map(|(address,nonce)|json!([blob(address),nonce.get().to_string()])).collect::<Vec<_>>(),"journal_active":ledger.journal_active()})
}
fn trace(input: &Value) -> Value {
    let accounts = input["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (bytes(v, "address"), account(v)))
        .collect::<BTreeMap<_, _>>();
    let mut ledger = match Ledger::from_accounts(accounts) {
        Ok(ledger) => ledger,
        Err(e) => return json!({"load_error":e.to_string()}),
    };
    let initial = snapshot(&ledger);
    let steps = input["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let result = match s["op"].as_str().unwrap() {
                "begin" => {
                    ledger.begin_journal();
                    Value::Null
                }
                "abort" => {
                    ledger.abort_journal();
                    Value::Null
                }
                "commit" => unit(ledger.commit_journal()),
                "clear_spent" => {
                    ledger.clear_spent_nonces();
                    Value::Null
                }
                "freeze" => unit(ledger.freeze().map(|_| ())),
                "flush" => {
                    ledger.acknowledge_account_flush();
                    Value::Null
                }
                "add" => unit(ledger.add_account(
                    &bytes(s, "address"),
                    integer(s, "amount"),
                    optional(s, "public_key"),
                )),
                "credit" => unit(ledger.credit(
                    &bytes(s, "address"),
                    &integer(s, "amount"),
                    optional(s, "encrypted_balance"),
                )),
                "debit" => unit(ledger.debit(
                    &bytes(s, "address"),
                    &integer(s, "amount"),
                    nonce(s, "nonce"),
                    optional(s, "encrypted_balance"),
                )),
                "debit_only" => {
                    unit(ledger.debit_amount_only(&bytes(s, "address"), &integer(s, "amount")))
                }
                "key" => {
                    ledger.register_public_key(&bytes(s, "address"), bytes(s, "public_key"));
                    Value::Null
                }
                "cipher" => {
                    ledger.update_encrypted_balance(
                        &bytes(s, "address"),
                        bytes(s, "encrypted_balance"),
                    );
                    Value::Null
                }
                "allowance" => {
                    ledger.update_decrypt_allowance(&bytes(s, "address"), integer(s, "amount"));
                    Value::Null
                }
                "transfer" => match ledger.transfer(
                    &bytes(s, "from"),
                    &bytes(s, "to"),
                    &integer(s, "amount"),
                    &integer(s, "fee"),
                    nonce(s, "nonce"),
                ) {
                    Ok(()) => Value::Null,
                    Err(TransferError::DebitRejected(e)) => json!(["debit", e]),
                    Err(TransferError::CreditRejected(e)) => json!(["credit", e]),
                },
                op => panic!("unknown op {op}"),
            };
            json!({"outcome":result,"state":snapshot(&ledger)})
        })
        .collect::<Vec<_>>();
    json!({"initial":initial,"steps":steps})
}
fn evaluate(input: &Value) -> Value {
    match input["operation"].as_str().unwrap() {
        "float" => tx::native_float(f64::from_bits(
            u64::from_str_radix(input["bits"].as_str().unwrap(), 16).unwrap(),
        ))
        .map_or_else(|e| json!({"error":e.to_string()}), |value| json!(value)),
        "base64" => tx::decode_base64(&bytes(input, "value")).map_or(Value::Null, |v| blob(&v)),
        "address" => {
            json!({"address":blob(&tx::address_from_public_key(&bytes(input,"key"))),"valid":tx::is_valid_address(&bytes(input,"address"))})
        }
        "transaction" => {
            let mut tx = transaction(input);
            if let Err(e) = tx.signing_bytes() {
                return json!({"error": e.to_string()});
            }
            if let Some(seed) = optional(input, "seed") {
                let secret = SigningKey::from_bytes(&seed.try_into().unwrap());
                tx.signature = STANDARD
                    .encode(secret.sign(&tx.signing_bytes().unwrap()).to_bytes())
                    .into_bytes();
            }
            json!({"signing":blob(&tx.signing_bytes().unwrap()),"json":blob(&tx.to_json_bytes().unwrap()),"hash":hex::encode(tx.hash().unwrap()),"signature":blob(&tx.signature),"verified":tx.public_key.as_ref().is_some_and(|key|tx.verify(key))})
        }
        "envelope" => {
            let tx = transaction(input);
            let normalized = match tx::normalize_envelope(
                &tx,
                optional(input, "sender_key").as_deref(),
            ) {
                Ok(tx) => {
                    json!({"signature":blob(&tx.signature),"public_key":blob(tx.public_key.as_ref().unwrap())})
                }
                Err(e) => json!({"tag":e.tag,"reason":e.reason}),
            };
            json!({"normalize":normalized,"check":unit(tx::check_envelope(&tx))})
        }
        "ledger" => trace(input),
        op => panic!("unknown operation {op}"),
    }
}
#[test]
fn transaction_and_ledger_match_pinned_native() {
    let report: Value =
        serde_json::from_str(include_str!("fixtures/transaction-state.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/upstream.json")).unwrap();
    let inventory: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(report["upstream_commit"], pin["commit"]);
    for (path, hash) in report["sources"].as_object().unwrap() {
        assert_eq!(&inventory["files"][path], hash, "source drift {path}");
    }
    let cases = report["cases"].as_array().unwrap();
    assert!(cases.len() > 5200);
    for (index, case) in cases.iter().enumerate() {
        assert_eq!(
            evaluate(&case["input"]),
            case["output"],
            "native fixture {index}: {}",
            case["input"]
        );
    }
}
#[test]
fn int63_boundaries_and_duplicate_envelopes_are_explicit() {
    assert!(Nonce::new(i64::MAX).is_err());
    assert!(Nonce::new(i64::MIN).is_err());
    assert_eq!(Nonce::MAX.successor(), Nonce::MIN);
    let report: Value =
        serde_json::from_str(include_str!("fixtures/transaction-state.json")).unwrap();
    let input = &report["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["input"]["operation"] == "envelope" && c["output"]["check"].is_null())
        .unwrap()["input"];
    let a = transaction(input);
    let mut b = a.clone();
    b.amount += 1;
    assert_eq!(
        tx::check_envelopes(tx::RuleMode::Active, &[a.clone(), b.clone()])
            .unwrap_err()
            .to_string(),
        "duplicate sender nonce"
    );
    assert!(tx::check_envelopes(tx::RuleMode::Prior, &[a, b]).is_ok());
}
#[test]
fn snapshots_require_flushed_no_journal_state_and_thaw_clears_epoch_nonces() {
    let mut ledger = Ledger::empty();
    ledger.credit(b"a", &20.into(), None).unwrap();
    ledger
        .debit(b"a", &1.into(), Nonce::new(1).unwrap(), None)
        .unwrap();
    assert!(ledger.freeze().is_err());
    ledger.acknowledge_account_flush();
    ledger.begin_journal();
    assert_eq!(
        ledger.freeze().unwrap_err().to_string(),
        "ledger clone requires no active journal"
    );
    ledger.abort_journal();
    let copy = Ledger::thaw(ledger.freeze().unwrap());
    assert_eq!(copy.accounts(), ledger.accounts());
    assert!(copy.spent_nonces().is_empty());
    assert!(!copy.is_dirty());
}
