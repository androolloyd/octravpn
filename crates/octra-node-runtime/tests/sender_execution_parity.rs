use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    state::{Account, Ledger},
    transaction::{Nonce, OpType, Transaction},
};
use octra_node_runtime::{
    execution::{self, Completion, Error, Executed, OperationHost, Outcome, Rejection, Route},
    state_batch::StateBatch,
};
use serde_json::{json, Value};
fn bytes(value: &Value, key: &str) -> Vec<u8> {
    STANDARD.decode(value[key].as_str().unwrap()).unwrap()
}
fn blob(value: &[u8]) -> Value {
    json!(STANDARD.encode(value))
}
fn nonce(value: &Value, key: &str) -> Nonce {
    Nonce::new(value[key].as_str().unwrap().parse().unwrap()).unwrap()
}
fn transaction(index: usize, value: &Value) -> Transaction {
    Transaction {
        from: bytes(value, "from"),
        to: bytes(value, "to"),
        amount: value["amount"].as_str().unwrap().parse().unwrap(),
        nonce: nonce(value, "nonce"),
        ou: value["ou"].as_str().unwrap().parse().unwrap(),
        timestamp: 1.,
        signature: index.to_string().into_bytes(),
        public_key: None,
        message: None,
        encrypted_data: None,
        op_type: OpType::parse(value["op"].as_str().unwrap().as_bytes()).unwrap(),
    }
}
struct Host<'a>(&'a [Value]);
impl OperationHost for Host<'_> {
    fn execute(
        &mut self,
        route: Route,
        tx: &Transaction,
        ledger: &mut Ledger,
        store: &mut StateBatch,
    ) -> Result<Completion, Error> {
        assert_eq!(route, Route::VirtualMachine);
        let index: usize = std::str::from_utf8(&tx.signature).unwrap().parse().unwrap();
        store
            .set(&[b"test", b"marker"], tx.signature.clone())
            .unwrap();
        store.set_stealth_counter(store.stealth_counter().wrapping_add(1));
        ledger.credit(b"host-account", &5.into(), None).unwrap();
        match self.0[index]["action"].as_str().unwrap() {
            "confirm" => Ok(Completion::Confirmed {
                created_account: None,
            }),
            action @ ("reject" | "consume" | "persist") => Ok(Completion::Rejected(Rejection {
                tag: "host_rejected".into(),
                reason: "fixture refusal".into(),
                notify_reason: None,
                consume_nonce: action == "consume",
                persist_state: action == "persist",
            })),
            "defer" => Ok(Completion::Deferred {
                consume_nonce: true,
            }),
            "error" => Err(Error("fixture host failure".into())),
            "panic" => panic!("fixture unwind"),
            other => panic!("unexpected action {other}"),
        }
    }
}
fn snapshot(ledger: &Ledger, store: &StateBatch) -> Value {
    json!({"accounts":ledger.accounts().iter().map(|(address,account)|json!([blob(address),blob(&account.to_json_bytes())])).collect::<Vec<_>>(),"supply":ledger.total_supply().to_string(),"active":ledger.active_accounts(),"spent":ledger.spent_nonces().iter().map(|(address,nonce)|json!([blob(address),nonce.get().to_string()])).collect::<Vec<_>>(),"marker":store.get(&[b"test",b"marker"]).map(blob),"burn":store.get(&[b"meta",b"op01_2026_burn_executed"]).map(blob),"counter":store.stealth_counter().to_string(),"journal":ledger.journal_active()})
}
fn event(event: Executed) -> Value {
    let outcome = match event.outcome {
        Outcome::NonceMismatch { expected, got } => {
            json!({"mismatch":[expected.get().to_string(),got.get().to_string()]})
        }
        Outcome::Completed(Completion::Confirmed { created_account }) => {
            json!({"confirmed":created_account.as_ref().map(|v|blob(v))})
        }
        Outcome::Completed(Completion::Deferred { consume_nonce }) => {
            json!({"deferred":consume_nonce})
        }
        Outcome::Completed(Completion::Rejected(r)) => {
            json!({"rejected":{"tag":r.tag,"reason":String::from_utf8(r.reason).unwrap(),"notify":r.notify_reason.map(|s|String::from_utf8(s).unwrap()),"consume":r.consume_nonce,"persist":r.persist_state}})
        }
    };
    json!({"index":event.input_index,"outcome":outcome})
}
fn evaluate(input: &Value) -> Value {
    let mut ledger = Ledger::from_accounts(
        input["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                (
                    bytes(v, "address"),
                    Account {
                        balance: v["balance"].as_str().unwrap().parse().unwrap(),
                        nonce: nonce(v, "nonce"),
                        ..Account::default()
                    },
                )
            })
            .collect(),
    )
    .unwrap();
    let mut store = StateBatch::default();
    store.begin().unwrap();
    let raw = input["transactions"].as_array().unwrap();
    let transactions = raw
        .iter()
        .enumerate()
        .map(|(i, v)| transaction(i, v))
        .collect::<Vec<_>>();
    let mut host = Host(raw);
    let outcome =
        match execution::execute_checked(&transactions, &mut ledger, &mut store, &mut host) {
            Ok(events) => json!({"events":events.into_iter().map(event).collect::<Vec<_>>()}),
            Err(e) => json!({"error":e.to_string()}),
        };
    json!({"outcome":outcome,"state":snapshot(&ledger,&store)})
}
#[test]
fn native_sender_public_execution_and_savepoints_match() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/sender-execution.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/upstream.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["commit"]);
    for (path, hash) in fixture["sources"].as_object().unwrap() {
        assert_eq!(&sources["files"][path], hash, "source drift {path}");
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 60);
    for (index, case) in cases.iter().enumerate() {
        assert_eq!(
            evaluate(&case["input"]),
            case["output"],
            "native sender case {index}: {}",
            case["input"]
        );
    }
}
#[test]
fn unwind_restores_entire_attempt_and_every_active_savepoint() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/sender-execution.json")).unwrap();
    let mut input = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["output"]["outcome"]["error"].is_string())
        .unwrap()["input"]
        .clone();
    for tx in input["transactions"].as_array_mut().unwrap() {
        if tx["action"] == "error" {
            tx["action"] = json!("panic");
        }
    }
    let mut ledger = Ledger::from_accounts(
        input["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                (
                    bytes(v, "address"),
                    Account {
                        balance: v["balance"].as_str().unwrap().parse().unwrap(),
                        nonce: nonce(v, "nonce"),
                        ..Account::default()
                    },
                )
            })
            .collect(),
    )
    .unwrap();
    let mut store = StateBatch::default();
    store.begin().unwrap();
    let before = snapshot(&ledger, &store);
    let raw = input["transactions"].as_array().unwrap();
    let txs = raw
        .iter()
        .enumerate()
        .map(|(i, v)| transaction(i, v))
        .collect::<Vec<_>>();
    let mut host = Host(raw);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execution::execute_checked(&txs, &mut ledger, &mut store, &mut host)
    }));
    assert!(result.is_err());
    assert_eq!(snapshot(&ledger, &store), before);
    assert_eq!(ledger.journal_depth(), 0);
}
#[test]
fn no_batch_cannot_leave_a_ledger_journal_open() {
    let mut ledger = Ledger::empty();
    let mut store = StateBatch::default();
    let mut host = Host(&[]);
    assert!(execution::execute_checked(&[], &mut ledger, &mut store, &mut host).is_err());
    assert_eq!(ledger.journal_depth(), 0);
    store.begin().unwrap();
    assert!(store.begin().is_err());
    let saved = store.save().unwrap();
    store.set(&[b"a", b"b"], b"value".to_vec()).unwrap();
    store.restore(saved).unwrap();
    assert_eq!(store.get(&[b"a", b"b"]), None);
}
