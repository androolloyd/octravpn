use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    native_json::Document, preverify_commit::Gate, transaction::Transaction,
};
use octra_node_runtime::{account_store, preverify_state, state_batch::StateBatch};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn raw(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
#[test]
fn native_committed_receipt_bindings_and_fault_precedence() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/preverify-state.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/preverify-state-oracle.ml"
        )))
    );
    assert_eq!(
        fixture["runner_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/native-oracle.py"
        )))
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let expected = &case["expected"];
        let mut state = StateBatch::default();
        state.begin().unwrap();
        for row in expected["entries"].as_array().unwrap() {
            let path = row[0]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_str().unwrap().as_bytes())
                .collect::<Vec<_>>();
            state.set(&path, raw(&row[1])).unwrap();
        }
        let root = raw(&expected["root"]);
        assert_eq!(
            hex::encode(state.root().unwrap()).as_bytes(),
            root,
            "root {index}"
        );
        state.acknowledge_commit().unwrap();
        state.begin().unwrap();
        state
            .set(&[b"meta", b"speculative"], b"true".to_vec())
            .unwrap();
        let ledger = account_store::ledger(&state).unwrap();
        let tx =
            Transaction::from_document(&Document::parse(&raw(&expected["transaction"])).unwrap())
                .unwrap();
        let receipts = expected["receipts"]
            .as_array()
            .unwrap()
            .iter()
            .map(raw)
            .collect::<Vec<_>>();
        let gate = Gate::parse(&receipts).unwrap();
        let result = preverify_state::check(
            &gate,
            &[tx],
            expected["crypto_active"].as_bool().unwrap(),
            &5000.into(),
            &root,
            &ledger,
            &state.snapshot(),
        );
        let actual = match result {
            Ok(()) => Value::Null,
            Err(octra_node_protocol::preverify_commit::Error::Invalid(reason)) => {
                json!(STANDARD.encode(reason))
            }
            Err(e) => panic!("operational failure {index}: {e}"),
        };
        assert_eq!(
            actual, expected["result"],
            "native binding {index}: {}",
            case["input"]
        );
    }
}
