//! Differential checks against outputs from the actual pinned OCaml module.
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::epoch_index::{self as eic, Error, Item};
use serde_json::{json, Value};

fn bytes(input: &Value, name: &str) -> Vec<u8> {
    STANDARD.decode(input[name].as_str().unwrap()).unwrap()
}

fn integer(input: &Value, name: &str) -> i64 {
    input[name].as_str().unwrap().parse().unwrap()
}

fn items(input: &Value) -> Vec<Item> {
    input["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| Item {
            txid: integer(item, "txid"),
            hash: bytes(item, "hash_b64"),
        })
        .collect()
}

fn pair((epoch, root): (eic::Hash, eic::Hash)) -> Value {
    json!([hex::encode(epoch), hex::encode(root)])
}

fn evaluate(input: &Value) -> Result<Value, Error> {
    match input["operation"].as_str().unwrap() {
        "genesis" => Ok(json!(hex::encode(eic::genesis_root()))),
        "normalize_hash" => eic::normalize_hash(&bytes(input, "hash_b64")).map(|s| json!(s)),
        "root_hex" => eic::root_hex(&bytes(input, "root_b64")).map(|s| json!(s)),
        "epoch" => {
            eic::epoch_hash(integer(input, "epoch"), &items(input)).map(|h| json!(hex::encode(h)))
        }
        "root" => eic::root_hash(&bytes(input, "previous_b64"), &bytes(input, "hash_b64"))
            .map(|h| json!(hex::encode(h))),
        "next" => eic::next_root(
            &bytes(input, "previous_b64"),
            integer(input, "epoch"),
            &items(input),
        )
        .map(pair),
        "next_from_hashes" => {
            let hashes: Vec<_> = input["hashes_b64"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| STANDARD.decode(value.as_str().unwrap()).unwrap())
                .collect();
            let entries = eic::items_from_hashes(integer(input, "start_txid"), &hashes)?;
            eic::next_root(
                &bytes(input, "previous_b64"),
                integer(input, "epoch"),
                &entries,
            )
            .map(pair)
        }
        "fold" => eic::folded_state_root(&bytes(input, "ledger_b64"), &bytes(input, "index_b64"))
            .map(|h| json!(hex::encode(h))),
        other => panic!("unknown fixture operation {other}"),
    }
}

#[test]
fn commitments_match_pinned_ocaml_including_raw_roots_and_signed_boundaries() {
    let report: Value = serde_json::from_str(include_str!("fixtures/epoch-index.json")).unwrap();
    assert_eq!(
        report["upstream_commit"],
        "d3e834919bd586e81f947d0dae91becc6c43c756"
    );
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/upstream.json")).unwrap();
    assert!(
        report["upstream_commit"] == pin["commit"]
            || pin["source_equivalent_commits"]
                .as_array()
                .is_some_and(|commits| commits.contains(&report["upstream_commit"])),
        "fixture pin must be current or verified source-equivalent"
    );
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    // The source inventory is checked against the pristine checkout in CI.
    assert_eq!(
        sources["files"][report["source"].as_str().unwrap()],
        report["source_sha256"]
    );
    let cases = report["cases"].as_array().unwrap();
    assert!(
        cases.len() >= 100,
        "oracle fixture selection unexpectedly shrank"
    );
    for case in cases {
        let result = match evaluate(&case["input"]) {
            Ok(value) => json!({"ok": value}),
            Err(error) => json!({"error": error.to_string()}),
        };
        assert_eq!(result, case["expected"], "input: {}", case["input"]);
    }
}
