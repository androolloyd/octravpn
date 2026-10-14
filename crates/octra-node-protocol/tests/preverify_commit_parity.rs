use base64::{engine::general_purpose::STANDARD, Engine as _};
use octra_node_protocol::{
    native_json::Document,
    preverify_commit::{self, Error, Gate},
    resource_lanes::{Budget, Lane},
    transaction::Transaction,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn result(value: Result<(), Error>) -> Value {
    match value {
        Ok(()) => Value::Null,
        Err(Error::Invalid(bytes)) => json!(STANDARD.encode(bytes)),
        Err(e) => panic!("operational failure: {e}"),
    }
}
#[test]
fn native_epoch_receipt_admission() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/preverify-commit.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], pin["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(
        fixture["oracle_sha256"],
        json!(hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/preverify-commit-oracle.ml"
        ))))
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let expected = &case["expected"];
        let txs: Vec<_> = expected["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| Transaction::from_document(&Document::parse(&bytes(v)).unwrap()).unwrap())
            .collect();
        let raws: Vec<_> = expected["raws"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect();
        let budget = |lane: Lane| {
            let v = &input["budget"];
            if v.is_null() {
                lane.budget()
            } else {
                Budget {
                    transactions: v["txs"].as_i64().unwrap(),
                    bytes: v["bytes"].as_i64().unwrap(),
                    ou: v["ou"].as_str().unwrap().parse().unwrap(),
                    proofs: v["proof"].as_i64().unwrap(),
                }
            }
        };
        let gate = Gate::parse(&raws)
            .map_err(|e| Error::Invalid(format!("receipt_parse:{e}").into_bytes()));
        let checked = gate.and_then(|g| {
            g.check_with(
                &txs,
                input["crypto"].as_bool().unwrap(),
                &5000.into(),
                budget,
            )
        });
        assert_eq!(result(checked), expected["check"], "case {index}: {input}");
        if input["budget"].is_null() {
            assert_eq!(
                result(preverify_commit::check_strings(
                    &raws,
                    &txs,
                    input["crypto"].as_bool().unwrap(),
                    &5000.into()
                )),
                expected["check"],
                "default gate {index}"
            );
        }
        let activation =
            preverify_commit::activation(input["activation"].as_str().map(str::as_bytes));
        assert_eq!(json!(activation), expected["activation"]);
        assert_eq!(
            json!(preverify_commit::should_check(
                input["epoch"].as_i64().unwrap(),
                activation,
                &raws
            )),
            expected["should_check"]
        );
    }
}
