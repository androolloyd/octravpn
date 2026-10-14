use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{native_json::Document, transaction::Transaction};
use octra_node_runtime::preverify_batch::{self, Checked, Kind};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[test]
fn native_dependency_isolation_ordered_work_and_retry() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/preverify-batch.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    // Only the interface exports an existing private helper; implementations
    // remain byte-identical to the adopted source map.
    let instrumentation = fixture["instrumentation"].as_object().unwrap();
    assert_eq!(instrumentation.len(), 1);
    let export = &instrumentation["node_runtime/consensus_proposal.mli"];
    assert_eq!(export["kind"], "test-only source prefix");
    assert_eq!(export["replacements"], json!([]));
    assert_eq!(
        export["original_sha256"],
        source["files"]["node_runtime/consensus_proposal.mli"]
    );
    for (name, bytes) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/preverify-batch-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/preverify-batch-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
        (
            "transaction_fixture_sha256",
            include_bytes!("fixtures/epoch-partition.json").as_slice(),
        ),
    ] {
        assert_eq!(fixture[name], hex::encode(Sha256::digest(bytes)), "{name}");
    }
    let pool = fixture["transaction_pool"]
        .as_array()
        .unwrap()
        .iter()
        .map(|raw| {
            let raw = STANDARD.decode(raw.as_str().unwrap()).unwrap();
            Transaction::from_document(&Document::parse(&raw).unwrap()).unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 502);
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let txs = input["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| pool[i.as_u64().unwrap() as usize].clone())
            .collect::<Vec<_>>();
        let hashes = txs
            .iter()
            .map(|tx| hex::encode(tx.hash().unwrap()))
            .collect::<Vec<_>>();
        let mut calls = Vec::new();
        let batch = preverify_batch::prepare(
            &txs,
            input["ordered"].as_bool().unwrap(),
            &5000.into(),
            |tx| {
                let hash = hex::encode(tx.hash().unwrap());
                let offset = hashes.iter().position(|h| *h == hash).unwrap();
                calls.push(hash);
                Ok(match input["verdicts"][offset].as_str().unwrap() {
                    "ready" => Checked::Ready(None),
                    "invalid" => Checked::Skip {
                        reason: b"fixture invalid".to_vec(),
                        kind: Kind::Invalid,
                    },
                    "unavailable" => Checked::Skip {
                        reason: b"fixture unavailable".to_vec(),
                        kind: Kind::Unavailable,
                    },
                    other => panic!("unexpected verdict {other}"),
                })
            },
        )
        .unwrap();
        let actual = json!({
            "ready": batch.ready.iter().map(|r| &hashes[r.index]).collect::<Vec<_>>(),
            "skipped": batch.skipped.iter().map(|s| json!({
                "hash": hashes[s.index], "reason": std::str::from_utf8(&s.reason).unwrap(),
                "kind": match s.kind { Kind::Deferred=>"deferred", Kind::Unavailable=>"unavailable", Kind::Invalid=>"invalid" }
            })).collect::<Vec<_>>(),
            "calls": calls, "retry": batch.may_retry(&txs).unwrap()
        });
        assert_eq!(
            actual, case["expected"],
            "native selection case {index}: {input}"
        );
    }
}
