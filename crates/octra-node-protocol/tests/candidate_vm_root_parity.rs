use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{contract, transaction::json_string};
use serde_json::Value;
use sha2::{Digest, Sha256};
#[test]
fn candidate_vm_root_and_json_bytes_match_native() {
    let report: Value =
        serde_json::from_str(include_str!("fixtures/candidate-vm-root.json")).unwrap();
    let candidate: Value = serde_json::from_str(include_str!(
        "../../../docs/rust-node/source-map-candidate.json"
    ))
    .unwrap();
    assert_eq!(report["upstream_commit"], candidate["upstream_commit"]);
    for (path, hash) in report["source_sha256"].as_object().unwrap() {
        assert_eq!(hash, &candidate["files"][path], "{path}");
    }
    for (field, source) in [
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/candidate-vm-root-oracle.py").as_slice(),
        ),
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/candidate-vm-root-oracle.ml").as_slice(),
        ),
    ] {
        assert_eq!(
            report[field],
            hex::encode(Sha256::digest(source)),
            "{field}"
        );
    }
    assert_eq!(report["roots"].as_array().unwrap().len(), 22);
    for (index, case) in report["roots"].as_array().unwrap().iter().enumerate() {
        let input = STANDARD.decode(case["input"].as_str().unwrap()).unwrap();
        let expected = &case["expected"];
        if let Some(error) = expected["error"].as_str() {
            assert_eq!(
                contract::tree_hash(&input).unwrap_err(),
                error,
                "case{index}"
            );
        } else {
            let raw = contract::tree_hash(&input).unwrap();
            assert_eq!(STANDARD.encode(&raw), expected["raw"], "case{index}");
            let mut json = vec![];
            json_string(&mut json, &raw);
            assert_eq!(STANDARD.encode(json), expected["json"], "case{index}");
        }
    }
}
