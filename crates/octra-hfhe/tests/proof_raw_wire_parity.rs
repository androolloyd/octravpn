use octra_hfhe::proof::zero::ZeroProof;
use serde_json::Value;
use sha2::{Digest, Sha256};
mod common;
#[test]
fn native_raw_zero_proof_wire_acceptance_and_canonical_output() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/proof_raw_wire.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-proof-raw-wire-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() > 900);
    for (index, case) in cases.iter().enumerate() {
        let expected = &case["expected"];
        let raw = hex::decode(case["input"].as_str().unwrap()).unwrap();
        let result = ZeroProof::from_raw_bytes(&raw);
        if let Some(error) = expected["error"].as_str() {
            assert_eq!(result.err().unwrap().to_string(), error, "refusal {index}");
        } else {
            let proof = result.unwrap();
            assert_eq!(proof.is_bound, expected["bound"].as_bool().unwrap());
            assert_eq!(
                hex::encode(proof.to_raw_bytes().unwrap()),
                expected["bytes"],
                "canonical bytes {index}"
            );
        }
    }
}
