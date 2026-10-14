use octra_hfhe::proof::wire::AnyRangeProof;
use serde_json::Value;
use sha2::{Digest, Sha256};
mod common;
#[test]
fn native_range_proof_wire_acceptance_and_canonical_output() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/range_wire.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-range-wire-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() > 900);
    for (index, case) in cases.iter().enumerate() {
        let expected = &case["expected"];
        let raw = hex::decode(case["input"].as_str().unwrap()).unwrap();
        let result = AnyRangeProof::from_bytes(&raw);
        if let Some(error) = expected["error"].as_str() {
            assert_eq!(result.err().unwrap().to_string(), error, "refusal {index}");
        } else {
            let proof = result.unwrap();
            let format = match &proof {
                AnyRangeProof::Legacy(_) => 0,
                AnyRangeProof::Aggregated(_) => 1,
                AnyRangeProof::Bound(_) => 2,
            };
            assert_eq!(format, expected["format"].as_u64().unwrap());
            assert_eq!(
                hex::encode(proof.to_bytes().unwrap()),
                expected["bytes"],
                "canonical bytes {index}"
            );
        }
    }
}
