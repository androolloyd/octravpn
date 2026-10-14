mod common;

use octra_hfhe::{field::Fp, keys::signed_commitment};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn signed_commitments_match_native_field_and_scalar_boundaries() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/commitments.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source], "native source {source}");
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-commitment-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(fixture["boundary_cases"], 130);
    assert_eq!(fixture["random_cases"], 2048);
    assert_eq!(cases.len(), 2178);
    for (index, case) in cases.iter().enumerate() {
        let field = Fp::from_bytes_le(
            hex::decode(case["field"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let blind = hex::decode(case["blind"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex::encode(signed_commitment(field, &blind)),
            case["expected"],
            "commitment case {index}"
        );
    }
}
