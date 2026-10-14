mod common;

use octra_hfhe::{cipher::Cipher, keys::PublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[test]
fn seeded_products_match_native_graph_bytes_and_refusals() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/products.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source], "native source {source}");
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-product-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    let input = |case: &Value, name: &str| {
        let hash = case[name].as_str().unwrap();
        let bytes = hex::decode(fixture["inputs"][hash].as_str().unwrap()).unwrap();
        assert_eq!(hex::encode(Sha256::digest(&bytes)), hash);
        bytes
    };
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 234);
    let negative_weight: Vec<_> = cases
        .iter()
        .filter(|case| case["error_weight"] == -1)
        .collect();
    assert_eq!(
        negative_weight
            .iter()
            .filter(|case| case["expected"]["bytes"].is_string())
            .count(),
        13
    );
    assert_eq!(
        negative_weight
            .iter()
            .filter(
                |case| case["expected"]["error"] == "pvac: unique sample negative domain rejected"
            )
            .count(),
        11
    );
    for (index, case) in cases.iter().enumerate() {
        let public = PublicKey::from_raw_bytes(&input(case, "public")).unwrap();
        let left = Cipher::from_bytes(&input(case, "left")).unwrap();
        let right = Cipher::from_bytes(&input(case, "right")).unwrap();
        let seed = hex::decode(case["seed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let repack = case["repack_slots"].as_u64().unwrap() as usize;
        let math = case["math"].as_bool().unwrap();
        let draw = case["draw_factor"].as_u64().unwrap() as usize;
        let mut result = Ok(left);
        for _ in 0..case["rounds"].as_u64().unwrap() {
            result = result.and_then(|cipher| {
                if case["mode"] == "mul" {
                    cipher.multiply_seeded(&public, &right, &seed, repack, math, draw)
                } else {
                    cipher.square_seeded(&public, &seed, repack, math)
                }
            });
        }
        let result = result.and_then(|cipher| cipher.to_bytes());
        let actual = match result {
            Ok(bytes) => json!({"bytes":hex::encode(bytes)}),
            Err(error) => json!({"error":error.to_string()}),
        };
        assert_eq!(actual, case["expected"], "case {index}: {}", case["mode"]);
    }
}

#[test]
fn legacy_unbounded_slots_return_allocation_error() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/products.json")).unwrap();
    let hash = fixture["cases"][0]["public"].as_str().unwrap();
    let bytes = hex::decode(fixture["inputs"][hash].as_str().unwrap()).unwrap();
    let public = PublicKey::from_raw_bytes(&bytes).unwrap();
    // Native legacy uncapped decoding accepts the declared slot count when all
    // vectors are empty. Product allocation must fail without a Rust panic.
    let mut wire = b"PVAC\x03\x00".to_vec();
    for value in [usize::MAX as u64, 0, 0, 0] {
        wire.extend_from_slice(&value.to_le_bytes());
    }
    let cipher = Cipher::from_bytes_with_policy(&wire, false, false).unwrap();
    for math in [false, true] {
        let error = cipher
            .square_seeded(&public, &[0; 32], 8, math)
            .unwrap_err();
        assert_eq!(error.to_string(), "HFHE allocation unavailable");
        let error = cipher
            .multiply_seeded(&public, &cipher, &[0; 32], 8, math, 0)
            .unwrap_err();
        assert_eq!(error.to_string(), "HFHE allocation unavailable");
    }
}
