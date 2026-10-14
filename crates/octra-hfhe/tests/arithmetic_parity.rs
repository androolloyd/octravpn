mod common;

use octra_hfhe::{
    cipher::Cipher,
    field::Fp,
    keys::{keygen_from_seed, Params, PublicKey},
    Error,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[test]
fn linear_arithmetic_and_compaction_match_complete_native_bytes() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/arithmetic.json")).unwrap();
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 530);
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source], "native source {source}");
    }
    let mut keys = BTreeMap::<u64, PublicKey>::new();
    for case in fixture["cases"].as_array().unwrap() {
        let budget = case["budget"].as_u64().unwrap();
        let public = keys.entry(budget).or_insert_with(|| {
            keygen_from_seed(
                Params {
                    basis: 7,
                    m_bits: 65,
                    n_bits: 17,
                    h_col_weight: 13,
                    x_col_weight: 7,
                    error_weight: 2,
                    lpn_n: 65,
                    lpn_t: 129,
                    edge_budget: budget,
                    ..Params::default()
                },
                &[0; 32],
            )
            .unwrap()
            .0
        });
        let left =
            Cipher::from_bytes(&hex::decode(case["left"].as_str().unwrap()).unwrap()).unwrap();
        let value = Fp::from_bytes_le(
            hex::decode(case["field"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let scalar: u64 = case["scalar_bits"].as_str().unwrap().parse().unwrap();
        let math = case["math"].as_bool().unwrap();
        let result = (|| -> Result<Cipher, Error> {
            Ok(match case["op"].as_str().unwrap() {
                "scale" => left.scale(value),
                "scale_i64" => left.mul_constant_i64(scalar as i64),
                "scale_u64" => left.mul_constant_u64(scalar),
                "neg" => left.negate(),
                "add_const" => left.add_constant(value, math)?,
                "sub_const" => left.subtract_constant(value, math)?,
                "div_const" => left.divide_constant(value)?,
                "add" | "sub" => {
                    let right =
                        Cipher::from_bytes(&hex::decode(case["right"].as_str().unwrap()).unwrap())?;
                    if case["op"] == "add" {
                        left.add(public, &right)?
                    } else {
                        left.subtract(public, &right)?
                    }
                }
                "compact_edges" | "compact_layers" | "guard" | "ubk" => {
                    let mut result = left;
                    if case["op"] == "compact_edges" {
                        result.compact_edges(public)?;
                    } else if case["op"] == "compact_layers" {
                        result.compact_layers()?;
                    } else if case["op"] == "ubk" {
                        result.apply_ubk(public)?;
                    } else {
                        result.compact_over_budget(public)?;
                    }
                    result
                }
                _ => panic!("unknown operation"),
            })
        })();
        let actual =
            match result.and_then(|cipher| Ok((cipher.to_bytes()?, cipher.commitment(public)))) {
                Ok((bytes, commitment)) => {
                    json!({"bytes": hex::encode(bytes), "commitment": hex::encode(commitment)})
                }
                Err(error) => json!({"error": error.to_string()}),
            };
        assert_eq!(actual, case["expected"], "case {}", case["name"]);
    }
}

#[test]
fn uncapped_legacy_constant_allocation_fails_without_panicking() {
    let mut bytes = b"PVAC\x03\x00".to_vec();
    bytes.extend_from_slice(&(usize::MAX as u64).to_le_bytes());
    bytes.extend_from_slice(&[0; 24]);
    let cipher = Cipher::from_bytes_with_policy(&bytes, false, false).unwrap();
    assert_eq!(
        cipher.add_constant(Fp::ONE, true).unwrap_err().to_string(),
        "HFHE allocation unavailable"
    );
    assert_eq!(
        cipher
            .subtract_constant(Fp::ONE, true)
            .unwrap_err()
            .to_string(),
        "HFHE allocation unavailable"
    );
    assert_eq!(cipher.add_constant(Fp::ONE, false).unwrap(), cipher);
}

#[test]
fn sigma_permutation_checks_native_out_of_bounds_accesses() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/arithmetic.json")).unwrap();
    let mut bytes = hex::decode(fixture["cases"][0]["left"].as_str().unwrap()).unwrap();
    // Last edge: 66-bit sigma and bit 65 set. The public inverse has 65 entries.
    let length = bytes.len();
    bytes[length - 32..length - 24].copy_from_slice(&66_u64.to_le_bytes());
    bytes[length - 8..].copy_from_slice(&2_u64.to_le_bytes());
    let mut cipher = Cipher::from_bytes(&bytes).unwrap();
    let original = cipher.clone();
    let (public, _) = keygen_from_seed(
        Params {
            basis: 7,
            m_bits: 65,
            n_bits: 17,
            h_col_weight: 13,
            x_col_weight: 7,
            error_weight: 2,
            lpn_n: 65,
            lpn_t: 129,
            ..Params::default()
        },
        &[0; 32],
    )
    .unwrap();
    assert_eq!(
        cipher.apply_ubk(&public).unwrap_err().to_string(),
        "HFHE sigma permutation shape rejected"
    );
    assert_eq!(cipher, original);
}
