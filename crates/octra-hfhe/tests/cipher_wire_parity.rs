mod common;

use octra_hfhe::{
    cipher::Cipher,
    compression,
    keys::{keygen_from_seed, Params},
};
use serde_json::{json, Value};

#[test]
fn cipher_legacy_imports_policy_and_complete_bytes_match_native() {
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
    let fixture: Value = serde_json::from_str(include_str!("fixtures/cipher-wire.json")).unwrap();
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 2219);
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source], "native source {source}");
    }
    for case in fixture["cases"].as_array().unwrap() {
        let mut input = hex::decode(case["input"].as_str().unwrap()).unwrap();
        input.resize(
            input.len() + case["zero_fill"].as_u64().unwrap() as usize,
            0,
        );
        let result = Cipher::from_bytes_with_policy(
            &input,
            case["strict"].as_bool().unwrap(),
            case["cap"].as_bool().unwrap(),
        );
        let actual = match result {
            Ok(cipher) => {
                let wire = cipher.to_bytes().unwrap();
                let packed = compression::pack(&wire).unwrap();
                assert_eq!(compression::unpack(&packed).unwrap(), wire);
                json!({"bytes": hex::encode(wire), "packed": hex::encode(packed), "slots": cipher.slots(), "compatible": cipher.compatible_with(&public), "commitment": hex::encode(cipher.commitment(&public))})
            }
            Err(error) => json!({"error": error.to_string()}),
        };
        assert_eq!(actual, case["expected"], "case {}", case["name"]);
    }
}

#[test]
fn legacy_public_layer_capacity_overflow_returns_allocation_failure() {
    // The uncapped legacy format can declare an impossible synthesized R_PC
    // allocation in a tiny input. Allocation failure is operational; it must
    // not unwind or abort the Rust process.
    let mut bytes = b"PVAC\x04\x00".to_vec();
    bytes.extend_from_slice(&u64::MAX.to_le_bytes());
    bytes.extend_from_slice(&1_u64.to_le_bytes());
    bytes.extend_from_slice(&[0; 25]);
    bytes.extend_from_slice(&[0; 16]);
    let error = Cipher::from_bytes_with_policy(&bytes, false, false).unwrap_err();
    if usize::BITS == 64 {
        assert_eq!(error.to_string(), "HFHE allocation unavailable");
    } else {
        assert_eq!(error.to_string(), "pvac_ser: cipher slots exceed maximum");
    }
}
