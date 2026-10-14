mod common;

use octra_hfhe::{
    compression,
    keys::{keygen_from_seed, pedersen_h, CircuitProfile, Params, PublicKey, SecretKey},
    matrix,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn fixtures() -> Value {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/keys.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source], "native source {source}");
    }
    fixture
}

#[test]
fn seeded_v5_keys_match_native_complete_bytes() {
    let fixture = fixtures();
    assert_eq!(fixture["keys"].as_array().unwrap().len(), 53);
    for (index, case) in fixture["keys"].as_array().unwrap().iter().enumerate() {
        let seed: [u8; 32] = hex::decode(case["seed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let values: Vec<_> = case["params"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_i64().unwrap() as i32)
            .collect();
        let params = Params {
            basis: values[0],
            m_bits: values[1],
            n_bits: values[2],
            h_col_weight: values[3],
            x_col_weight: values[4],
            error_weight: values[5],
            lpn_n: values[6],
            lpn_t: values[7],
            lpn_tau_den: values[8],
            ..Params::default()
        };
        let expected = &case["expected"];
        let result = keygen_from_seed(params, &seed);
        if let Some(error) = expected["error"].as_str() {
            assert_eq!(result.err().unwrap().to_string(), error, "case {index}");
            continue;
        }
        let (mut public, secret) = result.unwrap();
        if case["profile"] == 1 {
            public.set_circuit_profile(&secret, CircuitProfile::MimcX3V6);
        }
        assert_eq!(
            hex::encode(pedersen_h()),
            expected["h_generator"],
            "Pedersen H, case {index}"
        );
        assert_eq!(
            hex::encode(public.h_digest()),
            expected["h_digest"],
            "H, case {index}"
        );
        assert_eq!(
            hex::encode(public.circuit_commitment()),
            expected["commitment"],
            "commitment, case {index}"
        );
        let raw = public.to_raw_bytes();
        let packed = public.to_bytes().unwrap();
        assert_eq!(raw.len(), expected["raw_length"].as_u64().unwrap() as usize);
        assert_eq!(
            packed.len(),
            expected["packed_length"].as_u64().unwrap() as usize
        );
        assert_eq!(
            hex::encode(Sha256::digest(&raw)),
            expected["raw_sha256"],
            "raw digest, case {index}"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&packed)),
            expected["packed_sha256"],
            "packed digest, case {index}"
        );
        if expected["raw"].is_string() {
            assert_eq!(
                hex::encode(&raw),
                expected["raw"],
                "raw bytes, case {index}"
            );
            assert_eq!(
                hex::encode(&packed),
                expected["packed"],
                "packed bytes, case {index}"
            );
        }
        assert_eq!(
            hex::encode(secret.to_bytes().as_slice()),
            expected["secret"],
            "secret bytes, case {index}"
        );
        assert_eq!(
            compression::unpack(&packed).unwrap(),
            raw,
            "decompression, case {index}"
        );
        assert_eq!(PublicKey::from_bytes(&packed).unwrap().to_raw_bytes(), raw);
        assert_eq!(
            SecretKey::from_bytes(secret.to_bytes().as_slice())
                .unwrap()
                .to_bytes()
                .as_slice(),
            secret.to_bytes().as_slice()
        );
    }
}

#[test]
fn matrix_draw_order_and_effort_refusals_match_native() {
    let fixture = fixtures();
    for case in fixture["matrix"].as_array().unwrap() {
        let input = &case["input"];
        let result = matrix::choose_k(
            input[0].as_i64().unwrap() as i32,
            input[1].as_i64().unwrap() as i32,
            b"pvac.dom.h_gen",
            &[0, input[3].as_str().unwrap().parse().unwrap(), u64::MAX],
            input[2].as_u64().unwrap() as usize,
        );
        let actual = match result {
            Ok(indices) => json!({"indices": indices}),
            Err(error) => json!({"error": error.to_string()}),
        };
        assert_eq!(actual, case["expected"], "matrix input {input}");
    }
}

#[test]
fn compressed_bytes_and_malformed_refusals_match_native() {
    let fixture = fixtures();
    for mode in ["pack", "unpack"] {
        for case in fixture[mode].as_array().unwrap() {
            let input = hex::decode(case["input"].as_str().unwrap()).unwrap();
            let result = if mode == "pack" {
                compression::pack(&input)
            } else {
                compression::unpack(&input)
            };
            let actual = match result {
                Ok(bytes) => json!({"bytes": hex::encode(bytes)}),
                Err(error) => json!({"error": error.to_string()}),
            };
            assert_eq!(actual, case["expected"], "{mode}, input {}", case["input"]);
        }
    }
}

#[test]
fn legacy_and_malformed_key_imports_match_native() {
    let fixture = fixtures();
    for mode in ["import_pub", "import_sec"] {
        for (index, case) in fixture[mode].as_array().unwrap().iter().enumerate() {
            let input = hex::decode(case["input"].as_str().unwrap()).unwrap();
            let result = if mode == "import_pub" {
                PublicKey::from_bytes(&input).map(|key| hex::encode(key.to_raw_bytes()))
            } else {
                SecretKey::from_bytes(&input).map(|key| hex::encode(key.to_bytes().as_slice()))
            };
            let actual = match result {
                Ok(bytes) => json!({"bytes": bytes}),
                Err(error) => json!({"error": error.to_string()}),
            };
            assert_eq!(actual, case["expected"], "{mode}, case {index}");
        }
    }
}
