use octra_hfhe::{
    cipher::Cipher,
    encrypt,
    keys::{keygen_from_seed, CircuitProfile, Params},
    recrypt::{legacy, public},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
mod common;
#[test]
fn native_legacy_reset_rebalance_rank_and_shape() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/recrypt_legacy.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-recrypt-legacy-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 130);
    for (index, case) in cases.iter().enumerate() {
        let params = Params {
            basis: 126,
            m_bits: 65,
            n_bits: 17,
            h_col_weight: 13,
            x_col_weight: 7,
            error_weight: 2,
            lpn_n: 65,
            lpn_t: 127,
            noise_entropy_bits: case["noise"].as_f64().unwrap(),
            ..Params::default()
        };
        let (mut public, secret) =
            keygen_from_seed(params, &std::array::from_fn(|i| i as u8)).unwrap();
        public.set_circuit_profile(
            &secret,
            if case["profile"] == 1 {
                CircuitProfile::MimcX3V6
            } else {
                CircuitProfile::MimcX5V7
            },
        );
        let mut seed = std::array::from_fn(|i| 31 - i as u8);
        let values = (0..case["slots"].as_u64().unwrap())
            .map(|i| case["value"].as_u64().unwrap() + i)
            .collect::<Vec<_>>();
        let mut input = if case["variant"] == 3 {
            Cipher::default()
        } else {
            encrypt::values_seeded(&public, &secret, &values, &seed).unwrap()
        };
        if case["variant"] == 1 {
            input = input.square_seeded(&public, &seed, 4, true).unwrap();
        }
        if case["variant"] == 2 {
            input = input.add(&public, &input).unwrap();
        }
        let layers = case["layers"].as_u64().unwrap() as usize;
        let expected = &case["expected"];
        let result = if case["operation"] == 0 {
            legacy::make_key_seeded(&public, &secret, &input, layers, &seed).and_then(|key| {
                let output = legacy::apply_seeded(
                    &public,
                    &key,
                    &input,
                    &seed,
                    case["edges"].as_u64().unwrap() as usize,
                )?;
                let audit = key.audit(&input).unwrap();
                assert_eq!(
                    serde_json::json!(audit.rank),
                    expected["rank"],
                    "rank {index}"
                );
                assert_eq!(
                    serde_json::json!(audit.quotient),
                    expected["quotient"],
                    "quotient {index}"
                );
                assert_eq!(
                    audit.reusable_public_safe,
                    expected["reusable_public_safe"].as_bool().unwrap(),
                    "public key safety {index}"
                );
                assert_eq!(
                    key.require_reusable_public_safe(&input).is_ok(),
                    audit.reusable_public_safe
                );
                Ok(output)
            })
        } else {
            let mut key = legacy::EvalKey {
                zero_pool: Vec::new(),
                enc_one: encrypt::value_seeded(&public, &secret, 1, &seed).unwrap(),
            };
            for pool in 0..layers {
                seed[0] = pool as u8;
                key.zero_pool
                    .push(encrypt::zero_seeded(&public, &secret, &seed).unwrap());
            }
            seed[0] = 31;
            legacy::rebalance_seeded(&public, &key, &input, &seed)
        };
        if let Some(error) = expected["error"].as_str() {
            assert_eq!(result.err().unwrap().to_string(), error, "error {index}");
            continue;
        }
        let output = result.unwrap();
        assert_eq!(
            hex::encode(output.to_bytes().unwrap()),
            expected["bytes"],
            "full ciphertext {index}"
        );
        assert_eq!(
            legacy::sigma_needs_balance(&public, &input),
            expected["needs_balance"].as_bool().unwrap(),
            "density {index}"
        );
        assert_eq!(
            public::Key::new(2, 16, 1)
                .unwrap()
                .shape_ok(&public, &input, &output),
            expected["public_shape"].as_bool().unwrap(),
            "public shape {index}"
        );
    }
}
