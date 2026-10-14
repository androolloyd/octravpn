mod common;

use octra_hfhe::{
    decrypt::{self, DecPolicy},
    encrypt,
    field::Fp,
    keys::{keygen_from_seed, CircuitProfile, Params},
    seeded_rng::CtrRng,
};
use serde_json::Value;

#[test]
fn complete_seeded_ciphertexts_match_native_bytes_and_refusals() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/encrypt.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (path, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][path]);
    }
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let mut params = Params::default();
        if !case["full"].as_bool().unwrap() {
            params.m_bits = 65;
            params.n_bits = 17;
            params.h_col_weight = 13;
            params.x_col_weight = 7;
            params.error_weight = 2;
            params.lpn_n = 65;
            params.lpn_t = 127;
        }
        params.basis = case["basis"].as_i64().unwrap() as i32;
        params.noise_entropy_bits = case["entropy"].as_f64().unwrap();
        params.tuple2_fraction = case["fraction"].as_f64().unwrap();
        params.edge_budget = case["budget"].as_u64().unwrap();
        let key_seed: [u8; 32] = hex::decode(case["key_seed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let seed: [u8; 32] = hex::decode(case["seed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let values: Vec<u64> = case["values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().parse().unwrap())
            .collect();
        let (mut public, secret) = keygen_from_seed(params, &key_seed).unwrap();
        public.set_circuit_profile(
            &secret,
            if case["profile"] == 1 {
                CircuitProfile::MimcX3V6
            } else {
                CircuitProfile::MimcX5V7
            },
        );
        let depth = case["depth"].as_i64().unwrap() as i32;
        let actual = match case["operation"].as_str().unwrap() {
            "pipeline" => {
                let left = encrypt::values_seeded(&public, &secret, &values, &seed).unwrap();
                let right =
                    encrypt::values_seeded(&public, &secret, &values, &seed.map(|byte| byte ^ 255))
                        .unwrap();
                let shifted = left.add_constant(Fp::from_words(5, 0), true).unwrap();
                let scaled = right.mul_constant_u64(3);
                let product = shifted
                    .multiply_seeded(&public, &scaled, &seed, 8, true, 0)
                    .unwrap();
                let square = product.square_seeded(&public, &seed, 4, true).unwrap();
                let mut result = square
                    .divide_constant(Fp::from_words(7, 0))
                    .unwrap()
                    .subtract(&public, &left)
                    .unwrap();
                result.apply_ubk(&public).unwrap();
                Ok(result)
            }
            "value" => encrypt::value_seeded(&public, &secret, values[0], &seed),
            "value_depth" => encrypt::value_depth_seeded(&public, &secret, values[0], depth, &seed),
            "values" => encrypt::values_seeded(&public, &secret, &values, &seed),
            "zero" => encrypt::zero_seeded(&public, &secret, &seed),
            "raw" => encrypt::synthesize(
                &public,
                &secret,
                &values
                    .iter()
                    .map(|&v| Fp::from_words(v, 0))
                    .collect::<Vec<_>>(),
                depth,
                &mut CtrRng::seeded(&seed),
            ),
            _ => panic!("unexpected fixture mode"),
        };
        let expected = &case["expected"];
        if let Some(error) = expected.get("error") {
            assert_eq!(
                actual.unwrap_err().to_string(),
                error.as_str().unwrap(),
                "case {index}"
            );
        } else {
            let cipher = actual.unwrap();
            assert_eq!(
                hex::encode(cipher.to_bytes().unwrap()),
                expected["wire"],
                "case {index}"
            );
            let (n2, n3) = encrypt::plan_noise(&public, depth).unwrap();
            assert_eq!(
                serde_json::json!([n2, n3]),
                expected["noise"],
                "case {index}"
            );
            let clear = decrypt::values(&public, &secret, &cipher, DecPolicy::Standard).unwrap();
            let clear: Vec<_> = clear
                .iter()
                .map(|value| hex::encode(value.to_bytes_le()))
                .collect();
            assert_eq!(
                serde_json::to_value(clear).unwrap(),
                expected["clear"],
                "case {index}"
            );
        }
    }
}
