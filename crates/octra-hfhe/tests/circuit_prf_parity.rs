mod common;

use octra_hfhe::{
    circuit_prf,
    field::Fp,
    keys::{keygen_from_seed, CircuitProfile, Params},
};
use serde_json::Value;

fn fixture() -> Value {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/circuit-prf.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    fixture
}

fn profile(value: &Value) -> CircuitProfile {
    match value.as_u64().unwrap() {
        1 => CircuitProfile::MimcX3V6,
        2 => CircuitProfile::MimcX5V7,
        _ => panic!("fixture profile rejected"),
    }
}

fn word(value: &Value) -> u64 {
    value.as_str().unwrap().parse().unwrap()
}

fn field_hex(value: Fp) -> String {
    hex::encode(value.to_bytes_le())
}

fn check_fields(values: &[Fp], expected: &Value) {
    let actual: Vec<_> = values.iter().copied().map(field_hex).collect();
    assert_eq!(serde_json::to_value(actual).unwrap(), *expected);
}

fn check_points(values: &[[u8; 32]], expected: &Value) {
    let actual: Vec<_> = values.iter().map(hex::encode).collect();
    assert_eq!(serde_json::to_value(actual).unwrap(), *expected);
}

#[test]
fn active_round_constants_powers_and_profiles_match_native() {
    for case in fixture()["rounds"].as_array().unwrap() {
        let profile = profile(&case["profile"]);
        let input = Fp::from_words(word(&case["value"][0]), word(&case["value"][1]));
        assert_eq!(
            field_hex(circuit_prf::round_constant(
                profile,
                word(&case["round"]) as usize
            )),
            case["expected"]["constant"]
        );
        assert_eq!(
            field_hex(circuit_prf::power(profile, input)),
            case["expected"]["power"]
        );
        assert_eq!(
            circuit_prf::proof_version(profile),
            case["expected"]["version"]
        );
        assert_eq!(circuit_prf::ROUNDS as u64, case["expected"]["rounds"]);
    }
}

#[test]
fn active_masks_noise_and_complete_layer_commitments_match_native() {
    for case in fixture()["cases"].as_array().unwrap() {
        let seed: [u8; 32] = hex::decode(case["seed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let params = Params {
            m_bits: 65,
            n_bits: 17,
            h_col_weight: 13,
            x_col_weight: 7,
            error_weight: 2,
            lpn_n: case["n"].as_i64().unwrap() as i32,
            lpn_t: case["t"].as_i64().unwrap() as i32,
            lpn_tau_num: case["num"].as_i64().unwrap() as i32,
            lpn_tau_den: case["den"].as_i64().unwrap() as i32,
            ..Params::default()
        };
        let (mut public, secret) = keygen_from_seed(params, &seed).unwrap();
        public.set_circuit_profile(&secret, profile(&case["profile"]));
        let tag = word(&case["tag"]);
        let nonce = [word(&case["nonce"][0]), word(&case["nonce"][1])];
        let count = case["count"].as_u64().unwrap() as usize;
        let index = word(&case["index"]) as usize;
        let gid = case["gid"].as_u64().unwrap() as u32;
        let kind = case["kind"].as_u64().unwrap() as u8;
        let expected = &case["expected"];
        assert!(expected.get("error").is_none());
        assert_eq!(
            field_hex(circuit_prf::challenge(&public, tag, nonce, index).unwrap()),
            expected["challenge"]
        );
        assert_eq!(
            field_hex(circuit_prf::prf_r(&public, &secret, tag, nonce, index).unwrap()),
            expected["r"]
        );
        assert_eq!(
            hex::encode(*circuit_prf::rho_prod(&secret, nonce, index)),
            expected["rho_prod"]
        );
        assert_eq!(
            hex::encode(*circuit_prf::r_alpha(&secret, nonce, index)),
            expected["r_alpha"]
        );
        let masks = circuit_prf::slots(&public, &secret, tag, nonce, count).unwrap();
        check_fields(&masks, &expected["masks"]);
        assert_eq!(circuit_prf::slots_nonzero(&masks), expected["nonzero"]);
        let delta =
            circuit_prf::delta_slots(&public, &secret, tag, nonce, gid, kind, count).unwrap();
        check_fields(&delta, &expected["delta"]);
        assert_eq!(
            field_hex(circuit_prf::delta_scalar(&public, &secret, tag, nonce, gid, kind).unwrap()),
            expected["scalar_delta"]
        );
        assert_eq!(
            field_hex(
                circuit_prf::lpn_v2_core(&public, &secret, tag, nonce, b"pvac.v2.prf.noise.1")
                    .unwrap()
            ),
            expected["noise_core"]
        );
        assert_eq!(
            field_hex(circuit_prf::lpn_v2_noise(&public, &secret, tag, nonce).unwrap()),
            expected["noise"]
        );
        let commitment = circuit_prf::base_commitment(&public, tag, nonce, &masks);
        assert_eq!(hex::encode(commitment), expected["base_commitment"]);
        assert_eq!(
            hex::encode(circuit_prf::product_commitment(
                &commitment,
                &public.circuit_commitment()
            )),
            expected["product_commitment"]
        );
        let (r_pc, pc) = circuit_prf::layer_commitments(&secret, nonce, &masks).unwrap();
        check_points(&r_pc, &expected["r_pc"]);
        check_points(&pc, &expected["pc"]);
        check_points(
            &circuit_prf::product_commitments(&secret, nonce, &masks, &delta).unwrap(),
            &expected["product_pc"],
        );
    }
    assert!(circuit_prf::slots_nonzero(&[]));
    assert!(!circuit_prf::slots_nonzero(&[Fp::ONE, Fp::ZERO]));
}

#[test]
fn full_toeplitz_output_window_and_rejections_match_native() {
    for case in fixture()["toeplitz"].as_array().unwrap() {
        let words = |name| {
            case[name]
                .as_array()
                .unwrap()
                .iter()
                .map(word)
                .collect::<Vec<_>>()
        };
        let actual = circuit_prf::toeplitz_127_full(
            &words("top"),
            &words("y"),
            case["bits"].as_u64().unwrap() as usize,
        );
        if let Some(error) = case["expected"].get("error") {
            assert_eq!(actual.unwrap_err().to_string(), error.as_str().unwrap());
        } else {
            let bytes: Vec<_> = actual
                .unwrap()
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect();
            assert_eq!(hex::encode(bytes), case["expected"]["bits"]);
        }
    }
}
