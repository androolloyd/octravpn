mod common;

use octra_hfhe::{
    keys::{keygen_from_seed, Params},
    lpn,
};
use serde_json::Value;

fn fixture() -> Value {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/lpn.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    fixture
}

#[test]
fn retained_lpn_words_and_prf_fields_match_native() {
    for case in fixture()["lpn"].as_array().unwrap() {
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
        let (public, secret) = keygen_from_seed(params, &seed).unwrap();
        let tag = case["tag"].as_str().unwrap().parse().unwrap();
        let nonce = [
            case["nonce"][0].as_str().unwrap().parse().unwrap(),
            case["nonce"][1].as_str().unwrap().parse().unwrap(),
        ];
        let y = lpn::y_bits(&public, &secret, tag, nonce, b"pvac.prf.r.1").unwrap();
        let bytes: Vec<_> = y.iter().flat_map(|word| word.to_le_bytes()).collect();
        assert_eq!(hex::encode(bytes), case["expected"]["y"]);
        assert_eq!(
            hex::encode(
                lpn::prf_core(&public, &secret, tag, nonce, b"pvac.prf.r.1")
                    .unwrap()
                    .to_bytes_le()
            ),
            case["expected"]["core"]
        );
        assert_eq!(
            hex::encode(
                lpn::prf_r(&public, &secret, tag, nonce)
                    .unwrap()
                    .to_bytes_le()
            ),
            case["expected"]["r"]
        );
        assert_eq!(
            hex::encode(
                lpn::prf_noise(&public, &secret, tag, nonce)
                    .unwrap()
                    .to_bytes_le()
            ),
            case["expected"]["noise"]
        );
    }
}

#[test]
fn low_127_bit_convolution_matches_native_scalar_and_hardware() {
    for case in fixture()["toeplitz"].as_array().unwrap() {
        let words = |name| {
            case[name]
                .as_array()
                .unwrap()
                .iter()
                .map(|word| word.as_str().unwrap().parse().unwrap())
                .collect::<Vec<u64>>()
        };
        let output = lpn::toeplitz_127(&words("top"), &words("y"));
        let bytes: Vec<_> = output.iter().flat_map(|word| word.to_le_bytes()).collect();
        let actual = hex::encode(bytes);
        assert_eq!(actual, case["expected"]["scalar"]);
        assert_eq!(actual, case["expected"]["hardware"]);
    }
}
