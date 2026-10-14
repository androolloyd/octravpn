mod common;

use octra_hfhe::{
    field::Fp,
    scalar::{Scalar, ScalarRule},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixtures() -> Value {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/scalars.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source], "native source {source}");
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-scalar-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    fixture
}
fn bytes<const N: usize>(value: &Value) -> [u8; N] {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn reduction_preserves_native_prior_and_wide_profiles() {
    let fixture = fixtures();
    let cases = fixture["reduction"].as_array().unwrap();
    assert_eq!(cases.len(), 2046);
    assert!(cases.iter().any(|case| case["prior"] != case["wide"]));
    for (index, case) in cases.iter().enumerate() {
        let input = bytes(&case["input"]);
        let mut words = [0; 8];
        for (word, input) in words.iter_mut().zip(input.chunks_exact(8)) {
            *word = u64::from_le_bytes(input.try_into().unwrap());
        }
        for (rule, name) in [(ScalarRule::Prior, "prior"), (ScalarRule::Wide, "wide")] {
            assert_eq!(
                hex::encode(rule.reduce_bytes(&input).to_bytes()),
                case[name],
                "{name} reduction {index}"
            );
            assert_eq!(
                hex::encode(rule.reduce(&words).to_bytes()),
                case[name],
                "{name} words {index}"
            );
        }
    }
}

#[test]
fn raw_scalar_arithmetic_and_inverses_match_native() {
    let fixture = fixtures();
    let cases = fixture["arithmetic"].as_array().unwrap();
    assert_eq!(cases.len(), 580);
    assert!(cases
        .iter()
        .any(|case| case["expected"]["mul_prior"] != case["expected"]["mul_wide"]));
    for (index, case) in cases.iter().enumerate() {
        let input = bytes(&case["left"]);
        let left = Scalar::from_bytes_raw(&input);
        let right = Scalar::from_bytes_raw(&bytes(&case["right"]));
        let expected = &case["expected"];
        assert_eq!(left.is_canonical(), expected["left_canonical"] == "1");
        assert_eq!(right.is_canonical(), expected["right_canonical"] == "1");
        assert_eq!(hex::encode(left.to_bytes()), case["left"]);
        assert_eq!(Scalar::from_words(left.to_words()).to_bytes(), input);
        for (name, actual) in [
            ("add", left + right),
            ("sub", left - right),
            ("neg", -left),
            ("mul_prior", ScalarRule::Prior.mul(left, right)),
            ("mul_wide", ScalarRule::Wide.mul(left, right)),
            ("inverse_prior", ScalarRule::Prior.inverse(left)),
            ("inverse_wide", ScalarRule::Wide.inverse(left)),
            ("reduce256", ScalarRule::Prior.reduce256(&input)),
        ] {
            assert_eq!(
                hex::encode(actual.to_bytes()),
                expected[name],
                "{name} case {index}"
            );
        }
        assert_eq!(
            hex::encode(ScalarRule::Wide.reduce256(&input).to_bytes()),
            expected["reduce256"]
        );
    }
}

#[test]
fn signed_and_unsigned_field_conversion_match_native() {
    let fixture = fixtures();
    let cases = fixture["field"].as_array().unwrap();
    assert_eq!(cases.len(), 138);
    for (index, case) in cases.iter().enumerate() {
        let value = Fp::from_bytes_le(bytes(&case["input"])).unwrap();
        assert_eq!(
            hex::encode(Scalar::from_fp(value).to_bytes()),
            case["unsigned"],
            "unsigned case {index}"
        );
        assert_eq!(
            hex::encode(Scalar::from_fp_signed(value).to_bytes()),
            case["signed"],
            "signed case {index}"
        );
    }
}
