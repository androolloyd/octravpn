mod common;

use octra_hfhe::field::Fp;
use serde_json::Value;

#[test]
fn field_bytes_match_pinned_cpp_at_boundaries_and_random_inputs() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/field.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    assert_eq!(
        fixture["source_sha256"],
        sources["files"][fixture["source"].as_str().unwrap()]
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 1629);
    for case in cases {
        let input: Vec<u64> = case["input"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().parse().unwrap())
            .collect();
        let a = Fp::from_words(input[0], input[1]);
        let b = Fp::from_words(input[2], input[3]);
        let results = [
            a,
            b,
            a + b,
            a - b,
            -a,
            a * b,
            a.pow_u64(input[4]),
            a.inverse(),
        ];
        let mut actual: Vec<String> = results
            .iter()
            .map(|value| hex::encode(value.to_bytes_le()))
            .collect();
        actual.push(
            a.to_i64()
                .map_or_else(|| "none".into(), |value| value.to_string()),
        );
        let expected: Vec<_> = case["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(actual, expected, "input {input:?}");
        for value in results {
            assert_eq!(Fp::from_bytes_le(value.to_bytes_le()), Some(value));
        }
    }
    assert!(Fp::from_bytes_le(((1_u128 << 127) - 1).to_le_bytes()).is_none());
    assert!(Fp::from_bytes_le(u128::MAX.to_le_bytes()).is_none());
}
