mod common;

use octra_hfhe::seeded_rng::{derive_key, CtrRng};
use serde_json::Value;

#[test]
fn seeded_aes_counter_and_entropy_consumption_match_native() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/rng.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 140);
    for case in cases {
        let key: [u8; 32] = hex::decode(case["input"][0].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let nonce = case["input"][1].as_str().unwrap().parse().unwrap();
        let mut rng = CtrRng::new(&key, nonce);
        let mut actual = vec![rng.next_u64().to_string()];
        let mut block = [0; 5];
        rng.fill_u64(&mut block);
        actual.extend(block.map(|value| value.to_string()));
        for limit in [0, 1, 2, 3, 337, 8192, (1 << 63) + 1, u64::MAX] {
            actual.push(rng.bounded(limit).to_string());
        }
        actual.push(rng.next_u64().to_string());
        let mut seeded = CtrRng::seeded(&key);
        actual.push(hex::encode(seeded.fp_nonzero().to_bytes_le()));
        actual.extend(seeded.nonce128().map(|value| value.to_string()));
        let (derived, derived_nonce) = derive_key(
            &[1, 2, 3, u64::MAX],
            nonce,
            &key,
            337,
            [nonce, u64::MAX],
            b"pvac.prf.r.1",
        );
        actual.push(hex::encode(derived.as_ref()));
        actual.push(derived_nonce.to_string());
        let expected: Vec<_> = case["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(actual, expected, "input {}", case["input"]);
    }
}
