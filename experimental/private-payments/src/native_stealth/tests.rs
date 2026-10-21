use super::*;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../tests/native-stealth.json")).unwrap()
}
fn bytes<const N: usize>(value: &Value) -> [u8; N] {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn actual_native_view_ecdh_tag_and_claim_bindings_match() {
    let f = fixture();
    assert_eq!(
        f["oracle"]["upstream_commit"],
        "549536d6fbe265a4aace02bc9b85b5313ebb4868"
    );
    let secret = view_secret(&bytes(&f["seed"]));
    assert_eq!(*secret, bytes(&f["view_secret"]));
    let public = view_public(&secret);
    assert_eq!(public, bytes(&f["view_public"]));
    let key = shared(&bytes(&f["ephemeral_secret"]), &public).unwrap();
    assert_eq!(*key, bytes(&f["shared"]));
    assert_eq!(tag(&key), bytes(&f["tag"]));
    let claim = claim_secret(&key);
    assert_eq!(*claim, bytes(&f["claim_secret"]));
    assert_eq!(
        claim_public(&claim, f["recipient"].as_str().unwrap().as_bytes()),
        bytes(&f["claim_public"])
    );
    assert_ne!(
        claim_public(&claim, b"another recipient"),
        bytes(&f["claim_public"])
    );
}

#[test]
fn actual_native_aes_payloads_match_byte_for_byte() {
    let f = fixture();
    let key = bytes(&f["shared"]);
    for case in f["cases"].as_array().unwrap() {
        assert_eq!(case["native_round_trip"], true);
        let encoded = case["encrypted"].as_str().unwrap();
        let raw = STANDARD.decode(encoded).unwrap();
        let expected = Amount::new(
            case["amount"].as_str().unwrap().parse().unwrap(),
            bytes(&case["blinding"]),
        );
        let opened = open(&key, encoded).unwrap();
        assert_eq!(opened.value(), expected.value());
        assert_eq!(opened.blinding(), expected.blinding());
        assert_eq!(
            seal_with_nonce(&key, &expected, raw[..12].try_into().unwrap()).unwrap(),
            encoded
        );
    }
}

#[test]
fn authentication_rejects_each_corrupt_byte_wrong_key_and_wrong_length() {
    let f = fixture();
    let key = bytes(&f["shared"]);
    let encoded = f["cases"][2]["encrypted"].as_str().unwrap();
    let raw = STANDARD.decode(encoded).unwrap();
    for index in 0..raw.len() {
        let mut corrupt = raw.clone();
        corrupt[index] ^= 1;
        assert!(
            open(&key, &STANDARD.encode(corrupt)).is_err(),
            "byte {index}"
        );
    }
    let mut wrong_key = key;
    wrong_key[0] ^= 1;
    assert!(open(&wrong_key, encoded).is_err());
    assert!(open(&key, &STANDARD.encode(&raw[..67])).is_err());
    let mut oversized = raw;
    oversized.push(0);
    assert!(open(&key, &STANDARD.encode(oversized)).is_err());
    assert!(open(&key, &"A".repeat(1_000_000)).is_err());
    assert!(open(&key, &"?".repeat(92)).is_err());
}

#[test]
fn fresh_payloads_use_random_nonces_and_remain_decodable() {
    let key = [42; 32];
    let value = Amount::new(17, [81; 32]);
    let first = seal(&key, &value).unwrap();
    let second = seal(&key, &value).unwrap();
    assert_ne!(&first[..16], &second[..16]);
    for encoded in [first, second] {
        let opened = open(&key, &encoded).unwrap();
        assert_eq!(opened.value(), 17);
        assert_eq!(opened.blinding(), &[81; 32]);
    }
}

#[test]
fn low_order_view_peers_never_produce_a_shared_key() {
    assert!(shared(&[7; 32], &[0; 32]).is_err());
    let mut identity = [0; 32];
    identity[0] = 1;
    assert!(shared(&[7; 32], &identity).is_err());
}
