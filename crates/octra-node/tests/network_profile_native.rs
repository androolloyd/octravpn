//! The node must derive its actual HFHE engine commitment, rather than accept
//! the native KAT as an input to the protocol-only settings comparison.
use octra_node::network_profile::Profile;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[test]
fn node_profile_uses_native_crypto_engine_and_epoch_commitments() {
    let raw =
        include_bytes!("../../octra-node-protocol/tests/fixtures/consensus-profile-native.json");
    assert_eq!(
        hex::encode(Sha256::digest(raw)),
        "004d3981e170468ad8786696643d387d57cb40779ef861b159d6d7a3bb9b4d2b"
    );
    let fixture: Value = serde_json::from_slice(raw).unwrap();
    assert_eq!(
        fixture["native_pin"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    let mut valid = 0;
    let mut epochs = 0;
    for case in fixture["cases"].as_array().unwrap() {
        if !case["valid"].as_bool().unwrap() {
            continue;
        }
        valid += 1;
        let id = case["id"].as_str().unwrap();
        let values: BTreeMap<String, Vec<u8>> = case["env"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.as_str().unwrap().as_bytes().to_vec()))
            .collect();
        let profile = Profile::new(values).unwrap();
        assert_eq!(
            profile.status_release().crypto_engine,
            case["settings"]["crypto_engine"]
                .as_str()
                .unwrap()
                .as_bytes(),
            "{id}: actual node engine commitment"
        );
        for row in case["epochs"].as_array().unwrap() {
            epochs += 1;
            let epoch = row["epoch"].as_i64().unwrap();
            assert_eq!(
                hex::encode(
                    profile
                        .hash(case["chain_id"].as_str().unwrap().as_bytes(), epoch)
                        .unwrap()
                ),
                row["selected_hash"].as_str().unwrap(),
                "{id}: epoch {epoch}"
            );
        }
    }
    assert_eq!(valid, 57);
    assert_eq!(epochs, 1161);
}
