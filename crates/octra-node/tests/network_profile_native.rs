//! The node must derive its actual HFHE engine commitment, rather than accept
//! the native KAT as an input to the protocol-only settings comparison.
use octra_node::network_profile::Profile;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[test]
fn node_profile_uses_native_crypto_engine_and_epoch_commitments() {
    let raw = include_bytes!("../../octra-node-protocol/tests/fixtures/consensus-profile-c49.json");
    assert_eq!(
        hex::encode(Sha256::digest(raw)),
        "9129961d1c0a326ed3625e748e94e37f8eb91ca8daef168c31ec30af79b72fc2"
    );
    let fixture: Value = serde_json::from_slice(raw).unwrap();
    assert_eq!(
        fixture["native_pin"],
        "c49de45cf49ebbc2e5c0697eb956cbcada5845e7"
    );
    let provenance_bytes = include_bytes!(
        "../../octra-node-protocol/tests/fixtures/consensus-profile-c49-provenance.json"
    );
    assert_eq!(
        fixture["build_provenance_sha256"],
        hex::encode(Sha256::digest(provenance_bytes))
    );
    let provenance: Value = serde_json::from_slice(provenance_bytes).unwrap();
    let sources: Value = serde_json::from_str(include_str!(
        "../../../docs/rust-node/source-map-candidate.json"
    ))
    .unwrap();
    assert_eq!(sources["upstream_commit"], fixture["native_pin"]);
    assert_eq!(provenance["upstream_commit"], fixture["native_pin"]);
    for (path, hash) in provenance["source_sha256"].as_object().unwrap() {
        // Runtime manifests omit build recipes. This pinned original recipe
        // independently computes the compiler identity used by the profile.
        if path == "lib/vm/dune" {
            assert_eq!(
                hash.as_str(),
                Some("8d8fafa8e566621c1e9920aecee4557a6feaeb90ab281bf7ae5cd97aebcaf1e4")
            );
        } else {
            assert_eq!(&sources["files"][path], hash, "candidate source {path}");
        }
    }
    assert_eq!(
        fixture["oracle_source_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/candidate-profile-oracle.ml"
        )))
    );
    let input_bytes =
        include_bytes!("../../octra-node-protocol/tests/fixtures/consensus-profile-inputs.json");
    assert_eq!(
        fixture["case_inputs_sha256"],
        hex::encode(Sha256::digest(input_bytes))
    );
    let inputs: Value = serde_json::from_slice(input_bytes).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 96);
    assert_eq!(inputs["cases"].as_array().unwrap().len(), cases.len());
    for (input, case) in inputs["cases"].as_array().unwrap().iter().zip(cases) {
        for field in ["id", "chain_id", "env"] {
            assert_eq!(input[field], case[field], "original profile input {field}");
        }
        assert_eq!(input["expect_valid"], case["valid"]);
    }
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
    assert_eq!(epochs, 1491);
}
