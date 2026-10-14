use ed25519_dalek::SigningKey;
use octra_node_protocol::{
    consensus::{Validator, ValidatorSet},
    network::handshake,
};
use octra_node_runtime::query_peers;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[test]
fn native_query_rotation_validator_priority_and_waves() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/query-peers.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (field, file) in [
        ("oracle_sha256", "scripts/node-port/query-peers-oracle.ml"),
        ("runner_sha256", "scripts/node-port/native-oracle.py"),
    ] {
        assert_eq!(
            fixture[field],
            hex::encode(Sha256::digest(fs::read(root.join(file)).unwrap()))
        );
    }
    let public = |n: u8| SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes();
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let set = ValidatorSet::unweighted(
            (1..=input["validators"].as_u64().unwrap())
                .map(|n| Validator {
                    address: format!("v{n}").into_bytes(),
                    pubkey: public(n as u8).to_vec(),
                })
                .collect(),
        );
        let connected = input["connected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| match v.as_u64() {
                Some(n) => handshake::node_id(&public(n as u8)),
                None => hex::decode(v.as_str().unwrap()).unwrap(),
            })
            .collect::<Vec<_>>();
        let seed = hex::decode(input["seed"].as_str().unwrap()).unwrap();
        let ordered = query_peers::ordered(&set, &seed, &connected);
        let encoded = |v: &[Vec<u8>]| v.iter().map(hex::encode).collect::<Vec<_>>();
        assert_eq!(
            json!({
                "connected": encoded(&connected), "ordered": encoded(&ordered),
                "offset": query_peers::offset(&seed,input["count"].as_u64().unwrap() as usize),
                "waves": query_peers::bundle_waves(ordered).iter().map(|v| encoded(v)).collect::<Vec<_>>()
            }),
            case["expected"],
            "native peer plan {index}"
        );
    }
}
