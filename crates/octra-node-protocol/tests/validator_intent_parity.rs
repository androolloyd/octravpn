use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use octra_node_protocol::{
    transaction::address_from_public_key,
    validator::intent::{Identity, Intent},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn public(id: u8) -> Vec<u8> {
    STANDARD
        .encode(SigningKey::from_bytes(&[id; 32]).verifying_key().as_bytes())
        .into_bytes()
}
fn outcome<T>(result: Result<T, impl std::fmt::Display>, f: impl FnOnce(T) -> Value) -> Value {
    match result {
        Ok(value) => f(value),
        Err(reason) => json!({"error":reason.to_string()}),
    }
}

#[test]
fn signed_exit_intents_match_native_bytes_and_registration_replay_guards() {
    let report: Value = serde_json::from_str(include_str!("fixtures/duty-intent.json")).unwrap();
    let map: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(report["upstream_commit"], map["upstream_commit"]);
    assert_eq!(report["source_sha256"], map["files"]);
    assert_eq!(report["instrumentation"], json!({}));
    for (key, raw) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/duty-intent-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/duty-intent-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(report[key], hex::encode(Sha256::digest(raw)), "{key}");
    }
    let cases = report["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    for case in cases {
        let input = &case["input"];
        let expected = &case["expected"];
        let id: u8 = input["key"].as_u64().unwrap().try_into().unwrap();
        let mut pubkey = public(id);
        if input["bad_public"] == true {
            pubkey.push(b'=');
        }
        let identity = Identity {
            chain_id: input["chain"].as_str().unwrap().as_bytes().to_vec(),
            address: address_from_public_key(&public(if input["bad_address"] == true {
                id + 1
            } else {
                id
            })),
            pubkey,
            bonded_epoch: input["epoch"].as_str().unwrap().parse().unwrap(),
        };
        let private_id: u8 = input["private_key"].as_u64().unwrap().try_into().unwrap();
        let result = Intent::create(
            identity.clone(),
            STANDARD.encode([private_id; 32]).as_bytes(),
        );
        if let Some(reason) = expected["error"].as_str() {
            assert_eq!(result.unwrap_err().to_string(), reason, "{input}");
            continue;
        }
        let intent = result.unwrap();
        assert_eq!(
            intent.encode(),
            expected["encoded"].as_str().unwrap().as_bytes()
        );
        assert_eq!(intent.id().unwrap(), expected["id"].as_str().unwrap());
        let raw = expected["raw"].as_str().unwrap().as_bytes();
        let actual = outcome(Intent::decode(raw), |decoded| {
            let mut current = identity;
            current.bonded_epoch = input["expected_epoch"].as_str().unwrap().parse().unwrap();
            if input["other_chain"] == true {
                current.chain_id = b"another-chain".to_vec();
            }
            json!({"encoded":String::from_utf8(decoded.encode()).unwrap(),
                "applies":outcome(decoded.applies(&current),|value|json!(value))})
        });
        assert_eq!(actual, expected["decoded"], "{input}");
    }
}
