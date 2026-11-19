//! Validator eviction updates against output captured from the unchanged
//! native `Validator_set_update` at the candidate commit.
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    consensus::{hash, Validator, ValidatorSet},
    control_payload::ValidatorUpdate,
    transaction,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn b64(raw: &[u8]) -> Value {
    json!(STANDARD.encode(raw))
}
fn raw(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn int(value: &Value) -> i64 {
    value.as_str().unwrap().parse().unwrap()
}
fn address(id: u8) -> Vec<u8> {
    transaction::address_from_public_key(STANDARD.encode([id; 32]).as_bytes())
}
fn set(weights: impl Iterator<Item = i64>) -> ValidatorSet {
    ValidatorSet::weighted(
        weights
            .enumerate()
            .map(|(index, weight)| {
                let id = index as u8 + 1;
                (
                    Validator {
                        address: address(id),
                        pubkey: vec![id; 32],
                    },
                    weight.into(),
                )
            })
            .collect(),
    )
    .unwrap()
}
fn fixture() -> Value {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/validator-eviction-candidate.json")).unwrap();
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../docs/rust-node/source-map-candidate.json"
    ))
    .unwrap();
    assert_eq!(fixture["upstream_commit"], manifest["upstream_commit"]);
    for (path, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, manifest["files"][path], "candidate source {path}");
    }
    for (key, bytes) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/candidate-eviction-oracle.ml").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/candidate-eviction-oracle.py").as_slice(),
        ),
        (
            "dependency_runner_sha256",
            include_bytes!("../../../scripts/node-port/candidate-staging-intake-oracle.py")
                .as_slice(),
        ),
    ] {
        assert_eq!(fixture[key], hex::encode(Sha256::digest(bytes)), "{key}");
    }
    fixture
}
#[allow(clippy::needless_pass_by_value)] // Callers hand over owned error text.
fn failed(reason: impl ToString) -> Value {
    json!({"error": reason.to_string()})
}
fn parsed(stored: &[u8], epochs: &[i64]) -> Value {
    match ValidatorUpdate::of_string(stored) {
        Err(error) => failed(error),
        Ok(update) => json!({
            "fingerprint": update.fingerprint,
            "activate": update.activate_epoch.to_string(),
            "eviction": update.eviction.as_ref().map(|eviction| json!([
                eviction.epoch.to_string(),
                eviction.offenders.iter().map(|address| String::from_utf8(address.clone()).unwrap()).collect::<Vec<_>>(),
            ])),
            "bytes": b64(&update.to_bytes()),
            "set_at": epochs.iter().map(|epoch| {
                match update.check_set_at(octra_node_protocol::consensus::policy::DEVNET, *epoch) {
                    Ok(()) => json!(true),
                    Err(error) => failed(error.0),
                }
            }).collect::<Vec<_>>(),
        }),
    }
}
fn case(input: &Value, expected: &Value, epochs: &[i64]) -> Value {
    let weights = || {
        input["weights"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_i64().unwrap())
    };
    let current = set(weights());
    let other = set(weights().map(|weight| weight + 1));
    let offenders: Vec<_> = input["offenders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| address(id.as_u64().unwrap() as u8))
        .collect();
    let source = int(&input["source_epoch"]);
    let activate = source + int(&input["gap"]);
    let (update, weight) =
        match ValidatorUpdate::make_eviction(source, activate, &offenders, &current) {
            Ok(made) => made,
            Err(error) => return failed(error.0),
        };
    let check = |current: &ValidatorSet| update.check_eviction(source, &offenders, current);
    json!({
        "raw": b64(&update.to_bytes()),
        "weight": weight.to_string(),
        "check": match check(&current) {
            Ok((next, weight)) => json!([b64(&hash::validator_set_hash(&next).unwrap()), weight.to_string()]),
            Err(error) => failed(error.0),
        },
        "check_other": match check(&other) { Ok(_) => json!(true), Err(error) => failed(error.0) },
        // Each stored form is an input: the canonical update and the ways it
        // was altered. Only what the parser makes of it is compared.
        "parsed": expected["parsed"].as_array().map(|entries| entries.iter().map(|entry| json!({
            "name": entry["name"], "raw": entry["raw"],
            "result": parsed(&raw(&entry["raw"]), epochs),
        })).collect::<Vec<_>>()),
    })
}
#[test]
fn native_eviction_updates_are_built_encoded_and_refused_alike() {
    let fixture = fixture();
    let epochs: Vec<_> = fixture["epochs"]
        .as_array()
        .unwrap()
        .iter()
        .map(int)
        .collect();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 80);
    let (mut built, mut stored) = (0, 0);
    for case_value in cases {
        let expected = &case_value["expected"];
        assert!(expected.get("raised").is_none(), "{}", case_value["input"]);
        assert_eq!(
            case(&case_value["input"], expected, &epochs),
            *expected,
            "{}",
            case_value["input"]
        );
        if let Some(entries) = expected["parsed"].as_array() {
            built += 1;
            stored += entries.len();
        }
    }
    assert_eq!((built, stored), (18, 540));
}
