use base64::{engine::general_purpose::STANDARD, Engine};
use octra_hfhe::scalar::ScalarRule;
use octra_node_runtime::private_crypto::{self as crypto, AmountProof, Error, ResultPolicy};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn run(input: &Value) -> Result<Value, Error> {
    let current = bytes(&input["current"]);
    let delta = bytes(&input["delta"]);
    let strict = input["strict"].as_bool().unwrap();
    let cap = input["cap"].as_bool().unwrap();
    let math = if input["math"] == true {
        ScalarRule::Wide
    } else {
        ScalarRule::Prior
    };
    let policy = if input["recoverable"] == true {
        ResultPolicy::Recoverable
    } else {
        ResultPolicy::Legacy
    };
    match input["operation"].as_str().unwrap() {
        "guard" => crypto::check_private_input(&current, cap).map(|()| Value::Null),
        "refresh" => crypto::check_refresh_source(&current, cap).map(|()| Value::Null),
        "proof" => crypto::verify_amount(
            &crypto::proof_pubkey(&bytes(&input["public"]))?,
            &input["amount"].as_str().unwrap().parse().unwrap(),
            &AmountProof {
                cipher: &delta,
                proof: &bytes(&input["proof"]),
                commitment: &bytes(&input["commitment"]),
                blinding: &bytes(&input["blinding"]),
            },
            strict,
            math,
        )
        .map(|()| Value::Null),
        "range" => crypto::verify_range(
            &crypto::proof_pubkey(&bytes(&input["public"]))?,
            &current,
            &bytes(&input["range"]),
            strict,
            math,
        )
        .map(Value::Bool),
        operation => crypto::balance(
            &crypto::load_pubkey(&bytes(&input["public"]))?,
            &current,
            &crypto::decode_cipher(&delta, false, cap)?,
            operation == "withdraw",
            cap,
            policy,
        )
        .map(|v| json!(STANDARD.encode(v))),
    }
}
#[test]
fn native_private_proofs_arithmetic_and_recovery_boundaries() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/private-crypto.json")).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inventory: Value = serde_json::from_slice(
        &std::fs::read(root.join("docs/rust-node/source-map.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (key, name) in [
        ("oracle_sha256", "private-crypto-oracle.ml"),
        ("runner_sha256", "native-oracle.py"),
        ("generator_sha256", "private-crypto-fixtures.py"),
        ("material_generator_sha256", "private-balance-material.cpp"),
        ("entropy_adapter_sha256", "hfhe-zero-oracle.cpp"),
    ] {
        assert_eq!(
            fixture[key],
            hex::encode(Sha256::digest(
                std::fs::read(root.join("scripts/node-port").join(name)).unwrap()
            ))
        );
    }
    let mut valid_amount = 0;
    let mut valid_range = 0;
    let mut refusals = 0;
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let actual = match run(input) {
            Ok(value) => json!({"ok":value}),
            Err(Error::Rejected(reason)) => {
                refusals += 1;
                json!({"error":STANDARD.encode(reason)})
            }
            Err(Error::Unavailable(error)) if !error.is_operational() => {
                json!({"exception":format!("Failure({:?})",error.0)})
            }
            Err(error) => panic!("case {index}: {error}"),
        };
        assert_eq!(actual, case["expected"], "case {index}: {}", input["name"]);
        valid_amount += usize::from(input["operation"] == "proof" && actual.get("ok").is_some());
        valid_range += usize::from(input["operation"] == "range" && actual["ok"] == true);
    }
    assert!(valid_amount >= 2 && valid_range >= 2 && refusals >= 20);
}
