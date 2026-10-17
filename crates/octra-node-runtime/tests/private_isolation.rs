//! Full existing native primitive corpus through the actual packaged helper.
//! No proof verdict is supplied to the process or fabricated by this test.
#[path = "common/crypto_worker.rs"]
mod common;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_hfhe::scalar::ScalarRule;
use octra_node_runtime::private_crypto::isolated::{
    self as crypto, AmountProof, Error, ResultPolicy,
};
use serde_json::{json, Value};
use std::sync::{atomic::AtomicBool, Arc};
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
        .map(|value| json!(STANDARD.encode(value))),
    }
}
#[test]
fn native_private_corpus_survives_actual_process_images_and_errors() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/private-crypto.json")).unwrap();
    let _scope = common::scope(false);
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 259);
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let actual = match run(&case["input"]) {
            Ok(value) => json!({"ok":value}),
            Err(Error::Rejected(reason)) => json!({"error":STANDARD.encode(reason)}),
            Err(Error::Unavailable(reason)) if case["expected"].get("exception").is_some() => {
                json!({"exception":format!("Failure({reason:?})")})
            }
            Err(error) => panic!("native private worker case {index}: {error}"),
        };
        assert_eq!(
            actual, case["expected"],
            "native private process case {index}: {}",
            case["input"]["name"]
        );
    }
}
#[test]
fn scoped_cancellation_or_expiry_never_runs_local_key_decode() {
    let pool = common::pool();
    {
        let _scope = pool.scope(false, Arc::new(AtomicBool::new(true)));
        assert!(
            matches!(
                crypto::load_pubkey(b"malformed public key"),
                Err(Error::Unavailable(_))
            ),
            "local fallback would deterministically reject this key"
        );
    }
    {
        let _scope = pool.scope_until(
            false,
            Arc::new(AtomicBool::new(false)),
            std::time::Instant::now(),
        );
        assert!(matches!(
            crypto::decode_cipher(b"bad cipher", true, true),
            Err(Error::Unavailable(_))
        ));
    }
    let _scope = common::scope(false);
    assert!(
        matches!(
            crypto::load_pubkey(b"malformed public key"),
            Err(Error::Rejected(_))
        ),
        "released worker must execute actual validation again"
    );
}
