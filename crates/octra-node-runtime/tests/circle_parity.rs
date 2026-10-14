//! Compare the Rust host API with complete outputs from the pristine engine.
use std::{path::Path, sync::Arc};

use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{circle_storage::StorageTable, circle_wasm::receipt};
use octra_node_runtime::circle::{CircleRuntime, Error, HfheBackend};
use serde_json::Value;
use sha2::{Digest, Sha256};

struct NoHfhe;
impl HfheBackend for NoHfhe {
    fn call(&self, _: &Value) -> Result<Value, Error> {
        panic!("registry fixture unexpectedly invoked HFHE")
    }
}

#[test]
fn rust_host_matches_pristine_engine_storage_events_metering_and_refusals() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/circle-engine.json")).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let wasm = std::fs::read(
        root.join("target/wasm32-unknown-unknown/release/octravpn_circle_registry.wasm"),
    )
    .expect("build the registry WASM before runtime parity tests");
    assert_eq!(hex::encode(Sha256::digest(&wasm)), fixture["wasm_sha256"]);
    let pin: Value =
        serde_json::from_slice(&std::fs::read(root.join("docs/rust-node/upstream.json")).unwrap())
            .unwrap();
    assert_eq!(fixture["upstream_commit"], pin["commit"]);
    for (name, hash) in fixture["app_source_sha256"].as_object().unwrap() {
        assert_eq!(
            hex::encode(Sha256::digest(std::fs::read(root.join(name)).unwrap())),
            *hash,
            "stale registry fixture: {name}"
        );
    }
    let runtime = CircleRuntime::new(Arc::new(NoHfhe));
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for case in cases {
        let mut input = case["input"].clone();
        input["code_b64"] = Value::String(STANDARD.encode(&wasm));
        let result = runtime
            .execute(&serde_json::to_vec(&input).unwrap())
            .unwrap();
        let actual: Value = serde_json::from_slice(result.as_ref()).unwrap();
        assert_eq!(actual, case["expected"], "native input {}", case["input"]);
        if input["action"] == "describe" {
            let methods = octra_node_protocol::circle_wasm::methods(result.as_ref()).unwrap();
            assert_eq!(methods.len(), 3);
            continue;
        }
        let mut before = StorageTable::new(8);
        if let Some(items) = input["storage_pairs"].as_array() {
            for pair in items {
                before.replace(
                    STANDARD.decode(pair["key_b64"].as_str().unwrap()).unwrap(),
                    STANDARD
                        .decode(pair["value_b64"].as_str().unwrap())
                        .unwrap(),
                );
            }
        }
        let typed = runtime
            .execute_effects(&serde_json::to_vec(&input).unwrap(), &before)
            .unwrap();
        let expected =
            receipt::decode(&serde_json::to_vec(&case["expected"]).unwrap(), &before).unwrap();
        assert_eq!(typed, expected, "typed receipt for {}", case["input"]);
        if input["is_view"] == true {
            assert_eq!(typed.storage, before);
        }
    }
    assert!(matches!(
        runtime.execute(b"invalid-json"),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn native_input_limit_precedes_json_decoding() {
    use octra_node_runtime::circle::MAX_INPUT_BYTES;
    let runtime = CircleRuntime::new(Arc::new(NoHfhe));
    let bytes = vec![b'x'; MAX_INPUT_BYTES + 1];
    assert!(
        matches!(runtime.execute(&bytes),Err(Error::Rejected(error)) if error=="input too large: bytes=16777217 limit=16777216")
    );
    assert!(
        matches!(runtime.execute(&bytes[..MAX_INPUT_BYTES]),Err(Error::Rejected(error)) if !error.starts_with("input too large"))
    );
}
