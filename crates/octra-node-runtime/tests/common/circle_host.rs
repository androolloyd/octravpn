use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_runtime::{
    circle::{CircleRuntime, Error, HfheBackend},
    circle_store::{StableEntry, StableValue},
    state_batch::StateBatch,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

#[allow(dead_code)] // Shared by application suites; transaction-only suites also import this module.
pub(crate) fn view_profile(
    assets: &octra_node_runtime::circle_assets::CanonicalAssets,
    wasm: octra_node_runtime::circle::WasmRules,
) -> octra_node_runtime::circle_view::Profile {
    use octra_node_protocol::transaction::RuleMode;
    let epoch = octra_node_runtime::circle_view::epoch(
        assets.snapshot().get(&[b"meta", b"last_epoch"]),
        octra_node_runtime::circle_view::ReadKind::View,
    )
    .unwrap();
    octra_node_runtime::circle_view::Profile {
        math: wasm.math,
        proof_exec: if wasm.proof_exec {
            RuleMode::Active
        } else {
            RuleMode::Prior
        },
        wasm_float: if wasm.wasm_float {
            RuleMode::Active
        } else {
            RuleMode::Prior
        },
        ..octra_node_runtime::circle_view::Profile::prior(epoch)
    }
}

pub(crate) fn fixture() -> &'static Value {
    static FIXTURE: OnceLock<Value> = OnceLock::new();
    FIXTURE
        .get_or_init(|| serde_json::from_str(include_str!("../fixtures/circle-view.json")).unwrap())
}
pub(crate) fn runtime() -> CircleRuntime {
    struct NoHfhe;
    impl HfheBackend for NoHfhe {
        fn call(&self, _: &Value) -> Result<Value, Error> {
            panic!("public counter unexpectedly invoked HFHE")
        }
    }
    CircleRuntime::new(Arc::new(NoHfhe))
}
#[allow(dead_code)] // Used by browser and signed OCTB integration suites.
pub(crate) fn install_octb_counter(state: &mut StateBatch, circle: &[u8]) {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/circle-octb-view.json")).unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["input"]["name"] == "browser counter")
        .unwrap();
    for entry in case["input"]["entries"].as_array().unwrap() {
        let mut path = entry["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| STANDARD.decode(v.as_str().unwrap()).unwrap())
            .collect::<Vec<_>>();
        if path[0] != b"circles" {
            continue;
        }
        path[1] = circle.to_vec();
        state
            .set(
                &path.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                STANDARD.decode(entry["value"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
    }
}
pub(crate) fn install_counter(state: &mut StateBatch, circle: &[u8], count: &[u8]) {
    let fixture = fixture();
    for entry in fixture["cases"][0]["input"]["entries"].as_array().unwrap() {
        let mut path = entry["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| STANDARD.decode(v.as_str().unwrap()).unwrap())
            .collect::<Vec<_>>();
        if path[0] != b"circles" {
            continue;
        }
        path[1] = circle.to_vec();
        state
            .set(
                &path.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                STANDARD.decode(entry["value"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
    }
    let wasm = STANDARD
        .decode(fixture["wasm_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(fixture["wasm_sha256"], hex::encode(Sha256::digest(&wasm)));
    state
        .set(
            &[b"circles", circle, b"program", b"code_b64"],
            STANDARD.encode(wasm).into_bytes(),
        )
        .unwrap();
    state
        .set(
            &[b"circles", circle, b"code_hash"],
            fixture["wasm_sha256"].as_str().unwrap().as_bytes().to_vec(),
        )
        .unwrap();
    let hash = octra_node_protocol::circles::stable_key(b"counter");
    let entry = StableEntry {
        key: b"counter".to_vec(),
        hash: hash.as_bytes().to_vec(),
        value: StableValue::Inline(count.to_vec()),
    }
    .encode();
    state
        .set(
            &[b"circles", circle, b"stable", b"by_hash", hash.as_bytes()],
            entry,
        )
        .unwrap();
}
