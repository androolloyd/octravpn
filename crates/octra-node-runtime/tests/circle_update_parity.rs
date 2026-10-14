#[path = "common/circle_host.rs"]
mod host;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{circle_wasm::Error, native_json::Document};
use octra_node_runtime::{
    circle::WasmRules,
    circle_call::{self, Context},
    circle_receipt::ReceiptBudget,
    octb::Value as VmValue,
    state_batch::StateBatch,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn b64(v: &[u8]) -> Value {
    json!(STANDARD.encode(v))
}
fn value(v: Option<&VmValue>) -> Value {
    match v {
        None => Value::Null,
        Some(VmValue::Bool(v)) => json!(v),
        Some(v) => json!(String::from_utf8(v.text().into_owned()).unwrap()),
    }
}
#[test]
fn standard_wasm_updates_match_native_receipts_costs_and_state_roots() {
    check_updates(include_str!("fixtures/circle-update.json"), false);
}
#[test]
fn native_circle_receipt_capture_bindings_and_consumption() {
    check_updates(include_str!("fixtures/circle-bindings.json"), true);
}
fn check_updates(source: &str, capture: bool) {
    let fixture: Value = serde_json::from_str(source).unwrap();
    let inventory: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(if capture {
            include_bytes!("../../../scripts/node-port/circle-bindings-oracle.ml").as_slice()
        } else {
            include_bytes!("../../../scripts/node-port/circle-update-oracle.ml").as_slice()
        }))
    );
    assert_eq!(
        fixture["wasm_sha256"],
        hex::encode(Sha256::digest(bytes(&fixture["wasm_b64"])))
    );
    assert_eq!(
        fixture["guest_source_sha256"],
        host::fixture()["guest_source_sha256"]
    );
    let runtime = host::runtime();
    for (i, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let v = &case["input"];
        let mut state = StateBatch::default();
        state.begin().unwrap();
        let circle = v["circle"].as_str().unwrap().as_bytes();
        for e in v["entries"].as_array().unwrap() {
            let path = e["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(bytes)
                .collect::<Vec<_>>();
            state
                .set(
                    &path.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                    bytes(&e["value"]),
                )
                .unwrap();
        }
        state
            .set(
                &[b"circles", circle, b"program", b"code_b64"],
                fixture["wasm_b64"].as_str().unwrap().as_bytes().to_vec(),
            )
            .unwrap();
        state
            .set(
                &[b"circles", circle, b"code_hash"],
                fixture["wasm_sha256"].as_str().unwrap().as_bytes().to_vec(),
            )
            .unwrap();
        let ctx = Context {
            manifest: octra_node_runtime::circle::WasmProfile::Manifest,
            caller: v["caller"].as_str().unwrap().into(),
            tx_hash: v["tx_hash"].as_str().unwrap().into(),
            epoch: v["epoch"].as_i64().unwrap(),
            epoch_time_ms: 0,
            tree_hash: hex::encode(state.root().unwrap()).into_bytes(),
            node_id: circle.to_vec(),
            depth: v["depth"].as_i64().unwrap(),
            limit: v["limit"].as_i64().unwrap(),
            profile: WasmRules {
                proof_exec: v["proof"].as_bool().unwrap(),
                wasm_float: v["float"].as_bool().unwrap(),
                math: v["math"].as_bool().unwrap(),
            },
            inspect: v["inspect"].as_bool().unwrap(),
            update_policy: v["update_policy"].as_bool().unwrap(),
            hfhe_strict: true,
            storage_proof: v["storage_proof"].as_bool().unwrap(),
            fhe_work: false,
        };
        let before = state.snapshot();
        let params = Document::parse(&serde_json::to_vec(&v["params"]).unwrap()).unwrap();
        let mut budget = ReceiptBudget::default();
        let call = circle_call::execute_with_receipt(
            &runtime,
            &before,
            circle,
            v["method"].as_str().unwrap().as_bytes(),
            &params,
            &ctx,
            if capture {
                circle_call::ReceiptMode::Capture
            } else {
                circle_call::ReceiptMode::Direct
            },
            v["budget"].as_bool().unwrap().then_some(&mut budget),
        )
        .unwrap_or_else(|e| panic!("case {i}: {e:?}"));
        assert_eq!(
            before.root().unwrap(),
            state.root().unwrap(),
            "execution mutated tree"
        );
        let receipt = call.receipt();
        let commit = match call.apply(&mut state) {
            Ok(_) => Value::Null,
            Err(Error::Rejected(e)) => b64(&e),
            Err(e) => panic!("case {i} operational failure: {e:?}"),
        };
        if !commit.is_null() {
            assert_eq!(
                before.root().unwrap(),
                state.root().unwrap(),
                "refusal mutated tree"
            );
        }
        let mut actual = json!({"before_root":hex::encode(before.root().unwrap()),"root":hex::encode(state.root().unwrap()),"commit":commit,"stable":state.get(&[b"circles",circle,b"stable_root"]).map(b64),"receipt":{"success":receipt.success,"result":value(receipt.response.as_ref()),"effort":receipt.effort,"error":receipt.error.as_deref().map(b64),"events":receipt.events.iter().map(|e|json!([b64(&e.topic),e.values.iter().map(|v|b64(v)).collect::<Vec<_>>()])).collect::<Vec<_>>()},"storage":call.storage().map(|t|t.values().iter().map(|(k,v)|json!([b64(k),b64(v)])).collect::<Vec<_>>()).unwrap_or_default()});
        if capture {
            actual["binding"] = call.binding().map_or(Value::Null, |binding| json!({
                "circle":b64(&binding.circle_id),"code":b64(&binding.code_hash),"stable":b64(&binding.stable_root),
                "reads":b64(&binding.public_reads_hash),"context":b64(&binding.context_hash),
                "transcript":serde_json::from_slice::<Value>(&octra_node_protocol::circle_wasm::transcript::entries_json(&binding.transcript)).unwrap(),
            }));
            if let Some(binding) = call.binding() {
                let consumed = circle_call::execute_with_receipt(
                    &runtime,
                    &before,
                    circle,
                    v["method"].as_str().unwrap().as_bytes(),
                    &params,
                    &ctx,
                    circle_call::ReceiptMode::Consume(&binding.transcript),
                    v["budget"]
                        .as_bool()
                        .unwrap()
                        .then_some(&mut ReceiptBudget::default()),
                )
                .unwrap();
                assert_eq!(consumed.receipt(), call.receipt());
                assert_eq!(consumed.binding(), call.binding());
                assert_eq!(consumed.storage(), call.storage());
            }
        }
        assert_eq!(
            actual, case["expected"],
            "update case {i}: method={} proof={} limit={} budget={}",
            v["method"], v["proof"], v["limit"], v["budget"]
        );
    }
}

#[test]
fn updates_bind_snapshot_and_refuse_unimplemented_capabilities_without_mutation() {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    host::install_counter(&mut state, b"counter", b"4");
    let ctx = Context {
        manifest: octra_node_runtime::circle::WasmProfile::Manifest,
        caller: format!("oct{}", "2".repeat(44)),
        tx_hash: "1".repeat(64),
        epoch: 3,
        epoch_time_ms: 0,
        tree_hash: hex::encode(state.root().unwrap()).into_bytes(),
        node_id: b"counter".to_vec(),
        depth: 0,
        limit: 1_000_000,
        profile: WasmRules {
            proof_exec: true,
            wasm_float: false,
            math: false,
        },
        inspect: true,
        update_policy: true,
        hfhe_strict: true,
        storage_proof: true,
        fhe_work: false,
    };
    let params = Document::parse(b"[]").unwrap();
    let runtime = host::runtime();
    let before = state.snapshot();
    let call = circle_call::execute(
        &runtime,
        &before,
        b"counter",
        b"inc",
        &params,
        &ctx,
        Some(&mut ReceiptBudget::default()),
    )
    .unwrap();
    assert!(call.receipt().success);
    assert_eq!(call.receipt().response, Some(VmValue::int(5)));
    call.apply(&mut state).unwrap();
    let committed = state.root().unwrap();
    assert!(matches!(call.apply(&mut state), Err(Error::Unavailable(_))));
    assert_eq!(state.root().unwrap(), committed);
    assert!(matches!(
        circle_call::execute(
            &runtime,
            &state.snapshot(),
            b"counter",
            b"fhe_encrypt_of",
            &params,
            &ctx,
            None
        ),
        Err(Error::Unavailable(_))
    ));
    let code = state
        .get(&[b"circles", b"counter", b"code_hash"])
        .unwrap()
        .to_vec();
    state
        .set(&[b"circles", b"counter", b"call_code"], code)
        .unwrap();
    let root = state.root().unwrap();
    let call = circle_call::execute(
        &runtime,
        &state.snapshot(),
        b"counter",
        b"inc",
        &params,
        &ctx,
        None,
    )
    .unwrap();
    assert!(call.receipt().success);
    assert_eq!(call.receipt().response, Some(VmValue::int(6)));
    // The resumable interpreter, like the direct interpreter, only returns
    // speculative effects until the authenticated host applies the receipt.
    assert_eq!(state.root().unwrap(), root);
}
