use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    circle_storage::StorageTable,
    circle_wasm::{
        self as wasm,
        codec::{self, Scalar},
        receipt::{self, Receipt},
        transcript, Error, Execution,
    },
    circles::MetadataMode,
    native_json::Document,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn b64(v: impl AsRef<[u8]>) -> Value {
    json!(STANDARD.encode(v))
}
fn opt(v: Option<&[u8]>) -> Value {
    v.map_or(Value::Null, b64)
}
fn scalar(s: &Scalar) -> Value {
    match s {
        Scalar::Null => json!({"tag":0,"value":null}),
        Scalar::Bool(b) => json!({"tag":if *b{2}else{1},"value":null}),
        Scalar::Integer(v) => json!({"tag":3,"value":b64(v)}),
        Scalar::String(v) => json!({"tag":4,"value":b64(v)}),
    }
}
fn result(r: &Receipt) -> Value {
    json!({
        "success":r.success,"effort":r.effort_used.to_string(),"status":r.response_status.to_string(),
        "trace":r.compute_trace.as_ref().map(|t|b64(&t.root)),"steps":r.compute_trace.as_ref().map(|t|t.steps.to_string()),"operations":r.compute_trace.as_ref().map(|t|t.operations.to_string()),
        "exit":r.compute_exit.map(|v|v.to_string()),"fault":opt(r.compute_fault.as_deref()),"response":r.response.as_ref().map(scalar),
        "storage":r.storage.values().iter().map(|(k,v)|json!([b64(k),b64(v)])).collect::<Vec<_>>(),
        "storage_order":r.storage.keys().map(b64).collect::<Vec<_>>(),
        "events":r.events.iter().map(|e|json!([b64(&e.topic),b64(&e.data)])).collect::<Vec<_>>(),
        "spawns":r.spawns.iter().map(|e|json!({"circle":b64(&e.circle_id),"owner":match e.owner {receipt::SpawnOwner::Caller=>"caller",receipt::SpawnOwner::Parent=>"parent"},"nonce":e.nonce.to_string(),"payload":b64(&e.payload_json)})).collect::<Vec<_>>(),
        "assets":r.assets.iter().map(|e|json!({"circle":b64(&e.circle_id),"path":b64(&e.path),"type":b64(&e.content_type),"encoding":opt(e.encoding.as_deref()),"body":b64(&e.body_b64)})).collect::<Vec<_>>(),
        "encrypted":r.encrypted_assets.iter().map(|e|json!({"circle":b64(&e.circle_id),"path":opt(e.path.as_deref()),"slot":opt(e.slot_ref.as_deref()),"state":opt(e.state_ref.as_deref()),"type":b64(&e.content_type),"encoding":opt(e.encoding.as_deref()),"key":b64(&e.key_id),"hash":b64(&e.plaintext_hash),"padding":opt(e.padding_class.as_deref()),"activate":e.activate_after_epoch.map(|v|v.to_string()),"expire":e.expire_after_epoch.map(|v|v.to_string()),"metadata":e.metadata_mode.map(|m|match m {MetadataMode::Reveal=>"reveal",MetadataMode::Opaque=>"opaque"}),"body":b64(&e.ciphertext_b64)})).collect::<Vec<_>>(),
        "transcript":b64(transcript::canonical(&r.transcript)),"error":opt(r.error.as_deref())
    })
}
fn run(input: &Value) -> Result<Value, Error> {
    Ok(match input["op"].as_str().unwrap() {
        "base64"=>json!({"bytes":b64(octra_node_protocol::native_base64::decode(&bytes(&input["bytes"])).map_err(|error|Error::Rejected(error.to_string().into_bytes()))?)}),
        "request"=>{let doc=Document::parse(&bytes(&input["json"])).unwrap();json!({"bytes":b64(codec::encode_request(&bytes(&input["method"]),&codec::request_params(&doc)?)?)})},
        "literal"=>json!({"bytes":b64(codec::encode_request(&bytes(&input["method"]),&[Scalar::Integer(bytes(&input["literal"]))])?)}),
        "response"=>scalar(&codec::decode_response(&bytes(&input["bytes"]))?),
        "transcript"=>{let entries=transcript::decode(&bytes(&input["json"]))?;json!({"canonical":b64(transcript::canonical(&entries)),"hash":transcript::hash(&entries)})},
        "methods"=>json!(wasm::methods(&bytes(&input["json"]))?.iter().map(|m|json!({"name":b64(&m.name),"view":m.view,"execution":match m.execution {Execution::Standard=>"standard",Execution::Compute=>"compute"}})).collect::<Vec<_>>()),
        "execution"=>{let mut before=StorageTable::new(8);for v in input["before"].as_array().unwrap(){before.replace(bytes(&v[0]),bytes(&v[1]));}result(&receipt::decode(&bytes(&input["json"]),&before)?)},
        op=>panic!("unknown fixture op {op}")
    })
}
#[test]
fn native_circle_codec_manifests_transcripts_and_complete_effect_decoding_match() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/circle-call.json")).unwrap();
    let inventory: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/circle-call-oracle.ml"
        )))
    );
    for (i, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let actual = match run(&case["input"]) {
            Ok(value) => value,
            Err(Error::Rejected(e)) => json!({"error":b64(e)}),
            Err(Error::Unavailable(e)) => json!({"unavailable":b64(e)}),
        };
        assert_eq!(
            actual, case["expected"],
            "Circle call case {i}: {}",
            case["input"]["op"]
        );
    }
}
