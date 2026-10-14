use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    control_payload::{
        self as control, Bond, BondedReady, LegacyReady, ReadyExtra, ValidatorUpdate,
    },
    transaction::{self, OpType},
};
use serde_json::{json, Value};
fn blob(bytes: &[u8]) -> Value {
    json!(STANDARD.encode(bytes))
}
fn optional(bytes: Option<&[u8]>) -> Value {
    bytes.map_or(Value::Null, blob)
}
fn extra(v: &ReadyExtra) -> Value {
    json!({"chain":optional(v.chain_id.as_deref()),"binary":optional(v.binary_hash.as_deref()),"config":optional(v.config_hash.as_deref()),"catchup":v.catchup_head_epoch.map(|v|v.to_string()),"shadow":v.shadow_epochs.map(|v|v.to_string())})
}
fn result<T>(value: Result<T, control::Error>, f: impl FnOnce(T) -> Value) -> Value {
    match value {
        Ok(v) => json!({"ok":f(v)}),
        Err(e) => json!({"error":e.to_string()}),
    }
}
fn evaluate(input: &Value) -> Value {
    let message = input["message"]
        .as_str()
        .map(|v| STANDARD.decode(v).unwrap());
    let message = message.as_deref();
    match input["operation"].as_str().unwrap() {
        "int64" => transaction::parse_native_int64(message.unwrap())
            .map_or(Value::Null, |v| json!(v.to_string())),
        "int63" => transaction::parse_native_int(message.unwrap())
            .map_or(Value::Null, |v| json!(v.get().to_string())),
        "update" => result(
            ValidatorUpdate::parse(message),
            |v| json!({"activate":v.activate_epoch.to_string(),"source":v.source_epoch.map(|v|v.to_string()),"weighted":v.weighted,"fingerprint":v.fingerprint,"validators":v.validators.iter().map(|v|json!([blob(&v.address),blob(&v.public_key),v.weight.to_string()])).collect::<Vec<_>>() }),
        ),
        "legacy_ready" => result(
            LegacyReady::parse(message),
            |v| json!({"fingerprint":blob(&v.fingerprint),"epoch":v.head_epoch.to_string(),"root":blob(&v.state_root),"extra":extra(&v.extra)}),
        ),
        "bonded_ready" => result(
            BondedReady::parse(message),
            |v| json!({"key":blob(&v.consensus_public_key),"epoch":v.head_epoch.to_string(),"root":blob(&v.state_root),"proposal":optional(v.head_proposal_id.as_deref()),"extra":extra(&v.extra)}),
        ),
        "bond" => result(
            Bond::parse(message),
            |v| json!({"key":blob(&v.consensus_public_key),"proof":blob(&v.proof)}),
        ),
        "evidence" => result(control::evidence(message), |_| Value::Null),
        "admit" => result(
            control::validate_message(
                OpType::parse(input["op_type"].as_str().unwrap().as_bytes()).unwrap(),
                message,
            ),
            |_| Value::Null,
        ),
        operation => panic!("unexpected operation {operation}"),
    }
}
#[test]
fn validator_control_parsers_and_admission_match_native() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/control-payload.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/upstream.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["commit"]);
    for (path, hash) in fixture["sources"].as_object().unwrap() {
        assert_eq!(&sources["files"][path], hash, "source drift {path}");
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() > 1000);
    for (index, case) in cases.iter().enumerate() {
        let actual = evaluate(&case["input"]);
        let expected = &case["output"];
        if case["input"]["compare_error"] == false && expected.get("error").is_some() {
            assert!(
                actual.get("error").is_some(),
                "case {index} accepted native refusal"
            );
        } else {
            assert_eq!(
                &actual, expected,
                "native control case {index}: {}",
                case["input"]
            );
        }
    }
}
