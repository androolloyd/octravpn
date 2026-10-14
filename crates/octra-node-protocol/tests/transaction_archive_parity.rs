use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    native_json::Document,
    transaction::{parse_native_integer, OpType, Transaction},
    transaction_archive::{Archive, Error, Proof},
    transaction_payload::Limits,
};
use serde_json::{json, Value};
fn bytes(input: &Value, field: &str) -> Vec<u8> {
    STANDARD.decode(input[field].as_str().unwrap()).unwrap()
}
fn blob(bytes: &[u8]) -> Value {
    json!(STANDARD.encode(bytes))
}
fn evaluate(case: &Value) -> Value {
    let input = &case["input"];
    match input["operation"].as_str().unwrap() {
        "integer" => {
            parse_native_integer(&bytes(input, "raw")).map_or(Value::Null, |v| json!(v.to_string()))
        }
        "decode" => {
            let Ok(document) = Document::parse(&bytes(input, "raw")) else {
                return json!({"syntax_error":true});
            };
            let tx = match Transaction::from_document(&document) {
                Ok(tx) => tx,
                Err(e) => return json!({"decode_error":e.to_string()}),
            };
            let wire = match tx.to_json_bytes() {
                Ok(wire) => wire,
                Err(e) => return json!({"serialization_error":e.to_string()}),
            };
            json!({"json":blob(&wire),"signing":blob(&tx.signing_bytes().unwrap()),"hash":hex::encode(tx.hash().unwrap())})
        }
        "limits" => {
            let limits = Limits {
                encrypted_data: 10,
                message: 20,
                message_zkp: 30,
                message_validator: 40,
                message_program: 50,
            };
            let op = OpType::parse(input["op_type"].as_str().unwrap().as_bytes()).unwrap();
            json!({"message":limits.message_limit(op),"encrypted":limits.encrypted_data_limit(op)})
        }
        "archive" => {
            let output = &case["output"];
            let raw = bytes(output, "raw");
            let hash = output["hash"].as_str().unwrap();
            let result = match Archive::decode(hash.as_bytes(), &raw) {
                Ok(archive) => {
                    let account = input["account_key"]
                        .as_str()
                        .map(|v| STANDARD.decode(v).unwrap());
                    json!({"proof":match archive.proof(){Proof::Exact=>"exact",Proof::Signed=>"signed",Proof::SignedOperation=>"operation"},"visible":blob(&archive.visible_json().unwrap()),"proof_bytes":blob(archive.proof_bytes()),"transaction":blob(&archive.transaction().to_json_bytes().unwrap()),"verify":archive.verify(account.as_deref()).err().map(|e|e.to_string())})
                }
                Err(Error::Json(_)) => json!({"syntax_or_serialization_error":true}),
                Err(Error::Invalid(reason))
                    if reason.ends_with("value not allowed in standard JSON") =>
                {
                    json!({"syntax_or_serialization_error":true})
                }
                Err(error) => json!({"error":error.to_string()}),
            };
            json!({"raw":output["raw"],"hash":output["hash"],"result":result})
        }
        other => panic!("unexpected operation {other}"),
    }
}
#[test]
fn raw_transaction_payload_and_legacy_archive_match_native() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/transaction-archive.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/upstream.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["commit"]);
    for (path, hash) in fixture["sources"].as_object().unwrap() {
        assert_eq!(&sources["files"][path], hash, "source drift {path}");
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() > 700);
    for (index, case) in cases.iter().enumerate() {
        assert_eq!(
            evaluate(case),
            case["output"],
            "native archive fixture {index}: {}",
            case["input"]
        );
    }
}
#[test]
fn unknown_nested_fields_do_not_exhaust_call_stack() {
    let depth = 50_000;
    let mut raw = Vec::from(b"{\"ignored\":".as_slice());
    raw.extend(std::iter::repeat(b'[').take(depth));
    raw.extend_from_slice(b"null");
    raw.extend(std::iter::repeat(b']').take(depth));
    raw.extend_from_slice(b"}");
    let document = Document::parse(&raw).unwrap();
    assert_eq!(
        Transaction::from_document(&document)
            .unwrap_err()
            .to_string(),
        "Malformed JSON: missing or invalid fields"
    );
    drop(document);
}
#[test]
fn legacy_messages_and_keys_never_become_proved_execution_fields() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/transaction-archive.json")).unwrap();
    let mut verified = 0;
    for case in fixture["cases"].as_array().unwrap() {
        if case["input"]["operation"] != "archive" {
            continue;
        }
        let expected = &case["output"]["result"];
        if expected["proof"] != "signed" && expected["proof"] != "operation" {
            continue;
        }
        let archive = Archive::decode(
            case["output"]["hash"].as_str().unwrap().as_bytes(),
            &bytes(&case["output"], "raw"),
        )
        .unwrap();
        assert!(archive.transaction().message.is_none());
        assert!(archive.transaction().public_key.is_none());
        assert!(archive.transaction().encrypted_data.is_none());
        if expected["verify"].is_null() {
            let key = case["input"]["account_key"]
                .as_str()
                .map(|v| STANDARD.decode(v).unwrap());
            archive.verify(key.as_deref()).unwrap();
            verified += 1;
        }
    }
    assert!(verified >= 4);
}
