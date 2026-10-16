//! Exact pristine native request/auth/response vectors; no account persistence
//! or local Single launcher behavior is inferred from this pure boundary.
use octra_node_protocol::{native_json::Document, registration_rpc};
use serde_json::{json, Value};
#[test]
fn native_single_registration_auth_and_bft_ignored_order() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/single-registration-native.json")).unwrap();
    assert_eq!(
        fixture["upstream_commit"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 15);
    for case in cases {
        let raw = serde_json::to_vec(&case["params"]).unwrap();
        let doc = Document::parse(&raw).unwrap();
        let (outcome, registered) = if case["input"]["bft"].as_bool().unwrap() {
            let raw = registration_rpc::public_key_bft(&doc, doc.root());
            (
                json!({"result": serde_json::from_slice::<Value>(&raw).unwrap()}),
                json!([]),
            )
        } else {
            match registration_rpc::PublicKey::parse(&doc, doc.root()) {
                Ok(request) => {
                    let result: Value = serde_json::from_slice(&request.response()).unwrap();
                    let address = String::from_utf8(request.address().to_vec()).unwrap();
                    let public_key = String::from_utf8(request.public_key().to_vec()).unwrap();
                    (json!({"result":result}), json!([[address, public_key]]))
                }
                Err(error) => (
                    json!({"error":serde_json::from_slice::<Value>(&error.encode()).unwrap()}),
                    json!([]),
                ),
            }
        };
        assert_eq!(outcome, case["outcome"], "{}", case["input"]);
        assert_eq!(registered, case["registered"], "{}", case["input"]);
    }
}
