use base64::{engine::general_purpose::STANDARD, Engine as _};
use octra_node_protocol::{
    preverify_receipt::Receipt,
    transaction::{Nonce, OpType, Transaction},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn b(bytes: impl AsRef<[u8]>) -> Value {
    json!(STANDARD.encode(bytes))
}
#[test]
fn native_receipt_bytes_validation_and_state_commitments() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/preverify-receipt.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], pin["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(
        fixture["oracle_sha256"],
        json!(hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/preverify-receipt-oracle.ml"
        ))))
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let j = &case["input"];
        let tx = Transaction {
            from: b"a".to_vec(),
            to: b"b".to_vec(),
            amount: 1.into(),
            nonce: Nonce::new(1).unwrap(),
            ou: j["ou"].as_str().unwrap().parse().unwrap(),
            timestamp: 1.,
            signature: b"sig".to_vec(),
            public_key: None,
            message: None,
            encrypted_data: Some(b"payload".to_vec()),
            op_type: OpType::parse(j["op"].as_str().unwrap().as_bytes()).unwrap(),
        };
        let raw = STANDARD.decode(j["raw"].as_str().unwrap()).unwrap();
        let result = match Receipt::parse(&raw) {
            Err(e) => json!({"error":e}),
            Ok(r) => {
                let input = r.binding.input_hash(&tx).unwrap();
                let output = r.binding.output_hash(&tx, b"ok").unwrap();
                let made = match Receipt::for_tx(
                    &tx,
                    r.binding.clone(),
                    input.clone(),
                    output.clone(),
                    r.ok,
                    r.reason.clone(),
                    &j["minimum"].as_str().unwrap().parse().unwrap(),
                ) {
                    Ok(r) => json!({"ok":b(r.canonical())}),
                    Err(e) => json!({"error":e}),
                };
                json!({"canonical":b(r.canonical()),"hash":String::from_utf8(r.hash()).unwrap(),"valid":r.validate().err(),"input":String::from_utf8(input).unwrap(),"output":String::from_utf8(output).unwrap(),"made":made})
            }
        };
        assert_eq!(result, case["expected"], "case {index}: {j}");
    }
}
