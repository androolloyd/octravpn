//! Fresh native payload/decision vectors. A successful parse is diagnostic
//! only; neither declared count nor peer roots acquire state authority.
use octra_node_protocol::{
    legacy_epoch::{self, Event},
    native_base64,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn bytes(value: &Value) -> Vec<u8> {
    native_base64::decode(value.as_str().unwrap().as_bytes()).unwrap()
}
fn encoded(raw: &[u8]) -> Value {
    use base64::Engine as _;
    json!(base64::engine::general_purpose::STANDARD.encode(raw))
}
fn event(value: Event) -> Value {
    match value {
        Event::Silent => json!({"silent":true}),
        Event::Ignored {
            epoch,
            tx_count,
            root,
            producer,
        } => {
            json!({"epoch":epoch,"tx_count":tx_count,"root":encoded(&root),"producer":encoded(&producer)})
        }
    }
}
#[test]
#[allow(clippy::cast_possible_wrap)] // Native exposes signed Int64 JSON text for raw wire bits.
fn pristine_native_legacy_epoch_payload_and_diagnostic_decision() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/legacy-epoch-native.json")).unwrap();
    let inventory: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/legacy-epoch-oracle.ml"
        )))
    );
    assert_eq!(
        fixture["runner_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/resource-native-oracle.py"
        )))
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 11);
    for case in cases {
        let input = &case["input"];
        let serialized = case["serialized"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect::<Vec<_>>();
        let payload = legacy_epoch::payload(
            input["epoch"].as_i64().unwrap(),
            input["root"].as_str().unwrap().as_bytes(),
            input["declared"].as_i64().unwrap(),
            input["producer"].as_str().unwrap().as_bytes(),
            &serialized,
        )
        .unwrap();
        assert_eq!(encoded(&payload), case["encoded"], "{input}");
        let payload = bytes(&case["payload"]);
        let parsed = legacy_epoch::parse(&payload);
        assert_eq!(
            parsed.is_ok(),
            case["parsed"]["ok"].as_bool().unwrap(),
            "{input}"
        );
        if let Ok(parsed) = parsed {
            assert_eq!(
                json!({"ok":true,"epoch":(parsed.epoch as i64).to_string(),"root":encoded(&parsed.root),"declared":parsed.declared_count,"producer":encoded(&parsed.producer),"hashes":parsed.transactions.iter().map(|tx|hex::encode(tx.hash().unwrap())).collect::<Vec<_>>()}),
                case["parsed"],
                "{input}"
            );
            assert_eq!(
                event(legacy_epoch::observer_event(true, &payload).unwrap()),
                case["observer"],
                "{input}"
            );
            assert_eq!(
                event(legacy_epoch::observer_event(false, &payload).unwrap()),
                case["nonobserver"],
                "{input}"
            );
        } else {
            assert!(legacy_epoch::observer_event(true, &payload).is_err());
            assert!(legacy_epoch::observer_event(false, &payload).is_err());
            assert!(case["observer"]["error"].is_string());
            assert!(case["nonobserver"]["error"].is_string());
        }
    }
}
#[test]
fn legacy_epoch_transport_limits_do_not_allocate_from_declared_count() {
    let mut raw = legacy_epoch::payload(1, b"root", 0, b"producer", &[]).unwrap();
    let count = raw.len() - 4;
    raw[count..].copy_from_slice(&i32::MAX.to_be_bytes());
    assert!(legacy_epoch::parse(&raw).is_err());
    let huge = vec![0; legacy_epoch::MAX_PAYLOAD + 1];
    assert!(legacy_epoch::payload(1, &huge, 0, b"producer", &[]).is_err());
    assert!(legacy_epoch::parse(&huge).is_err());
}
