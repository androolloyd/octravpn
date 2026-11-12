//! Candidate-native root and emission-cost projection of historical receipts.
//! The old complete-epoch oracle remains authoritative for every unrelated byte.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn fixture() -> &'static Value {
    static FIXTURE: OnceLock<Value> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let report: Value = serde_json::from_str(include_str!(
            "../../../octra-node-protocol/tests/fixtures/candidate-vm-root.json"
        ))
        .unwrap();
        let candidate: Value = serde_json::from_str(include_str!(
            "../../../../docs/rust-node/source-map-candidate.json"
        ))
        .unwrap();
        assert_eq!(report["upstream_commit"], candidate["upstream_commit"]);
        for (path, hash) in report["source_sha256"].as_object().unwrap() {
            assert_eq!(hash, &candidate["files"][path], "{path}");
        }
        for (field, source) in [
            (
                "generator_sha256",
                include_bytes!("../../../../scripts/node-port/candidate-vm-root-oracle.py")
                    .as_slice(),
            ),
            (
                "oracle_sha256",
                include_bytes!("../../../../scripts/node-port/candidate-vm-root-oracle.ml")
                    .as_slice(),
            ),
        ] {
            assert_eq!(
                report[field],
                hex::encode(Sha256::digest(source)),
                "{field}"
            );
        }
        for (name, source) in [
            (
                "circle-octb-execution.json",
                include_bytes!("../fixtures/circle-octb-execution.json").as_slice(),
            ),
            (
                "circle-octb-journal.json",
                include_bytes!("../fixtures/circle-octb-journal.json").as_slice(),
            ),
        ] {
            assert_eq!(
                report["historical_sha256"][name],
                hex::encode(Sha256::digest(source)),
                "{name}"
            );
        }
        assert_eq!(report["projections"].as_array().unwrap().len(), 56);
        report
    })
}
pub(crate) fn expected(name: &str, index: usize, historical: &Value) -> Value {
    let mut expected = historical.clone();
    for projection in fixture()["projections"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["fixture"] == name && row["case"] == index)
    {
        assert_eq!(
            bytes(&projection["root"]),
            historical["before"].as_str().unwrap().as_bytes()
        );
        let row = expected["receipts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row[0] == projection["tx_hash"])
            .expect("native projected receipt exists");
        let old = bytes(&row[1]);
        assert_eq!(
            projection["old_receipt_sha256"],
            hex::encode(Sha256::digest(&old))
        );
        let needle = bytes(&projection["old_literal"]);
        let replacement = bytes(&projection["replacement"]);
        let mut converted = vec![];
        let mut remaining = old.as_slice();
        let mut count = 0;
        while let Some(at) = remaining
            .windows(needle.len())
            .position(|window| window == needle)
        {
            converted.extend_from_slice(&remaining[..at]);
            converted.extend_from_slice(&replacement);
            remaining = &remaining[at + needle.len()..];
            count += 1;
        }
        converted.extend_from_slice(remaining);
        assert_eq!(projection["count"], count);
        let old_effort = projection["old_effort"].as_u64().unwrap();
        let new_effort = projection["new_effort"].as_u64().unwrap();
        assert_eq!(
            new_effort,
            old_effort - projection["old_event_cost"].as_u64().unwrap()
                + projection["new_event_cost"].as_u64().unwrap()
        );
        let needle = format!("\"effort\":{old_effort}").into_bytes();
        let replacement = format!("\"effort\":{new_effort}").into_bytes();
        let positions: Vec<_> = converted
            .windows(needle.len())
            .enumerate()
            .filter_map(|(at, window)| (window == needle).then_some(at))
            .collect();
        assert_eq!(positions.len(), 1);
        let at = positions[0];
        converted.splice(at..at + needle.len(), replacement);
        assert_eq!(converted, bytes(&projection["projected_receipt"]));
        row[1] = projection["projected_receipt"].clone();
    }
    expected
}
