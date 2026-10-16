use octra_node_protocol::{native_json::Document, submit_rpc::Fees};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[test]
fn native_fee_advice_matches_bytes_tiers_and_machine_integer_edges() {
    let report: Value = serde_json::from_str(include_str!("fixtures/submit-fees.json")).unwrap();
    let map: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(report["upstream_commit"], map["upstream_commit"]);
    assert_eq!(report["source_sha256"], map["files"]);
    assert_eq!(report["instrumentation"], json!({}));
    for (key, raw) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/submit-fees-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/submit-fees-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(report[key], hex::encode(Sha256::digest(raw)), "{key}");
    }
    let cases = report["cases"].as_array().unwrap();
    assert!(cases.len() > 100);
    for case in cases {
        let input = &case["input"];
        let expected = &case["expected"];
        let settings = &input["settings"];
        let fees = Fees::capture(|key| settings[key].as_str().map(|s| s.as_bytes().to_vec()));
        let doc = Document::parse(&serde_json::to_vec(&input["params"]).unwrap()).unwrap();
        let mut pick_range = None;
        let response = fees.response(
            &doc,
            doc.root(),
            &input["staging_ou"].as_str().unwrap().parse().unwrap(),
            input["staging_size"].as_u64().unwrap() as usize,
            |range| {
                pick_range = Some(range);
                if input["last"] == true {
                    range - 1
                } else {
                    0
                }
            },
        );
        assert_eq!(
            String::from_utf8(response).unwrap(),
            expected["response"].as_str().unwrap(),
            "{input}"
        );
        assert_eq!(json!(pick_range), expected["pick_range"], "{input}");
    }
}
