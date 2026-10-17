//! Pure policy from the complete unchanged native driver; actor TCP tests are
//! separate and do not turn this corpus into whole-driver parity evidence.
use octra_node_protocol::consensus::{
    driver_policy::{self, PastRound},
    evidence, Vote, VoteType,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const INPUT_SHA256: &str = "d76549250f15fecd75bf8c42cd4c0bb5258aee630e9e96cc5809585775b8abe6";

fn integer(value: &Value, key: &str) -> i64 {
    value[key].as_str().unwrap().parse().unwrap()
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(name, value)| (name.clone(), canonical(value)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
        value => value.clone(),
    }
}

fn run(input: &Value) -> Value {
    if input["group"] == "frame" {
        return json!(hex::encode(driver_policy::frame_id(
            integer(input, "generation"),
            input["message"].as_u64().unwrap() as u8,
            &hex::decode(input["payload"].as_str().unwrap()).unwrap(),
        )));
    }
    let conflict = |input: &Value| {
        let vote = Vote {
            chain_id: b"driver-round-recovery-fixture".to_vec(),
            epoch_id: integer(input, "epoch"),
            round: input.get("round").map_or(0, |_| integer(input, "round")),
            vote_type: VoteType::Prevote,
            proposal_id: vec![0; 32],
            validator: b"validator-1".to_vec(),
            signature: vec![0; 64],
        };
        let mut second = vote.clone();
        second.proposal_id = vec![
            input
                .get("value")
                .map_or(1, |value| value.as_u64().unwrap() as u8);
            32
        ];
        evidence::vote_conflict(&vote, &second).unwrap()
    };
    if input["group"] == "evidence-window" {
        return json!(evidence::in_window(
            integer(input, "current"),
            &conflict(input)
        ));
    }
    if input["group"] == "evidence-pool" {
        let mut pool = evidence::Pool::default();
        return json!(input["steps"].as_array().unwrap().iter().map(|step| json!({"accepted":pool.remember(&conflict(step)).unwrap(),"count":pool.len()})).collect::<Vec<_>>());
    }
    let prior = (!input["prior"].is_null()).then(|| {
        let prior = &input["prior"];
        PastRound {
            epoch_id: integer(prior, "epoch"),
            target: integer(prior, "target"),
            sent_at: integer(prior, "sent"),
            tries: integer(prior, "tries"),
        }
    });
    driver_policy::next_past_round(
        integer(input, "height"),
        integer(input, "round"),
        integer(input, "limit"),
        prior.as_ref(),
        integer(input, "now"),
    )
    .map_or(Value::Null, |(target, tries)| {
        json!([target.to_string(), tries.to_string()])
    })
}

#[test]
fn exact_native_driver_round_cursor_and_duplicate_identity() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/driver-round-recovery.json")).unwrap();
    assert_eq!(
        fixture["upstream_commit"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(
        fixture["builder_image"],
        "sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95"
    );
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/driver-round-recovery-oracle.ml"
        )))
    );
    assert_eq!(
        fixture["runner_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/native-oracle.py"
        )))
    );
    let source_map: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["source_sha256"], source_map["files"]);
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 1202);
    assert_eq!(fixture["input_sha256"], INPUT_SHA256);
    let inputs = Value::Array(cases.iter().map(|case| case["input"].clone()).collect());
    assert_eq!(
        hex::encode(Sha256::digest(
            serde_json::to_vec(&canonical(&inputs)).unwrap()
        )),
        INPUT_SHA256
    );
    assert_eq!(
        fixture["groups"],
        json!({"frame":360,"cursor":162,"clock":420,"bounds":216,"evidence-window":42,"evidence-pool":2})
    );
    for (index, case) in cases.iter().enumerate() {
        assert_eq!(
            run(&case["input"]),
            case["expected"],
            "native case {index}: {}",
            case["input"]
        );
    }
}

#[test]
fn only_native_replayable_frames_change_identity_with_generation() {
    for message in [0x30, 0x31] {
        assert_ne!(
            driver_policy::frame_id(1, message, b"same signed frame"),
            driver_policy::frame_id(2, message, b"same signed frame")
        );
    }
    for message in [0x32, 0x3c, 0x3d, 0x3e, 0x3f] {
        assert_eq!(
            driver_policy::frame_id(1, message, b"same frame"),
            driver_policy::frame_id(2, message, b"same frame")
        );
    }
    assert_ne!(
        driver_policy::frame_id(1, 0x30, b"x"),
        driver_policy::frame_id(1, 0x31, b"x")
    );
}
