//! Exact pure native liveness policy, not driver scheduling or network recovery.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use octra_node_protocol::consensus::{
    engine::TimeoutConfig,
    liveness::{self as policy, DriverSnapshot, Outcome, Reset, Sample, State},
    RoundStep,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SOURCE: &str = "node_runtime/consensus_liveness.ml";
const INPUT_SHA256: &str = "f25f55bf50ce913e29387437282e9e2c50eece5ea0da73a1b1613ec9f484c79b";

// Sort recursively, independently of serde_json's optional preserve_order feature.
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

fn bytes(input: &Value, name: &str) -> Vec<u8> {
    STANDARD.decode(input[name].as_str().unwrap()).unwrap()
}
fn integer(input: &Value, name: &str) -> i64 {
    input[name].as_str().unwrap().parse().unwrap()
}
fn float(input: &Value) -> f64 {
    f64::from_bits(u64::from_str_radix(input.as_str().unwrap(), 16).unwrap())
}
fn optional_float(input: &Value) -> Option<f64> {
    (!input.is_null()).then(|| float(input))
}
fn encoded(value: &[u8]) -> Value {
    json!(STANDARD.encode(value))
}
fn bits(value: f64) -> Value {
    json!(format!("{:016x}", value.to_bits()))
}
fn optional_bits(value: Option<f64>) -> Value {
    value.map_or(Value::Null, bits)
}
fn read_state(input: &Value) -> State {
    State {
        key: bytes(input, "key"),
        key_started_at: float(&input["key_started_at"]),
        height_key: bytes(input, "height_key"),
        height_started_at: float(&input["height_started_at"]),
        resets: integer(input, "resets"),
    }
}
fn state(value: &State) -> Value {
    json!({"key":encoded(&value.key),"key_started_at":bits(value.key_started_at),
        "height_key":encoded(&value.height_key),"height_started_at":bits(value.height_started_at),
        "resets":value.resets.to_string()})
}
fn reset(value: &Reset) -> Value {
    json!({"height":value.height.to_string(),"round":value.round.to_string(),
        "step":encoded(&value.step),"expected":value.expected.to_string(),
        "source":encoded(&value.source),"stall_sec":bits(value.stall_sec),
        "step_timeout_sec":optional_bits(value.step_timeout_sec),
        "state_age":bits(value.state_age),"height_age":bits(value.height_age),
        "resets":value.resets.to_string()})
}
fn result(value: &Outcome) -> Value {
    json!({"state":state(&value.state),"reset":value.reset.as_ref().map_or(Value::Null,reset)})
}
fn snapshot(value: &DriverSnapshot) -> Value {
    json!({"height":value.height.to_string(),"round":value.round.to_string(),
        "step":encoded(&value.step),"step_timeout_sec":optional_bits(value.step_timeout_sec)})
}
fn sample<'a>(input: &Value, step: &'a [u8], source: &'a [u8]) -> Sample<'a> {
    let boolean = |name: &str| input[name].as_bool().unwrap();
    Sample {
        height: integer(input, "height"),
        round: integer(input, "round"),
        step,
        expected: integer(input, "expected"),
        now: float(&input["now"]),
        source,
        stall_sec: float(&input["stall_sec"]),
        step_timeout_sec: optional_float(&input["step_timeout_sec"]),
        observer: boolean("observer"),
        voting: boolean("voting"),
        catchup_active: boolean("catchup_active"),
        quarantine_active: boolean("quarantine_active"),
        state_attested: boolean("state_attested"),
        pending_finalized: boolean("pending_finalized"),
        proposal_active: boolean("proposal_active"),
    }
}
fn run(input: &Value) -> Value {
    match input["op"].as_str().unwrap() {
        "record" => {
            let initial = if input["seed"].is_null() {
                State::new(float(&input["created_at"]))
            } else {
                read_state(&input["seed"])
            };
            let mut current = initial.clone();
            let rows: Vec<Value> = input["samples"]
                .as_array()
                .unwrap()
                .iter()
                .map(|input| {
                    let step = bytes(input, "step");
                    let source = bytes(input, "source");
                    let value = sample(input, &step, &source);
                    let next = policy::record(&current, &value);
                    let row = json!({"protocol":optional_bits(policy::protocol_realign_sec(&value)),
                        "stall":bits(policy::effective_stall_sec(&value)),
                        "blocked_true":policy::blocked(&value,true),
                        "blocked_false":policy::blocked(&value,false),
                        "result":result(&next),"snapshot_result":result(&next)});
                    current = next.state;
                    row
                })
                .collect();
            json!({"initial":state(&initial),"rows":rows,"final":state(&current)})
        }
        "timeout" => {
            let step = match input["step"].as_str().unwrap() {
                "propose" => RoundStep::Propose,
                "prevote" => RoundStep::Prevote,
                "precommit" => RoundStep::Precommit,
                value => panic!("unknown round step {value}"),
            };
            let timeouts = TimeoutConfig {
                base: integer(input, "base"),
                propose: integer(input, "propose"),
                per_round: integer(input, "per_round"),
            };
            let round = integer(input, "round");
            json!({"milliseconds":timeouts.milliseconds(round,step).to_string(),
                "snapshot":snapshot(&policy::driver_snapshot(integer(input,"height"),round,step,timeouts))})
        }
        value => panic!("unknown liveness oracle operation {value}"),
    }
}

#[test]
fn liveness_policy_matches_unchanged_native_module_and_real_consensus_timeouts() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/liveness.json");
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(path).expect("generate the pinned native liveness oracle fixture"),
    )
    .unwrap();
    let inventory_bytes = include_bytes!("../../../docs/rust-node/source-map.json");
    let inventory: Value = serde_json::from_slice(inventory_bytes).unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    for (name, contents) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/liveness-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/liveness-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/liveness-fixtures.py").as_slice(),
        ),
    ] {
        assert_eq!(
            fixture[name],
            hex::encode(Sha256::digest(contents)),
            "{name}"
        );
    }
    assert_eq!(fixture["runner_kind"], "immutable-offline-builder");
    assert_eq!(
        fixture["runner_path"],
        "scripts/node-port/liveness-fixtures.py"
    );
    assert_eq!(
        fixture["builder_image"],
        "sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95"
    );
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(fixture["adapters"], json!({}));
    let native = &fixture["native"];
    assert_eq!(native["compiler_version"], "4.14.2");
    assert_eq!(
        native["source_map_sha256"],
        hex::encode(Sha256::digest(inventory_bytes))
    );
    assert_eq!(
        native["verified_source_count"],
        inventory["files"].as_object().unwrap().len()
    );
    assert_eq!(native["compiled_sources"].as_object().unwrap().len(), 1);
    for name in ["original_sha256", "compiled_sha256"] {
        assert_eq!(
            native["compiled_sources"][SOURCE][name],
            inventory["files"][SOURCE]
        );
    }
    let interface = format!("{SOURCE}i");
    assert_eq!(native["omitted_interface"]["path"], interface);
    assert_eq!(
        native["omitted_interface"]["source_sha256"],
        inventory["files"][&interface]
    );
    assert_eq!(
        native["run_environment_overrides"],
        json!({"OCAMLRUNPARAM":""})
    );
    for tool in ["opam", "ocamlopt", "ocamlfind", "dune"] {
        assert!(native["tools"][tool]["path"]
            .as_str()
            .unwrap()
            .starts_with('/'));
        assert_eq!(native["tools"][tool]["sha256"].as_str().unwrap().len(), 64);
    }
    assert_eq!(native["executable_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(native["worker_sha256"].as_str().unwrap().len(), 64);
    let commands = native["commands"].as_array().unwrap();
    let build = commands
        .iter()
        .find(|command| command["name"] == "build")
        .unwrap();
    assert!(build["argv"].as_array().unwrap().contains(&json!("dune")));
    assert!(commands.iter().any(|command| command["name"] == "oracle"));

    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(fixture["input_sha256"], INPUT_SHA256);
    let inputs = Value::Array(cases.iter().map(|case| case["input"].clone()).collect());
    assert_eq!(
        hex::encode(Sha256::digest(
            serde_json::to_vec(&canonical(&inputs)).unwrap()
        )),
        INPUT_SHA256,
        "native inputs differ from the complete generated corpus"
    );
    assert_eq!(cases.len(), 1_012, "changed liveness qualification corpus");
    assert_eq!(fixture["vector_groups"].as_object().unwrap().len(), 9);
    for (group, expected) in [
        ("timers", 6),
        ("blockers", 256),
        ("threshold-selection", 300),
        ("threshold-boundaries", 42),
        ("clock-bits", 100),
        ("byte-keys", 100),
        ("seed-keys", 5),
        ("counter-wrap", 5),
        ("timeouts", 198),
    ] {
        let count = cases
            .iter()
            .filter(|case| case["input"]["group"] == group)
            .count();
        assert_eq!(count, expected, "changed {group} vectors");
        assert_eq!(fixture["vector_groups"][group], count, "{group}");
    }
    for (index, case) in cases.iter().enumerate() {
        assert_eq!(
            run(&case["input"]),
            case["expected"],
            "native case {index}: {}",
            case["input"]
        );
    }
}
