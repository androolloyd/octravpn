//! Pure policy against unchanged adopted OCaml bodies, with recorded type and
//! unused-dependency adapters. No driver/network/recovery qualification claim.
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::consensus::health::{self, Majority, RootQuorum};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ENV_SOURCE: &str = "node_runtime/env.ml";
const PROBE_SOURCE: &str = "node_runtime/consensus_health_probe.ml";
const LIMITS_SOURCE: &str = "node_runtime/startup_runtime_limits.ml";
const ENV_PREFIX: &str = "\
(* Oracle-only environment acquisition; the native body follows unchanged. *)
module Health_oracle_env = struct
  let values : (string * string) list ref = ref []
  let getenv_opt name = List.assoc_opt name !values
end
module Sys = struct
  include Sys
  let getenv_opt = Health_oracle_env.getenv_opt
end
";

fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn encoded(raw: impl AsRef<[u8]>) -> Value {
    json!(STANDARD.encode(raw))
}
fn number(input: &Value, name: &str) -> i64 {
    input[name].as_str().unwrap().parse().unwrap()
}
fn flag(input: &Value, name: &str) -> bool {
    input[name].as_bool().unwrap()
}
fn kind(name: &str) -> Value {
    json!({"kind":name})
}
fn majority(value: &Majority) -> Value {
    json!({"root":encoded(&value.root),"count":value.count.to_string()})
}
fn with_majority(name: &str, value: &Majority) -> Value {
    json!({"kind":name,"majority":majority(value)})
}
fn optional(value: Option<&Majority>) -> Value {
    value.map_or(Value::Null, majority)
}
fn quorum(value: &RootQuorum) -> Value {
    match value {
        RootQuorum::NoRoot => kind("none"),
        RootQuorum::Missing(value) => with_majority("missing", value),
        RootQuorum::Matching(value) => with_majority("matching", value),
        RootQuorum::Mismatching(value) => with_majority("mismatching", value),
    }
}
fn in_sync(value: health::InSyncPlan) -> Value {
    match value {
        health::InSyncPlan::PeerRootMismatch(value) => with_majority("mismatch", &value),
        health::InSyncPlan::AcceptGenesis => kind("genesis"),
        health::InSyncPlan::MissingPeerRootQuorum(value) => {
            json!({"kind":"missing","count":value.to_string()})
        }
        health::InSyncPlan::AcceptCurrentRoot => kind("current"),
    }
}
fn retry(value: health::RetryPlan) -> Value {
    match value {
        health::RetryPlan::Retry(value) => json!({"kind":"retry","remaining":value.to_string()}),
        health::RetryPlan::Stop => kind("stop"),
    }
}
fn ahead_current(value: health::AheadCurrentRootPlan) -> Value {
    match value {
        health::AheadCurrentRootPlan::CurrentRootMatches => kind("matches"),
        health::AheadCurrentRootPlan::CurrentRootMismatch(value) => {
            with_majority("mismatch", &value)
        }
        health::AheadCurrentRootPlan::WaitCurrentRootQuorum => kind("wait"),
    }
}
fn ahead_quorum(value: health::AheadQuorumPlan) -> Value {
    match value {
        health::AheadQuorumPlan::StayActive { wake_ready } => {
            json!({"kind":"stay","wake":wake_ready})
        }
        health::AheadQuorumPlan::DelayQuarantine { wake_ready } => {
            json!({"kind":"delay","wake":wake_ready})
        }
        health::AheadQuorumPlan::QuarantineAhead => kind("quarantine"),
    }
}
fn lag(value: health::LagPlan) -> Value {
    let (label, value) = match value {
        health::LagPlan::SnapshotFallback(value) => ("snapshot", value),
        health::LagPlan::LaggingSoft(value) => ("soft", value),
        health::LagPlan::LaggingQuarantine(value) => ("quarantine", value),
    };
    json!({"kind":label,"lag":value.to_string()})
}

fn run(input: &Value) -> Value {
    match input["op"].as_str().unwrap() {
        "required" => json!(health::required_attesters(
            number(input, "f"),
            number(input, "n"),
            number(input, "configured")
        )
        .to_string()),
        "roots" => {
            let roots = input["roots"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| (!value.is_null()).then(|| bytes(value)))
                .collect::<Vec<_>>();
            let required = number(input, "required");
            let selected = health::peer_root_majority(roots.iter().map(Option::as_deref));
            let quorum_value = health::peer_root_quorum(
                required,
                &bytes(&input["local"]),
                roots.iter().map(Option::as_deref),
            );
            assert_eq!(
                quorum_value,
                health::compare_root(required, &bytes(&input["local"]), selected.clone())
            );
            json!({
                "majority":optional(selected.as_ref()),
                "with_quorum":optional(health::root_with_quorum(required,selected).as_ref()),
                "peer_with_quorum":optional(health::peer_root_with_quorum(required,roots.iter().map(Option::as_deref)).as_ref()),
                "quorum":quorum(&quorum_value),
                "count":health::root_quorum_count(&quorum_value).to_string(),
                "has_quorum":health::root_quorum_has_quorum(&quorum_value),
                "in_sync":in_sync(health::in_sync_plan(required,flag(input,"committed"),flag(input,"genesis"),&quorum_value)),
                "ahead_current":ahead_current(health::ahead_current_root_plan(&quorum_value)),
            })
        }
        "retry" => json!({
            "moving":retry(health::moving_head_plan(number(input,"retries"))),
            "stale":retry(health::stale_sample_plan(flag(input,"attested"),number(input,"retries"))),
        }),
        "ahead" => {
            let (head, ahead, grace, tolerance, quarantined) = (
                number(input, "head"),
                number(input, "ahead"),
                number(input, "grace"),
                number(input, "tolerance"),
                flag(input, "quarantined"),
            );
            json!({
                "within":health::within_ahead_grace(head,ahead,grace,tolerance),
                "without_quorum":kind(match health::ahead_no_quorum_plan(head,ahead,grace,tolerance,quarantined) {
                    health::AheadNoQuorumPlan::WaitCurrentHead=>"wait",
                    health::AheadNoQuorumPlan::ProbeCurrentHead=>"probe",
                }),
                "with_quorum":ahead_quorum(health::ahead_quorum_plan(head,ahead,number(input,"streak"),grace,tolerance,number(input,"threshold"),quarantined)),
            })
        }
        "lag" => {
            let (value, soft) = (number(input, "lag"), number(input, "soft"));
            json!({
                "mode":kind(match health::classify_lag_mode(value,soft) {
                    health::LagMode::Soft=>"soft",health::LagMode::Quarantine=>"quarantine",
                }),
                "snapshot":lag(health::snapshot_plan(value)),
                "catchup":lag(health::catchup_lag_plan(value,soft)),
            })
        }
        "config" => {
            let environment = input["environment"]
                .as_object()
                .unwrap()
                .iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(name, value)| (name.as_str(), bytes(value)))
                .collect::<Vec<_>>();
            let config = health::Config::from_inputs(|name| {
                environment
                    .iter()
                    .find_map(|(key, value)| (*key == name).then_some(value.as_slice()))
            });
            json!({
                "state_attest_min_peers":config.state_attest_min_peers.to_string(),
                "ahead_streak_threshold":config.ahead_streak_threshold.to_string(),
                "ahead_grace_epochs":config.ahead_grace_epochs.to_string(),
                "ahead_drift_tolerance":config.ahead_drift_tolerance.to_string(),
                "soft_catchup_max_lag":config.soft_catchup_max_lag.to_string(),
            })
        }
        op => panic!("unknown health oracle operation: {op}"),
    }
}

#[test]
fn pure_health_policy_matches_original_native_bodies() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/health-policy.json");
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(path).expect("generate the pinned health-policy native oracle fixture"),
    )
    .unwrap();
    let source_bytes = include_bytes!("../../../docs/rust-node/source-map.json");
    let source: Value = serde_json::from_slice(source_bytes).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    for (key, bytes) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/health-policy-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/health-policy-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/health-policy-fixtures.py").as_slice(),
        ),
    ] {
        assert_eq!(fixture[key], hex::encode(Sha256::digest(bytes)), "{key}");
    }
    assert_eq!(fixture["runner_kind"], "host-ocaml");
    assert_eq!(
        fixture["runner_path"],
        "scripts/node-port/health-policy-fixtures.py"
    );
    assert!(fixture.get("builder_image").is_none());
    let host = &fixture["host"];
    assert_eq!(
        host["source_map_sha256"],
        hex::encode(Sha256::digest(source_bytes))
    );
    assert_eq!(
        host["verified_source_count"],
        source["files"].as_object().unwrap().len()
    );
    let compiled = host["compiled_sources"].as_object().unwrap();
    assert_eq!(compiled.len(), 3);
    for name in [ENV_SOURCE, PROBE_SOURCE, LIMITS_SOURCE] {
        assert_eq!(compiled[name]["original_sha256"], source["files"][name]);
        if name != ENV_SOURCE {
            assert_eq!(compiled[name]["compiled_sha256"], source["files"][name]);
        }
    }
    assert_eq!(
        host["run_environment_overrides"],
        json!({"OCAMLRUNPARAM":""})
    );
    assert_eq!(
        host["engine_declaration"]["path"],
        "lib/consensus/c_engine.ml"
    );
    assert_eq!(
        host["engine_declaration"]["source_sha256"],
        source["files"]["lib/consensus/c_engine.ml"]
    );
    assert_eq!(
        host["engine_declaration"]["source"],
        "let max_timeout_ms = 120_000"
    );
    let instrumentation = fixture["instrumentation"].as_object().unwrap();
    assert_eq!(instrumentation.len(), 1);
    let injected = &instrumentation[ENV_SOURCE];
    assert_eq!(injected["kind"], "test-only source prefix");
    assert_eq!(injected["prefix"], ENV_PREFIX);
    assert_eq!(
        injected["prefix_sha256"],
        hex::encode(Sha256::digest(ENV_PREFIX))
    );
    assert_eq!(injected["original_sha256"], source["files"][ENV_SOURCE]);
    assert_eq!(injected["replacements"], json!([]));
    let adapters = fixture["adapters"].as_object().unwrap();
    assert_eq!(adapters.len(), 2);
    for name in ["octra_consensus.ml", "consensus_proposal.ml"] {
        assert_eq!(
            adapters[name]["sha256"],
            hex::encode(Sha256::digest(adapters[name]["source"].as_str().unwrap()))
        );
    }
    assert!(fixture["qualification"]["body"]
        .as_str()
        .unwrap()
        .contains("Unchanged adopted"));
    assert!(fixture["qualification"]["excluded"]
        .as_str()
        .unwrap()
        .contains("orchestrator"));
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 1_800, "truncated health qualification");
    for group in [
        "required",
        "roots",
        "retry",
        "ahead",
        "ahead-extremes",
        "lag",
        "config",
    ] {
        let count = cases
            .iter()
            .filter(|case| case["input"]["group"] == group)
            .count();
        assert!(count > 0, "missing {group} vectors");
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
