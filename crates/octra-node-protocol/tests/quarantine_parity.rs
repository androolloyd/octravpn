//! Byte-level policy and native entry/clear transitions. This does not qualify
//! network evidence, the recovery supervisor or any history rollback backend.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use octra_node_protocol::consensus::quarantine::{self as policy, RootEvidence};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SOURCE: &str = "node_runtime/consensus_runtime_state.ml";

fn bytes(input: &Value, name: &str) -> Vec<u8> {
    STANDARD.decode(input[name].as_str().unwrap()).unwrap()
}
fn encoded(value: &[u8]) -> Value {
    json!(STANDARD.encode(value))
}
fn state(active: bool, reason: &[u8], since: i64, attested: bool) -> Value {
    json!({"active":active,"reason":encoded(reason),"since":since.to_string(),
        "attested":attested,"attested_head":attested,
        "streaks":if active { ["3","4","1"] } else { ["0","0","0"] }})
}
fn run(input: &Value) -> Value {
    match input["op"].as_str().unwrap() {
        "classify" => {
            let reason = bytes(input, "reason");
            json!({
                "root":policy::root_attestation_recovers(&reason),
                "consensus":policy::consensus_root_attestation_recovers(&reason),
                "catchup":policy::catchup_recovers(&reason),
                "recoverable":policy::recoverable_reason(&reason),
            })
        }
        "evidence" => json!(policy::root_evidence(&bytes(input, "evidence"))),
        "recovery" => {
            let reason = bytes(input, "reason");
            let evidence = bytes(input, "evidence");
            policy::root_recovery_evidence(
                &reason,
                &evidence,
                input["consensus"].as_bool().unwrap(),
            )
            .map_or(Value::Null, encoded)
        }
        "clear" => json!(policy::clear_allowed(
            &bytes(input, "reason"),
            &bytes(input, "evidence")
        )),
        "inactive" => json!({"kind":"inactive"}),
        "transition" => {
            let old = bytes(input, "reason");
            let incoming = bytes(input, "incoming");
            let evidence = bytes(input, "evidence");
            let epoch: i64 = input["epoch"].as_str().unwrap().parse().unwrap();
            let replaced = policy::replace_reason(&old, &incoming);
            let reason = if replaced { &incoming } else { &old };
            let allowed = policy::clear_allowed(reason, &evidence);
            // Native entry revokes initial attestation. A later hard cause
            // revokes fresh attestation without changing the original epoch.
            let attested = !replaced;
            json!({"first":true,"initial":state(true,&old,epoch,false),
                "second":false,"entered":state(true,reason,epoch,attested),
                "clear":if allowed { json!({"kind":"cleared"}) }
                    else { json!({"kind":"refused","reason":encoded(reason)}) },
                "final":if allowed { state(false,b"",-1,attested) }
                    else { state(true,reason,epoch,attested) },
            })
        }
        op => panic!("unknown quarantine oracle operation: {op}"),
    }
}

#[test]
fn quarantine_policy_and_entry_transitions_match_unchanged_native_body() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/quarantines.json");
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(path).expect("generate the pinned native quarantine oracle fixture"),
    )
    .unwrap();
    let source_bytes = include_bytes!("../../../docs/rust-node/source-map.json");
    let source: Value = serde_json::from_slice(source_bytes).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    for (name, value) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/quarantine-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/quarantine-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/quarantine-fixtures.py").as_slice(),
        ),
    ] {
        assert_eq!(fixture[name], hex::encode(Sha256::digest(value)), "{name}");
    }
    assert_eq!(fixture["runner_kind"], "host-ocaml");
    assert_eq!(
        fixture["runner_path"],
        "scripts/node-port/quarantine-fixtures.py"
    );
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(fixture["adapters"], json!({}));
    let host = &fixture["host"];
    assert_eq!(host["compiler_version"], "4.14.2");
    assert_eq!(
        host["source_map_sha256"],
        hex::encode(Sha256::digest(source_bytes))
    );
    assert_eq!(
        host["verified_source_count"],
        source["files"].as_object().unwrap().len()
    );
    let compiled = host["compiled_sources"].as_object().unwrap();
    assert_eq!(compiled.len(), 1);
    assert_eq!(compiled[SOURCE]["original_sha256"], source["files"][SOURCE]);
    assert_eq!(compiled[SOURCE]["compiled_sha256"], source["files"][SOURCE]);
    let interface = format!("{SOURCE}i");
    assert_eq!(host["omitted_interface"]["path"], interface);
    assert_eq!(
        host["omitted_interface"]["source_sha256"],
        source["files"][&interface]
    );
    assert_eq!(
        host["run_environment_overrides"],
        json!({"OCAMLRUNPARAM":""})
    );
    for name in ["opam", "ocamlfind", "ocamlopt"] {
        assert!(host["tools"][name]["path"]
            .as_str()
            .unwrap()
            .starts_with('/'));
        assert_eq!(host["tools"][name]["sha256"].as_str().unwrap().len(), 64);
    }
    let commands = host["commands"].as_array().unwrap();
    let build = commands
        .iter()
        .find(|command| command["name"] == "build")
        .unwrap();
    let argv = build["argv"].as_array().unwrap();
    assert!(argv.contains(&json!("consensus_runtime_state.ml")));
    assert!(!argv.contains(&json!("consensus_runtime_state.mli")));
    assert!(commands.iter().any(|command| command["name"] == "oracle"));

    for (value, expected) in [
        (RootEvidence::GenesisInSync, b"genesis_in_sync".as_slice()),
        (RootEvidence::InSync, b"in_sync"),
        (
            RootEvidence::AheadWaitCurrentHead,
            b"ahead_wait_current_head",
        ),
        (
            RootEvidence::AheadCurrentRootQuorum,
            b"ahead_current_root_quorum",
        ),
        (RootEvidence::SoftLagCurrentRoot, b"soft_lag_current_root"),
    ] {
        assert_eq!(value.as_bytes(), expected);
        assert!(policy::root_evidence(value.as_bytes()));
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 5_000, "truncated quarantine qualification");
    for group in [
        "reason-bytes",
        "reason-recovery",
        "evidence-bytes",
        "clear-evidence-bytes",
        "evidence-recovery",
        "known-clear",
        "known-recovery",
        "entry-transitions",
        "transition-clear",
        "inactive",
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
