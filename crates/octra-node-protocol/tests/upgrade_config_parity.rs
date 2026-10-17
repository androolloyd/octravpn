//! The adopted native parser body with an explicitly instrumented environment
//! getter. This does not qualify process-environment acquisition or the launcher.
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::network::{upgrade, Error};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const NATIVE_SOURCE: &str = "net/p2p_upgrade_plan.ml";
const PREFIX: &str = "\
(* Test-only getter injection; the original parser body follows unchanged. *)
module Octra_upgrade_env = struct
  let values : (string * string) list ref = ref []
  let reads : string list ref = ref []
  let getenv_opt name =
    reads := name :: !reads;
    List.assoc_opt name !values
end
module Sys = struct
  include Sys
  let getenv_opt = Octra_upgrade_env.getenv_opt
end
";

fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn encoded(raw: impl AsRef<[u8]>) -> Value {
    json!(STANDARD.encode(raw))
}
fn target(value: &upgrade::Target) -> Value {
    json!({"epoch": value.epoch.to_string(), "binary": encoded(&value.binary_hash), "config": encoded(&value.config_hash)})
}
fn plan(value: Option<&upgrade::Plan>) -> Value {
    value.map_or(Value::Null, |value| {
        let mut row = target(&value.target);
        row["rollback"] = value.rollback.as_ref().map_or(Value::Null, target);
        row
    })
}
fn observe(value: Option<&upgrade::Plan>, input: &Value) -> Result<Value, Error> {
    let epoch = input["epoch"].as_str().unwrap().parse().unwrap();
    let config = bytes(&input["config"]);
    let binary = bytes(&input["binary"]);
    let required = input["required"].as_bool().unwrap();
    Ok(json!({
        "handshake": encoded(upgrade::handshake_hash(epoch, &config, &binary, required, value)?),
        "active": value.is_some_and(|value| value.active(epoch)),
        "rollback": value.is_some_and(|value| value.rollback_active(epoch)),
        "required": upgrade::binary_required(epoch, required, value),
        "expected": encoded(upgrade::expected_binary(epoch, &binary, value)),
        "ready": value.and_then(|value| value.ready(epoch, &config, &binary, required).err()).map(|error| error.to_string()),
        "schedule": value.map(|value| value.schedule_hash(&config).map(encoded)).transpose()?,
    }))
}
fn failure(error: Error) -> Value {
    json!({"error": encoded(error.into_bytes())})
}
fn run(input: &Value) -> Value {
    let environment = input["environment"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, value)| !value.is_null())
        .map(|(name, value)| (name.as_str(), bytes(value)))
        .collect::<Vec<_>>();
    let base = bytes(&input["base_config"]);
    let mut reads = Vec::new();
    let result = upgrade::from_inputs(&base, input["required"].as_bool().unwrap(), |name| {
        reads.push(name.to_owned());
        environment
            .iter()
            .find_map(|(key, value)| (*key == name).then_some(value.as_slice()))
    });
    let result = match result {
        Err(error) => failure(error),
        Ok(value) => json!({
            "plan": plan(value.as_ref()),
            "observations": input["probes"].as_array().unwrap().iter()
                .map(|input| observe(value.as_ref(), input).unwrap_or_else(failure)).collect::<Vec<_>>(),
        }),
    };
    reads.sort();
    json!({"result": result, "reads": reads})
}

#[test]
fn trusted_upgrade_configuration_matches_instrumented_native_getter() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/upgrade-config.json");
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(path).expect("generate the pinned upgrade-config native oracle fixture"),
    )
    .unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    for (key, bytes) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/upgrade-config-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/upgrade-config-fixtures.py").as_slice(),
        ),
    ] {
        assert_eq!(fixture[key], hex::encode(Sha256::digest(bytes)), "{key}");
    }
    let (runner_path, runner_bytes) = match fixture["runner_kind"].as_str().unwrap() {
        "docker" => (
            "scripts/node-port/native-oracle.py",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
        "host-ocaml" => {
            assert!(fixture.get("builder_image").is_none());
            assert_eq!(
                fixture["host"]["verified_source_count"],
                source["files"].as_object().unwrap().len()
            );
            assert_eq!(
                fixture["host"]["compiled_sources"]
                    .as_object()
                    .unwrap()
                    .len(),
                5
            );
            (
                "scripts/node-port/upgrade-config-fixtures.py",
                include_bytes!("../../../scripts/node-port/upgrade-config-fixtures.py").as_slice(),
            )
        }
        kind => panic!("unrecognized oracle runner {kind}"),
    };
    assert_eq!(fixture["runner_path"], runner_path);
    assert_eq!(
        fixture["runner_sha256"],
        hex::encode(Sha256::digest(runner_bytes))
    );
    let instrumentation = fixture["instrumentation"].as_object().unwrap();
    assert_eq!(instrumentation.len(), 1);
    let injected = &instrumentation[NATIVE_SOURCE];
    assert_eq!(injected["kind"], "test-only source prefix");
    assert_eq!(injected["prefix"], PREFIX);
    assert_eq!(
        injected["prefix_sha256"],
        hex::encode(Sha256::digest(PREFIX))
    );
    assert_eq!(injected["original_sha256"], source["files"][NATIVE_SOURCE]);
    assert_eq!(injected["replacements"], json!([]));
    assert!(fixture["qualification"]["environment_acquisition"]
        .as_str()
        .unwrap()
        .contains("test-only injected"));
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 400, "truncated parser qualification");
    for group in [
        "absence",
        "disabled",
        "partial",
        "upgrade-epoch",
        "rollback-epoch",
        "hashes",
        "defaults",
        "priority",
        "boundaries",
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
