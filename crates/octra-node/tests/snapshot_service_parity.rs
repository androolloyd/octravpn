//! Exact native local service scheduling and disabled gossip refusal vectors.
use octra_node_protocol::{
    consensus::resource_gossip,
    state_sync::{cycle, lease},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn integer(value: &Value) -> i64 {
    value.as_i64().unwrap()
}

fn run(case: &Value) -> Result<Value, String> {
    match case["op"].as_str().unwrap() {
        "policy" => {
            let p = cycle::Policy::new(integer(&case["interval"]), integer(&case["retain"]))
                .map_err(|e| e.to_string())?;
            Ok(json!([p.interval(), p.retention()]))
        }
        "cycle" => {
            let mut state = cycle::Cycle::new(case["published"].as_i64());
            let mut rows = Vec::new();
            for row in case["events"].as_array().unwrap() {
                let event = match row[0].as_str().unwrap() {
                    "head" => cycle::Event::Finalized(integer(&row[1])),
                    "after" => cycle::Event::FinalizedAfter {
                        epoch: integer(&row[1]),
                        minimum: integer(&row[2]),
                    },
                    "complete" => cycle::Event::Completed {
                        epoch: integer(&row[1]),
                        outcome: if row[2][0] == "failed" {
                            cycle::Outcome::Failed
                        } else {
                            cycle::Outcome::Published(integer(&row[2][1]))
                        },
                    },
                    _ => unreachable!(),
                };
                match state.step(cycle::Policy::default(), event) {
                    Ok((next, effects)) => {
                        state = next;
                        rows.push(json!({"ok":{"published":state.published,"running":state.running,"effects":effects.into_iter().map(|effect|match effect {cycle::Effect::Capture(epoch)=>json!(["capture",epoch]),cycle::Effect::Retain(n)=>json!(["retain",n])}).collect::<Vec<_>>()}}));
                    }
                    Err(error) => {
                        rows.push(json!({"error":error.to_string()}));
                        break;
                    }
                }
            }
            Ok(json!(rows))
        }
        "override" => Ok(json!(cycle::publisher_override(
            case["value"].as_str().map(str::as_bytes)
        )
        .map_err(|e| e.to_string())?)),
        "retention" => {
            let snapshots = case["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    (
                        row[0].as_str().unwrap().as_bytes().to_vec(),
                        integer(&row[1]),
                    )
                })
                .collect::<Vec<_>>();
            Ok(json!(cycle::retention_plan(
                integer(&case["retain"]) as usize,
                case["current"].as_str().unwrap().as_bytes(),
                &snapshots
            )
            .into_iter()
            .map(|id| String::from_utf8(id).unwrap())
            .collect::<Vec<_>>()))
        }
        "lease" => Ok(json!(lease::active(
            case["now"].as_f64().unwrap(),
            case["published"].as_f64().unwrap(),
            case["last_seen"].as_f64().unwrap()
        ))),
        "leases" => {
            let leases = case["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| lease::Lease {
                    snapshot_id: row[0].as_str().unwrap().as_bytes().to_vec(),
                    last_seen: row[1].as_f64().unwrap(),
                })
                .collect::<Vec<_>>();
            Ok(json!(lease::retained(&leases)
                .iter()
                .map(|id| String::from_utf8(id.clone()).unwrap())
                .collect::<Vec<_>>()))
        }
        "disabled_gossip" => {
            use base64::Engine;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(case["raw"].as_str().unwrap())
                .unwrap();
            resource_gossip::disabled_reason(case["chain"].as_str().unwrap().as_bytes(), &raw)
                .map(|reason| json!(String::from_utf8_lossy(reason)))
                // The protocol exposes the native failure reason; the oracle
                // serializes the enclosing OCaml Failure exception.
                .map_err(|error| format!("Failure({})", json!(error.to_string())))
        }
        op => panic!("unknown op {op}"),
    }
}
#[test]
fn native_cycle_lease_and_disabled_resource_gossip_match_pinned_oracle() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/snapshot-service.json");
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(path).expect("generate pinned snapshot-service oracle fixture"),
    )
    .unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], pin["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (name, source) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/snapshot-service-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/snapshot-service-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(fixture[name], json!(hex::encode(Sha256::digest(source))));
    }
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let actual = match run(case) {
            Ok(value) => json!({"ok":value}),
            Err(error) => json!({"error":error}),
        };
        assert_eq!(actual, case["expected"], "case {index}: {case}");
    }
}
