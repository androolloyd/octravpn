use base64::{engine::general_purpose::STANDARD, Engine as _};
use octra_node_protocol::{
    native_integer,
    single::{self, Gate, Preverify},
};
use serde_json::{json, Value};
fn raw(v: &Value) -> Option<Vec<u8>> {
    v.as_str().map(|s| STANDARD.decode(s).unwrap())
}
fn encoded(raw: impl AsRef<[u8]>) -> Value {
    json!(STANDARD.encode(raw))
}
#[test]
fn pristine_roles_timer_proposer_validator_pairs_and_private_gate() {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/single-policy.json")).unwrap();
    assert_eq!(
        fixture["upstream_commit"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    assert_eq!(fixture["instrumentation"], json!({}));
    use sha2::{Digest as _, Sha256};
    let source_map: Value =
        serde_json::from_slice(include_bytes!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["source_sha256"], source_map["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/single-policy-oracle.ml"
        )))
    );
    assert_eq!(
        fixture["runner_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/resource-native-oracle.py"
        )))
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 227);
    for case in cases {
        let i = &case["input"];
        let actual = match i["kind"].as_str().unwrap() {
            "role" => {
                let mode = raw(&i["mode"]);
                let role = single::Role::of_mode(i["cli"].as_bool().unwrap(), mode.as_deref());
                json!({"label":role.label(),"consensus":role.consensus(),"voting":role.voting(),"observer":role.observer()})
            }
            "tick" => {
                let elapsed = match i["elapsed"].as_str().unwrap() {
                    "inf" => f64::INFINITY,
                    "-inf" => f64::NEG_INFINITY,
                    "nan" => f64::NAN,
                    s => s.parse().unwrap(),
                };
                let value = single::tick(elapsed);
                json!([value.apply, value.log_tick, value.next_sleep])
            }
            "proposer" => {
                let validators = i["validators"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| raw(v).unwrap())
                    .collect::<Vec<_>>();
                let fee = raw(&i["fee"]);
                let over = raw(&i["override"]);
                match single::proposer(
                    i["epoch"].as_i64().unwrap(),
                    &validators,
                    fee.as_deref(),
                    over.as_deref().map(|v| (v, 7)),
                ) {
                    Ok(value) => json!([
                        STANDARD.encode(value.address),
                        value.source,
                        value.commit_round
                    ]),
                    Err(e) if e == "List.nth" => {
                        json!({"exception":"Invalid_argument(\"List.nth\")"})
                    }
                    Err(e) => json!({"error":e}),
                }
            }
            "validators" => {
                let current = raw(&i["current"]);
                let next = raw(&i["next"]);
                let activation =
                    raw(&i["activation"]).and_then(|s| native_integer::parse_int63(&s));
                let values = single::validator_pairs(
                    current.as_deref(),
                    next.as_deref(),
                    activation,
                    (b"octWallet", b"raw-key"),
                    i["epoch"].as_i64().unwrap(),
                );
                json!(values
                    .into_iter()
                    .map(|(a, k)| json!([STANDARD.encode(a), STANDARD.encode(k)]))
                    .collect::<Vec<_>>())
            }
            "gate" => {
                let reason = raw(&i["reason"]).unwrap();
                let state = match i["state"].as_str().unwrap() {
                    "missing" => Preverify::Missing,
                    "pending" => Preverify::Pending,
                    "ready" => Preverify::Ready,
                    "failed" => Preverify::Failed(reason),
                    "unavailable" => Preverify::Unavailable(
                        [b"proof worker unavailable: ".as_slice(), &reason].concat(),
                    ),
                    _ => unreachable!(),
                };
                match single::preverify_gate(
                    &state,
                    i["count"].as_i64().unwrap(),
                    i["maximum"].as_i64().unwrap(),
                ) {
                    Gate::Ready => json!(["ready"]),
                    Gate::Failed(reason) => json!(["failed", encoded(reason)]),
                    Gate::Timeout(reason) => json!(["timeout", encoded(reason)]),
                    Gate::Defer { next_count, status } => {
                        json!(["defer", next_count, encoded(status)])
                    }
                    Gate::Unavailable { next_count, reason } => {
                        json!(["unavailable", next_count, encoded(reason)])
                    }
                }
            }
            "cache" | "cache-table" => {
                let float = |value: &Value| match value.as_str().unwrap() {
                    "nan" => f64::NAN,
                    "inf" => f64::INFINITY,
                    "-inf" => f64::NEG_INFINITY,
                    s => s.parse().unwrap(),
                };
                let mut entries = i["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| single::CacheEntry {
                        key: raw(&row["key"]).unwrap(),
                        timestamp: float(&row["time"]),
                        pending: row["pending"].as_bool().unwrap(),
                    })
                    .collect::<Vec<_>>();
                if i["kind"] == "cache-table" {
                    let mut table = octra_node_protocol::native_table::Table::new(100);
                    for entry in entries {
                        table.replace(entry.key.clone(), entry);
                    }
                    entries = table.iter().map(|(_, entry)| entry.clone()).collect();
                    entries.reverse();
                }
                let maximum = i["maximum"].as_u64().unwrap() as usize;
                let prune =
                    single::cache_prune(float(&i["now"]), float(&i["ttl"]), maximum, &entries);
                let (drop, requested) = single::cache_hard_cap(maximum, &entries);
                json!({"order":entries.iter().map(|e|encoded(&e.key)).collect::<Vec<_>>(),"expired":prune.expired.iter().map(encoded).collect::<Vec<_>>(),"overflow":prune.overflow.iter().map(encoded).collect::<Vec<_>>(),"hard_drop":drop.iter().map(encoded).collect::<Vec<_>>(),"requested":requested})
            }
            _ => unreachable!(),
        };
        assert_eq!(actual, case["expected"], "{i}");
    }
}
