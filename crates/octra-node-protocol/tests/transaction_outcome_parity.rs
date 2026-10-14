use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    native_json::Document,
    transaction::{RuleMode, Transaction},
    transaction_outcome::{self as outcome, Error, Item, Partition, Rejection},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn encoded(value: &[u8]) -> Value {
    json!(STANDARD.encode(value))
}
fn tx(value: &Value) -> Transaction {
    Transaction::from_document(&Document::parse(&bytes(value)).unwrap()).unwrap()
}
fn txs(value: &Value) -> Vec<Transaction> {
    value.as_array().unwrap().iter().map(tx).collect()
}
fn raws(value: &Value) -> Vec<Vec<u8>> {
    value.as_array().unwrap().iter().map(bytes).collect()
}
fn rejection(value: &Value) -> Rejection {
    Rejection {
        position: value["position"].as_i64().unwrap(),
        tx: tx(&value["tx"]),
        error_type: bytes(&value["error_type"]),
        reason: bytes(&value["reason"]),
        charged: value["charged"].as_bool().unwrap(),
    }
}
fn rejected(values: &[Rejection]) -> Value {
    json!(values
        .iter()
        .map(|r| encoded(&outcome::encode_rejection(r).unwrap()))
        .collect::<Vec<_>>())
}
fn partition(value: Partition) -> Value {
    json!({"preverify":value.preverify.into_iter().map(|v|encoded(&v)).collect::<Vec<_>>(),"rejections":rejected(&value.rejections)})
}
fn hashes(values: Vec<Transaction>) -> Value {
    json!(values
        .into_iter()
        .map(|tx| hex::encode(tx.hash().unwrap()))
        .collect::<Vec<_>>())
}
fn caught<T>(value: Result<T, Error>, convert: impl FnOnce(T) -> Value) -> Value {
    match value {
        Ok(value) => convert(value),
        Err(Error::Rejected(error)) => json!({"error":error}),
        Err(Error::Unavailable(error)) => panic!("unqualified operational failure: {error}"),
    }
}
fn run(input: &Value) -> Value {
    let admit = || input["admit"].as_bool().unwrap();
    match input["op"].as_str().unwrap() {
        "normalize" => json!([
            encoded(&outcome::normalize_error_type(&bytes(&input["error_type"]))),
            encoded(&outcome::normalize_reason(
                &bytes(&input["error_type"]),
                &bytes(&input["reason"])
            ))
        ]),
        "encode" => encoded(&outcome::encode_rejection(&rejection(&input["rejection"])).unwrap()),
        "parse" => caught(
            outcome::parse(&bytes(&input["raw"]), admit()),
            |v| match v {
                Item::Preverify(v) => json!({"preverify":encoded(&v)}),
                Item::Rejection(r) => {
                    json!({"rejection":encoded(&outcome::encode_rejection(&r).unwrap())})
                }
            },
        ),
        "split" => caught(outcome::split(&raws(&input["raws"]), admit()), partition),
        "decode" => caught(
            outcome::decode(&txs(&input["confirmed"]), &raws(&input["raws"]), admit()),
            partition,
        ),
        "build" => {
            let rejections: Vec<_> = input["rejected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    let r = rejection(v);
                    (r.tx, r.error_type, r.reason)
                })
                .collect();
            caught(
                outcome::build(&txs(&input["inputs"]), &rejections, &txs(&input["charged"])),
                |rs| rejected(&rs),
            )
        }
        "merge" => {
            let confirmed = txs(&input["confirmed"]);
            let rs: Vec<_> = input["rejections"]
                .as_array()
                .unwrap()
                .iter()
                .map(rejection)
                .collect();
            json!({"merge":caught(outcome::merge(&confirmed,&rs),hashes),"executed":hashes(outcome::executed(&confirmed,&rs).unwrap())})
        }
        "envelope" => {
            let mode = |key| {
                if input[key].as_bool().unwrap() {
                    RuleMode::Active
                } else {
                    RuleMode::Prior
                }
            };
            caught(
                outcome::check_envelopes(
                    outcome::Rules {
                        envelope: mode("envelope"),
                        compute: mode("compute"),
                        settle: mode("settle"),
                    },
                    &txs(&input["confirmed"]),
                    &raws(&input["raws"]),
                ),
                |()| Value::Null,
            )
        }
        _ => panic!("unknown outcome fixture"),
    }
}
#[test]
fn native_outcome_bytes_reconstruction_and_rule_selected_envelope_gates() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/transaction-outcome.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/outcome-oracle.ml"
        )))
    );
    for (i, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            run(&case["input"]),
            case["expected"],
            "case {i} {}",
            case["input"]["op"]
        );
    }
}
#[test]
fn malformed_json_never_becomes_a_fabricated_consensus_outcome() {
    for raw in [b"{".as_slice(), b"<variant>", b"[", b"\xff", b""] {
        assert!(matches!(
            outcome::parse(raw, false),
            Err(Error::Unavailable(_))
        ));
    }
}
