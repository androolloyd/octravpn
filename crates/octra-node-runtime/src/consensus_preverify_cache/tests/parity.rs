//! Real unchanged native cache, with supplied proof verdicts. Other tests cover
//! concurrent ownership; this corpus does not simulate cryptographic checks.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::native_json::Document;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const INPUT_SHA256: &str = "8a4a62c4b76997925968aa13c6603d9a3f7e6bdfdb0485b305789c7398c90cf8";

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(name, value)| (name.clone(), canonical(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
        value => value.clone(),
    }
}
fn purpose(value: &Value) -> Purpose {
    match value.as_str().unwrap() {
        "build" => Purpose::Build,
        "validate" => Purpose::Validate,
        other => panic!("unexpected fixture purpose {other}"),
    }
}
fn run(input: &Value) -> Value {
    if input["group"] == "key" {
        return json!(hex::encode(item_key(
            input["epoch"].as_str().unwrap().parse().unwrap(),
            purpose(&input["purpose"]),
            &hex::decode(input["root"].as_str().unwrap()).unwrap(),
            &hex::decode(input["tx_hash"].as_str().unwrap()).unwrap(),
        )));
    }
    let cache = Cache::new(
        input["capacity"].as_u64().unwrap() as usize,
        input["limit"].as_u64().unwrap() as usize,
    );
    let txs = input["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|raw| {
            let raw = STANDARD.decode(raw.as_str().unwrap()).unwrap();
            Transaction::from_document(&Document::parse(&raw).unwrap()).unwrap()
        })
        .collect::<Vec<_>>();
    if input["group"] == "shared" {
        let shared = Shared::new(
            input["capacity"].as_u64().unwrap() as usize,
            input["limit"].as_u64().unwrap() as usize,
        );
        return json!(input["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| {
                let values = step
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|i| txs[i.as_u64().unwrap() as usize].clone())
                    .collect::<Vec<_>>();
                let announced = shared
                    .share(&values)
                    .unwrap()
                    .into_iter()
                    .map(|hash| String::from_utf8(hash).unwrap())
                    .collect::<Vec<_>>();
                let available = txs
                    .iter()
                    .map(|tx| {
                        shared
                            .find(hex::encode(tx.hash().unwrap()).as_bytes())
                            .unwrap()
                            .is_some()
                    })
                    .collect::<Vec<_>>();
                json!({"announced":announced,"available":available})
            })
            .collect::<Vec<_>>());
    }
    let mut calls = 0;
    json!(input["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| {
            let scope = cache
                .select(&hex::decode(step["root"].as_str().unwrap()).unwrap(), ())
                .unwrap();
            let result = cache.run(
                &scope,
                step["epoch"].as_str().unwrap().parse().unwrap(),
                purpose(&step["purpose"]),
                &txs[step["tx"].as_u64().unwrap() as usize],
                || {
                    calls += 1;
                    match step["verdict"].as_str().unwrap() {
                        "ready" => Ok(ready()),
                        "invalid" => Ok(skipped(Kind::Invalid)),
                        "unavailable" => Ok(skipped(Kind::Unavailable)),
                        "deferred" => Ok(skipped(Kind::Deferred)),
                        "error" => Err(Error("fixture error".into())),
                        other => panic!("unexpected fixture verdict {other}"),
                    }
                },
            );
            let outcome = match result {
                Ok(Checked::Ready(_)) => "ready",
                Ok(Checked::Skip {
                    kind: Kind::Invalid,
                    ..
                }) => "invalid",
                Ok(Checked::Skip {
                    kind: Kind::Unavailable,
                    ..
                }) => "unavailable",
                Ok(Checked::Skip {
                    kind: Kind::Deferred,
                    ..
                }) => "deferred",
                Err(_) => "error",
            };
            let (entries, queue, bytes) = stats(&cache);
            json!({"outcome":outcome, "calls":calls,"entries":entries,"queue":queue,"bytes":bytes})
        })
        .collect::<Vec<_>>())
}

#[test]
fn exact_native_item_keys_retention_and_bounded_fifo() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/consensus-preverify-cache.json"
    ))
    .unwrap();
    let source: Value = serde_json::from_str(include_str!(
        "../../../../../docs/rust-node/source-map.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["upstream_commit"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(
        fixture["builder_image"],
        "sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95"
    );
    for (name, bytes) in [
        (
            "oracle_sha256",
            include_bytes!("../../../../../scripts/node-port/consensus-preverify-cache-oracle.ml")
                .as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!(
                "../../../../../scripts/node-port/consensus-preverify-cache-fixtures.py"
            )
            .as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
        (
            "transaction_fixture_sha256",
            include_bytes!("../../../tests/fixtures/epoch-partition.json").as_slice(),
        ),
    ] {
        assert_eq!(fixture[name], hex::encode(Sha256::digest(bytes)), "{name}");
    }
    assert_eq!(fixture["groups"], json!({"key":336,"trace":48,"shared":16}));
    assert_eq!(fixture["input_sha256"], INPUT_SHA256);
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 400);
    let inputs = Value::Array(cases.iter().map(|case| case["input"].clone()).collect());
    assert_eq!(
        hex::encode(Sha256::digest(
            serde_json::to_vec(&canonical(&inputs)).unwrap()
        )),
        INPUT_SHA256
    );
    for (index, case) in cases.iter().enumerate() {
        assert_eq!(
            run(&case["input"]),
            case["expected"],
            "native item-cache case {index}"
        );
    }
}
