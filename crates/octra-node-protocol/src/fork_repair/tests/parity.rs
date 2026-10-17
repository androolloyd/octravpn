use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const INPUT_SHA256: &str = "022b1c69baca8b73cc0d6d452ad95ebf11726a74396512a3558f01da2910518d";

fn raw(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn encoded(value: &[u8]) -> Value {
    json!(STANDARD.encode(value))
}
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
fn run(input: &Value) -> Value {
    match input["op"].as_str().unwrap() {
        "parse" => match Plan::parse(&raw(&input["raw"])) {
            Err(_) => json!({"accepted":false}),
            Ok(value) => json!({"accepted":true,"encoded":encoded(&value.encode().unwrap()),
                "source":encoded(&encode_head(&value.source).unwrap()),
                "head":encoded(&encode_head(&value.head).unwrap())}),
        },
        "source" => {
            let value = Plan::parse(&raw(&input["plan"])).unwrap();
            let current = parse_head(&raw(&input["current"])).unwrap();
            json!({"same_source":same_source(&current,&value.source),"accepts":value.accepts_source(&current)})
        }
        "finish" => {
            let optional = |name: &str| (!input[name].is_null()).then(|| raw(&input[name]));
            let mut backend = Backend {
                plan: optional("plan").map(|raw| Plan::parse(&raw).unwrap()),
                head: optional("current").map(|raw| parse_head(&raw).unwrap()),
                entries: input["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| {
                        let epoch = value["height"].as_str().unwrap().parse().unwrap();
                        (
                            epoch,
                            Entry {
                                epoch,
                                root: raw(&value["root"]),
                                txid: value["txid"].as_str().unwrap().parse().unwrap(),
                            },
                        )
                    })
                    .collect(),
                trace: Vec::new(),
                fail: input["fail"].as_str().map(str::to_owned),
                committed: input["committed"].as_bool().unwrap(),
            };
            assert_eq!(input["dropped"], "3");
            let result = match finish(&mut backend) {
                Ok(Finish::Idle) => json!({"ok":{"kind":"idle"}}),
                Ok(Finish::Resumed {
                    target,
                    head,
                    dropped,
                }) => json!({"ok":{"kind":"resumed", "target":target.to_string(),
                    "head":head.to_string(),"dropped":dropped.to_string()}}),
                Err(error) => json!({"error":error.to_string()}),
            };
            json!({"result":result,"trace":backend.trace})
        }
        value => panic!("unknown fork repair vector {value}"),
    }
}

#[test]
fn adopted_native_record_source_and_finish_policies_match_complete_corpus() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fork-repair.json");
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(path).expect("generate unchanged native fork repair core fixtures"),
    )
    .unwrap();
    let source: Value = serde_json::from_slice(include_bytes!(
        "../../../../../docs/rust-node/source-map.json"
    ))
    .unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    for (name, content) in [
        (
            "oracle_sha256",
            include_bytes!("../../../../../scripts/node-port/fork-repair-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../../../scripts/node-port/fork-repair-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(
            fixture[name],
            hex::encode(Sha256::digest(content)),
            "{name}"
        );
    }
    for path in [
        "lib/core/head_record.ml",
        "lib/core/head_manifest.ml",
        "lib/core/fork_repair_log.ml",
        "lib/core/fork_head_repair.ml",
        "node_runtime/fork_repair_boot.ml",
    ] {
        assert_eq!(fixture["source_sha256"][path].as_str().unwrap().len(), 64);
    }
    assert_eq!(
        fixture["builder_image"],
        "sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95"
    );
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(fixture["adapters"], json!({}));
    assert_eq!(fixture["input_sha256"], INPUT_SHA256);
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 173);
    let inputs = Value::Array(cases.iter().map(|case| case["input"].clone()).collect());
    assert_eq!(
        hex::encode(Sha256::digest(
            serde_json::to_vec(&canonical(&inputs)).unwrap()
        )),
        INPUT_SHA256
    );
    assert_eq!(fixture["vector_groups"].as_object().unwrap().len(), 8);
    for (group, expected) in [
        ("valid-records", 15),
        ("int64-encoding", 6),
        ("scalar-shapes", 25),
        ("head-shapes", 40),
        ("plan-guards", 37),
        ("field-selection", 8),
        ("source-binding", 19),
        ("finish", 23),
    ] {
        let count = cases
            .iter()
            .filter(|case| case["input"]["group"] == group)
            .count();
        assert_eq!(count, expected, "{group}");
        assert_eq!(fixture["vector_groups"][group], count, "{group}");
    }
    for (index, case) in cases.iter().enumerate() {
        assert_eq!(
            run(&case["input"]),
            case["expected"],
            "native case{index}:{}",
            case["input"]
        );
    }
}
