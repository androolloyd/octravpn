use base64::{engine::general_purpose::STANDARD, Engine as _};
use octra_node_protocol::{
    consensus::{Validator, ValidatorSet},
    native_json::{Document, Value as Native},
    state_sync::{checkpoint, manifest, Result},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn bytes(value: &Value) -> Vec<u8> {
    value.as_str().unwrap().as_bytes().to_vec()
}
fn text(value: &Native) -> &[u8] {
    match value {
        Native::String(value) => value,
        _ => panic!("fixture string"),
    }
}
fn validator_set(case: &Value) -> ValidatorSet {
    let entries: Vec<_> = case["validators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                Validator {
                    address: bytes(&v["address"]),
                    pubkey: STANDARD.decode(bytes(&v["pubkey"])).unwrap(),
                },
                v["weight"].as_i64().unwrap().into(),
            )
        })
        .collect();
    let mut set = if case["weighted"].as_bool().unwrap() {
        ValidatorSet::weighted(entries).unwrap()
    } else {
        ValidatorSet::unweighted(entries.into_iter().map(|(v, _)| v).collect())
    };
    // Bootstrap signer sets commit to base64 keys; consensus sets use raw keys.
    for validator in &mut set.validators {
        validator.pubkey = STANDARD.encode(&validator.pubkey).into_bytes();
    }
    set
}
fn run(case: &Value) -> Result<Value> {
    let raw = STANDARD.decode(bytes(&case["raw"])).unwrap();
    let doc = Document::parse(&raw).unwrap();
    let value = doc.root();
    match case["op"].as_str().unwrap() {
        "checkpoint" => Ok(json!(hex::encode(
            checkpoint::Body::parse(&doc, value)?.hash()?
        ))),
        "manifest" => Ok(json!(hex::encode(
            manifest::Body::parse(&doc, value)?.hash()?
        ))),
        "reference" => {
            manifest::Body::parse(&doc, value)?.validate_reference()?;
            Ok(json!(true))
        }
        "file" => {
            manifest::File::parse(&doc, value)?.validate(case["chunk_size"].as_i64().unwrap())?;
            Ok(json!(true))
        }
        "draft" => {
            manifest::Draft::parse(&doc, value)?.verify()?;
            Ok(json!(true))
        }
        "certificate" => {
            let cert = manifest::Certificate::parse(&raw)?;
            cert.draft.verify()?;
            Ok(json!({
                "reference": matches!(cert.authority, manifest::Authority::Finalized(_)),
                "fresh": cert.fresh(case["now"].as_str().unwrap().parse().unwrap())
            }))
        }
        "entries" => {
            let Native::List(entries) = value else {
                panic!("fixture entries")
            };
            let entries: Vec<_> = entries
                .iter()
                .map(|i| text(doc.get(*i).unwrap()).to_vec())
                .collect();
            Ok(json!(String::from_utf8(manifest::set_hash(
                &manifest::signer_set(&entries)?
            )?)
            .unwrap()))
        }
        "pubkey" => Ok(json!(hex::encode(checkpoint::raw_pubkey(text(value))?))),
        "signature" => Ok(json!(hex::encode(checkpoint::raw_signature(text(value))?))),
        "path" => Ok(json!(manifest::valid_path(text(value)))),
        "reference_file" => Ok(json!(manifest::reference_file(text(value)))),
        "same" => {
            let left = checkpoint::Body::parse(&doc, doc.field(value, b"left").unwrap())?;
            let right = checkpoint::Body::parse(&doc, doc.field(value, b"right").unwrap())?;
            Ok(json!(left.same_finalized_state(&right)))
        }
        "quorum" | "exporters" => {
            let set = validator_set(case);
            let signatures: Vec<_> = case["signatures"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| checkpoint::Signature {
                    signer: bytes(&v["signer"]),
                    signature: bytes(&v["signature"]),
                })
                .collect();
            if case["op"] == "quorum" {
                checkpoint::Body::parse(&doc, value)?.verify_quorum(&set, &signatures)?;
            } else {
                let mut message = STANDARD.decode(bytes(&case["message"])).unwrap();
                if case["mutate"] == true {
                    message.extend_from_slice(b"changed");
                }
                manifest::verify_exporters(
                    &set,
                    case["required"].as_u64().unwrap() as usize,
                    &message,
                    &signatures,
                )?;
            }
            Ok(json!(true))
        }
        op => panic!("unknown operation: {op}"),
    }
}

#[test]
fn native_snapshot_commitments_and_signatures() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/state-sync.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], pin["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (field, source) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/state-sync-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/state-sync-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(fixture[field], json!(hex::encode(Sha256::digest(source))));
    }
    let mut failures = Vec::new();
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let actual = match run(case) {
            Ok(value) => json!({ "ok": value }),
            Err(error) => json!({ "error": error.to_string() }),
        };
        if actual != case["expected"] {
            failures.push(format!(
                "{index} {}: expected {} got {actual}",
                case["op"], case["expected"]
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
