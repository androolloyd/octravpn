use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    consensus::{
        codec::Wire, policy::Protocol, reward, reward_attribution as r, Error, Finalize,
        ValidatorSet,
    },
    epoch_rewards::Attribution,
    oce1::Writer,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn raw(j: &Value, name: &str) -> Vec<u8> {
    hex::decode(j[name].as_str().unwrap()).unwrap()
}
fn attribution(a: &Attribution) -> Value {
    json!({"proposer":hex::encode(&a.proposer),"key":a.proposer_public_key.as_ref().map(hex::encode),
        "validators":a.validators.iter().map(|v|json!({"address":hex::encode(&v.address),"key":v.public_key.as_ref().map(hex::encode),"weight":v.weight.to_string()})).collect::<Vec<_>>()})
}
fn result<T>(r: Result<T, Error>, f: impl FnOnce(T) -> Value) -> Value {
    match r {
        Ok(x) => json!({"ok":f(x)}),
        Err(e) => json!({"error":e.to_string()}),
    }
}
#[test]
fn native_reward_attribution_binds_parent_members_and_historical_protocols() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/reward-attribution.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/reward-attribution-oracle.ml"
        )))
    );
    assert_eq!(
        fixture["runner_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/native-oracle.py"
        )))
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let j = &case["input"];
        let set = ValidatorSet::decode(&raw(j, "validators")).unwrap();
        let mut finalized = Finalize::decode(&raw(j, "wire")).unwrap();
        finalized.parent_commit = Some(
            octra_node_protocol::consensus::ParentCommit::decode(&raw(j, "parent_wire")).unwrap(),
        );
        finalized.chain_id = raw(j, "chain");
        finalized.epoch_id = j["epoch"].as_str().unwrap().parse().unwrap();
        finalized.header.chain_id = finalized.chain_id.clone();
        finalized.header.epoch_id = finalized.epoch_id;
        finalized.header.proto_version = j["version"].as_i64().unwrap();
        match j["parent"].as_str().unwrap() {
            "none" => finalized.parent_commit = None,
            "empty" => {
                if let Some(p) = &mut finalized.parent_commit {
                    p.certificate.precommits.clear();
                }
            }
            "unknown" => {
                if let Some(p) = &mut finalized.parent_commit {
                    p.certificate.header.creator_addr = b"unknown".to_vec();
                }
            }
            "unknown_member" => {
                if let Some(p) = &mut finalized.parent_commit {
                    for vote in &mut p.certificate.precommits {
                        vote.validator = b"unknown".to_vec();
                    }
                }
            }
            _ => (),
        }
        let keys = set
            .validators
            .iter()
            .map(|v| (v.address.clone(), STANDARD.encode(&v.pubkey).into_bytes()))
            .collect::<Vec<_>>();
        let mut supplied = r::full_set(&finalized.header.creator_addr, &keys);
        match j["supply"].as_str().unwrap() {
            "parent" => {
                if let Some(p) = &finalized.parent_commit {
                    if let Ok(a) = r::of_parent(p) {
                        supplied = a;
                    }
                }
            }
            "reverse" => supplied.validators.reverse(),
            "weight" => {
                for v in &mut supplied.validators {
                    v.weight = 17.into();
                }
            }
            "bad_key" => supplied.proposer_public_key = Some(b"%%%%".to_vec()),
            "short_key" => supplied.proposer_public_key = Some(b"AA==".to_vec()),
            "duplicate" => supplied.validators.extend(supplied.validators.clone()),
            "empty" => supplied.validators.clear(),
            "no_key" => supplied.proposer_public_key = None,
            _ => (),
        }
        let source = r::to_source(&supplied);
        let wire = result(source.clone(), |s| {
            let mut w = Writer::new();
            reward::put(&mut w, &s).unwrap();
            json!(hex::encode(w.into_bytes()))
        });
        assert_eq!(
            json!({
                "supplied":attribution(&supplied),
                "source":wire,
                "roundtrip":result(source.and_then(|s|r::of_source(&s)),|a|attribution(&a)),
                "bind":result(r::bind_finality(&set,&finalized,&supplied),|a|attribution(&a)),
                "resolve":result(r::resolve(&finalized.chain_id,finalized.epoch_id,Protocol::new(j["activation"].as_str().unwrap().parse().unwrap()).unwrap(),&finalized.header.creator_addr,&keys,finalized.parent_commit.as_ref()),|a|attribution(&a)),
            }),
            case["expected"],
            "native reward case {index}"
        );
    }
}
