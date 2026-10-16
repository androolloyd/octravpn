//! Actual pinned OCaml exported-API differential, including ordered pool state.
use num_bigint::BigInt;
use octra_node_protocol::{
    consensus::{
        resource_attestation_admission as a, resource_attestation_flow as f,
        resource_attestations as r, ValidatorSet,
    },
    oce1::{Error, Writer},
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
#[path = "../../octra-node/src/resource_attestation.rs"]
pub mod logging;
fn bytes(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}
fn int(v: &Value, k: &str) -> i64 {
    v[k].as_i64()
        .unwrap_or_else(|| v[k].as_str().unwrap().parse().unwrap())
}
fn z(v: &Value, k: &str) -> BigInt {
    v[k].as_str().unwrap().parse().unwrap()
}
fn hx(raw: impl AsRef<[u8]>) -> Value {
    json!(hex::encode(raw))
}
fn boxed(result: Result<Value, Error>) -> Value {
    match result {
        Ok(value) => json!({"ok":value}),
        Err(error) => json!({"error":error.to_string()}),
    }
}
fn attempt(f: impl FnOnce() -> Result<Value, Error>) -> Value {
    boxed(f())
}
macro_rules! fields {($($name:literal => $body:expr),* $(,)?)=>{{
    let mut map=Map::new();$(map.insert($name.into(),attempt(||->Result<Value,Error>{Ok($body)}));)* Value::Object(map)
}};}
fn att(v: &Value) -> r::Attestation {
    r::Attestation {
        chain_id: bytes(v, "chain_id"),
        epoch_id: int(v, "epoch_id"),
        node_id: bytes(v, "node_id"),
        kind: r::attestation_kind_of_u8(int(v, "kind").try_into().unwrap()).unwrap(),
        commitment: bytes(v, "commitment"),
        proof_hash: bytes(v, "proof_hash"),
        weight: int(v, "weight"),
        score: bytes(v, "score"),
        signature: bytes(v, "signature"),
    }
}
fn wire(v: &r::Attestation) -> Result<Value, Error> {
    Ok(hx(r::encode_attestation(v)?))
}
fn attestations(v: &Value) -> Vec<r::Attestation> {
    v["attestations"]
        .as_array()
        .unwrap()
        .iter()
        .map(att)
        .collect()
}
fn wires(values: &[r::Attestation]) -> Result<Value, Error> {
    values
        .iter()
        .map(wire)
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}
fn storage(v: &Value) -> r::StorageEvidence {
    r::StorageEvidence {
        leaf_index: int(v, "leaf_index"),
        leaf_count: int(v, "leaf_count"),
        chunk: bytes(v, "chunk"),
        path: v["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| r::MerkleStep {
                side: r::merkle_side_of_u8(int(s, "side").try_into().unwrap()).unwrap(),
                sibling_hash: bytes(s, "sibling_hash"),
            })
            .collect(),
    }
}
fn seed(v: &Value) -> f::EpochSeed {
    f::EpochSeed {
        chain_id: bytes(v, "chain_id"),
        epoch_id: int(v, "epoch_id"),
        prev_state_root: bytes(v, "prev_state_root"),
        prev_qc_randomness: bytes(v, "prev_qc_randomness"),
    }
}
fn window(v: &Value) -> a::Window {
    a::Window {
        current_epoch: int(v, "current_epoch"),
        fraud_window: int(v, "fraud_window"),
        future_window: int(v, "future_window"),
    }
}
fn payouts(values: &[r::Payout]) -> Value {
    json!(values
        .iter()
        .map(|p| json!([hx(&p.node_id), p.amount.to_string()]))
        .collect::<Vec<_>>())
}
fn snapshot(s: &f::CommitteeSnapshot) -> Result<Value, Error> {
    Ok(
        json!({"target_epoch":s.target_epoch.to_string(),"source_epoch":s.source_epoch.to_string(),
    "challenge":hx(&s.challenge),"committee":wires(&s.committee)?,"root":hx(&s.committee_root),"total":s.total_weight.to_string(),"quorum":s.quorum_weight.to_string()}),
    )
}
fn validators(s: &ValidatorSet) -> Value {
    json!({"members":s.validators.iter().map(|v|json!([hx(&v.address),hx(&v.pubkey)])).collect::<Vec<_>>(),
    "n":s.n,"f":s.f,"quorum":s.quorum,"weighted":s.weighted,"total":s.total_weight.to_string(),"quorum_weight":s.quorum_weight.to_string()})
}
fn gossip(v: &Value) -> f::Gossip {
    f::Gossip {
        chain_id: bytes(v, "chain_id"),
        seen_epoch: int(v, "seen_epoch"),
        attestation: att(&v["attestation"]),
    }
}
fn reason(v: &str) -> a::Reason {
    match v {
        "disabled" => a::Reason::Disabled,
        "capacity" => a::Reason::Capacity,
        "chain_mismatch" => a::Reason::ChainMismatch,
        "epoch_too_old" => a::Reason::EpochTooOld,
        "epoch_too_new" => a::Reason::EpochTooNew,
        "missing_challenge" => a::Reason::MissingChallenge,
        "malformed" => a::Reason::Malformed,
        "bad_score" => a::Reason::BadScore,
        "unknown_node" => a::Reason::UnknownNode,
        "bad_signature" => a::Reason::BadSignature,
        "conflicting_identity" => a::Reason::ConflictingIdentity,
        _ => panic!("fixture reason"),
    }
}
fn decision(v: &Value) -> a::Decision {
    match v["decision"].as_str().unwrap() {
        "accept" => a::Decision::Accept,
        "reject" => a::Decision::Reject(reason(v["reason"].as_str().unwrap())),
        "quarantine" => a::Decision::Quarantine(reason(v["reason"].as_str().unwrap())),
        _ => panic!("fixture decision"),
    }
}
fn evidence(e: &a::Evidence) -> Result<Value, Error> {
    Ok(
        json!({"node_id":hx(&e.node_id),"epoch_id":e.epoch_id.to_string(),"reason":a::reason_to_string(e.reason),
    "id":hx(&e.attestation_id),"observed":e.observed_epoch.to_string(),"evidence_id":hx(a::evidence_id(e)?)}),
    )
}
fn pool(v: &a::Pool) -> Result<Value, Error> {
    let mut identity = v
        .identity_index
        .iter()
        .map(|(k, v)| json!([hx(k), hx(v)]))
        .collect::<Vec<_>>();
    identity.reverse();
    Ok(
        json!({"accepted":wires(&a::accepted(v))?,"rejected":a::rejected(v).iter().map(evidence).collect::<Result<Vec<_>,_>>()?,
        "quarantined":a::quarantined(v).iter().map(evidence).collect::<Result<Vec<_>,_>>()?,"identity":identity}),
    )
}
fn counts(v: &a::Pool) -> Value {
    json!([
        v.accepted.values().len(),
        v.rejected.values().len(),
        v.quarantined.values().len()
    ])
}
fn known(v: &Value, calls: &mut Vec<Vec<u8>>, node: &[u8]) -> Option<Vec<u8>> {
    calls.push(node.to_vec());
    (!v["public"].is_null()).then(|| bytes(v, "public"))
}

fn generated(v: &Value, index: i64) -> Result<r::Attestation, Error> {
    let mut node = bytes(v, "prefix");
    node.extend_from_slice((int(v, "start") + index).to_string().as_bytes());
    let value = r::unsigned_attestation(
        bytes(v, "chain_id"),
        int(v, "epoch"),
        node,
        r::attestation_kind_of_u8(int(v, "kind").try_into().unwrap())?,
        bytes(v, "commitment"),
        vec![0; 32],
        int(v, "weight"),
    );
    r::sign_attestation(&[7; 32], r::with_score(&bytes(v, "challenge"), value)?)
}
fn run(v: &Value) -> Result<Value, Error> {
    Ok(match v["op"].as_str().unwrap() {
        "constants" => json!([
            a::MAX_ACCEPTED,
            a::MAX_EVIDENCE,
            f::MAX_CHAIN_ID_BYTES,
            f::MAX_ATTESTATION_BYTES
        ]),
        "enum" => fields! {
        "kind"=>{let raw=u8::try_from(int(v,"kind")).map_err(|_|Error::from("bad resource attestation kind"))?;let k=r::attestation_kind_of_u8(raw)?;json!([r::attestation_kind_to_u8(k),r::attestation_kind_to_string(k)])},
        "side"=>json!(r::merkle_side_to_u8(r::merkle_side_of_u8(u8::try_from(int(v,"side")).map_err(|_|Error::from("bad merkle side"))?)?))},
        "attestation" => {
            let a = att(&v["attestation"]);
            let ch = bytes(v, "challenge");
            let private = bytes(v, "private");
            fields! {
            "unsigned"=>wire(&r::unsigned_attestation(a.chain_id.clone(),a.epoch_id,a.node_id.clone(),a.kind,a.commitment.clone(),a.proof_hash.clone(),a.weight))?,
            "score"=>hx(r::attestation_score(&ch,&a)?),"scored"=>wire(&r::with_score(&ch,a.clone())?)?,"sign_bytes"=>hx(r::attestation_sign_bytes(&a)?),
            "id"=>hx(r::attestation_id(&a)?),"sign"=>wire(&r::sign_attestation(&private,a.clone())?)?,
            "public"=>{let seed:&[u8;32]=private.as_slice().try_into().map_err(|_|Error::from("fixture key"))?;hx(ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes())},
            "verify"=>json!(r::verify_attestation_signature(&bytes(v,"public"),&a)?),"well_formed"=>json!(r::is_well_formed(&a)),
            "encoded"=>wire(&a)?,"decode"=>wire(&r::decode_attestation(&bytes(v,"raw"))?)?,"proof_payload_hash"=>hx(r::proof_payload_hash(&bytes(v,"raw")))}
        }
        "math" => {
            let values = attestations(v);
            let total = z(v, "total");
            fields! {
            "sum"=>json!(r::sum_weight(&values).to_string()),"quorum"=>json!(r::quorum_weight(&total).to_string()),
            "intersection"=>json!(r::qc_intersection_floor(&total,&z(v,"left"),&z(v,"right")).to_string()),
            "conflicting"=>json!(r::conflicting_qc_impossible(&total,&z(v,"byzantine"))),
            "proportion"=>json!(r::proportional_amount(&z(v,"budget_z"),&total,int(v,"weight"))?.to_string()),
            "rewards"=>payouts(&r::distribute_resource_rewards(int(v,"budget"),&values)?),"committee"=>wires(&r::select_committee(int(v,"size"),&values))?,
            "take"=>wires(&r::take(int(v,"size"),&values))?,"root"=>hx(r::attestations_root(&values)?),
            "compare"=>json!(values.iter().map(|a|values.iter().map(|b|match r::compare_attestation(a,b){std::cmp::Ordering::Less=>-1,std::cmp::Ordering::Equal=>0,std::cmp::Ordering::Greater=>1}).collect::<Vec<_>>()).collect::<Vec<_>>()),
            "add_amount"=>{let mut map=r::NodeMap::new();for row in v["prior"].as_array().unwrap(){map.insert(hex::decode(row[0].as_str().unwrap()).unwrap(),row[1].as_str().unwrap().parse().unwrap());}
                json!(r::add_amount(&bytes(v,"node"),&z(v,"amount"),map).into_iter().map(|(k,n)|json!([hx(k),n.to_string()])).collect::<Vec<_>>())}}
        }
        "float" => {
            let float =
                |key| f64::from_bits(u64::from_str_radix(v[key].as_str().unwrap(), 16).unwrap());
            fields! {
            "kl"=>json!(format!("{:016x}",r::kl_divergence(float("p"),float("q"))?.to_bits())),
            "bound"=>json!(format!("{:016x}",r::committee_capture_bound(int(v,"size"),float("q"),float("p"))?.to_bits()))}
        }
        "pow" => {
            let a = att(&v["attestation"]);
            let ch = bytes(v, "challenge");
            let nonce = bytes(v, "nonce");
            fields! {
            "encoded"=>hx(r::encode_pow_evidence(&nonce)?),"proof"=>hx(r::pow_proof_hash(&nonce)?),"attempt"=>hx(r::pow_attempt_hash(&ch,&a,&nonce)?),
            "assigned"=>json!(r::assigned(&bytes(v,"commitment"),int(v,"max_weight"),&a)),
            "verify"=>json!(r::verify_pow_attestation(&ch,&bytes(v,"commitment"),int(v,"max_weight"),int(v,"difficulty"),&a,&nonce)?),
            "leading"=>json!(r::leading_zero_bits(&bytes(v,"digest"))),"byte_leading"=>json!(r::byte_leading_zero_bits(int(v,"byte")))}
        }
        "storage" => {
            let a = att(&v["attestation"]);
            let e = storage(&v["evidence"]);
            let ch = bytes(v, "challenge");
            fields! {
            "leaf"=>hx(r::storage_leaf_hash(&e.chunk)),"parent"=>hx(r::storage_parent_hash(&bytes(v,"left"),&bytes(v,"right"))?),
            "path"=>json!(r::storage_path(&e)),"root"=>hx(r::merkle_root_from_evidence(&e)?),"encoded"=>hx(r::encode_storage_evidence(&e)?),
            "proof"=>hx(r::storage_evidence_hash(&e)?),"prefix"=>json!(r::u64_prefix(&bytes(v,"digest"))?.to_string()),
            "index"=>json!(r::storage_challenge_index(&ch,int(v,"leaf_count"),&a)?.map(|i|i.to_string())),
            "verify"=>json!(r::verify_storage_attestation(&ch,&bytes(v,"commitment"),int(v,"max_weight"),int(v,"leaf_count"),&a,&e)?)}
        }
        "hashchain" => {
            let a = att(&v["attestation"]);
            let raw = &v["evidence"];
            let e = r::UsefulHashChainEvidence {
                input: bytes(raw, "input"),
                iterations: int(raw, "iterations"),
                result: bytes(raw, "result"),
            };
            let ch = bytes(v, "challenge");
            fields! {
            "task"=>hx(r::useful_hash_chain_task_id(&ch,&e.input,e.iterations)?),"encoded"=>hx(r::encode_useful_hash_chain_evidence(&e)?),
            "proof"=>hx(r::useful_hash_chain_evidence_hash(&e)?),"result"=>if v["encode_only"]==true{Value::Null}else{json!(r::useful_hash_chain_result(&e.input,e.iterations)?.map(hex::encode))},
            "verify"=>if v["encode_only"]==true{Value::Null}else{json!(r::verify_useful_hash_chain_attestation(&ch,&bytes(v,"commitment"),int(v,"max_weight"),int(v,"min_iterations"),int(v,"max_iterations"),&a,&e)?)}}
        }
        "flow" => {
            let values = attestations(v);
            let seed = seed(&v["seed"]);
            let ch = bytes(v, "challenge");
            let select = || {
                f::select_snapshot(
                    int(v, "delay"),
                    int(v, "size"),
                    int(v, "target"),
                    &seed,
                    &values,
                )
            };
            fields! {
            "challenge"=>hx(f::challenge(&seed)?),"activated"=>json!(f::activated_source_epoch(int(v,"delay"),int(v,"target"))?.map(|i|i.to_string())),
            "eligible"=>wires(&f::eligible_attestations(int(v,"source"),&ch,&values)?)?,
            "matches"=>json!(values.iter().map(|a|f::matches_epoch_challenge(int(v,"source"),&ch,a)).collect::<Result<Vec<_>,_>>()?),
            "root"=>hx(f::committee_root(int(v,"target"),int(v,"source"),&ch,&values)?),"snapshot"=>select()?.as_ref().map(snapshot).transpose()?.unwrap_or(Value::Null),
            "ready"=>json!(select()?.as_ref().map(|s|f::ready_for_voting(int(v,"minimum"),s))),
            "rewards"=>select()?.as_ref().map(|s|f::rewards_for_snapshot(int(v,"budget"),s).map(|p|payouts(&p))).transpose()?.unwrap_or(Value::Null),
            "validators"=>{let mut calls=vec![];let missing=bytes(v,"missing");let result=f::validator_set_of_committee(&mut|node|if node==missing{None}else{known(v,&mut calls,node)},&values);json!([result.as_ref().map(validators),calls.into_iter().map(hx).collect::<Vec<_>>()])}}
        }
        "gossip" => {
            let g = gossip(&v["gossip"]);
            fields! {"encoded"=>hx(f::encode_gossip(&g)?),"decode"=>hx(f::encode_gossip(&f::decode_gossip(&bytes(v,"raw"))?)?)}
        }
        "logging" => {
            let g = gossip(&v["gossip"]);
            let s = logging::seen(&g);
            fields! {
            "seen"=>json!([s.seen_epoch.to_string(),hx(&s.node),s.kind,s.weight.to_string()]),"message"=>hx(s.message()),
            "ready"=>{use std::{future::Future,task::{Context,Poll,Waker}};let mut ready=std::pin::pin!(logging::log_seen(&g));let result=ready.as_mut().poll(&mut Context::from_waker(Waker::noop()));json!(matches!(result,Poll::Ready(Ok(()))))}}
        }
        "admission" => {
            let mut state = a::create_pool();
            let mut results = vec![];
            for event in v["events"].as_array().unwrap() {
                results.push(attempt(|| -> Result<Value, Error> {
                    let w = window(&event["window"]);
                    Ok(match event["action"].as_str().unwrap() {
                        "snapshot" => pool(&state)?,
                        "prune" => {
                            a::prune(&mut state, w);
                            counts(&state)
                        }
                        "expired" => {
                            json!([a::valid_window(w), a::expired(w, int(event, "epoch"))])
                        }
                        "remember" => {
                            a::remember(
                                &mut state,
                                w,
                                decision(event),
                                &att(&event["attestation"]),
                            )?;
                            counts(&state)
                        }
                        action @ ("ingest_many" | "remember_many") => {
                            let mut results = vec![];
                            for index in 0..int(event, "count") {
                                let value = generated(event, index)?;
                                let d = if action == "remember_many" {
                                    let d = decision(event);
                                    a::remember(&mut state, w, d, &value)?;
                                    d
                                } else {
                                    let mut calls = vec![];
                                    a::ingest(
                                        &bytes(event, "chain_id"),
                                        &bytes(event, "challenge"),
                                        w,
                                        &mut |node| known(event, &mut calls, node),
                                        &mut state,
                                        &value,
                                    )?
                                };
                                results.push(a::decision_to_string(d));
                            }
                            json!([results, counts(&state)])
                        }
                        action @ ("classify" | "ingest") => {
                            let value = att(&event["attestation"]);
                            let mut calls = vec![];
                            let mut public = |node: &[u8]| known(event, &mut calls, node);
                            let decision = if action == "ingest" {
                                a::ingest(
                                    &bytes(event, "chain_id"),
                                    &bytes(event, "challenge"),
                                    w,
                                    &mut public,
                                    &mut state,
                                    &value,
                                )?
                            } else {
                                a::classify(
                                    &bytes(event, "chain_id"),
                                    &bytes(event, "challenge"),
                                    w,
                                    &mut public,
                                    &state,
                                    &value,
                                )?
                            };
                            json!([
                                a::decision_to_string(decision),
                                calls.into_iter().map(hx).collect::<Vec<_>>(),
                                counts(&state),
                                hx(a::identity_key(&value)),
                                if decision == a::Decision::Reject(a::Reason::Malformed) {
                                    Value::Null
                                } else {
                                    evidence(&a::evidence(w, a::Reason::BadScore, &value)?)?
                                }
                            ])
                        }
                        _ => panic!("fixture action"),
                    })
                }));
            }
            Value::Array(results)
        }
        "plugin" => run_plugin(v)?,
        _ => return Err("fixture op".into()),
    })
}

#[test]
fn pinned_native_resource_exported_apis_match() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/optional-resource.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/resource-attestation-oracle.ml"
        )))
    );
    let mut mismatches = vec![];
    assert_eq!(
        fixture["runner_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/resource-native-oracle.py"
        )))
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 1070);
    let positive = cases
        .iter()
        .filter(|case| {
            case["input"]["label"]
                .as_str()
                .unwrap()
                .starts_with("proof/")
                && case["input"]["label"]
                    .as_str()
                    .unwrap()
                    .ends_with("/positive")
        })
        .collect::<Vec<_>>();
    assert_eq!(positive.len(), 25);
    assert!(positive
        .iter()
        .all(|case| case["expected"]["ok"]["verify"] == json!({"ok":true})));
    for (index, case) in cases.iter().enumerate() {
        let actual = boxed(run(&case["input"]));
        if actual != case["expected"] {
            eprintln!(
                "case {index} {} actual={actual} expected={}",
                case["input"]["label"], case["expected"]
            );
            mismatches.push(index);
        }
    }
    assert!(
        mismatches.is_empty(),
        "native exported-API mismatches: {mismatches:?}"
    );
}

fn run_plugin(v: &Value) -> Result<Value, Error> {
    let a = att(&v["attestation"]);
    let ch = bytes(v, "challenge");
    let raw = &v["evidence"];
    Ok(match int(v, "plugin") {
        1 => {
            let e = r::PvacKatEvidence {
                key_id: bytes(raw, "key_id"),
                pubkey_hash: bytes(raw, "pubkey_hash"),
                kat_input_hash: bytes(raw, "kat_input_hash"),
                kat_output: bytes(raw, "kat_output"),
                expected_output_hash: bytes(raw, "expected_output_hash"),
                work_units: int(raw, "work_units"),
            };
            fields! {"plugin"=>json!([r::useful_plugin_to_u8(r::UsefulPlugin::PvacKat),r::useful_plugin_to_string(r::UsefulPlugin::PvacKat)]),
            "task"=>hx(r::useful_plugin_task_id(&ch,r::UsefulPlugin::PvacKat,&bytes(v,"subject"),&bytes(v,"resource_hash"),int(v,"work_units"))?),
            "nonempty"=>json!(r::nonempty_hash32(&bytes(v,"hash"))),
            "fits"=>json!(r::attestation_weight_fits_resource(&a,int(v,"work_units"))),
            "encoded"=>hx(r::encode_pvac_kat_evidence(&e)?),
            "resource"=>hx(r::pvac_kat_resource_hash(&e)?),
            "proof"=>hx(r::pvac_kat_evidence_hash(&e)?),
            "verify"=>json!(r::verify_pvac_kat_attestation(&ch,&bytes(v,"commitment"),int(v,"max_weight"),&bytes(v,"output_hash"),&a,&e)?),
            "output"=>hx(r::pvac_kat_output_hash(&e)?)}
        }
        2 => {
            let e = r::FheReceiptEvidence {
                verifier_pubkey: bytes(raw, "verifier_pubkey"),
                proof_kind: bytes(raw, "proof_kind"),
                program_id: bytes(raw, "program_id"),
                input_hash: bytes(raw, "input_hash"),
                output_hash: bytes(raw, "output_hash"),
                cost_units: int(raw, "cost_units"),
                receipt_signature: bytes(raw, "receipt_signature"),
            };
            fields! {"plugin"=>json!([r::useful_plugin_to_u8(r::UsefulPlugin::FheProofReceipt),r::useful_plugin_to_string(r::UsefulPlugin::FheProofReceipt)]),
            "task"=>hx(r::useful_plugin_task_id(&ch,r::UsefulPlugin::FheProofReceipt,&bytes(v,"subject"),&bytes(v,"resource_hash"),int(v,"work_units"))?),
            "nonempty"=>json!(r::nonempty_hash32(&bytes(v,"hash"))),
            "fits"=>json!(r::attestation_weight_fits_resource(&a,int(v,"work_units"))),
            "encoded"=>hx(r::encode_fhe_receipt_evidence(&e)?),
            "resource"=>hx(r::fhe_receipt_resource_hash(&e)?),
            "proof"=>hx(r::fhe_receipt_evidence_hash(&e)?),
            "verify"=>json!(r::verify_fhe_receipt_attestation(&ch,&bytes(v,"commitment"),int(v,"max_weight"),&bytes(v,"public"),&a,&e)?),
            "sign_bytes"=>hx(r::fhe_receipt_sign_bytes(&e)?),
            "signed"=>hx(r::sign_fhe_receipt_evidence(&bytes(v,"private"),&e)?)}
        }
        3 => {
            let e = r::CircleAssetEvidence {
                circle_id: bytes(raw, "circle_id"),
                resource_path: bytes(raw, "resource_path"),
                asset_root: bytes(raw, "asset_root"),
                byte_count: int(raw, "byte_count"),
                storage: storage(&raw["storage"]),
            };
            fields! {"plugin"=>json!([r::useful_plugin_to_u8(r::UsefulPlugin::CircleAssetAvailability),r::useful_plugin_to_string(r::UsefulPlugin::CircleAssetAvailability)]),
            "task"=>hx(r::useful_plugin_task_id(&ch,r::UsefulPlugin::CircleAssetAvailability,&bytes(v,"subject"),&bytes(v,"resource_hash"),int(v,"work_units"))?),
            "nonempty"=>json!(r::nonempty_hash32(&bytes(v,"hash"))),
            "fits"=>json!(r::attestation_weight_fits_resource(&a,int(v,"work_units"))),
            "encoded"=>hx(r::encode_circle_asset_evidence(&e)?),
            "resource"=>hx(r::circle_asset_resource_hash(&e)?),
            "proof"=>hx(r::circle_asset_evidence_hash(&e)?),
            "verify"=>json!(r::verify_circle_asset_attestation(&ch,&bytes(v,"commitment"),int(v,"max_weight"),int(v,"leaf_count"),&a,&e)?)}
        }
        4 => {
            let e = r::SnapshotAvailabilityEvidence {
                state_root: bytes(raw, "state_root"),
                range_start: int(raw, "range_start"),
                range_end: int(raw, "range_end"),
                snapshot_root: bytes(raw, "snapshot_root"),
                byte_count: int(raw, "byte_count"),
                storage: storage(&raw["storage"]),
            };
            fields! {"plugin"=>json!([r::useful_plugin_to_u8(r::UsefulPlugin::SnapshotAvailability),r::useful_plugin_to_string(r::UsefulPlugin::SnapshotAvailability)]),
            "task"=>hx(r::useful_plugin_task_id(&ch,r::UsefulPlugin::SnapshotAvailability,&bytes(v,"subject"),&bytes(v,"resource_hash"),int(v,"work_units"))?),
            "nonempty"=>json!(r::nonempty_hash32(&bytes(v,"hash"))),
            "fits"=>json!(r::attestation_weight_fits_resource(&a,int(v,"work_units"))),
            "encoded"=>hx(r::encode_snapshot_availability_evidence(&e)?),
            "resource"=>hx(r::snapshot_availability_resource_hash(&e)?),
            "proof"=>hx(r::snapshot_availability_evidence_hash(&e)?),
            "verify"=>json!(r::verify_snapshot_availability_attestation(&ch,&bytes(v,"commitment"),int(v,"max_weight"),int(v,"leaf_count"),&a,&e)?)}
        }
        5 => {
            let e = r::DeterministicTraceEvidence {
                runtime_id: bytes(raw, "runtime_id"),
                source_hash: bytes(raw, "source_hash"),
                input_hash: bytes(raw, "input_hash"),
                output_hash: bytes(raw, "output_hash"),
                step_limit: int(raw, "step_limit"),
                trace_root: bytes(raw, "trace_root"),
                sampled_step: storage(&raw["sampled_step"]),
            };
            fields! {"plugin"=>json!([r::useful_plugin_to_u8(r::UsefulPlugin::DeterministicComputationTrace),r::useful_plugin_to_string(r::UsefulPlugin::DeterministicComputationTrace)]),
            "task"=>hx(r::useful_plugin_task_id(&ch,r::UsefulPlugin::DeterministicComputationTrace,&bytes(v,"subject"),&bytes(v,"resource_hash"),int(v,"work_units"))?),
            "nonempty"=>json!(r::nonempty_hash32(&bytes(v,"hash"))),
            "fits"=>json!(r::attestation_weight_fits_resource(&a,int(v,"work_units"))),
            "encoded"=>hx(r::encode_deterministic_trace_evidence(&e)?),
            "resource"=>hx(r::deterministic_trace_resource_hash(&e)?),
            "proof"=>hx(r::deterministic_trace_evidence_hash(&e)?),
            "verify"=>json!(r::verify_deterministic_trace_attestation(&ch,&bytes(v,"commitment"),int(v,"max_weight"),int(v,"leaf_count"),&a,&e)?)}
        }
        6 => {
            let e = r::PerturbedMatrixTraceEvidence {
                runtime_id: bytes(raw, "runtime_id"),
                matrix_a_root: bytes(raw, "matrix_a_root"),
                matrix_b_root: bytes(raw, "matrix_b_root"),
                config_hash: bytes(raw, "config_hash"),
                chain_state_hash: bytes(raw, "chain_state_hash"),
                tile_row: int(raw, "tile_row"),
                tile_col: int(raw, "tile_col"),
                tile_depth: int(raw, "tile_depth"),
                tile_trace_root: bytes(raw, "tile_trace_root"),
                sampled_tile: storage(&raw["sampled_tile"]),
                field_modulus: int(raw, "field_modulus"),
                perturbed_left_values: raw["perturbed_left_values"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| {
                        v.as_i64()
                            .unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
                    })
                    .collect(),
                perturbed_right_values: raw["perturbed_right_values"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| {
                        v.as_i64()
                            .unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
                    })
                    .collect(),
                claimed_value: int(raw, "claimed_value"),
                opening_nonce: bytes(raw, "opening_nonce"),
                difficulty_bits: int(raw, "difficulty_bits"),
                work_units: int(raw, "work_units"),
            };
            fields! {"plugin"=>json!([r::useful_plugin_to_u8(r::UsefulPlugin::PerturbedMatrixTrace),r::useful_plugin_to_string(r::UsefulPlugin::PerturbedMatrixTrace)]),
            "task"=>hx(r::useful_plugin_task_id(&ch,r::UsefulPlugin::PerturbedMatrixTrace,&bytes(v,"subject"),&bytes(v,"resource_hash"),int(v,"work_units"))?),
            "nonempty"=>json!(r::nonempty_hash32(&bytes(v,"hash"))),
            "fits"=>json!(r::attestation_weight_fits_resource(&a,int(v,"work_units"))),
            "encoded"=>hx(r::encode_perturbed_matrix_trace_evidence(&e)?),
            "resource"=>hx(r::perturbed_matrix_trace_resource_hash(&e)?),
            "proof"=>hx(r::perturbed_matrix_trace_evidence_hash(&e)?),
            "verify"=>json!(r::verify_perturbed_matrix_trace_attestation(&ch,&bytes(v,"commitment"),int(v,"max_weight"),int(v,"leaf_count"),int(v,"difficulty"),&a,&e)?),
            "noise"=>hx(r::perturbed_matrix_noise_seed(&ch,&e)?),
            "chunk"=>hx(r::perturbed_matrix_cell_chunk(&ch,&e)?),
            "opening"=>hx(r::perturbed_matrix_opening_hash(&ch,&e)?),
            "field"=>json!(r::field_dot_mod(e.field_modulus,&e.perturbed_left_values,&e.perturbed_right_values).map(|n|n.to_string())),
            "valid_values"=>json!(e.perturbed_left_values.iter().map(|n|r::field_value_is_valid(e.field_modulus,*n)).collect::<Vec<_>>()),
            "length"=>json!(r::int64_of_list_length(&e.perturbed_left_values)?.to_string()),
            "put_list"=>{let mut w=Writer::new();r::put_u64_list(&mut w,&e.perturbed_left_values)?;hx(w.into_bytes())}}
        }
        _ => return Err("fixture plugin".into()),
    })
}
