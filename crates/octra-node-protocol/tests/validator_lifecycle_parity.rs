use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use num_bigint::BigInt;
use octra_node_protocol::{
    consensus::{evidence::vote_conflict, hash::vote_sign_bytes, Vote, VoteType},
    control_payload::Bond,
    transaction::{address_from_public_key, Nonce, RuleMode},
    validator::{
        admission::{self, Candidate, Parameters, Snapshot},
        evidence,
        policy::{self, Policy},
        registry::{self, Registry},
        Error,
    },
};
use serde_json::{json, Value};
fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap()
}
fn i(v: &Value, key: &str) -> i64 {
    s(v, key).parse().unwrap()
}
fn n(v: &Value, key: &str) -> i64 {
    v[key].as_i64().unwrap()
}
fn z(v: &Value, key: &str) -> BigInt {
    s(v, key).parse().unwrap()
}
fn raw(v: &Value, key: &str) -> Vec<u8> {
    STANDARD.decode(s(v, key)).unwrap()
}
fn b64(raw: &[u8]) -> Value {
    json!(STANDARD.encode(raw))
}
fn key(id: i64) -> SigningKey {
    SigningKey::from_bytes(&[id as u8; 32])
}
fn public(id: i64) -> Vec<u8> {
    key(id).verifying_key().to_bytes().to_vec()
}
fn address(id: i64) -> Vec<u8> {
    address_from_public_key(STANDARD.encode(public(id)).as_bytes())
}
fn result<T>(v: Result<T, Error>, f: impl FnOnce(T) -> Value) -> Value {
    match v {
        Ok(v) => f(v),
        Err(e) => json!({"error":e.to_string()}),
    }
}
fn params(v: &Value) -> Parameters {
    Parameters {
        min_bond: z(v, "min"),
        max_validators: n(v, "max"),
        activation_delay: i(v, "delay"),
        unbonding_epochs: i(v, "wait"),
    }
}
fn candidate(v: &Value) -> Candidate {
    Candidate {
        address: raw(v, "address"),
        pubkey: raw(v, "key"),
        bond: z(v, "bond"),
        bonded_epoch: i(v, "bonded"),
        ready_epoch: v["ready"].as_str().map(|v| v.parse().unwrap()),
        exit_epoch: v["exit"].as_str().map(|v| v.parse().unwrap()),
    }
}
fn snapshot(v: &Snapshot) -> Value {
    json!({"source":v.source_epoch.to_string(),"activate":v.activate_epoch.to_string(),"validators":v.validators.iter().map(|v|json!([b64(&v.address),b64(&v.pubkey),v.weight.to_string()])).collect::<Vec<_>>(),"total":v.total_weight.to_string(),"quorum":v.quorum_weight.to_string(),"fingerprint":v.fingerprint})
}
fn vote(step: &Value, pid: u8) -> Vote {
    let mut v = Vote {
        chain_id: raw(step, "chain"),
        epoch_id: i(step, "vote_epoch"),
        round: n(step, "round"),
        vote_type: VoteType::Precommit,
        proposal_id: vec![pid; 32],
        validator: address(n(step, "offender")),
        signature: Vec::new(),
    };
    v.signature = if step["corrupt"] == true {
        vec![0; 64]
    } else {
        key(n(step, "signer"))
            .sign(&vote_sign_bytes(&v).unwrap())
            .to_bytes()
            .to_vec()
    };
    v
}
fn sequence(input: &Value) -> Value {
    let mut registry = Registry::default();
    let parameters = params(&input["parameters"]);
    Value::Array(
        input["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| {
                let change: Result<(Registry, Value), Error> = match s(step, "op") {
                    "bond" => {
                        let id = n(step, "key");
                        let addr = address(n(step, "address"));
                        let amount = z(step, "amount");
                        let nonce = Nonce::new(n(step, "nonce")).unwrap();
                        let chain = raw(step, "chain");
                        let proof_amount =
                            (!step["proof_amount"].is_null()).then(|| z(step, "proof_amount"));
                        let msg = registry::bond_message(
                            &chain,
                            &addr,
                            proof_amount.as_ref().unwrap_or(&amount),
                            nonce,
                            &public(id),
                        );
                        let payload = Bond {
                            consensus_public_key: STANDARD.encode(public(id)).into_bytes(),
                            proof: if step["corrupt"] == true {
                                b"bad".to_vec()
                            } else {
                                STANDARD.encode(key(id).sign(&msg).to_bytes()).into_bytes()
                            },
                        };
                        let sender = if step["sender"] == "bad" {
                            b"bad".to_vec()
                        } else {
                            STANDARD.encode(public(n(step, "sender"))).into_bytes()
                        };
                        registry
                            .apply_bond(
                                &parameters,
                                &chain,
                                i(step, "epoch"),
                                &addr,
                                &sender,
                                &amount,
                                nonce,
                                &payload,
                            )
                            .map(|r| (r, Value::Null))
                    }
                    "ready" => registry
                        .mark_ready(
                            i(step, "epoch"),
                            &address(n(step, "address")),
                            &if step["key"] == "bad" {
                                b"bad".to_vec()
                            } else {
                                STANDARD.encode(public(n(step, "key"))).into_bytes()
                            },
                        )
                        .map(|r| (r, Value::Null)),
                    "exit" => registry
                        .request_exit(i(step, "epoch"), &address(n(step, "address")))
                        .map(|r| (r, Value::Null)),
                    "withdraw" => registry
                        .withdraw(
                            &parameters,
                            i(step, "epoch"),
                            &step["active"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|v| address(v.as_i64().unwrap()))
                                .collect::<Vec<_>>(),
                            &address(n(step, "address")),
                        )
                        .map(|(r, a)| (r, json!(a.to_string()))),
                    "slash" => match registry.find(&address(n(step, "offender"))) {
                        None => Err("validator bond not found".into()),
                        Some(candidate) => {
                            let conflict = vote_conflict(&vote(step, 1), &vote(step, 2)).unwrap();
                            evidence::verify(
                                &raw(step, "expected_chain"),
                                i(step, "epoch"),
                                i(step, "window"),
                                candidate,
                                &conflict,
                            )
                            .and_then(|e| {
                                registry.apply_slash(i(step, "epoch"), i(step, "window"), &e)
                            })
                            .map(|(r, a)| (r, json!(a.to_string())))
                        }
                    },
                    "reload" => {
                        Registry::from_bytes(&registry.to_bytes()).map(|r| (r, Value::Null))
                    }
                    "snapshot" => registry
                        .snapshot(&parameters, i(step, "epoch"))
                        .map(|v| (registry.clone(), snapshot(&v))),
                    _ => panic!("step"),
                };
                let out = result(change, |(r, v)| {
                    registry = r;
                    v
                });
                json!({"result":out,"state":b64(&registry.to_bytes())})
            })
            .collect(),
    )
}
fn evaluate(input: &Value) -> Value {
    match s(input, "kind") {
        "decode" => result(Registry::from_bytes(&raw(input, "raw")), |r| {
            b64(&r.to_bytes())
        }),
        "policy" => result(
            Policy::from_value(
                input["raw"]
                    .as_str()
                    .map(|s| STANDARD.decode(s).unwrap())
                    .as_deref(),
            ),
            |p| {
                let mode = if input["active"] == true {
                    RuleMode::Active
                } else {
                    RuleMode::Prior
                };
                json!({"id":p.consensus_id(),"activation":p.activation_epoch().map(|v|v.to_string()),"lifecycle":p.lifecycle_enabled(),"snapshot":p.snapshot_activation(i(input,"source")).unwrap().map(|v|v.to_string()),"custom":result(p.snapshot_at(i(input,"source"),i(input,"cadence"),i(input,"delay")),|v|json!(v.map(|v|v.to_string()))),"wait":policy::exit_parameters(mode,&policy::parameters()).unbonding_epochs.to_string(),"evidence":policy::evidence_age(mode,i(input,"window")).to_string()})
            },
        ),
        "snapshot" => {
            let candidates = input["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .map(candidate)
                .collect::<Vec<_>>();
            let incumbents = input["incumbents"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| STANDARD.decode(v.as_str().unwrap()).unwrap())
                .collect::<Vec<_>>();
            result(
                admission::snapshot(
                    &params(&input["parameters"]),
                    i(input, "activate"),
                    &candidates,
                    &incumbents,
                ),
                |v| {
                    let signers = input["signers"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| STANDARD.decode(v.as_str().unwrap()).unwrap())
                        .collect::<Vec<_>>();
                    json!({"snapshot":snapshot(&v),"signed":result(v.signed_weight(&signers),|v|json!(v.to_string())),"quorum":result(v.has_quorum(&signers),|v|json!(v)),"leader":result(v.leader(&raw(input,"seed"),i(input,"epoch"),n(input,"round")),|v|b64(&v.address))})
                },
            )
        }
        "sequence" => sequence(input),
        _ => panic!("kind"),
    }
}
#[test]
fn native_validator_lifecycle() {
    let fixtures: Value =
        serde_json::from_slice(include_bytes!("fixtures/validator-lifecycle.json")).unwrap();
    let sources: Value =
        serde_json::from_slice(include_bytes!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixtures["upstream_commit"], sources["upstream_commit"]);
    assert_eq!(fixtures["source_sha256"], sources["files"]);
    for (index, case) in fixtures["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            evaluate(&case["input"]),
            case["expected"],
            "case {index}: {}",
            case["input"]
        );
    }
}
