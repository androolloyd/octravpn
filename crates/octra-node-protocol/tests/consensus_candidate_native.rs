//! Independent candidate evidence; the adopted pin and historical vectors stay unchanged.
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use octra_node_protocol::{
    consensus::{
        codec::Wire,
        hash,
        measure::{self, Ask, Gap},
        policy::{self, QuorumPolicy, Rule},
        validators::{EvictionChoice, SetChoice, SetError},
        Error, Validator, ValidatorSet,
    },
    rules::{self, Fault, Graph, RootRead, ALL},
    transaction::RuleMode,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const CANDIDATE: &str = "8f785a93a4e7392a0f3e65674f9de89854d33dbc";
fn b64(raw: &[u8]) -> Value {
    json!(STANDARD.encode(raw))
}
fn raw(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn member(id: u8) -> Validator {
    Validator {
        address: format!("v{id}").into_bytes(),
        pubkey: vec![id; 32],
    }
}
fn mode(value: RuleMode) -> Value {
    json!(value == RuleMode::Active)
}
fn checked<T>(value: Result<T, Fault>, f: impl FnOnce(T) -> Value) -> Value {
    match value {
        Ok(v) => f(v),
        Err(e) => json!({"error": b64(&e.message())}),
    }
}
fn fixture() -> Value {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/consensus-candidate.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], CANDIDATE);
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../docs/rust-node/source-map-candidate.json"
    ))
    .unwrap();
    assert_eq!(manifest["upstream_commit"], CANDIDATE);
    for (path, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, manifest["files"][path], "candidate source {path}");
    }
    let wrapper = include_bytes!("../../../scripts/node-port/candidate-consensus-oracle.ml");
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(wrapper))
    );
    assert_eq!(fixture["source_sha256"].as_object().unwrap().len(), 13);
    fixture
}
fn policy_case(input: &Value) -> Value {
    let chain = raw(&input["chain"]);
    let epoch = input["epoch"].as_str().unwrap().parse::<i64>().unwrap();
    let policy = QuorumPolicy::for_chain(&chain);
    let mut set = ValidatorSet::weighted(
        (1..=4)
            .map(|id| {
                (
                    member(id),
                    if id == 1 && input["skew"] == true {
                        1000.into()
                    } else {
                        1.into()
                    },
                )
            })
            .collect(),
    )
    .unwrap();
    if input["authors"] == true {
        set.authors = Some((1_740_000, vec![(member(5), 17.into())]));
    }
    let set = set.for_epoch(&chain, epoch).unwrap();
    let encoded = set.encode().unwrap();
    let decoded = ValidatorSet::decode(&encoded).unwrap();
    let light = octra_node_protocol::light_rpc::ValidatorSetProof::of_set(
        chain.clone(),
        hash::config_hash(&chain, &set, None, None, None)
            .unwrap()
            .to_vec(),
        &set,
        None,
        None,
        None,
    )
    .unwrap();
    let quorums: Vec<_> = (0..16)
        .map(|bits| {
            let addresses = (0..4)
                .filter(|n| bits & (1 << n) != 0)
                .map(|n| member(n + 1).address)
                .collect::<Vec<_>>();
            set.has_quorum_for_policy(policy, epoch, &addresses)
                .unwrap()
        })
        .collect();
    json!({
        "rule": match policy.select(epoch) { Rule::Prior => "prior", Rule::Capped => "capped", Rule::Stake => "stake" },
        "id": policy.id_at(&chain, epoch), "round_wait": policy.round_wait(epoch),
        "epochs": policy.epochs().iter().map(i64::to_string).collect::<Vec<_>>(),
        "wire": b64(&encoded), "hash": b64(&hash::validator_set_hash(&set).unwrap()),
        "roundtrip": decoded.encode().unwrap() == encoded,
        "light_verified": light.verify().unwrap(),
        "light_config_hash": b64(&light.recomputed_config_hash().unwrap()),
        "weights": set.entries().unwrap().iter().map(|(v,w)| json!([b64(&v.address), w.to_string()])).collect::<Vec<_>>(),
        "leader": b64(&set.leader(epoch, 7).unwrap().address),
        "source_wire": set.source_set(&chain, epoch).map(|s| b64(&s.encode().unwrap())),
        "author": set.is_author(&chain, epoch, &member(5).address), "quorums": quorums,
        "rewind": policy.rewind_allowed(epoch, epoch-1),
    })
}
fn graph_case(input: &Value) -> Value {
    let chain = raw(&input["chain"]);
    let epoch = input["epoch"].as_i64().unwrap();
    let graph = Graph::new(chain.clone(), None);
    let plans = ALL.map(|r| graph.activation(r));
    let root = |height| match input["root"].as_str().unwrap() {
        "missing" => RootRead::Missing,
        "bad" => RootRead::Root(b"wrong-root".to_vec()),
        "unreadable" => RootRead::Unreadable(b"disk unavailable".to_vec()),
        "good" => plans
            .iter()
            .flatten()
            .find(|p| p.anchor_epoch == height)
            .map_or(RootRead::Missing, |p| {
                RootRead::Root(p.anchor_state_root.clone())
            }),
        _ => unreachable!(),
    };
    json!({
        "plans": plans.iter().map(|p| p.as_ref().map(|p| json!([p.anchor_epoch,b64(&p.anchor_state_root),p.activation_epoch]))).collect::<Vec<_>>(),
        "modes": ALL.iter().map(|r| checked(graph.mode(*r,epoch,&root), mode)).collect::<Vec<_>>(),
        "overlap": checked(graph.program_overlap(epoch,&root), |v| json!(v)),
        "profiles": rules::profile_epochs(&chain), "live": rules::live_chain(&chain),
        "id": b64(&rules::consensus_id(&chain, epoch)), "program_inputs": mode(rules::program_inputs_at(&chain, epoch)),
        "floor": input["probes"].as_array().unwrap().iter().map(|p| {
            rules::root_after_floor(&chain, input["floor"].as_i64().unwrap(), p.as_i64().unwrap()).map(|v| b64(&v))
        }).collect::<Vec<_>>(),
    })
}
#[test]
fn native_policy_author_wire_hash_and_quorums() {
    let fixture = fixture();
    let cases = fixture["policy"].as_array().unwrap();
    assert_eq!(cases.len(), 132);
    for case in cases {
        assert_eq!(
            policy_case(&case["input"]),
            case["expected"],
            "{}",
            case["input"]
        );
    }
}
#[test]
fn native_anchored_rule_graph() {
    let fixture = fixture();
    let cases = fixture["graph"].as_array().unwrap();
    assert_eq!(cases.len(), 536);
    for case in cases {
        assert_eq!(
            graph_case(&case["input"]),
            case["expected"],
            "{}",
            case["input"]
        );
    }
}

fn big(value: &Value) -> BigInt {
    value.as_str().unwrap().parse().unwrap()
}
fn epoch(input: &Value) -> i64 {
    input["epoch"].as_str().unwrap().parse().unwrap()
}
fn bits(values: impl IntoIterator<Item = bool>) -> Value {
    json!(values
        .into_iter()
        .map(|bit| if bit { '1' } else { '0' })
        .collect::<String>())
}
fn measure_case(input: &Value, targets: &[Vec<(Vec<u8>, BigInt)>]) -> Value {
    let weights: Vec<(Vec<u8>, BigInt)> = input["weights"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, weight)| {
            (
                format!("v{}", index + 1).into_bytes(),
                weight.as_i64().unwrap().into(),
            )
        })
        .collect();
    let seats = weights.len() as i64;
    let space = measure::space(
        QuorumPolicy::for_chain(policy::DEVNET),
        epoch(input),
        input["declared"] == true,
        &weights,
    );
    let shape = measure::shape(seats, weights.iter().map(|(_, weight)| weight).sum());
    let probes: Vec<_> = input["probes"]
        .as_array()
        .unwrap()
        .iter()
        .map(big)
        .collect();
    let grid = |f: &dyn Fn(i64, &BigInt) -> bool| {
        bits((0..seats + 2).flat_map(|seats| probes.iter().map(move |weight| f(seats, weight))))
    };
    let replies = [0, 1, 2, 5, 100].map(|configured| space.replies(configured));
    let meets = [
        Ask::Quorum,
        Ask::Skip,
        Ask::Source,
        Ask::Pair,
        Ask::Ahead,
        Ask::Start,
        Ask::Promise,
    ]
    .map(|ask| grid(&|seats, weight| space.meets(ask, seats, weight)));
    let attested = [0, 1, 2, seats]
        .map(|required| grid(&|seats, weight| space.attested(required, seats, weight)));
    json!({
        "shape": [json!(shape.n), json!(shape.f), json!(shape.quorum),
            json!(shape.total_weight.to_string()), json!(shape.quorum_weight.to_string())],
        "minority": measure::minority(&shape).to_string(), "valid": space.valid(),
        "label": space.label(), "start": space.start_text(), "promise": space.promise_text(),
        "wave": space.wave(), "fanout": space.fanout(),
        "replies": replies, "meets": meets, "attested": attested,
        "live": bits(probes.iter().map(|lost| measure::live(&shape.total_weight, lost))),
        "overlap": targets.iter().map(|target| match space.overlap(target) {
            Ok(()) => "ok",
            Err(Gap::FewSeats) => "few_seats",
            Err(Gap::LowWeight) => "low_weight",
            Err(Gap::NoProof) => "no_proof",
        }).collect::<Vec<_>>(),
    })
}
#[test]
fn native_quorum_measure_for_every_rule_including_seatless() {
    let fixture = fixture();
    let targets: Vec<Vec<_>> = fixture["measure_targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|target| {
            target
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| (raw(&entry[0]), big(&entry[1])))
                .collect()
        })
        .collect();
    let cases = fixture["measure"].as_array().unwrap();
    assert_eq!(cases.len(), 120);
    for case in cases {
        assert_eq!(
            measure_case(&case["input"], &targets),
            case["expected"],
            "{}",
            case["input"]
        );
    }
}
fn set_from(value: &Value) -> ValidatorSet {
    let list = |key: &str| value[key].as_array().unwrap();
    ValidatorSet {
        validators: list("validators")
            .iter()
            .map(|entry| Validator {
                address: raw(&entry[0]),
                pubkey: raw(&entry[1]),
            })
            .collect(),
        weights: list("weights")
            .iter()
            .map(|entry| (raw(&entry[0]), big(&entry[1])))
            .collect(),
        n: value["n"].as_i64().unwrap(),
        f: value["f"].as_i64().unwrap(),
        quorum: value["quorum"].as_i64().unwrap(),
        total_weight: big(&value["total"]),
        quorum_weight: big(&value["quorum_weight"]),
        weighted: value["weighted"] == true,
        authors: value["authors"].as_array().map(|authors| {
            (
                authors[0].as_str().unwrap().parse().unwrap(),
                authors[1]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|entry| {
                        (
                            Validator {
                                address: raw(&entry[0]),
                                pubkey: raw(&entry[1]),
                            },
                            big(&entry[2]),
                        )
                    })
                    .collect(),
            )
        }),
    }
}
fn digest(set: &ValidatorSet) -> Value {
    json!([
        hash::validator_set_hash(set).ok().map(|hash| b64(&hash)),
        [
            json!(set.n),
            json!(set.f),
            json!(set.quorum),
            json!(set.total_weight.to_string()),
            json!(set.quorum_weight.to_string()),
            json!(set.weighted)
        ],
        set.validators
            .iter()
            .map(|member| b64(&member.address))
            .collect::<Vec<_>>(),
        set.weights
            .iter()
            .map(|(address, weight)| json!([b64(address), weight.to_string()]))
            .collect::<Vec<_>>(),
        set.authors.as_ref().map(|(height, entries)| json!([
            height.to_string(),
            entries
                .iter()
                .map(|(member, weight)| json!([
                    b64(&member.address),
                    b64(&member.pubkey),
                    weight.to_string()
                ]))
                .collect::<Vec<_>>()
        ])),
    ])
}
fn failed(error: &Error) -> Value {
    json!({"error": error.to_string()})
}
fn set_result(value: Result<ValidatorSet, SetError>) -> Value {
    match value {
        Ok(set) => digest(&set),
        Err(SetError::Shape(error)) => failed(&error),
        Err(SetError::SeatCap) => json!({"seat_cap": true}),
    }
}
fn set_case(input: &Value) -> Value {
    let quorum = QuorumPolicy::for_chain(policy::DEVNET);
    let epoch = epoch(input);
    let base = ValidatorSet::weighted(
        input["base"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(index, weight)| (member(index as u8 + 1), weight.as_i64().unwrap().into()))
            .collect(),
    )
    .unwrap();
    let set = set_from(&input["set"]);
    let lists = |key: &str| -> Vec<Vec<Vec<u8>>> {
        input[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|list| list.as_array().unwrap().iter().map(raw).collect())
            .collect()
    };
    let (signers, offenders) = (lists("signers"), lists("offenders"));
    let choice = |value: Result<SetChoice, SetError>| match value {
        Ok(SetChoice::Active(set)) => json!({"active": digest(&set)}),
        Ok(SetChoice::Pending(set)) => json!({"pending": digest(&set)}),
        Err(SetError::Shape(error)) => failed(&error),
        Err(SetError::SeatCap) => json!({"seat_cap": true}),
    };
    let known = |signers: &[Vec<u8>]| -> BigInt {
        signers
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter_map(|address| set.weight(address))
            .sum()
    };
    let each = |f: &dyn Fn(&[Vec<u8>]) -> bool| -> Vec<bool> {
        signers.iter().map(|signers| f(signers)).collect()
    };
    json!({
        "shape": set_result(set.validate_shape()),
        "structural": set_result(set.structural_for_policy(quorum, epoch)),
        "validate": set_result(set.validate_for_policy(quorum, epoch)),
        "checked": match set.checked_for_policy(quorum, epoch) { Ok(set) => digest(&set), Err(error) => failed(&error) },
        "same_base": base.same_voting_set(&set),
        "pending_active": choice(set.pending_for_policy(quorum, epoch, Some(&base))),
        "pending_alone": choice(set.pending_for_policy(quorum, epoch, None)),
        "plans": offenders.iter().map(|offenders| match set.plan_eviction(offenders) {
            Ok(EvictionChoice::Remove(next, weight)) => json!({"remove": digest(&next), "weight": weight.to_string()}),
            Ok(EvictionChoice::Retain(weight)) => json!({"retain": weight.to_string()}),
            Err(error) => failed(&error),
        }).collect::<Vec<_>>(),
        "evict": offenders.iter().map(|offenders| match set.evict(offenders) {
            Ok((next, weight)) => json!({"set": digest(&next), "weight": weight.to_string()}),
            Err(error) => failed(&error),
        }).collect::<Vec<_>>(),
        "skip_weight": set.round_skip_weight().to_string(),
        "quorum": each(&|signers| set.has_quorum_for_policy(quorum, epoch, signers).unwrap()),
        "pair": each(&|signers| set.pair_for_policy(quorum, epoch, signers)),
        "promise": each(&|signers| set.promise_for_policy(quorum, epoch, signers)),
        "reached": each(&|signers| set.quorum_reached_for_policy(quorum, epoch, signers.len() as i64, &known(signers))),
        "skip": each(&|signers| set.round_skip_reached_for_policy(quorum, epoch, signers.len() as i64, &known(signers))),
    })
}
#[test]
fn native_set_shape_seat_cap_eviction_and_pending_choice() {
    let fixture = fixture();
    let cases = fixture["sets"].as_array().unwrap();
    assert_eq!(cases.len(), 336);
    for case in cases {
        assert_eq!(
            set_case(&case["input"]),
            case["expected"],
            "{} {}",
            case["input"]["name"],
            case["input"]["epoch"]
        );
    }
}

#[test]
fn light_proof_binds_relief_authors_without_admitting_them_as_voters() {
    use octra_node_protocol::{consensus::policy, light_rpc::ValidatorSetProof};
    let mut set =
        ValidatorSet::weighted((1..=4).map(|id| (member(id), 1.into())).collect()).unwrap();
    let make = |set: &ValidatorSet| {
        ValidatorSetProof::of_set(
            policy::DEVNET.to_vec(),
            hash::config_hash(policy::DEVNET, set, None, None, None)
                .unwrap()
                .to_vec(),
            set,
            None,
            None,
            None,
        )
        .unwrap()
    };
    let plain = make(&set);
    assert!(plain.verify().unwrap());
    let plain_json: Value = serde_json::from_slice(&plain.to_json()).unwrap();
    assert!(plain_json.get("authors").is_none());
    set.authors = Some((policy::ROUND_ACTIVATION, vec![(member(5), 17.into())]));
    let proof = make(&set);
    assert!(proof.verify().unwrap());
    assert_ne!(proof.config_hash, plain.config_hash);
    let rendered: Value = serde_json::from_slice(&proof.to_json()).unwrap();
    assert_eq!(
        rendered["authors"]["height"],
        policy::ROUND_ACTIVATION.to_string()
    );
    assert_eq!(rendered["authors"]["validators"][0]["address"], "v5");
    assert_eq!(rendered["authors"]["validators"][0]["weight"], "17");
    assert!(!set.is_validator(b"v5"));
    assert!(set.is_author(policy::DEVNET, policy::ROUND_ACTIVATION, b"v5"));
    let mut stripped = proof.clone();
    stripped.authors = None;
    assert!(!stripped.verify().unwrap());
    let mut overlap = proof;
    overlap
        .authors
        .as_mut()
        .unwrap()
        .1
        .push(overlap.validators[0].clone());
    assert!(overlap.recomputed_config_hash().is_err());
    assert!(!overlap.verify().unwrap());
    set.authors.as_mut().unwrap().0 = policy::STAKE_ACTIVATION - 1;
    assert!(!make(&set).verify().unwrap());
}
