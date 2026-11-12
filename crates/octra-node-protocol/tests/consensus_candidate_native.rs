//! Independent candidate evidence; the adopted pin and historical vectors stay unchanged.
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    consensus::{
        codec::Wire,
        hash,
        policy::{QuorumPolicy, Rule},
        Validator, ValidatorSet,
    },
    rules::{self, Fault, Graph, RootRead, ALL},
    transaction::RuleMode,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const CANDIDATE: &str = "c49de45cf49ebbc2e5c0697eb956cbcada5845e7";
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
        serde_json::from_str(include_str!("fixtures/consensus-staged-c49.json")).unwrap();
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
    assert_eq!(fixture["source_sha256"].as_object().unwrap().len(), 12);
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
fn native_c49_policy_author_wire_hash_and_quorums() {
    let fixture = fixture();
    let cases = fixture["policy"].as_array().unwrap();
    assert_eq!(cases.len(), 96);
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
fn native_c49_anchored_rule_graph() {
    let fixture = fixture();
    let cases = fixture["graph"].as_array().unwrap();
    assert_eq!(cases.len(), 512);
    for case in cases {
        assert_eq!(
            graph_case(&case["input"]),
            case["expected"],
            "{}",
            case["input"]
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
