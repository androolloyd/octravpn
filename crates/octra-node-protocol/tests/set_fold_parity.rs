use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{
    consensus::{
        hash, policy::Protocol, CommitCertificate, EpochHeader, ParentCommit, Validator,
        ValidatorSet, Vote, VoteType,
    },
    control_payload::ReadyExtra,
    validator::{
        admission::Candidate,
        ready,
        set_fold::{CapMode, Config, Exclusion, Final, Minimum, Proof, State},
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
fn raw(v: &Value, key: &str) -> Vec<u8> {
    STANDARD.decode(s(v, key)).unwrap()
}
fn b64(v: &[u8]) -> Value {
    json!(STANDARD.encode(v))
}
fn bytes(v: &Value, key: &str) -> Vec<Vec<u8>> {
    v[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| STANDARD.decode(v.as_str().unwrap()).unwrap())
        .collect()
}
fn key(id: i64) -> SigningKey {
    SigningKey::from_bytes(&[id as u8; 32])
}
fn address(id: i64) -> Vec<u8> {
    format!("v{id}").into_bytes()
}
fn number(v: i64) -> Value {
    json!(v.to_string())
}
fn result<T>(r: Result<T, Error>, f: impl FnOnce(T) -> Value) -> Value {
    match r {
        Ok(v) => f(v),
        Err(e) => json!({"error":e.to_string()}),
    }
}
fn config(v: &Value) -> Config {
    Config {
        window: i(v, "window"),
        challenge: i(v, "challenge"),
        rejoin_span: i(v, "rejoin"),
        pulse_gap: i(v, "gap"),
        cadence: i(v, "cadence"),
        delay: i(v, "delay"),
        max_members: n(v, "max"),
        minimum: if v["share"].is_null() {
            Minimum::Any
        } else {
            Minimum::Share {
                numerator: n(&v["share"], "n"),
                denominator: n(&v["share"], "d"),
            }
        },
    }
}
fn parent(v: &Value) -> ParentCommit {
    let chain_id = raw(v, "chain");
    let epoch_id = i(v, "epoch");
    let round = n(v, "round");
    let validator_set = ValidatorSet::unweighted(
        (1..=n(v, "members"))
            .map(|id| Validator {
                address: address(id),
                pubkey: key(id).verifying_key().to_bytes().to_vec(),
            })
            .collect(),
    );
    let header = EpochHeader {
        proto_version: Protocol::default().version_at(epoch_id),
        chain_id: chain_id.clone(),
        epoch_id,
        prev_state_root: vec![1; 32],
        tx_list_hash: vec![2; 32],
        receipt_root: vec![3; 32],
        proposed_state_root: vec![4; 32],
        parent_commit_hash: vec![0; 32],
        creator_addr: address(1),
        txid_hi: 7,
        ts: 1.,
    };
    let proposal_id = hash::proposal_id(&header).unwrap().to_vec();
    let precommits = v["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| {
            let id = id.as_i64().unwrap();
            let mut vote = Vote {
                chain_id: chain_id.clone(),
                epoch_id,
                round,
                vote_type: VoteType::Precommit,
                proposal_id: proposal_id.clone(),
                validator: address(id),
                signature: vec![],
            };
            vote.signature = if v["corrupt"] == true {
                vec![0; 64]
            } else {
                key(id)
                    .sign(&hash::vote_sign_bytes(&vote).unwrap())
                    .to_bytes()
                    .to_vec()
            };
            vote
        })
        .collect();
    ParentCommit {
        validator_set,
        certificate: CommitCertificate {
            chain_id,
            epoch_id,
            commit_round: round,
            header,
            proposal_id,
            precommits,
        },
    }
}
fn finality(v: &Value) -> Final {
    Final {
        epoch: i(v, "epoch"),
        proposal_id: raw(v, "pid"),
        set_hash: raw(v, "set"),
    }
}
fn parent_final(p: &ParentCommit) -> Final {
    Final {
        epoch: p.certificate.epoch_id,
        proposal_id: p.certificate.proposal_id.clone(),
        set_hash: hash::validator_set_hash(&p.validator_set).unwrap().to_vec(),
    }
}
fn exclusion(e: &Exclusion) -> Value {
    match *e {
        Exclusion::MemberMissing => json!("member"),
        Exclusion::PulseMissing => json!("pulse"),
        Exclusion::PulseFuture(n) => json!(["future", number(n)]),
        Exclusion::PulseOld(n) => json!(["old", number(n)]),
        Exclusion::PulseShort { first, last } => json!(["short", number(first), number(last)]),
        Exclusion::MarksShort {
            low,
            high,
            signed,
            required,
        } => json!(["marks", number(low), number(high), signed, required]),
    }
}
fn update(state: &mut State, r: Result<State, Error>) -> Value {
    result(r, |v| {
        *state = v;
        Value::Null
    })
}
fn trace(input: &Value, cfg: &Config) -> Value {
    let mut state = if input["initial"].is_null() {
        State::default()
    } else {
        State::from_bytes(&raw(input, "initial")).unwrap()
    };
    let start = i(input, "start");
    let probes = bytes(input, "probes");
    let candidates: Vec<_> = probes
        .iter()
        .map(|address| Candidate {
            address: address.clone(),
            pubkey: vec![0; 32],
            bond: 1.into(),
            bonded_epoch: 0,
            ready_epoch: None,
            exit_epoch: None,
        })
        .collect();
    json!(input["steps"].as_array().unwrap().iter().enumerate().map(|(index,step)|{
        let cap=if step["prune"]==true{CapMode::Prune}else{CapMode::Reject};
        let answer=match s(step,"op") {
            "set"=>{let r=state.note_set(cfg,i(step,"at"),&bytes(step,"active"));update(&mut state,r)},
            "lock"=>result(state.lock(cfg,&bytes(step,"active")),|(v,changed)|{state=v;json!(changed)}),
            "delay"=>{let r=state.delay(cfg,i(step,"at"));update(&mut state,r)},
            "pulse"=>{let credit=(!step["credit"].is_null()).then(||i(step,"credit"));let r=state.note_pulse(cfg,cap,credit,i(step,"at"),step["active"].as_bool().unwrap(),&raw(step,"address"));update(&mut state,r)},
            "final"|"parent_final"=>{let f=if step["op"]=="final"{finality(&step["final"])}else{parent_final(&parent(&step["parent"]))};let r=state.note_final(cfg,cap,i(step,"at"),&bytes(step,"active"),&f,&bytes(step,"signers"));update(&mut state,r)},
            "advance"=>{let p=(!step["parent"].is_null()).then(||parent(&step["parent"]));result(state.advance(cfg,cap,&raw(step,"chain"),i(step,"start"),i(step,"at"),p.as_ref()),|(v,reason,changed)|{state=v;json!([reason,changed])})},
            "proof"=>{
                let commit=parent(&step["parent"]);let v=&step["vote"];
                let mut vote=Vote{chain_id:raw(v,"chain"),epoch_id:i(v,"epoch"),round:n(v,"round"),vote_type:if n(v,"type")==2{VoteType::Precommit}else{VoteType::Prevote},proposal_id:if v["other_pid"]==true{vec![9;32]}else{commit.certificate.proposal_id.clone()},validator:raw(v,"owner"),signature:vec![]};
                vote.signature=if v["corrupt"]==true{vec![0;64]}else{key(n(v,"signer")).sign(&hash::vote_sign_bytes(&vote).unwrap()).to_bytes().to_vec()};
                let r=state.apply_proof(cfg,cap,&raw(step,"chain"),i(step,"at"),step["active"].as_bool().unwrap(),&raw(step,"address"),&Proof{vote,commit});update(&mut state,r)
            },
            "reference"=>{let p=(!step["parent"].is_null()).then(||parent(&step["parent"]));let proposal=match step["proposal"].as_str(){None=>None,Some("auto")=>Some(hex::encode(&p.as_ref().unwrap().certificate.proposal_id).into_bytes()),Some(v)=>Some(STANDARD.decode(v).unwrap())};result(ready::reference(i(step,"at"),i(step,"head"),proposal.as_deref(),p.as_ref(),&state),|()|Value::Null)},
            "reload"=>{let r=State::from_bytes(&state.to_bytes());update(&mut state,r)},
            "query"=>Value::Null,
            _=>panic!("unknown step {index}"),
        };
        let source=i(step,"source");let (selected,counts)=state.filter(cfg,start,source,&candidates);
        json!({"result":answer,"state":b64(&state.to_bytes()),"seats":state.seats(),"probes":probes.iter().map(|addr|{let receipt=state.receipt(addr);json!({"allows":state.allows(cfg,start,source,addr),"exclude":state.exclusion(cfg,start,source,addr).as_ref().map(exclusion),"marks":receipt.marked.into_iter().map(number).collect::<Vec<_>>(),"pulse":receipt.pulse.map(number)})}).collect::<Vec<_>>(),"filter":[selected.iter().map(|c|b64(&c.address)).collect::<Vec<_>>(),counts.live,counts.shadow,counts.allowed]})
    }).collect::<Vec<_>>())
}
fn evaluate(input: &Value) -> Value {
    let cfg = config(&input["cfg"]);
    match s(input, "kind") {
        "config" => {
            json!({"valid":result(cfg.validate(),|()|Value::Null),"id":cfg.consensus_id(),"replacement":number(cfg.replacement_limit())})
        }
        "decode" => result(
            State::from_bytes(&raw(input, "raw")),
            |s| b64(&s.to_bytes()),
        ),
        "claim" => result(
            ready::validate(
                &raw(input, "chain"),
                &raw(input, "config"),
                i(input, "head"),
                &ReadyExtra {
                    chain_id: (!input["claim_chain"].is_null()).then(|| raw(input, "claim_chain")),
                    config_hash: (!input["claim_config"].is_null())
                        .then(|| raw(input, "claim_config")),
                    catchup_head_epoch: (!input["catchup"].is_null()).then(|| i(input, "catchup")),
                    ..Default::default()
                },
                input["prior"].as_bool().unwrap(),
            ),
            |()| Value::Null,
        ),
        "trace" => trace(input, &cfg),
        _ => panic!("kind"),
    }
}
#[test]
fn native_finalized_duty_and_readiness() {
    let fixtures: Value = serde_json::from_slice(include_bytes!("fixtures/set-fold.json")).unwrap();
    let sources: Value =
        serde_json::from_slice(include_bytes!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixtures["upstream_commit"], sources["upstream_commit"]);
    assert_eq!(fixtures["source_sha256"], sources["files"]);
    for (index, case) in fixtures["cases"].as_array().unwrap().iter().enumerate() {
        if case["input"]["kind"] == "native_exception" {
            // The native helper has no result at an int63-wrapped bit index.
            // Record that boundary without pretending it is parity coverage.
            assert_eq!(
                case["expected"],
                json!({"exception":"Invalid_argument(\"Z.testbit\")"})
            );
            let finite = evaluate(&case["input"]["trace"]);
            assert_eq!(finite[1]["probes"][0]["allows"], false);
            continue;
        }
        let actual = evaluate(&case["input"]);
        if case["input"]["kind"] == "trace" {
            for (step, (a, e)) in actual
                .as_array()
                .unwrap()
                .iter()
                .zip(case["expected"].as_array().unwrap())
                .enumerate()
            {
                assert_eq!(
                    a, e,
                    "case {index} step {step}: {}",
                    case["input"]["steps"][step]
                );
            }
            assert_eq!(
                actual.as_array().unwrap().len(),
                case["expected"].as_array().unwrap().len()
            );
        } else {
            assert_eq!(actual, case["expected"], "case {index}: {}", case["input"]);
        }
    }
}
