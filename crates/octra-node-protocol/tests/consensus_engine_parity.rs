use ed25519_dalek::{Signer as _, SigningKey};
use num_bigint::BigInt;
use octra_node_protocol::consensus::{
    codec::Wire,
    engine::{Engine, Output, TimeoutConfig},
    policy::Protocol,
    EpochHeader, Error, Finalize, Proposal, RoundStep, RoundSync, Validator, ValidatorSet, Vote,
};
use serde_json::{json, Value};
fn raw(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn int(v: &Value, key: &str, default: i64) -> i64 {
    v[key].as_i64().unwrap_or(default)
}
fn caught(v: Result<Value, Error>) -> Value {
    v.unwrap_or_else(|e| json!({"error":e.to_string()}))
}
fn set(n: i64, weighted: bool) -> ValidatorSet {
    let validators: Vec<_> = (1..=n)
        .map(|i| Validator {
            address: format!("validator-{i}").into_bytes(),
            pubkey: SigningKey::from_bytes(&[i as u8; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        })
        .collect();
    if weighted {
        ValidatorSet::weighted(
            validators
                .into_iter()
                .enumerate()
                .map(|(i, v)| (v, BigInt::from(if i == 0 { 1000 } else { 1 })))
                .collect(),
        )
        .unwrap()
    } else {
        ValidatorSet::unweighted(validators)
    }
}
fn output(v: Output) -> Value {
    match v {
        Output::SendProposal(p) => json!({"proposal":hex::encode(p.encode().unwrap())}),
        Output::SendVote(v, p) => {
            json!({"vote":hex::encode(v.encode().unwrap()),"proposal":p.map(|p|hex::encode(p.encode().unwrap()))})
        }
        Output::SendFinalize(f) => json!({"send_finalize":hex::encode(f.encode().unwrap())}),
        Output::RequestProposal { round, proposal_id } => {
            json!({"request_round":round,"proposal_id":hex::encode(proposal_id)})
        }
        Output::RequestRoundEvidence(round) => json!({"evidence_round":round}),
        Output::ScheduleTimeout {
            step,
            round,
            delay_ms,
            generation,
        } => json!({"step":step as u8,"round":round,"delay":delay_ms,"generation":generation}),
        Output::Finalized { epoch_id, finalize } => {
            json!({"epoch_id":epoch_id.to_string(),"finalized":hex::encode(finalize.encode().unwrap())})
        }
    }
}
fn snapshot(engine: &mut Engine, result: &Value) -> Value {
    let outputs: Vec<_> = engine.drain_outputs().into_iter().map(output).collect();
    let s = engine.state();
    json!({"result":result,"height":s.height.to_string(),"round":s.round,"step":s.step as u8,"locked_round":s.locked_round,"locked":s.locked_value.as_ref().map(|h|hex::encode(h.encode().unwrap())),"valid_round":s.valid_round,"valid":s.valid_value.as_ref().map(|h|hex::encode(h.encode().unwrap())),"generation":engine.generation(),"finalized_height":engine.finalized_height().to_string(),"pending":engine.pending_finalized().map(|f|hex::encode(f.encode().unwrap())),"outputs":outputs,"pristine":engine.is_pristine()})
}
#[test]
fn native_signed_consensus_state_transition_traces() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/consensus-engine.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], manifest["upstream_commit"]);
    for (path, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, manifest["files"][path]);
    }
    for (case_index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let config = &case["input"];
        let me = int(config, "me", 1);
        let key = SigningKey::from_bytes(&[me as u8; 32]);
        let mut sign = |message: &[u8]| Ok(key.sign(message).to_bytes().to_vec());
        let mut engine = Engine::new(
            raw(&config["chain"]),
            format!("validator-{me}").into_bytes(),
            set(int(config, "n", 4), config["weighted"].as_bool().unwrap()),
            config["epoch"].as_str().unwrap().parse().unwrap(),
            Protocol::default(),
            TimeoutConfig::default(),
        );
        engine.set_voting_ready(config["ready"].as_bool().unwrap());
        for (index, input) in config["steps"].as_array().unwrap().iter().enumerate() {
            let round = int(input, "round", engine.state().round);
            let op = input["op"].as_str().unwrap();
            let result = caught((|| -> Result<Value, Error> {
                match op {
                    "start" => engine.start_round(round),
                    "height" => {
                        engine.start_height(input["height"].as_str().unwrap().parse().unwrap());
                    }
                    "realign" => engine.realign_round(round)?,
                    "ready" => {
                        engine.set_voting_ready(input["ready"].as_bool().unwrap());
                        engine.on_ready(&mut sign)?;
                    }
                    "skip_ready" => engine.set_round_skip_ready(input["ready"].as_bool().unwrap()),
                    "proposal" => engine.on_proposal(
                        Proposal::decode(&raw(&input["wire"]))?,
                        &mut |_| Ok(input["execute"].as_bool().unwrap_or(true)),
                        &mut sign,
                    )?,
                    "local_proposal" => engine.do_propose(
                        EpochHeader::decode(&raw(&input["header"]))?,
                        input["hashes"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(raw)
                            .collect(),
                        None,
                        &mut sign,
                    )?,
                    "vote" => engine.on_vote(Vote::decode(&raw(&input["wire"]))?, &mut sign)?,
                    "sync" => {
                        return Ok(json!(
                            engine.on_round_sync(&RoundSync::decode(&raw(&input["wire"]))?)?
                        ))
                    }
                    "timeout" => engine.on_timeout(
                        RoundStep::from_byte(int(input, "step", 1) as u8)?,
                        round,
                        int(input, "generation", engine.generation()),
                        &mut sign,
                    )?,
                    "restore" => {
                        engine.restore_precommit_lock(Proposal::decode(&raw(&input["wire"]))?)?;
                    }
                    "reconfigure" => engine.reconfigure_validator_set(
                        round,
                        ValidatorSet::decode(&raw(&input["validators"]))?,
                    )?,
                    "finalize" => {
                        return Ok(json!(
                            engine.accept_finalize(Finalize::decode(&raw(&input["wire"]))?)?
                        ))
                    }
                    "ack" => {
                        return Ok(json!(engine
                            .pending_finalized()
                            .cloned()
                            .is_some_and(|f| engine.ack_finalized(&f))))
                    }
                    "drain" => {}
                    _ => panic!("unknown engine fixture operation"),
                }
                Ok(Value::Null)
            })());
            assert_eq!(
                snapshot(&mut engine, &result),
                case["expected"][index],
                "trace {case_index}, step {index}, {op}"
            );
        }
    }
}
