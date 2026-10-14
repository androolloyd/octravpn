use num_bigint::BigInt;
use octra_node_protocol::consensus::{
    codec::Wire,
    hash,
    policy::{self, ProposalKind, TimeRule},
    reward, Bytes, Error, Validator, ValidatorSet,
};
use serde_json::{json, Value};
fn fixture() -> Value {
    let value: Value =
        serde_json::from_str(include_str!("fixtures/consensus-validators.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(value["upstream_commit"], manifest["upstream_commit"]);
    for (p, h) in value["source_sha256"].as_object().unwrap() {
        assert_eq!(*h, manifest["files"][p]);
    }
    value
}
fn raw(v: &Value) -> Bytes {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn int(v: &Value) -> i64 {
    v.as_str().unwrap().parse().unwrap()
}
fn big(v: &Value) -> BigInt {
    v.as_str().unwrap().parse().unwrap()
}
fn result(value: Result<Value, Error>) -> Value {
    value.unwrap_or_else(|e| json!({"error":e.to_string()}))
}
fn time_result(value: Result<i64, Error>) -> Value {
    result(value.map(|n| json!(n.to_string())))
}
fn set(v: &Value) -> Result<ValidatorSet, Error> {
    let entries: Vec<_> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                Validator {
                    address: raw(&e["address"]),
                    pubkey: raw(&e["pubkey"]),
                },
                big(&e["weight"]),
            )
        })
        .collect();
    if v["weighted"] == true {
        ValidatorSet::weighted(entries)
    } else {
        Ok(ValidatorSet::unweighted(
            entries.into_iter().map(|(v, _)| v).collect(),
        ))
    }
}
fn set_json(set: &ValidatorSet) -> Result<Value, Error> {
    Ok(
        json!({"n":set.n,"f":set.f,"quorum":set.quorum,"weighted":set.weighted,"total":set.total_weight.to_string(),"quorum_weight":set.quorum_weight.to_string(),"entries":set.validators.iter().map(|v|json!({"address":hex::encode(&v.address),"pubkey":hex::encode(&v.pubkey),"weight":set.weight(&v.address).unwrap().to_string()})).collect::<Vec<_>>(),"hash":hex::encode(hash::validator_set_hash(set)?),"wire":hex::encode(set.encode()?)}),
    )
}
fn execute(v: &Value) -> Result<Value, Error> {
    Ok(match v["op"].as_str().unwrap() {
        "set" => {
            let set = set(v)?;
            let chain = raw(&v["chain_id"]);
            let epoch = int(&v["epoch_id"]);
            let signers: Vec<_> = v["signers"].as_array().unwrap().iter().map(raw).collect();
            let count = v["signer_count"].as_i64().unwrap();
            let weight = big(&v["signed_weight"]);
            let effective = set.for_epoch(&chain, epoch)?;
            json!({"set":set_json(&set)?,"cap":set.count_weight_cap()?.to_string(),"effective":set_json(&effective)?,"leaders":v["rounds"].as_array().unwrap().iter().map(|round|result(effective.leader(epoch,round.as_i64().unwrap()).map(|v|json!(hex::encode(&v.address))))).collect::<Vec<_>>(),"signed_weight":set.signed_weight(&signers).map(|w|w.to_string()),"weight_quorum":set.has_weight_quorum(&signers),"quorum":set.has_quorum(&signers),"quorum_at":set.has_quorum_at(&chain,epoch,&signers)?,"reached":effective.quorum_reached_at(&chain,epoch,count,&weight),"skip_weight":effective.round_skip_weight().to_string(),"skip_reached":effective.round_skip_reached_at(&chain,epoch,count,&weight)})
        }
        "decode_set" => set_json(&ValidatorSet::decode(&raw(&v["wire"]))?)?,
        "parse_weight" => json!(reward::parse_weight(&raw(&v["value"])).map(|w| w.to_string())),
        "policy" => {
            let chain = raw(&v["chain_id"]);
            let epoch = int(&v["epoch_id"]);
            json!({"quorum_active":policy::quorum_active(&chain,epoch),"quorum_id":policy::quorum_consensus_id(&chain),"rewind_allowed":policy::rewind_allowed(&chain,epoch,int(&v["to_epoch"])),"version":policy::Protocol::new(int(&v["activation"]))?.version_at(epoch),"time_rule":if policy::time_rule(&chain,epoch)==TimeRule::Historical{"historical"}else{"uniform"}})
        }
        "time" => {
            let bits = |key: &str| u64::from_str_radix(&v[key].as_str().unwrap()[2..], 16).unwrap();
            let now = f64::from_bits(bits("now_bits"));
            let candidate = f64::from_bits(bits("candidate_bits"));
            let previous = if v["previous"].is_null() {
                None
            } else {
                Some(int(&v["previous"]))
            };
            let rule = if v["rule"] == "historical" {
                TimeRule::Historical
            } else {
                TimeRule::Uniform
            };
            let kind = if v["kind"] == "fresh" {
                ProposalKind::Fresh
            } else {
                ProposalKind::Reproposal
            };
            json!({"convert":time_result(policy::time_of_seconds(candidate)),"check":time_result(policy::check_proposal_time(rule,kind,now,previous,candidate)),"delay":policy::next_delay_ms(now,candidate).to_string()})
        }
        _ => panic!("unknown native validator fixture"),
    })
}
#[test]
fn native_validator_sets_quorum_leaders_canonical_wire_and_time() {
    for (index, case) in fixture()["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            result(execute(&case["input"])),
            case["expected"],
            "case {index} {}",
            case["input"]["op"]
        );
    }
}
