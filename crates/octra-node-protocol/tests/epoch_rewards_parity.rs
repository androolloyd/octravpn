use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use octra_node_protocol::{
    emission::{self, Binding, Schedule},
    epoch_rewards::{self, Attribution, Input, Plan, Validator},
    transaction::Error,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn z(v: &Value, key: &str) -> BigInt {
    v[key].as_str().unwrap().parse().unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn plan(v: &Value) -> Result<Plan, Error> {
    epoch_rewards::build(
        &Input {
            fee_burn_active: v["active"].as_bool().unwrap(),
            supply_retired: z(v, "retired"),
            validator_count: v["count"].as_i64().unwrap(),
            emission_remaining: z(v, "remaining"),
            confirmed_fees: z(v, "fees"),
            prev_supply: z(v, "supply"),
        },
        v["base"].as_str().map(|s| s.parse().unwrap()),
    )
}
fn encoded(p: &Plan) -> Value {
    json!({"base_reward":p.base_reward.to_string(),"fees_burned":p.fees_burned.to_string(),"fees_rewarded":p.fees_rewarded.to_string(),"total_reward":p.total_reward.to_string(),"proposer_total":p.proposer_total.to_string(),"each_validator":p.each_validator.to_string(),"remainder":p.remainder.to_string(),"new_emission_remaining":p.new_emission_remaining.to_string(),"new_total_supply":p.new_total_supply.to_string(),"new_supply_retired":p.new_supply_retired.to_string(),"supply_tracking_active":p.supply_tracking_active})
}
fn schedule(v: &Value) -> Schedule {
    v["activation"]
        .as_i64()
        .map_or(Schedule::Inactive, |activation_epoch| {
            Schedule::SecurityCurve { activation_epoch }
        })
}
fn result(v: Result<Value, Error>) -> Value {
    match v {
        Ok(v) => json!({"ok":v}),
        Err(e) => json!({"error":e.0}),
    }
}
fn run(v: &Value) -> Value {
    match v["op"].as_str().unwrap(){
  "plan"=>result(plan(v).map(|p|encoded(&p))),
  "credits"=>result(plan(v).and_then(|p|epoch_rewards::credits(&Attribution{proposer:bytes(&v["proposer"]),proposer_public_key:None,validators:v["validators"].as_array().unwrap().iter().map(|a|Validator{address:bytes(&a["address"]),public_key:None,weight:z(a,"weight")}).collect()},&p)).map(|values|json!(values.into_iter().map(|c|json!({"address":STANDARD.encode(c.address),"proposer":c.proposer,"validator":c.validator,"amount":c.amount.to_string()})).collect::<Vec<_>>()))),
  "binding"=>{
    let stored=["standard","stored_activation","initial","stored_retired"].map(|key|(!v[key].is_null()).then(||bytes(&v[key])));
    result(emission::bind(schedule(v),v["epoch"].as_i64().unwrap(),&z(v,"remaining"),&z(v,"headroom"),stored.each_ref().map(|s|s.as_deref())).map(|b|json!({"initial":b.initial.to_string(),"remaining":b.remaining.to_string(),"retired":b.retired.to_string(),"active":b.active,"activated":b.activated,"writes":b.writes.iter().map(|(k,v)|json!([STANDARD.encode(k),STANDARD.encode(v)])).collect::<Vec<_>>() })))
  },
  "reward"=>result(emission::reward(schedule(v),v["epoch"].as_i64().unwrap(),&Binding{initial:z(v,"initial"),remaining:z(v,"remaining"),retired:0.into(),active:true,activated:false,writes:vec![]}).map(|v|json!(v.to_string()))),
  "cumulative"=>json!(emission::cumulative(&z(v,"initial"),v["elapsed"].as_i64().unwrap()).to_string()),
  _=>panic!("unknown operation")
 }
}
#[test]
fn native_emission_binding_reward_plans_and_weighted_distribution() {
    let f: Value = serde_json::from_str(include_str!("fixtures/epoch-rewards.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(f["upstream_commit"], source["upstream_commit"]);
    assert_eq!(f["source_sha256"], source["files"]);
    assert_eq!(
        f["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/reward-oracle.ml"
        )))
    );
    for (i, c) in f["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            run(&c["input"]),
            c["expected"],
            "native case {i}: {}",
            c["input"]
        );
    }
}
