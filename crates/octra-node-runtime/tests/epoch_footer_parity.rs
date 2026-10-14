use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    emission::Schedule,
    epoch_rewards::{Attribution, Validator},
    state::Account,
    transaction::{Nonce, RuleMode},
};
use octra_node_runtime::{
    account_store,
    epoch_footer::{self, Policy, Request},
    state_batch::StateBatch,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn optional(v: &Value) -> Option<Vec<u8>> {
    (!v.is_null()).then(|| bytes(v))
}
#[test]
fn native_epoch_footer_matches_accounts_keys_supply_metadata_and_rollback() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/epoch-footer.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/footer-oracle.ml"
        )))
    );
    for (i, c) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &c["input"];
        let mut state = StateBatch::default();
        state.begin().unwrap();
        for v in input["meta"].as_array().unwrap() {
            state.set(&[b"meta", &bytes(&v[0])], bytes(&v[1])).unwrap();
        }
        let accounts = input["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                (
                    bytes(&v["address"]),
                    Account {
                        balance: v["balance"].as_str().unwrap().parse().unwrap(),
                        nonce: Nonce::new(v["nonce"].as_i64().unwrap()).unwrap(),
                        public_key: optional(&v["key"]),
                        ..Account::default()
                    },
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for (address, account) in &accounts {
            account_store::set(&mut state, address, account, RuleMode::Prior).unwrap();
        }
        let mut ledger = account_store::ledger(&state).unwrap();
        let before = hex::encode(state.root().unwrap());
        let reward = Attribution {
            proposer: bytes(&input["proposer"]),
            proposer_public_key: optional(&input["proposer_key"]),
            validators: input["validators"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| Validator {
                    address: bytes(&v["address"]),
                    public_key: optional(&v["key"]),
                    weight: v["weight"].as_str().unwrap().parse().unwrap(),
                })
                .collect(),
        };
        let fallback = input["fallback"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| (bytes(&v[0]), bytes(&v[1])))
            .collect::<Vec<_>>();
        let request = Request {
            epoch: input["epoch"].as_i64().unwrap(),
            reward: &reward,
            validator_keys: &fallback,
            confirmed_fees: input["fees"].as_str().unwrap().parse().unwrap(),
        };
        let policy = Policy {
            emission_guard: input["guard"].as_bool().unwrap(),
            schedule: input["activation"]
                .as_i64()
                .map_or(Schedule::Inactive, |activation_epoch| {
                    Schedule::SecurityCurve { activation_epoch }
                }),
            legacy_total: optional(&input["legacy"]),
        };
        let outcome = match epoch_footer::apply(&policy, &request, &mut ledger, &mut state) {
            Ok(f) => {
                json!({"fees":f.plan.total_reward.to_string(),"base":f.plan.base_reward.to_string(),"burned":f.plan.fees_burned.to_string(),"recipients":f.credits.iter().map(|c|json!({"address":STANDARD.encode(&c.address),"role":match(c.proposer,c.validator){(true,true)=>"proposer_validator",(true,false)=>"proposer",(false,true)=>"validator",_=>panic!("empty role")},"amount":c.amount.to_string()})).collect::<Vec<_>>() })
            }
            Err(e) => json!({"error":e.0}),
        };
        let speculative = hex::encode(state.root().unwrap());
        account_store::flush_dirty(&mut ledger, &mut state, RuleMode::Prior).unwrap();
        let actual = json!({"outcome":outcome,"before":before,"speculative":speculative,"flushed":hex::encode(state.root().unwrap()),"supply":ledger.total_supply().to_string(),"active":ledger.active_accounts(),"journal":ledger.journal_active(),"accounts":ledger.accounts().iter().map(|(a,v)|json!([STANDARD.encode(a),STANDARD.encode(v.to_json_bytes())])).collect::<Vec<_>>() });
        assert_eq!(actual, c["expected"], "native footer case {i}: {input}");
    }
}
