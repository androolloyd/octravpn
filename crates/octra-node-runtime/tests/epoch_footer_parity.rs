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
            execution: &octra_node_runtime::epoch_footer::Execution::default(),
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

/// Candidate release `8f785a93` on the devnet chain: the historical cases
/// around seatless activation, reward exclusion and burn for slashed or
/// penalised validators, and the execution profile marker.
#[test]
fn candidate_epoch_footer_matches_seatless_burn_and_marker() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/epoch-footer-candidate.json")).unwrap();
    let pin: Value = serde_json::from_str(include_str!(
        "../../../docs/rust-node/source-map-candidate.json"
    ))
    .unwrap();
    assert_eq!(fixture["upstream_commit"], pin["upstream_commit"]);
    for (key, raw) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/candidate-footer-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/candidate-footer-oracle.py").as_slice(),
        ),
        (
            "generator_dependency_sha256",
            include_bytes!("../../../scripts/node-port/footer-fixtures.py").as_slice(),
        ),
    ] {
        assert_eq!(fixture[key], hex::encode(Sha256::digest(raw)), "{key}");
    }
    let mut failures = Vec::new();
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
        let chain = bytes(&input["chain"]);
        let epoch = input["epoch"].as_i64().unwrap();
        let profiles: std::collections::BTreeMap<i64, Vec<u8>> = input["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p[0].as_i64().unwrap(),
                    hex::decode(p[1].as_str().unwrap()).unwrap(),
                )
            })
            .collect();
        // Native `execution_profile` here is the fixture's table, as in the oracle.
        let current = profiles.get(&epoch).cloned();
        let execution = epoch_footer::Execution {
            seatless: octra_node_protocol::validator::update::seatless_at(&chain, epoch),
            previous: current
                .as_ref()
                .filter(|_| epoch > 0)
                .and_then(|_| profiles.get(&(epoch - 1)).cloned()),
            profile: current,
        };
        let checked = epoch_footer::check_parent(epoch, &execution, &state);
        let request = Request {
            execution: &execution,
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
        let outcome = match checked
            .and_then(|()| epoch_footer::apply(&policy, &request, &mut ledger, &mut state))
        {
            Ok(f) => {
                json!({"fees":f.plan.total_reward.to_string(),"base":f.plan.base_reward.to_string(),"burned":f.plan.fees_burned.to_string(),"reward_burned":f.plan.reward_burned.to_string(),"excluded":f.plan.excluded.iter().map(|a|STANDARD.encode(a)).collect::<Vec<_>>(),"recipients":f.credits.iter().map(|c|json!({"address":STANDARD.encode(&c.address),"role":match(c.proposer,c.validator){(true,true)=>"proposer_validator",(true,false)=>"proposer",(false,true)=>"validator",_=>panic!("empty role")},"amount":c.amount.to_string()})).collect::<Vec<_>>() })
            }
            Err(e) => json!({"error":e.0}),
        };
        let speculative = hex::encode(state.root().unwrap());
        account_store::flush_dirty(&mut ledger, &mut state, RuleMode::Prior).unwrap();
        let meta_keys: [&[u8]; 6] = [
            b"emission_remaining",
            b"total_supply",
            b"supply_retired",
            b"last_epoch",
            b"current_epoch",
            b"execution_profile",
        ];
        let meta: Vec<_> = meta_keys
            .iter()
            .map(|k| state.get(&[b"meta", k]).map(|v| STANDARD.encode(v)))
            .collect();
        let actual = json!({"outcome":outcome,"before":before,"speculative":speculative,"flushed":hex::encode(state.root().unwrap()),"supply":ledger.total_supply().to_string(),"active":ledger.active_accounts(),"journal":ledger.journal_active(),"meta":meta,"accounts":ledger.accounts().iter().map(|(a,v)|json!([STANDARD.encode(a),STANDARD.encode(v.to_json_bytes())])).collect::<Vec<_>>() });
        if actual != c["expected"] {
            failures.push(format!(
                "case {i}: got {actual}\n  native {}",
                c["expected"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
