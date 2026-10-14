use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    consensus::{codec::Wire, ParentCommit},
    rules::{self, Activation, Fault, Graph, RootRead, ALL},
    transaction::RuleMode,
};
use octra_node_runtime::{
    state_batch::StateBatch, validator_epoch::BoundFold, validator_transaction::EpochFold,
};
use serde_json::{json, Value};

fn raw(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn b64(v: &[u8]) -> Value {
    json!(STANDARD.encode(v))
}
fn result<T>(r: Result<T, Fault>, f: impl FnOnce(T) -> Value) -> Value {
    match r {
        Ok(v) => f(v),
        Err(e) => json!({"error": b64(&e.message())}),
    }
}
fn mode(m: RuleMode) -> Value {
    json!(m == RuleMode::Active)
}
fn root(kind: &str, good: Option<Vec<u8>>) -> RootRead {
    match kind {
        "missing" => RootRead::Missing,
        "bad" => RootRead::Root(b"wrong-root".to_vec()),
        "unreadable" => RootRead::Unreadable(b"disk unavailable".to_vec()),
        "good" => good.map_or(RootRead::Missing, RootRead::Root),
        _ => panic!("unknown root case"),
    }
}
fn run(input: &Value, expected: &Value) -> Value {
    let epoch = input["epoch"].as_i64().unwrap();
    if input["kind"] == "activation" {
        let plan = (!input["plan"].is_null()).then(|| Activation {
            anchor_epoch: input["plan"]["anchor"].as_i64().unwrap(),
            anchor_state_root: raw(&input["plan"]["root"]),
            activation_epoch: input["plan"]["activate"].as_i64().unwrap(),
        });
        return result(
            rules::activation_mode(
                &|_| {
                    root(
                        input["default"].as_str().unwrap(),
                        plan.as_ref().map(|p| p.anchor_state_root.clone()),
                    )
                },
                plan.as_ref(),
                epoch,
            ),
            mode,
        );
    }
    let chain = raw(&input["chain"]);
    let graph = Graph::new(
        chain.clone(),
        (!input["config"].is_null()).then(|| raw(&input["config"])),
    );
    let plans = ALL.map(|r| graph.activation(r));
    let root_at = |e: i64| {
        root(
            input["roots"][e.to_string()]
                .as_str()
                .unwrap_or(input["default"].as_str().unwrap()),
            plans
                .iter()
                .flatten()
                .find(|p| p.anchor_epoch == e)
                .map(|p| p.anchor_state_root.clone()),
        )
    };
    // Native-signed parent bytes are an input here. Signature and codec parity
    // are independently exercised by set_fold_parity and consensus fixtures.
    let parent = (!expected["parent"].is_null())
        .then(|| ParentCommit::decode(&raw(&expected["parent"])).unwrap());
    let legacy = vec![b"legacy".to_vec()];
    let binding = BoundFold::bind(
        &graph,
        &raw(&input["bind_chain"]),
        epoch,
        parent,
        &legacy,
        &root_at,
    )
    .and_then(|b| b.resolve(input["target"].as_i64().unwrap(), &StateBatch::default()));
    let binding = match binding {
        Err(e) => json!({"error": e.to_string()}),
        Ok(c) => {
            assert_eq!(
                c.active_addresses,
                if c.standard_mode == RuleMode::Prior {
                    legacy
                } else {
                    c.members.clone()
                }
            );
            json!({
                "modes": ([c.mode,c.ready_mode,c.ready_ref_mode,c.live_mode,c.seat_mode,c.open_mode,c.account_mode,c.standard_mode,c.plan_mode,c.exit_mode,c.ready_exec_mode,c.program_mode,c.fhe_work,c.proof_exec,c.vm_bytes,c.wasm_float].map(mode)),
                "overlap":c.program_overlap,"math":c.math,
                "prune":c.cap_mode == octra_node_protocol::validator::set_fold::CapMode::Prune,
                "config":c.ready_config_hash.as_deref().map(b64),
                "start":c.start.to_string(),"profile":c.profile_start.to_string(),
                "members":c.members.iter().map(|v| b64(v)).collect::<Vec<_>>()
            })
        }
    };
    json!({
        "plans":plans.iter().map(|p| p.as_ref().map(|p| json!([p.anchor_epoch,b64(&p.anchor_state_root),p.activation_epoch]))).collect::<Vec<_>>(),
        "modes":ALL.map(|r| result(graph.mode(r,epoch,&root_at),mode)),
        "overlap":result(graph.program_overlap(epoch,&root_at),|v| json!(v)),
        "profiles":rules::profile_epochs(&chain),"live":rules::live_chain(&chain),
        "id":b64(&rules::consensus_id(&chain,epoch)),
        "floor":input["probes"].as_array().unwrap().iter().map(|e| rules::root_after_floor(&chain,input["floor"].as_i64().unwrap(),e.as_i64().unwrap()).as_deref().map(b64)).collect::<Vec<_>>(),
        "parent":expected["parent"],"bind":binding
    })
}
#[test]
fn native_anchored_rules_and_bound_validator_context() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/rule-activation.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixtures["upstream_commit"], sources["upstream_commit"]);
    assert_eq!(fixtures["source_sha256"], sources["files"]);
    let cases = fixtures["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 450);
    for (i, case) in cases.iter().enumerate() {
        assert_eq!(
            run(&case["input"], &case["expected"]),
            case["expected"],
            "case {i}: {}",
            case["input"]
        );
    }
}
