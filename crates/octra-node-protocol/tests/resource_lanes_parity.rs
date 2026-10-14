use num_bigint::BigInt;
use octra_node_protocol::{
    resource_lanes::{self, Budget, Lane, Usage},
    transaction::{Nonce, OpType, RuleMode, Transaction},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn z(v: &Value) -> BigInt {
    v.as_str().unwrap().parse().unwrap()
}
fn usage(v: &Value) -> Usage {
    Usage {
        transactions: v["txs"].as_i64().unwrap(),
        bytes: v["bytes"].as_i64().unwrap(),
        ou: z(&v["ou"]),
        proofs: v["proof"].as_i64().unwrap(),
    }
}
fn json_usage(v: &Usage) -> Value {
    json!({"txs":v.transactions,"bytes":v.bytes,"ou":v.ou.to_string(),"proof":v.proofs})
}
#[test]
fn native_resource_lanes_costs_and_queue_activation_match() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/resource-lanes.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/resource-lanes-oracle.ml"
        )))
    );
    assert_eq!(fixture["instrumentation"], json!({}));
    let mut operations = std::collections::BTreeSet::new();
    for (i, c) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let v = &c["input"];
        let op = OpType::parse(v["op"].as_str().unwrap().as_bytes()).unwrap();
        operations.insert(op.as_str());
        let tx = Transaction {
            from: b"a".to_vec(),
            to: b"b".to_vec(),
            amount: 1.into(),
            nonce: Nonce::new(1).unwrap(),
            ou: z(&v["ou"]),
            timestamp: 1.,
            signature: b"sig".to_vec(),
            public_key: None,
            message: v["message"].as_str().map(|s| s.as_bytes().to_vec()),
            encrypted_data: Some(vec![b'x'; v["length"].as_u64().unwrap() as usize]),
            op_type: op,
        };
        let minimum = z(&v["minimum"]);
        let lane = Lane::of(op);
        let defaults = lane.budget();
        let budget = usage(&v["budget"]);
        let budget = Budget {
            transactions: budget.transactions,
            bytes: budget.bytes,
            ou: budget.ou,
            proofs: budget.proofs,
        };
        let used = usage(&v["used"]);
        let cost = resource_lanes::cost(&tx, &minimum).unwrap();
        let admit = match resource_lanes::admit(&budget, &used, &tx, &minimum) {
            Ok(used) => json!({"ok":json_usage(&used)}),
            Err(e) => json!({"error":e.to_string()}),
        };
        let actual = json!({"lane":lane.as_str(),"queue":lane.preverify_queue(),"managed":lane.preverify_queue()>0,
   "budget":{"txs":defaults.transactions,"bytes":defaults.bytes,"ou":defaults.ou.to_string(),"proof":defaults.proofs},"cost":json_usage(&cost),"work":json_usage(&resource_lanes::work(&tx,&minimum).unwrap()),"vm":resource_lanes::vm_limit(&tx.ou),
   "prior":resource_lanes::queue_check(&tx,RuleMode::Prior,&minimum).err().map(|e|e.to_string()),"active":resource_lanes::queue_check(&tx,RuleMode::Active,&minimum).err().map(|e|e.to_string()),
   "add":json_usage(&used.add(&cost)),"over":budget.over(&used),"admit":admit});
        assert_eq!(actual, c["expected"], "native resource case {i}: {v}");
    }
    assert_eq!(operations.len(), OpType::ALL.len());
}
