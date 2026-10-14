use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use num_traits::Zero;
use octra_node_protocol::{
    circle_storage::StorageTable,
    octb::{
        work::{Budget, Limits},
        Image, StorageKind,
    },
};
use octra_node_runtime::octb::{
    self, Capability, Context, Host, Machine, Options, Progress, Unavailable, Value as Cell,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn encoded(v: &[u8]) -> Value {
    json!(STANDARD.encode(v))
}
fn flag(v: &Value, k: &str) -> bool {
    v[k].as_bool().unwrap_or(false)
}
fn integer(v: &Value, k: &str, default: i64) -> i64 {
    v[k].as_i64().unwrap_or(default)
}
fn rows<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v[k].as_array().map_or(&[], Vec::as_slice)
}
fn cap(v: &Value) -> Capability {
    Capability {
        scope: bytes(&v["scope"]),
        kind: v["kind"].as_i64().unwrap(),
        id: v["id"].as_i64().unwrap(),
        revision: v["revision"].as_i64().unwrap(),
    }
}
fn cap_json(c: &Capability) -> Value {
    json!({"scope":encoded(&c.scope),"kind":c.kind,"id":c.id,"revision":c.revision})
}
fn cell(v: &Value) -> Cell {
    let (k, v) = v.as_object().unwrap().iter().next().unwrap();
    match k.as_str() {
        "int" => Cell::int(v.as_str().unwrap().parse::<BigInt>().unwrap()),
        "bool" => Cell::Bool(v.as_bool().unwrap()),
        "str" => Cell::string(bytes(v)),
        "bytes" => Cell::Bytes(bytes(v).into()),
        "bytes32" => Cell::Bytes32(bytes(v).into()),
        "addr" => Cell::Address(bytes(v).into()),
        "cap" => Cell::Capability(cap(v)),
        "u64" => Cell::U64(Arc::new(v.as_str().unwrap().parse().unwrap())),
        "u128" => Cell::U128(Arc::new(v.as_str().unwrap().parse().unwrap())),
        "u256" => Cell::U256(Arc::new(v.as_str().unwrap().parse().unwrap())),
        _ => panic!("unknown fixture type"),
    }
}
fn render(v: &Cell) -> Value {
    let (k, v) = match v {
        Cell::Int(v) => ("int", json!(v.to_string())),
        Cell::Bool(v) => ("bool", json!(v)),
        Cell::String(v) => ("str", encoded(v)),
        Cell::Bytes(v) => ("bytes", encoded(v)),
        Cell::Bytes32(v) => ("bytes32", encoded(v)),
        Cell::Address(v) => ("addr", encoded(v)),
        Cell::U64(v) => ("u64", json!(v.to_string())),
        Cell::U128(v) => ("u128", json!(v.to_string())),
        Cell::U256(v) => ("u256", json!(v.to_string())),
        Cell::Capability(v) => ("cap", cap_json(v)),
        _ => panic!("unexpected private handle"),
    };
    json!({k:v})
}
fn kind(v: &Value) -> StorageKind {
    match v.as_u64().unwrap() {
        0 => StorageKind::Int,
        1 => StorageKind::Bool,
        2 => StorageKind::String,
        3 => StorageKind::Bytes,
        4 => StorageKind::Bytes32,
        5 => StorageKind::U64,
        6 => StorageKind::U128,
        7 => StorageKind::U256,
        8 => StorageKind::Addr,
        _ => panic!(),
    }
}
struct FixtureHost {
    calls: Vec<Value>,
    transfer: bool,
    live: bool,
    spawn: bool,
    spawn_effort: i64,
    depth: i64,
}
impl Host for FixtureHost {
    fn spawn(
        &mut self,
        request: octb::SpawnRequest<'_>,
        _budget: Option<&mut Budget>,
    ) -> Result<Option<octb::Spawned>, Unavailable> {
        self.calls.push(json!([
            "spawn",
            encoded(request.parent),
            encoded(request.code),
            request.nonce,
            request.params.iter().map(render).collect::<Vec<_>>(),
            request.limit
        ]));
        Ok(self.spawn.then(|| octb::Spawned {
            address: format!("oct{}", "5".repeat(44)).into_bytes(),
            effort: self.spawn_effort,
            events: vec![octb::Event {
                contract: request.parent.to_vec(),
                depth: self.depth + 1,
                name: b"spawned".to_vec(),
                values: vec![Cell::string(b"child\xff".to_vec())],
            }],
        }))
    }
    fn balance(&mut self, address: &[u8]) -> Result<BigInt, Unavailable> {
        self.calls.push(json!(["balance", encoded(address)]));
        Ok(123_456.into())
    }
    fn transfer(&mut self, from: &[u8], to: &[u8], amount: &BigInt) -> Result<bool, Unavailable> {
        self.calls.push(json!([
            "transfer",
            encoded(from),
            encoded(to),
            amount.to_string()
        ]));
        Ok(self.transfer)
    }
    fn cap_live(&mut self, cap: &Capability) -> Result<bool, Unavailable> {
        self.calls.push(json!(["cap", cap_json(cap)]));
        Ok(self.live)
    }
}
fn run(v: &Value, stepped: bool) -> Value {
    let image = Image::decode(&bytes(&v["raw"]), true).unwrap();
    let code = octb::fix_jumps(&image.code);
    let mut budget = if flag(v, "bytes") {
        Some(if let Some(l) = v["limits"].as_array() {
            Budget::new(Limits {
                key_bytes: l[0].as_i64().unwrap(),
                value_bytes: l[1].as_i64().unwrap(),
                copy_bytes: l[2].as_i64().unwrap(),
                write_bytes: l[3].as_i64().unwrap(),
                alloc_bytes: l[4].as_i64().unwrap(),
                unit_bytes: l[5].as_i64().unwrap(),
            })
            .unwrap()
        } else {
            Budget::default()
        })
    } else {
        None
    };
    let mut host = FixtureHost {
        calls: vec![],
        transfer: flag(v, "transfer_ok"),
        live: flag(v, "cap_live"),
        spawn: flag(v, "spawn_ok"),
        spawn_effort: integer(v, "spawn_effort", 0),
        depth: integer(v, "depth", 0),
    };
    let mut storage = StorageTable::new(16);
    for row in rows(v, "storage") {
        storage.replace(bytes(&row[0]), bytes(&row[1]));
    }
    let context = Context {
        caller: format!("oct{}", "2".repeat(44)).into_bytes(),
        origin: format!("oct{}", "3".repeat(44)).into_bytes(),
        address: format!("oct{}", "4".repeat(44)).into_bytes(),
        value: 456.into(),
        epoch: 123,
        epoch_time_ms: 1_791_930_000_123,
        tree_hash: b"fixture-tree".to_vec(),
        node_id: b"fixture-node".to_vec(),
        tx_hash: b"fixture-tx".to_vec(),
        depth: integer(v, "depth", 0),
    };
    let options = Options {
        fhe_work: flag(v, "fhe_work"),
        async_exec: flag(v, "async"),
        limit: integer(v, "limit", 1_000_000),
        strict: flag(v, "strict"),
        typed_bytes: flag(v, "typed"),
        integer_work: flag(v, "integer_work"),
        point_ops: flag(v, "point"),
        is_view: flag(v, "view"),
        storage_kinds: rows(v, "kinds")
            .iter()
            .map(|r| (bytes(&r[0]), kind(&r[1])))
            .collect::<BTreeMap<_, _>>(),
    };
    let mut machine = Machine::new(context, options, storage);
    for row in rows(v, "regs") {
        machine.regs[row[0].as_u64().unwrap() as usize] = cell(&row[1]);
    }
    for row in rows(v, "memory") {
        let index = row[0].as_i64().unwrap();
        machine.memory.insert(index, cell(&row[1]));
        machine.memory_size = machine.memory_size.max(index + 1);
    }
    machine.effort = integer(v, "used", 0);
    machine.pc = integer(v, "pc", 0) as usize;
    let ok = if stepped {
        loop {
            match machine.step(&code, &mut host, budget.as_mut()).unwrap() {
                Progress::Running => (),
                Progress::Finished => break true,
                Progress::Refused => break false,
            }
        }
    } else {
        machine.run(&code, &mut host, budget.as_mut()).unwrap()
    };
    let registers: Vec<_> = machine
        .regs
        .iter()
        .enumerate()
        .filter(|(_, v)| !matches!(v,Cell::Int(n) if n.is_zero()))
        .map(|(r, v)| json!([r, render(v)]))
        .collect();
    json!({"ok":ok,"pc":machine.pc,"effort":machine.effort,"reverted":machine.reverted,"output_ready":machine.output_ready,"regs":registers,
  "memory":machine.memory.iter().map(|(i,v)|json!([i,render(v)])).collect::<Vec<_>>(),"memory_size":machine.memory_size,
  "storage":machine.storage.values().iter().map(|(k,v)|json!([encoded(k),encoded(v)])).collect::<Vec<_>>(),
  "blobs":machine.blobs.iter().map(|(k,v)|json!([encoded(k),encoded(v)])).collect::<Vec<_>>(),
  "events":machine.events.iter().map(|e|json!({"contract":encoded(&e.contract),"depth":e.depth,"name":encoded(&e.name),"values":e.values.iter().map(render).collect::<Vec<_>>()})).collect::<Vec<_>>(),
  "closes":machine.closes.iter().map(cap_json).collect::<Vec<_>>(),"host_calls":host.calls,
  "budget":budget.map(|b|json!([b.remaining(),b.available(),b.event_left()]))})
}
#[test]
fn native_octb_execution_preserves_state_cost_and_refusal_order() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/octb-execution.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], pin["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (key, raw) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/octb-execution-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/octb-execution-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(fixture[key], hex::encode(Sha256::digest(raw)), "{key}");
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 13528);
    compare(cases);
}

#[test]
fn native_octb_spawn_preserves_nonce_budget_scope_and_host_completion() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/octb-spawn.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], pin["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (key, raw) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/octb-spawn-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/octb-spawn-fixtures.py").as_slice(),
        ),
        (
            "generator_dependency_sha256",
            include_bytes!("../../../scripts/node-port/octb-execution-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(fixture[key], hex::encode(Sha256::digest(raw)), "{key}");
    }
    compare(fixture["cases"].as_array().unwrap());
}

fn compare(cases: &[Value]) {
    let mut failures = vec![];
    for (index, case) in cases.iter().enumerate() {
        for stepped in [false, true] {
            let actual = run(case, stepped);
            if actual != case["expected"] {
                let fields: Vec<_> = actual
                    .as_object()
                    .unwrap()
                    .iter()
                    .filter(|(k, v)| **v != case["expected"][*k])
                    .map(|(k, v)| format!("{k}: got {v}, native {}", case["expected"][k]))
                    .collect();
                failures.push(format!(
                    "case {index}, stepped {stepped}, {}: {}",
                    case["name"],
                    fields.join("; ")
                ));
                break;
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures
            .iter()
            .take(25)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn unavailable_execution_is_never_a_consensus_refusal() {
    use octra_node_protocol::octb::Instruction;
    struct MissingHost;
    impl Host for MissingHost {}
    for limit in [0, 1_000_000] {
        let mut machine = Machine::new(
            Context::default(),
            Options {
                limit,
                ..Options::default()
            },
            StorageTable::new(0),
        );
        let mut budget = Budget::default();
        let before = budget.clone();
        let error = machine
            .run(
                &[Instruction::FheMul(0, 1, 2, 3)],
                &mut MissingHost,
                Some(&mut budget),
            )
            .unwrap_err();
        assert!(error.0.contains("not available"));
        assert!(!machine.reverted);
        assert_eq!(machine.effort, 0);
        assert_eq!(budget, before);
    }
    let mut machine = Machine::new(Context::default(), Options::default(), StorageTable::new(0));
    machine.regs[1] = Cell::Address(Arc::from(b"address".as_slice()));
    let error = machine
        .run(&[Instruction::Balance(0, 1)], &mut MissingHost, None)
        .unwrap_err();
    assert!(error.0.contains("balance host"));
    assert!(!machine.reverted);
    assert!(!machine.output_ready);
}
