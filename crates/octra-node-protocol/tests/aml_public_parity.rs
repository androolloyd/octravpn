use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use octra_node_protocol::aml::core::{
    entropy,
    graph::{self, Rule, Sign},
    machine::Literal,
    octb::Operation,
    vm, Natural,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
fn n(v: &Value) -> u32 {
    v.as_u64().unwrap().try_into().unwrap()
}
fn nat(v: &Value) -> Natural {
    Natural::from_u32(n(v)).unwrap()
}
fn z(v: &Value) -> BigInt {
    v.as_str().unwrap().parse().unwrap()
}
fn failure(raw: impl AsRef<[u8]>) -> Value {
    json!({"error":String::from_utf8(raw.as_ref().to_vec()).unwrap()})
}
fn literal(v: &Value) -> Literal {
    match v[0].as_str().unwrap() {
        "int" => Literal::Int(Arc::new(z(&v[1]))),
        "bool" => Literal::Bool(v[1].as_bool().unwrap()),
        "bytes" => Literal::Bytes(STANDARD.decode(v[1].as_str().unwrap()).unwrap().into()),
        "cap" => Literal::Cap(nat(&v[1]), nat(&v[2])),
        _ => panic!("unsupported fixture literal"),
    }
}
fn literal_json(value: &Literal) -> Value {
    match value {
        Literal::Int(v) => json!(["int", v.to_string()]),
        Literal::Bool(v) => json!(["bool", v]),
        Literal::Bytes(v) => json!(["bytes", STANDARD.encode(v)]),
        Literal::Cap(a, b) => json!(["cap", a.get(), b.get()]),
        Literal::Data(_) => panic!("unrequested data literal"),
    }
}
fn op(v: &Value) -> Operation {
    let r = |at| u8::try_from(n(&v[at])).unwrap();
    match v[0].as_str().unwrap() {
        "load" => Operation::Load(r(1), literal(&v[2])),
        "move" => Operation::Move(r(1), r(2)),
        "plus" => Operation::Plus(r(1), r(2), r(3)),
        "minus" => Operation::Minus(r(1), r(2), r(3)),
        "times" => Operation::Times(r(1), r(2), r(3)),
        "quotient" => Operation::Quotient(r(1), r(2), r(3)),
        "remainder" => Operation::Remainder(r(1), r(2), r(3)),
        "negate" => Operation::Negate(r(1), r(2)),
        "absolute" => Operation::Absolute(r(1), r(2)),
        "same" => Operation::Same(r(1), r(2), r(3)),
        "different" => Operation::Different(r(1), r(2), r(3)),
        "less" => Operation::Less(r(1), r(2), r(3)),
        "greater" => Operation::Greater(r(1), r(2), r(3)),
        "join" => Operation::Join(r(1), r(2), r(3)),
        "size" => Operation::Size(r(1), r(2)),
        "slice" => Operation::Slice(r(1), r(2), r(3), r(4)),
        "close" => Operation::CapClose(nat(&v[1]), r(2)),
        "jump" => Operation::Jump(n(&v[1])),
        "jump_if" => Operation::JumpIf(r(1), n(&v[2])),
        "mark" => Operation::Mark(n(&v[1])),
        "noop" => Operation::Noop,
        "stop" => Operation::Stop,
        _ => panic!("unsupported fixture instruction"),
    }
}
fn run(v: &Value) -> Value {
    match v["kind"].as_str().unwrap() {
        "vm" => {
            let options = vm::Options {
                cap: v["cap"].as_i64().unwrap(),
                activate: v["activate"].as_str().map(|s| s.parse().unwrap()),
                epoch: z(&v["epoch"]),
            };
            let inputs = v["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(literal)
                .collect::<Vec<_>>();
            let mut vm = match vm::Vm::make_in(options, &inputs) {
                Ok(vm) => vm,
                Err(error) => return failure(error.text()),
            };
            let code = v["code"]
                .as_array()
                .unwrap()
                .iter()
                .map(op)
                .collect::<Vec<_>>();
            let error = vm
                .run(&code)
                .err()
                .map(|e| String::from_utf8(e.text()).unwrap());
            json!({"error":error,"pc":vm.pc(),"steps":vm.steps(),"work":vm.work().to_string(),"halted":vm.halted(),"registers":(0..8).map(|r|literal_json(vm.value(r))).collect::<Vec<_>>(),"closes":vm.closes().iter().map(|(a,b)|json!([a.get(),b.get()])).collect::<Vec<_>>()})
        }
        "entropy" => match entropy::plan(&entropy::production(), nat(&v["depth"])) {
            Err(e) => failure(e.text()),
            Ok(p) => {
                json!({"depth":p.depth().get(),"cap":p.capacity().to_string(),"binary":p.binary().to_string(),"ternary":p.ternary().to_string(),"groups":p.groups().to_string(),"edges":p.edges().to_string()})
            }
        },
        "graph" => {
            let config = match graph::Config::new(
                nat(&v["basis"]),
                nat(&v["slots"]),
                nat(&v["sigma"]),
                z(&v["cap"]),
            ) {
                Ok(c) => c,
                Err(e) => return failure(e.text()),
            };
            let layers = v["layers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| match v[1].as_str().unwrap() {
                    "base" => graph::base(nat(&v[0])),
                    _ => graph::prod(nat(&v[0]), nat(&v[2]), nat(&v[3])),
                })
                .collect();
            let edges = v["edges"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    graph::edge(
                        nat(&v[0]),
                        nat(&v[1]),
                        if v[2] == "+" { Sign::Pos } else { Sign::Neg },
                        v[3].as_array().unwrap().iter().map(z).collect(),
                        v[4].as_array()
                            .unwrap()
                            .iter()
                            .map(|v| v.as_bool().unwrap())
                            .collect(),
                    )
                })
                .collect::<Result<Vec<_>, _>>();
            let edges = match edges {
                Ok(e) => e,
                Err(e) => return failure(e.text()),
            };
            let value = graph::graph(layers, edges);
            let depth = match graph::mul_depth(&value) {
                Ok(d) => json!(d.get()),
                Err(e) => failure(e.text()),
            };
            let norm = match graph::norm(&config, &value) {
                Err(e) => failure(e.text()),
                Ok(info) => {
                    json!({"merged":info.merged(),"layers":info.graph().layers().iter().map(|l|match l.rule(){Rule::Base=>json!([l.tag().get(),"base"]),Rule::Prod(a,b)=>json!([l.tag().get(),"prod",a.get(),b.get()])}).collect::<Vec<_>>(),"edges":info.graph().edges().iter().map(|e|json!([e.layer().get(),e.index().get(),if e.sign()==Sign::Pos{"+"}else{"-"},e.weight().iter().map(ToString::to_string).collect::<Vec<_>>(),e.sigma()])).collect::<Vec<_>>(),"layer_count":info.layer_count().to_string(),"edge_count":info.edge_count().to_string(),"removed":info.removed().to_string()})
                }
            };
            json!({"valid":graph::valid(&config,&value),"depth":depth,"norm":norm})
        }
        _ => panic!("unsupported fixture operation"),
    }
}
#[test]
fn adopted_native_aml_public_differential() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/aml-public.json")).unwrap();
    let map: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], map["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], map["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (key, raw) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/aml-public-oracle.ml").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/aml-public-fixtures.py").as_slice(),
        ),
    ] {
        assert_eq!(fixture[key], hex::encode(Sha256::digest(raw)), "{key}");
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() > 200);
    for (index, case) in cases.iter().enumerate() {
        assert_eq!(
            run(&case["input"]),
            case["expected"],
            "native AML public case{index}: {}",
            case["input"]
        );
    }
}
#[test]
fn checked_public_arena_references_fail_before_insertion() {
    use octra_node_protocol::aml::core::{
        arena,
        term::{Term, Terms},
        types::{Type, Types},
    };
    let mut types = Types::default();
    let typ = types.insert(Type::Int).unwrap();
    let mut empty = Types::default();
    let error = empty.insert(Type::Pair(typ, typ)).unwrap_err();
    assert_eq!(
        (error.kind, error.index, error.length),
        (arena::Kind::Type, 0, 0)
    );
    assert!(empty.try_get(typ).is_none());
    let mut source = Terms::default();
    let term = source.insert(&types, Term::Unit).unwrap();
    let mut target = Terms::default();
    let error = target.insert(&empty, Term::Inl(term, typ)).unwrap_err();
    assert_eq!(error.kind, arena::Kind::Term);
    assert!(target.try_get(term).is_none());
    let unit = target.insert(&empty, Term::Unit).unwrap();
    let error = target.insert(&empty, Term::Inl(unit, typ)).unwrap_err();
    assert_eq!(error.kind, arena::Kind::Type);
    assert_eq!(
        target.insert(&types, Term::Inl(unit, typ)).unwrap(),
        source.insert(&types, Term::Unit).unwrap()
    );
}
