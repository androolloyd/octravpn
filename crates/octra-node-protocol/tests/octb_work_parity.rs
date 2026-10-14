use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::octb::work::{self as w, Budget, IntegerOp, Limits, Request};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn number(v: &Value) -> i64 {
    v.as_str().unwrap().parse().unwrap()
}
fn numbers(v: &Value) -> Vec<i64> {
    v.as_array().unwrap().iter().map(number).collect()
}
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn num(v: Option<i64>) -> Value {
    v.map_or(Value::Null, |n| json!(n.to_string()))
}
fn requests(v: &Value) -> Vec<Request> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|v| match v[0].as_str().unwrap() {
            "write" => Request::Write(number(&v[1]), number(&v[2])),
            "erase" => Request::Erase(number(&v[1])),
            "copy" => Request::Copy(number(&v[1]), number(&v[2])),
            "alloc" => Request::Allocate(number(&v[1])),
            "scan" => Request::Scan(number(&v[1])),
            _ => panic!(),
        })
        .collect()
}
fn render(rs: &[Request]) -> Value {
    json!(rs
        .iter()
        .map(|v| match v {
            Request::Write(a, b) => json!(["write", a.to_string(), b.to_string()]),
            Request::Erase(a) => json!(["erase", a.to_string()]),
            Request::Copy(a, b) => json!(["copy", a.to_string(), b.to_string()]),
            Request::Allocate(a) => json!(["alloc", a.to_string()]),
            Request::Scan(a) => json!(["scan", a.to_string()]),
        })
        .collect::<Vec<_>>())
}
fn limits(v: &Value) -> Limits {
    let p = numbers(v);
    Limits {
        key_bytes: p[0],
        value_bytes: p[1],
        copy_bytes: p[2],
        write_bytes: p[3],
        alloc_bytes: p[4],
        unit_bytes: p[5],
    }
}
fn run(v: &Value) -> Value {
    let n = |k: &str| number(&v[k]);
    match v["op"].as_str().unwrap() {
        "cost" => {
            json!({"charge":num(w::charge(n("used"),n("cost"),n("limit"))),"charge_z":num(w::charge_integer(n("used"),&v["z"].as_str().unwrap().parse().unwrap(),n("limit"))),"product":num(w::scaled_product(&numbers(&v["factors"]),n("divisor")))})
        }
        "integer" => {
            let left = v["left"].as_str().unwrap().parse().unwrap();
            let right = v["right"].as_str().unwrap().parse().unwrap();
            let op = match v["kind"].as_str().unwrap() {
                "add" => IntegerOp::Add,
                "sub" => IntegerOp::Sub,
                "mul" => IntegerOp::Mul,
                "div" => IntegerOp::Div,
                "mod" => IntegerOp::Mod,
                "neg" => IntegerOp::Neg,
                "abs" => IntegerOp::Abs,
                _ => panic!(),
            };
            json!({"variable":op.variable(&left,&right).to_string(),"prior":op.cost(false,n("base"),&left,&right).to_string(),"active":op.cost(true,n("base"),&left,&right).to_string(),"value":op.eval(&left,&right).map(|v|v.to_string())})
        }
        "helpers" => {
            json!({"parsing":w::parsing(n("length"),n("count")).map(|(base,rs)|json!([base.to_string(),render(&rs)])),"encoded_size":num(w::encoded_size(n("length"))),"cell_bytes":num(w::cell_bytes(n("count"),n("bits"))),"decoding":w::decoding(n("length"),n("count"),n("bits"),v["cached"].as_bool().unwrap()).map(|v|json!({"max_bytes":v.max_bytes.to_string(),"requests":render(&v.requests)}))})
        }
        "plan" => w::plan(
            limits(&v["limits"]),
            n("remaining"),
            n("available"),
            n("used"),
            n("limit"),
            n("base"),
            &requests(&v["requests"]),
        )
        .map_or(Value::Null, |p| {
            json!([
                p.effort.to_string(),
                p.remaining.to_string(),
                p.available.to_string()
            ])
        }),
        "budget" => {
            let Some(mut b) = Budget::new(limits(&v["limits"])) else {
                return Value::Null;
            };
            json!(v["actions"].as_array().unwrap().iter().map(|a|{
  let used=number(&a["used"]);let limit=number(&a["limit"]);
  let got=match a["action"].as_str().unwrap(){"charge"=>b.charge(used,limit,number(&a["base"]),&requests(&a["requests"])),"output"=>b.output(used,limit,number(&a["size"])),"emit"=>b.emit(used,limit,number(&a["size"])),_=>panic!()};
  json!({"result":num(got),"remaining":b.remaining().to_string(),"available":b.available().to_string(),"event_left":b.event_left().to_string()})
 }).collect::<Vec<_>>())
        }
        "text" => num(w::text_size(n("limit"), &bytes(&v["value"]))),
        "event" => {
            let values: Vec<_> = v["values"].as_array().unwrap().iter().map(bytes).collect();
            num(w::event_size(
                n("limit"),
                &bytes(&v["address"]),
                n("depth"),
                &bytes(&v["name"]),
                &values.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            ))
        }
        _ => panic!(),
    }
}
#[test]
fn native_integer_and_byte_work_preserve_costs_caps_and_atomic_charges() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/octb-work.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], pin["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (key, raw) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/octb-work-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/octb-work-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(fixture[key], hex::encode(Sha256::digest(raw)));
    }
    let mut errors = Vec::new();
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let got = run(&case["input"]);
        if got != case["expected"] {
            errors.push(format!(
                "case {index}: {}\ngot {got}\nexpected {}",
                case["input"], case["expected"]
            ));
            if errors.len() == 5 {
                break;
            }
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}
