use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    account_pack::{self as pack, Data, Part},
    state::{Account, Ledger},
    transaction::{Nonce, RuleMode},
};
use octra_node_runtime::{account_store, state_batch::StateBatch};
use serde_json::{json, Value};
fn bytes(v: &Value, k: &str) -> Vec<u8> {
    STANDARD.decode(v[k].as_str().unwrap()).unwrap()
}
fn blob(v: &[u8]) -> Value {
    json!(STANDARD.encode(v))
}
fn optional(v: &Value, k: &str) -> Option<Vec<u8>> {
    v[k].as_str().map(|v| STANDARD.decode(v).unwrap())
}
fn account(v: &Value) -> Account {
    Account {
        balance: v["balance"].as_str().unwrap().parse().unwrap(),
        nonce: Nonce::new(v["nonce"].as_str().unwrap().parse().unwrap()).unwrap(),
        public_key: optional(v, "public_key"),
        encrypted_balance: optional(v, "encrypted_balance"),
        decrypt_allowance: v["decrypt_allowance"].as_str().unwrap().parse().unwrap(),
    }
}
fn result<T, E: std::fmt::Display>(result: Result<T, E>, f: impl FnOnce(T) -> Value) -> Value {
    match result {
        Ok(v) => json!({"ok":f(v)}),
        Err(e) => json!({"error":e.to_string()}),
    }
}
fn evaluate(input: &Value) -> Value {
    match input["kind"].as_str().unwrap() {
        "image" => {
            let image = pack::image(&account(&input["account"]));
            json!({"data":blob(&image.data),"meta":image.meta.as_deref().map(blob),"parts":image.parts.iter().map(|p|json!([blob(&p.id),blob(&p.raw)])).collect::<Vec<_>>(),"id":image.id.as_deref().map(blob),"restore":result(pack::read(pack::data(&image.data).unwrap(),image.meta.as_deref(),|id|image.parts.iter().find(|p|p.id==id).map(|p|p.raw.clone())),|v|blob(&v.to_json_bytes()))})
        }
        "data" => result(pack::data(&bytes(input, "raw")), |v| match v {
            Data::Old(a) => json!(["old", blob(&a.to_json_bytes())]),
            Data::Parts(a, id) => json!(["parts", blob(&a.to_json_bytes()), blob(&id)]),
        }),
        "meta" => result(pack::meta(&bytes(input, "raw")), |v| {
            blob(&v.to_json_bytes())
        }),
        "join" => {
            let parts = input["parts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| Part {
                    id: STANDARD.decode(v[0].as_str().unwrap()).unwrap(),
                    raw: STANDARD.decode(v[1].as_str().unwrap()).unwrap(),
                })
                .collect::<Vec<_>>();
            result(
                pack::join(
                    &bytes(input, "id"),
                    input["size"].as_str().unwrap().parse().unwrap(),
                    &parts,
                ),
                |v| blob(&v),
            )
        }
        "store" => {
            let mut store = StateBatch::default();
            store.begin().unwrap();
            let address = bytes(input, "address");
            json!(input["steps"].as_array().unwrap().iter().map(|step|{
  let action=match step["op"].as_str().unwrap(){
   "set"=>account_store::set(&mut store,&address,&account(&step["account"]),if step["active"]==true{RuleMode::Active}else{RuleMode::Prior}).map_err(|e|e.to_string()),
   op=>{let path=step["path"].as_array().unwrap().iter().map(|v|STANDARD.decode(v.as_str().unwrap()).unwrap()).collect::<Vec<_>>();let refs=path.iter().map(Vec::as_slice).collect::<Vec<_>>();match op{"write"=>store.set(&refs,bytes(step,"raw")),"remove"=>store.remove(&refs),_=>panic!("action")}.map_err(|e|e.to_string())}
  };json!({"action":action.err(),"load":result(account_store::load(&store,&address),|v|v.as_ref().map_or(Value::Null,|a|blob(&a.to_json_bytes()))),"data":store.get(&[b"accounts",&address,b"data"]).map(blob),"meta":store.get(&[b"accounts",&address,b"cipher",b"meta"]).map(blob),"root":hex::encode(store.root().unwrap())})
 }).collect::<Vec<_>>())
        }
        other => panic!("unexpected {other}"),
    }
}
#[test]
fn account_chunks_and_persistence_match_native() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/account-pack.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/upstream.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["commit"]);
    for (path, hash) in fixture["sources"].as_object().unwrap() {
        assert_eq!(&sources["files"][path], hash, "source drift {path}");
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() > 100);
    for (index, case) in cases.iter().enumerate() {
        compare(
            &evaluate(&case["input"]),
            &case["output"],
            &format!("case {index}"),
        );
    }
}
#[test]
fn failed_account_flush_keeps_dirty_ledger_and_restores_tree() {
    let mut ledger = Ledger::empty();
    ledger.add_account(b"a", 10.into(), None).unwrap();
    ledger.add_account(b"b", 10.into(), None).unwrap();
    ledger.update_encrypted_balance(b"b", b"hfhe_v1|AA==".to_vec());
    let mut store = StateBatch::default();
    store.begin().unwrap();
    store
        .set(&[b"accounts", b"b", b"data"], b"bad".to_vec())
        .unwrap();
    let root = store.root().unwrap();
    assert!(account_store::flush_dirty(&mut ledger, &mut store, RuleMode::Active).is_err());
    assert_eq!(store.root().unwrap(), root);
    assert_eq!(ledger.dirty_addresses().len(), 2);
    assert!(store.get(&[b"accounts", b"a", b"data"]).is_none());
    store.remove(&[b"accounts", b"b", b"data"]).unwrap();
    account_store::flush_dirty(&mut ledger, &mut store, RuleMode::Active).unwrap();
    assert!(ledger.dirty_addresses().is_empty());
    assert_eq!(
        account_store::load(&store, b"b").unwrap(),
        ledger.account(b"b").cloned()
    );
}

fn compare(actual: &Value, expected: &Value, path: &str) {
    if actual == expected {
        return;
    }
    match (actual, expected) {
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
            for (i, (a, b)) in a.iter().zip(b).enumerate() {
                compare(a, b, &format!("{path}[{i}]"));
            }
        }
        (Value::Object(a), Value::Object(b)) if a.len() == b.len() => {
            for (k, b) in b {
                compare(&a[k], b, &format!("{path}.{k}"));
            }
        }
        _ => panic!(
            "{path}: actual={} expected={}",
            actual.to_string().chars().take(160).collect::<String>(),
            expected.to_string().chars().take(160).collect::<String>()
        ),
    }
}
