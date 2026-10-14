use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use octra_node_protocol::transaction::{Nonce, OpType, RuleMode, Transaction};
use octra_node_runtime::staging::{
    self, preview, DropReason, DropRecord, Limits, Pool, QueueState,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn b(v: impl AsRef<[u8]>) -> Value {
    json!(STANDARD.encode(v))
}
fn optional(v: &Value) -> Option<Vec<u8>> {
    (!v.is_null()).then(|| bytes(v))
}
fn n(v: &Value) -> Nonce {
    Nonce::new(v.as_i64().unwrap()).unwrap()
}
fn z(v: &Value) -> BigInt {
    v.as_str().unwrap().parse().unwrap()
}
fn f(v: &Value) -> f64 {
    v.as_str().unwrap().parse().unwrap()
}
fn bits(v: f64) -> Value {
    json!(format!("{:016x}", v.to_bits()))
}
fn transaction(v: &Value) -> Transaction {
    Transaction {
        from: bytes(&v["from"]),
        to: bytes(&v["to"]),
        amount: z(&v["amount"]),
        nonce: n(&v["nonce"]),
        ou: z(&v["ou"]),
        timestamp: f(&v["timestamp"]),
        signature: bytes(&v["signature"]),
        public_key: None,
        message: optional(&v["message"]),
        encrypted_data: optional(&v["encrypted"]),
        op_type: OpType::parse(v["op"].as_str().unwrap().as_bytes()).unwrap(),
    }
}
fn hash(tx: &Transaction) -> Vec<u8> {
    hex::encode(tx.hash().unwrap()).into_bytes()
}
fn hashes<'a>(txs: impl IntoIterator<Item = &'a Transaction>) -> Value {
    json!(txs.into_iter().map(|tx| b(hash(tx))).collect::<Vec<_>>())
}
fn drop(d: &DropRecord) -> Value {
    json!({"hash":b(&d.hash),"from":b(&d.from),"to":b(&d.to),"nonce":d.nonce.get(),"ou":d.ou.to_string(),"op":d.operation.as_str(),
        "reason":match d.reason { DropReason::Evicted=>"evicted",DropReason::Expired=>"expired" },"detail":d.detail,"time":bits(d.timestamp)})
}
fn drops(ds: &[DropRecord]) -> Value {
    json!(ds.iter().map(drop).collect::<Vec<_>>())
}
fn sorted_drops(mut ds: Vec<DropRecord>) -> Value {
    ds.sort_by(|a, b| a.hash.cmp(&b.hash));
    drops(&ds)
}
fn result<T, E: ToString>(v: Result<T, E>, map: impl FnOnce(T) -> Value) -> Value {
    match v {
        Ok(value) => json!({"ok":map(value)}),
        Err(reason) => json!({"error":reason.to_string()}),
    }
}
fn head(base: i64, s: &Value) -> Option<i64> {
    s["head"]
        .as_str()
        .map(|v| base.wrapping_add(v.parse::<i64>().unwrap()))
}
fn message(base: i64, h: Vec<u8>, s: &Value) -> preview::Message {
    match s["kind"].as_str().unwrap() {
        "check" => preview::Message::Check(head(base, s), h),
        "ready" => preview::Message::Ready(head(base, s), h),
        kind => {
            let head = head(base, s).unwrap();
            let epoch = base.wrapping_add(s["epoch"].as_str().unwrap().parse().unwrap());
            if kind == "hold" {
                preview::Message::Hold {
                    head,
                    epoch,
                    hash: h,
                }
            } else {
                preview::Message::Refuse {
                    head,
                    epoch,
                    hash: h,
                }
            }
        }
    }
}
type Accounts = BTreeMap<Vec<u8>, (BigInt, Nonce)>;
fn account(accounts: &mut Accounts, v: &Value) {
    let sender = bytes(&v["sender"]);
    if v["balance"].is_null() {
        accounts.remove(&sender);
    } else {
        accounts.insert(sender, (z(&v["balance"]), n(&v["nonce"])));
    }
}
fn snapshot(
    pool: &Pool,
    txs: &[Transaction],
    accounts: &Accounts,
    minimum: &BigInt,
    s: &Value,
) -> Value {
    let capacity = z(&s["capacity"]);
    let excluded = s["exclude"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| hash(&txs[i.as_u64().unwrap() as usize]))
        .collect::<BTreeSet<_>>();
    let confirmed = |a: &[u8]| accounts.get(a).map(|(_, n)| *n);
    let states = pool
        .all()
        .map(|tx| {
            let h = hash(tx);
            let status = match pool
                .queue_state(&h, confirmed(&tx.from).unwrap_or_default())
                .unwrap()
            {
                QueueState::Ready { expires_at } => json!(["ready", bits(expires_at)]),
                QueueState::WaitNonce {
                    expected,
                    expires_at,
                } => json!(["wait", expected.get(), bits(expires_at)]),
                QueueState::NonceUsed {
                    confirmed,
                    expires_at,
                } => json!(["used", confirmed.get(), bits(expires_at)]),
            };
            json!([b(h), status])
        })
        .collect::<Vec<_>>();
    let senders=txs.iter().map(|tx|tx.from.as_slice()).collect::<BTreeSet<_>>().into_iter().map(|sender| {
        let nonce=confirmed(sender).unwrap_or_default();
        json!({"sender":b(sender),"balance":pool.virtual_balance(sender).map(ToString::to_string),"expected":pool.expected_nonce(sender).get(),
            "missing":pool.first_missing_nonce(sender,nonce).get(),"pending":pool.pending_nonce(sender,nonce).get(),"duty":pool.duty_nonce(sender,nonce).map(Nonce::get)})
    }).collect::<Vec<_>>();
    json!({"all":hashes(pool.all()),"sample":pool.sample(5).map(|e|b(&e.hash)).collect::<Vec<_>>(),"recent":pool.recent(5).map(|e|b(&e.hash)).collect::<Vec<_>>(),
        "epoch":pool.epoch(&capacity).iter().map(|e|b(&e.hash)).collect::<Vec<_>>(),
        "ready":pool.ready_epoch(&capacity,&confirmed,&|tx|!excluded.contains(&hash(tx))).iter().map(|e|b(&e.hash)).collect::<Vec<_>>(),
        "total":pool.total_ou().to_string(),"size":pool.len(),"usage":pool.usage_percent().to_string().parse::<i64>().unwrap(),
        "states":states,"senders":senders,"fees":txs.iter().map(|tx|pool.min_relay_fee(tx,minimum).to_string()).collect::<Vec<_>>(),
        "drops":pool.drops().map(drop).collect::<Vec<_>>()})
}
#[test]
fn native_queue_matches_replacement_eviction_selection_preview_and_expiry() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/staging.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/staging-oracle.ml"
        )))
    );
    let injection = &fixture["instrumentation"]["lib/core/tx_staging.ml"];
    assert_eq!(
        injection["original_sha256"],
        source["files"]["lib/core/tx_staging.ml"]
    );
    assert_eq!(injection["prefix"],"(* Oracle-only deterministic wall clock; original source verified before injection. *)\nlet oracle_time = ref 0.\nmodule Unix = struct include Unix let gettimeofday () = !oracle_time end\n");
    assert_eq!(
        injection["prefix_sha256"],
        hex::encode(Sha256::digest(
            injection["prefix"].as_str().unwrap().as_bytes()
        ))
    );
    for (i, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let v = &case["input"];
        let steps = v["steps"].as_array().unwrap();
        if v["mode"] == "preview" {
            let mut state = preview::State::default();
            for (k, s) in steps.iter().enumerate() {
                let out = result(
                    state.step(
                        v["limit"].as_u64().unwrap() as usize,
                        &message(0, bytes(&s["hash"]), s),
                    ),
                    |()| Value::Null,
                );
                assert_eq!(out, case["expected"][k], "preview case {i} step {k}: {s}");
            }
            continue;
        }
        let txs = v["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(transaction)
            .collect::<Vec<_>>();
        let mut accounts = Accounts::new();
        for a in v["accounts"].as_array().unwrap() {
            account(&mut accounts, a);
        }
        let minimum = z(&v["minimum"]);
        let base = case["base"].as_str().unwrap().parse().unwrap();
        let mut pool = Pool::default();
        pool.preview(preview::Message::Check(Some(base), b"reset".to_vec()))
            .unwrap();
        for (k, s) in steps.iter().enumerate() {
            let now = f(&s["now"]);
            let clock = || now;
            let tx = &txs[s["index"].as_u64().unwrap() as usize];
            let h = hash(tx);
            let out = match s["kind"].as_str().unwrap() {
                "add" => result(
                    pool.add(
                        tx.clone(),
                        &Limits {
                            ou: z(&s["limit"]),
                            transactions: s["count"].as_i64().unwrap(),
                            stealth_minimum: minimum.clone(),
                        },
                        head(base, s),
                        &|a| accounts.get(a).cloned(),
                        &clock,
                    ),
                    |ds| drops(&ds),
                ),
                "remove" => json!(pool.remove(&h)),
                "processed" => {
                    pool.remove_processed(
                        &s["indices"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|i| hash(&txs[i.as_u64().unwrap() as usize]))
                            .collect::<Vec<_>>(),
                    );
                    Value::Null
                }
                "clear" => {
                    pool.clear();
                    Value::Null
                }
                "account" => {
                    account(&mut accounts, s);
                    Value::Null
                }
                "expire" => {
                    sorted_drops(pool.expire_old(&|a| accounts.get(a).map(|(_, n)| *n), &clock))
                }
                "cleanup" => {
                    pool.cleanup_dropped(now);
                    Value::Null
                }
                "drop_preview" => pool
                    .drop_preview(&h, now)
                    .as_ref()
                    .map_or(Value::Null, drop),
                "duty" => drops(&pool.expire_duty(
                    optional(&s["sender"]).as_deref(),
                    head(0, s),
                    if s["active"] == true {
                        RuleMode::Active
                    } else {
                        RuleMode::Prior
                    },
                    &clock,
                )),
                "inspect" => Value::Null,
                _ => result(pool.preview(message(base, h, s)), |()| Value::Null),
            };
            let actual = json!({"result":out,"state":snapshot(&pool,&txs,&accounts,&minimum,s)});
            let expected = &case["expected"][k];
            if actual != *expected {
                assert_eq!(
                    actual["result"], expected["result"],
                    "case {i} step {k} result: {s}"
                );
                for (field, value) in actual["state"].as_object().unwrap() {
                    assert_eq!(
                        value, &expected["state"][field],
                        "case {i} step {k} field {field}: {s}"
                    );
                }
            }
        }
    }
}
#[test]
fn expiry_explanations_preserve_native_int63_nonce_rollover() {
    assert_eq!(
        staging::expiry_reason(Nonce::new(4).unwrap(), Nonce::new(7).unwrap()),
        "TTL exceeded: waiting for nonce 5 before nonce 7"
    );
    assert_eq!(
        staging::expiry_reason(Nonce::MAX, Nonce::MIN),
        format!(
            "TTL exceeded: nonce {} was already consumed at {}",
            Nonce::MIN.get(),
            Nonce::MAX.get()
        )
    );
}
