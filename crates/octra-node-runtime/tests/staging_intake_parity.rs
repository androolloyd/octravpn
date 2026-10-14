use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer as _, SigningKey};
use num_bigint::BigInt;
use octra_node_protocol::{
    state::{Account, Ledger},
    transaction::{address_from_public_key, Nonce, OpType, RuleMode, Transaction},
    transaction_policy::Profile,
};
use octra_node_runtime::{
    admission,
    staging::{
        intake::{self, Host, Rpc, Rules},
        preview, DropReason, DropRecord, Pool,
    },
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
fn prepared(v: &Value) -> Transaction {
    Transaction {
        from: bytes(&v["from"]),
        to: bytes(&v["to"]),
        amount: v["amount"].as_str().unwrap().parse().unwrap(),
        nonce: Nonce::new(v["nonce"].as_i64().unwrap()).unwrap(),
        ou: v["ou"].as_str().unwrap().parse().unwrap(),
        timestamp: f64::from_bits(
            u64::from_str_radix(v["timestamp_bits"].as_str().unwrap(), 16).unwrap(),
        ),
        signature: bytes(&v["signature"]),
        public_key: optional(&v["public_key"]),
        message: optional(&v["message"]),
        encrypted_data: optional(&v["encrypted"]),
        op_type: OpType::parse(v["op"].as_str().unwrap().as_bytes()).unwrap(),
    }
}
fn hash(tx: &Transaction) -> Vec<u8> {
    hex::encode(tx.hash().unwrap()).into_bytes()
}
fn public(seed: u8) -> Vec<u8> {
    STANDARD
        .encode(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
        .into_bytes()
}
fn drop(d: &DropRecord) -> Value {
    json!([
        b(&d.hash),
        match d.reason {
            DropReason::Evicted => "evicted",
            DropReason::Expired => "expired",
        },
        d.detail
    ])
}
struct Effects {
    events: Vec<Value>,
    refuse: Option<String>,
    invalidated: Vec<Vec<u8>>,
}
impl Host for Effects {
    fn preverify(&mut self, tx: &Transaction, pool: &Pool) -> Result<(), String> {
        let h = hash(tx);
        assert!(pool.find(&h).is_some());
        self.events.push(json!(["preverify", b(h)]));
        assert_ne!(
            self.refuse.as_deref(),
            Some("__panic__"),
            "fixture worker panic"
        );
        self.refuse.clone().map_or(Ok(()), Err)
    }
    fn save_drops(&mut self, drops: &[DropRecord]) {
        self.events
            .push(json!(["drops", drops.iter().map(drop).collect::<Vec<_>>()]));
    }
    fn invalidate(&mut self, hash: &[u8]) {
        self.invalidated.push(hash.to_vec());
    }
    fn changed(&mut self, _: &Pool) {}
    fn accepted(&mut self, tx: &Transaction, pool: &Pool) {
        assert!(pool.find(&hash(tx)).is_some());
    }
}
fn result(value: Result<Vec<u8>, admission::Error>) -> Value {
    match value {
        Ok(h) => json!({"ok":b(h)}),
        Err(admission::Error::Rejected(e)) => json!({"error":[e.tag,e.reason]}),
        Err(e) => panic!("unexpected operational failure: {e}"),
    }
}
fn mode(v: &Value) -> RuleMode {
    if *v == true {
        RuleMode::Active
    } else {
        RuleMode::Prior
    }
}
fn num(v: &Value) -> Nonce {
    Nonce::new(v.as_i64().unwrap()).unwrap()
}
#[test]
fn native_rpc_and_peer_intake_match_normalization_replacement_and_worker_refusal() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/staging-intake.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/staging-intake-oracle.ml"
        )))
    );
    assert_eq!(fixture["instrumentation"].as_object().unwrap().len(), 2);
    for (path, v) in fixture["instrumentation"].as_object().unwrap() {
        assert_eq!(v["original_sha256"], source["files"][path]);
        assert_eq!(
            v["prefix_sha256"],
            hex::encode(Sha256::digest(v["prefix"].as_str().unwrap().as_bytes()))
        );
    }
    let mut worker_refusals = 0;
    let mut accepted = 0;
    for (i, c) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let v = &c["input"];
        let base: i64 = c["base"].as_str().unwrap().parse().unwrap();
        let txs = c["expected"]["prepared"]
            .as_array()
            .unwrap()
            .iter()
            .map(prepared)
            .collect::<Vec<_>>();
        let mut accounts = BTreeMap::new();
        for a in v["accounts"].as_array().unwrap() {
            if a["exists"] == false {
                continue;
            }
            let key = public(a["seed"].as_u64().unwrap() as u8);
            let address = address_from_public_key(&key);
            let public_key = match a["key"].as_str().unwrap() {
                "none" => None,
                "wrong" => Some(public(99)),
                _ => Some(key),
            };
            accounts.insert(
                address,
                Account {
                    balance: a["balance"].as_str().unwrap().parse().unwrap(),
                    nonce: num(&a["nonce"]),
                    public_key,
                    ..Account::default()
                },
            );
        }
        let ledger = Ledger::from_accounts(accounts).unwrap();
        let mut pool = Pool::default();
        pool.preview(preview::Message::Check(Some(base), b"reset".to_vec()))
            .unwrap();
        for (k, s) in v["steps"].as_array().unwrap().iter().enumerate() {
            let now: f64 = s["now"].as_str().unwrap().parse().unwrap();
            let head = base + s["head"].as_str().unwrap().parse::<i64>().unwrap();
            let duty = (!s["duty"].is_null()).then(|| {
                (
                    s["duty"]["head"].as_str().unwrap().parse().unwrap(),
                    mode(&s["duty"]["active"]),
                )
            });
            let rules = Rules {
                bft: s["bft"] == true,
                profile: Profile::from_values(
                    Some(s["profile"].as_str().unwrap().as_bytes()),
                    None,
                    None,
                ),
                compute: mode(&s["compute"]),
                settle: mode(&s["settle"]),
                proof: mode(&s["proof"]),
                duty,
                queue_head: Some(head),
                stealth_minimum: s["minimum"].as_str().unwrap().parse::<BigInt>().unwrap(),
            };
            let tx = &txs[s["index"].as_u64().unwrap() as usize];
            let h = hash(tx);
            let mut host = Effects {
                events: vec![],
                refuse: s["refuse"].as_str().map(str::to_owned),
                invalidated: vec![],
            };
            let out = match s["route"].as_str().unwrap() {
                "hold" => json!(pool
                    .preview(preview::Message::Hold {
                        head,
                        epoch: head + 1,
                        hash: h
                    })
                    .err()),
                "refuse" => json!(pool
                    .preview(preview::Message::Refuse {
                        head,
                        epoch: head + 1,
                        hash: h
                    })
                    .err()),
                "clear" => {
                    pool.clear();
                    Value::Null
                }
                "stage" => result(
                    intake::stage(&mut pool, tx, &ledger, &rules, &mut host, &|| now)
                        .map_err(|e| admission::Error::Rejected(intake::staging_error(e))),
                ),
                _ => result(intake::submit(
                    &mut pool,
                    tx,
                    &ledger,
                    &rules,
                    &Rpc {
                        now,
                        max_drift: 300.,
                        observer: s["observer"] == true,
                        preverify_capacity: true,
                        preverify_pending: Nonce::default(),
                        preverify_maximum: Nonce::new(6).unwrap(),
                        nonce_window: num(&s["window"]),
                    },
                    &mut host,
                    &|| now,
                )),
            };
            if out.get("ok").is_some() {
                accepted += 1;
            }
            if host.refuse.is_some() && host.events.iter().any(|e| e[0] == "preverify") {
                worker_refusals += 1;
                assert_eq!(host.invalidated.last(), Some(&hash(tx)));
                assert!(pool.find(&hash(tx)).is_none());
            }
            let senders = txs
                .iter()
                .map(|tx| tx.from.as_slice())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|a| {
                    json!([
                        b(a),
                        pool.virtual_balance(a).map(ToString::to_string),
                        pool.expected_nonce(a).get()
                    ])
                })
                .collect::<Vec<_>>();
            let actual = json!({"result":out,"events":host.events,"all":pool.all().map(|tx|b(hash(tx))).collect::<Vec<_>>(),"total":pool.total_ou().to_string(),"senders":senders,"drops":pool.drops().map(drop).collect::<Vec<_>>()});
            let expected = &c["expected"]["traces"][k];
            if actual != *expected {
                for (field, value) in actual.as_object().unwrap() {
                    assert_eq!(
                        value, &expected[field],
                        "native intake case {i} step {k} field {field}: {s}"
                    );
                }
            }
        }
    }
    assert!(accepted > 50);
    assert!(worker_refusals > 0);
}

#[test]
fn worker_panic_refunds_new_reservation_without_restoring_replaced_transaction() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/staging-intake.json")).unwrap();
    let tx = prepared(&fixture["cases"][0]["expected"]["prepared"][0]);
    let ledger = Ledger::from_accounts(BTreeMap::from([(
        tx.from.clone(),
        Account {
            balance: 1_000_000.into(),
            public_key: tx.public_key.clone(),
            ..Account::default()
        },
    )]))
    .unwrap();
    let rules = Rules {
        bft: true,
        profile: Profile::default(),
        compute: RuleMode::Prior,
        settle: RuleMode::Prior,
        proof: RuleMode::Active,
        duty: None,
        queue_head: Some(1),
        stealth_minimum: 5000.into(),
    };
    let mut host = Effects {
        events: vec![],
        refuse: None,
        invalidated: vec![],
    };
    let mut pool = Pool::default();
    let old = intake::stage(&mut pool, &tx, &ledger, &rules, &mut host, &|| 1000.).unwrap();
    let mut replacement = tx;
    replacement.ou = 1100.into();
    replacement.signature = STANDARD
        .encode(
            SigningKey::from_bytes(&[42; 32])
                .sign(&replacement.signing_bytes().unwrap())
                .to_bytes(),
        )
        .into_bytes();
    let new = hash(&replacement);
    host.refuse = Some("__panic__".into());
    let error = intake::stage(&mut pool, &replacement, &ledger, &rules, &mut host, &|| {
        1000.
    })
    .unwrap_err();
    assert!(error.starts_with("pre_verify_unavailable"));
    assert!(pool.is_empty());
    assert_eq!(pool.total_ou(), &BigInt::from(0));
    assert_eq!(
        pool.virtual_balance(&replacement.from),
        Some(&BigInt::from(1_000_000))
    );
    assert_eq!(pool.expected_nonce(&replacement.from).get(), 2);
    assert_eq!(
        pool.dropped(&old).unwrap().detail,
        "replaced by higher fee-rate"
    );
    assert_eq!(host.invalidated, vec![new]);
}

#[test]
fn canonical_account_changes_rebase_pending_reservations_before_intake() {
    let native: Value = serde_json::from_str(include_str!("fixtures/staging-rebase.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(native["upstream_commit"], source["upstream_commit"]);
    assert_eq!(native["source_sha256"], source["files"]);
    assert_eq!(native["candidate_fix"], true);
    assert_eq!(
        native["instrumentation"]["lib/core/tx_staging.ml"]["replacements"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/staging-intake.json")).unwrap();
    let mut tx = prepared(&fixture["cases"][0]["expected"]["prepared"][0]);
    let account = |balance, nonce| {
        Ledger::from_accounts(BTreeMap::from([(
            tx.from.clone(),
            Account {
                balance: BigInt::from(balance),
                nonce: Nonce::new(nonce).unwrap(),
                public_key: tx.public_key.clone(),
                ..Account::default()
            },
        )]))
        .unwrap()
    };
    let original = account(5000, 0);
    let committed = account(3999, 1);
    let credited = account(10000, 1);
    let mut rules = Rules {
        bft: true,
        profile: Profile::default(),
        compute: RuleMode::Prior,
        settle: RuleMode::Prior,
        proof: RuleMode::Active,
        duty: None,
        queue_head: Some(1),
        stealth_minimum: 5000.into(),
    };
    let mut pool = Pool::default();
    let mut host = Effects {
        events: vec![],
        refuse: None,
        invalidated: vec![],
    };
    let first = intake::stage(&mut pool, &tx, &original, &rules, &mut host, &|| 1000.).unwrap();
    let sign = |tx: &mut Transaction| {
        tx.signature = STANDARD
            .encode(
                SigningKey::from_bytes(&[42; 32])
                    .sign(&tx.signing_bytes().unwrap())
                    .to_bytes(),
            )
            .into_bytes();
    };
    tx.nonce = Nonce::new(2).unwrap();
    sign(&mut tx);
    intake::stage(&mut pool, &tx, &original, &rules, &mut host, &|| 1000.).unwrap();
    pool.remove_processed(&[first]);
    rules.queue_head = Some(2);
    tx.nonce = Nonce::new(3).unwrap();
    tx.amount = 2999.into();
    sign(&mut tx);
    let refusal =
        intake::stage(&mut pool, &tx, &committed, &rules, &mut host, &|| 1000.).unwrap_err();
    let expected = native["cases"][0]["expected"]
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(refusal, expected["result"]["error"].as_str().unwrap());
    assert_eq!(
        pool.virtual_balance(&tx.from).unwrap().to_string(),
        expected["state"]["senders"][0]["balance"].as_str().unwrap()
    );
    assert_eq!(pool.len(), 1);
    assert!(pool.find(&hash(&tx)).is_none());
    // Canonical credits likewise become available; a stale cache must not strand them.
    rules.queue_head = Some(3);
    intake::stage(&mut pool, &tx, &credited, &rules, &mut host, &|| 1000.).unwrap();
    assert_eq!(pool.virtual_balance(&tx.from), Some(&5000.into()));
}
