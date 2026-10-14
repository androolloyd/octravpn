use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use octra_node_protocol::{
    network::transaction_gossip::Message,
    oce1::Writer,
    transaction::{address_from_public_key, Nonce, OpType, Transaction},
};
use octra_node_runtime::p2p_transaction::{self, Effect, Host, Ingress, Rules, Verdict};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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
struct Queue {
    pool: BTreeMap<Vec<u8>, Transaction>,
    now: f64,
    key: String,
    refuse: bool,
    effects: Vec<Value>,
    attempts: Vec<Value>,
}
impl Host for Queue {
    fn now(&self) -> f64 {
        self.now
    }
    fn has(&self, h: &[u8]) -> bool {
        self.pool.contains_key(h)
    }
    fn find(&self, h: &[u8]) -> Option<Transaction> {
        self.pool.get(h).cloned()
    }
    fn sender_key(&self, tx: &Transaction) -> Option<Vec<u8>> {
        match self.key.as_str() {
            "none" => None,
            "account" => Some(public(42)),
            "wrong" => Some(public(99)),
            _ => tx.public_key.clone(),
        }
    }
    fn add(&mut self, tx: Transaction) -> Result<Vec<u8>, String> {
        self.attempts.push(b(tx.to_json_bytes().unwrap()));
        if self.refuse {
            return Err("queue refused".into());
        }
        let h = hash(&tx);
        self.pool.insert(h.clone(), tx);
        Ok(h)
    }
    fn emit(&mut self, e: Effect) {
        self.effects.push(match e {
            Effect::Send(p) => json!(["send", b(p)]),
            Effect::Broadcast(p) => json!(["broadcast", b(p)]),
            Effect::ReportBad(r) => json!(["bad", r]),
            Effect::Close => json!(["close", null]),
        });
    }
}
fn payload(s: &Value, txs: &[Transaction]) -> Vec<u8> {
    let tx = &txs[s["index"].as_u64().unwrap_or(0) as usize];
    match s["kind"].as_str().unwrap() {
        "raw" => bytes(&s["raw"]),
        "large" => vec![0; s["length"].as_u64().unwrap() as usize],
        "legacy" => {
            let mut w = Writer::new();
            w.put_bytes(&tx.to_json_bytes().unwrap()).unwrap();
            let mut out = w.into_bytes();
            out.extend(bytes(&s["append"]));
            out
        }
        kind @ ("inv" | "get") => {
            let hashes = s["indices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| hash(&txs[i.as_u64().unwrap() as usize]))
                .collect();
            if kind == "inv" {
                Message::Inventory(hashes)
            } else {
                Message::Get(hashes)
            }
            .encode()
            .unwrap()
        }
        _ => Message::Transaction {
            hash: if s["wrong_hash"] == true {
                vec![b'0'; 64]
            } else {
                hash(tx)
            },
            json: tx.to_json_bytes().unwrap(),
        }
        .encode()
        .unwrap(),
    }
}
#[test]
fn native_signed_gossip_receiver_normalizes_throttles_and_emits_queue_effects() {
    let f: Value = serde_json::from_str(include_str!("fixtures/p2p-transaction.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(f["upstream_commit"], source["upstream_commit"]);
    assert_eq!(f["source_sha256"], source["files"]);
    assert_eq!(
        f["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/p2p-transaction-oracle.ml"
        )))
    );
    for (i, c) in f["cases"].as_array().unwrap().iter().enumerate() {
        let v = &c["input"];
        let txs = c["expected"]["prepared"]
            .as_array()
            .unwrap()
            .iter()
            .map(prepared)
            .collect::<Vec<_>>();
        let mut receiver = Ingress::default();
        let mut host = Queue {
            pool: BTreeMap::new(),
            now: 0.,
            key: String::new(),
            refuse: false,
            effects: vec![],
            attempts: vec![],
        };
        for index in v["known"].as_array().unwrap() {
            let tx = txs[index.as_u64().unwrap() as usize].clone();
            host.pool.insert(hash(&tx), tx);
        }
        let rules = Rules {
            max_drift: v["drift"].as_str().unwrap().parse().unwrap(),
            duty: None,
            bft: false,
        };
        for (n, s) in v["steps"].as_array().unwrap().iter().enumerate() {
            host.now = s["now"].as_str().unwrap().parse().unwrap();
            host.key = s["key"].as_str().unwrap().to_owned();
            host.refuse = s["refuse"].as_bool().unwrap();
            host.effects.clear();
            host.attempts.clear();
            receiver
                .receive(b"peer", &payload(s, &txs), rules, &mut host)
                .unwrap();
            let verdict = match p2p_transaction::admit(
                &txs[s["index"].as_u64().unwrap_or(0) as usize],
                host.now,
                rules,
            )
            .unwrap()
            {
                Verdict::Accept => "accept",
                Verdict::InvalidAddress => "address",
                Verdict::InvalidPayload => "payload",
                Verdict::TimestampDrift => "drift",
                Verdict::InvalidSignature => "signature",
            };
            assert_eq!(
                json!({"effects":host.effects,"attempts":host.attempts,"pool":host.pool.keys().map(b).collect::<Vec<_>>(),"verdict":verdict}),
                c["expected"]["traces"][n],
                "native case {i} step {n}: {s}"
            );
        }
    }
    // Fixture identities are deterministic public development keys, not user wallets.
    assert!(address_from_public_key(&public(42)).starts_with(b"oct"));
}
