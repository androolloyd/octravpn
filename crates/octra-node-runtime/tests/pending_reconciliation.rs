use octra_node_protocol::consensus::{pending_log::PendingCommit, Bytes, Error};
use octra_node_runtime::{
    consensus_recovery::Restored,
    pending_reconciliation::{self as recovery, Host},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{cell::Cell, fs, path::PathBuf};
struct Fixture {
    input: Value,
    head: i64,
    pending: Vec<PendingCommit>,
    reads: Cell<i64>,
    calls: Vec<Value>,
}
impl Fixture {
    fn new(input: &Value) -> Self {
        Self {
            input: input.clone(),
            head: input["head"].as_i64().unwrap(),
            reads: Cell::new(0),
            calls: vec![],
            pending: input["pending"]
                .as_array()
                .unwrap()
                .iter()
                .map(|j| PendingCommit {
                    epoch_id: j["epoch"].as_i64().unwrap(),
                    round: j["round"].as_i64().unwrap(),
                    proposed_state_root: j["root"].as_str().unwrap().as_bytes().to_vec(),
                    proposal_id: vec![],
                    txid_hi: 0,
                    ts: 0.,
                    validator_addr: vec![],
                    proposal_b64: None,
                    vote_b64: None,
                    tx_hashes: vec![],
                    txs_json: vec![],
                    receipts_json: vec![],
                })
                .collect(),
        }
    }
    fn fault(&self, name: &str) -> Result<(), Error> {
        if self.input["fault"] == name {
            Err(format!("Failure(\"fixture {name}\")").into())
        } else {
            Ok(())
        }
    }
}
#[async_trait::async_trait]
impl Host for Fixture {
    fn head_epoch(&self) -> Result<i64, Error> {
        self.fault("head")?;
        Ok(self.head)
    }
    fn pending(&self) -> Result<Vec<PendingCommit>, Error> {
        self.reads.set(self.reads.get() + 1);
        if self.input["read_fault"] == self.reads.get() {
            Err("fixture read".into())
        } else {
            Ok(self.pending.clone())
        }
    }
    fn restore(&mut self, p: &PendingCommit) -> Restored {
        self.calls.push(json!(["restore", p.epoch_id, p.round]));
        match self.input["restore"].as_str().unwrap() {
            "lock" => Restored::Lock,
            "invalid" => Restored::Invalid("invalid record".into()),
            _ => Restored::Legacy,
        }
    }
    async fn query(&mut self, epoch: i64) -> Result<Vec<Option<Bytes>>, Error> {
        self.calls.push(json!(["query", epoch]));
        self.fault("query")?;
        Ok(self.input["responses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().and_then(|s| recovery::root(s.as_bytes())))
            .collect())
    }
    async fn catchup(&mut self, epoch: i64) -> Result<(), Error> {
        self.calls
            .push(json!(["catchup", epoch, "pending_commit_recovery"]));
        self.fault("catchup")?;
        self.head = self.input["after"].as_i64().unwrap();
        Ok(())
    }
    fn delete(&mut self, epoch: i64, round: i64) -> Result<(), Error> {
        self.calls.push(json!(["delete", epoch, round]));
        self.fault("delete")?;
        self.pending
            .retain(|p| p.epoch_id != epoch || p.round != round);
        Ok(())
    }
}
#[tokio::test]
async fn native_startup_recovery_holds_restores_queries_and_deletes_in_order() {
    let f: Value =
        serde_json::from_str(include_str!("fixtures/pending-reconciliation.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(f["upstream_commit"], source["upstream_commit"]);
    assert_eq!(f["source_sha256"], source["files"]);
    assert_eq!(f["instrumentation"], json!({}));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (field, path) in [
        (
            "oracle_sha256",
            "scripts/node-port/pending-reconciliation-oracle.ml",
        ),
        ("runner_sha256", "scripts/node-port/native-oracle.py"),
    ] {
        assert_eq!(
            f[field],
            hex::encode(Sha256::digest(fs::read(root.join(path)).unwrap()))
        );
    }
    for (index, case) in f["cases"].as_array().unwrap().iter().enumerate() {
        let j = &case["input"];
        let mut host = Fixture::new(j);
        let result = match recovery::run_once(
            &mut host,
            j["validators"].as_i64().unwrap(),
            j["quorum"].as_i64().unwrap(),
        )
        .await
        {
            Ok(v) => json!(v),
            Err(e) => json!(e.to_string()),
        };
        let actual = json!({"result":result,"calls":host.calls,"head":host.head,"reads":host.reads.get(),"pending":host.pending.iter().map(|p|vec![p.epoch_id,p.round]).collect::<Vec<_>>()});
        assert_eq!(
            actual, case["expected"],
            "native recovery flow {index}: {j}"
        );
    }
}
