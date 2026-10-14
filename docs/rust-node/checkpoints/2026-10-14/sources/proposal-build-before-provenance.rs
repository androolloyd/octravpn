use octra_node_protocol::{
    transaction::{Nonce, OpType, Transaction},
    transaction_outcome,
};
use octra_node_runtime::{
    epoch_execution::{Artifacts, Refusal, Rejected},
    execution::Error,
    proposal_build::{self, Failure, Host, Preview, Selection},
};
use serde_json::{json, Value};

fn transaction(j: &Value) -> Transaction {
    Transaction {
        from: j["from"].as_str().unwrap().as_bytes().to_vec(),
        to: b"oct_receiver".to_vec(),
        amount: 0.into(),
        nonce: Nonce::new(j["nonce"].as_i64().unwrap()).unwrap(),
        ou: 1000.into(),
        timestamp: 1.,
        signature: b"sig".to_vec(),
        public_key: Some(b"pub".to_vec()),
        message: Some(j["id"].to_string().into_bytes()),
        encrypted_data: None,
        op_type: OpType::Standard,
    }
}
fn label(tx: &Transaction) -> usize {
    std::str::from_utf8(tx.message.as_deref().unwrap())
        .unwrap()
        .parse()
        .unwrap()
}
fn labels(txs: &[Transaction]) -> Vec<usize> {
    txs.iter().map(label).collect()
}
struct Script<'a> {
    input: &'a Value,
    live: bool,
    requests: Vec<Vec<usize>>,
    refused: Vec<usize>,
    held: Vec<usize>,
}
impl Host for Script<'_> {
    type Value = ();
    fn current(&self) -> bool {
        self.live
    }
    fn select(&mut self, inputs: &[Transaction]) -> Result<Selection, Error> {
        Ok(Selection {
            inputs: inputs.to_vec(),
            selected: inputs
                .iter()
                .take(self.input["cap"].as_u64().unwrap().max(1) as usize)
                .cloned()
                .collect(),
        })
    }
    fn preview(&mut self, inputs: &[Transaction]) -> Result<Preview<()>, Failure> {
        let response = &self.input["responses"][self.requests.len()];
        self.requests.push(labels(inputs));
        if response["revoke"] == true {
            self.live = false;
        }
        if response["fail"] == true {
            return Err(Error("script failure".into()).into());
        }
        if response["unknown_resource"] == true {
            return Err(Failure::Exhausted([b'x'; 32]));
        }
        let status = |tx: &Transaction| response["status"][label(tx)].as_str().unwrap_or("ok");
        if let Some(tx) = inputs.iter().find(|tx| status(tx) == "exhausted") {
            return Err(Failure::Exhausted(tx.hash().unwrap()));
        }
        let mut artifacts = Artifacts {
            transaction_count: inputs.len(),
            ..Default::default()
        };
        for (input_index, tx) in inputs.iter().enumerate() {
            match status(tx) {
                "ok" => artifacts.confirmed.push((input_index, 0)),
                verdict => artifacts.rejected.push(Rejected {
                    input_index,
                    charged: verdict == "paid",
                    refusal: Refusal {
                        error_type: match verdict {
                            "unavailable" => b"vm_transition_incomplete".to_vec(),
                            "exception" => b"vm_transition_exception".to_vec(),
                            _ => b"bad".to_vec(),
                        },
                        reason: b"rejected".to_vec(),
                    },
                }),
            }
        }
        if response["duplicate"] == true {
            artifacts.confirmed.extend(artifacts.confirmed.clone());
        }
        Ok(Preview {
            artifacts,
            value: (),
        })
    }
    fn refuse(&mut self, tx: &Transaction) {
        self.refused.push(label(tx));
    }
    fn hold(&mut self, tx: &Transaction) {
        self.held.push(label(tx));
    }
}

#[test]
fn native_ordered_recovery_traces_and_rejection_bytes() {
    let report: Value = serde_json::from_str(include_str!("fixtures/proposal-build.json")).unwrap();
    let mut holds = 0;
    let mut six = 0;
    for case in report["cases"].as_array().unwrap() {
        let input = &case["input"];
        let mut script = Script {
            input,
            live: true,
            requests: vec![],
            refused: vec![],
            held: vec![],
        };
        let txs = input["txs"]
            .as_array()
            .unwrap()
            .iter()
            .map(transaction)
            .collect::<Vec<_>>();
        let result = proposal_build::build(&mut script, &txs);
        let (confirmed, receipts) = match &result {
            Ok(built) => (
                json!(labels(&built.confirmed)),
                json!(transaction_outcome::encode(&[], &built.rejections)
                    .unwrap()
                    .iter()
                    .map(|r| std::str::from_utf8(r).unwrap())
                    .collect::<Vec<_>>()),
            ),
            Err(_) => (Value::Null, Value::Null),
        };
        let actual = json!({"built":result.is_ok(), "requests":script.requests, "refused":script.refused, "held":script.held, "confirmed":confirmed, "receipts":receipts});
        assert_eq!(actual, case["expected"], "{}", input["name"]);
        assert!(script.requests.len() <= 6);
        holds += usize::from(!script.held.is_empty());
        six += usize::from(script.requests.len() == 6);
    }
    assert!(holds > 0 && six > 0, "reserve budget was not exercised");
}
