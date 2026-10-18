//! Actual JSON-RPC -> Submission -> Native -> pending ownership, followed by
//! ordered proposal execution and a real signed QC. The parent module supplies
//! funded local keys, the isolated application graph and post-genesis deployment;
//! it does not replace this intake path or fabricate a Circle receipt.
//!
//! Queue eligibility follows adopted bin/octra_node.ml and
//! lib/core/preverify_worker.ml: Circle calls/cells are not private queue jobs.
//! Their state/proof binding remains in the ordered proposal stage.
use super::*;
use crate::rpc::{http, Submission};
use octra_node_protocol::{
    network::{endpoint::Endpoint, session::Timeouts, swarm, swarm::Swarm},
    preverify_receipt::{Binding, Receipt},
    transaction_outcome,
};
use octra_node_runtime::{circle_store, staging::Pool};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{net::TcpListener, task::JoinHandle};

struct Rpc {
    url: String,
    pending: Arc<executor::Pending>,
    task: Option<JoinHandle<()>>,
}
impl Drop for Rpc {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl Rpc {
    async fn open(fixture: &Fixture, native: executor::Native) -> Self {
        let endpoint = Endpoint {
            host: b"127.0.0.1".to_vec(),
            port: 1,
        };
        // No peer or mock intake: announce has nobody to notify, while HTTP
        // still uses the real owned Submission and native queue worker.
        let swarm = Swarm::new(
            swarm::Config {
                chain_id: CHAIN.as_bytes().to_vec(),
                node_address: payment_host::address(1).into_bytes(),
                config_hash: vec![1; 32],
                binary_hash: vec![0; 32],
                require_binary_hash: false,
                upgrade: None,
                profiles: vec![],
                allowed_public_keys: validators()
                    .validators
                    .iter()
                    .map(|validator| validator.pubkey.clone())
                    .collect(),
                bootstrap: vec![],
                maximum_validators: 4,
                advertised: endpoint,
                timeouts: Timeouts::default(),
                head: Arc::new(|| (0, [0; 32])),
            },
            payment_host::key(1),
        )
        .unwrap();
        let pending = Arc::new(executor::Pending::new(Pool::default()));
        let submission = Arc::new(Submission {
            node: fixture.node.clone(),
            executor: native,
            pending: pending.clone(),
            swarm,
            policy: Policy {
                protocol: fixture.protocol,
                genesis_time: Some(GENESIS_SECONDS),
            },
            address: payment_host::address(1).into_bytes(),
            compute: None,
            vpn_program: None,
            status: None,
            tokens: None,
            staging_notify: Arc::new(|| {}),
            history_epoch_limit: 100,
            fees: octra_node_protocol::submit_rpc::Fees::default(),
            http: Arc::new(http::Service::new(
                fixture.directory.path().to_owned(),
                Some(
                    &octra_node_protocol::consensus::profile::Settings::from_values(
                        std::collections::BTreeMap::new(),
                    )
                    .unwrap(),
                ),
                CHAIN.as_bytes().to_vec(),
                payment_host::key(1).verifying_key().to_bytes().to_vec(),
            )),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/rpc", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, submission.router()).await.unwrap();
        });
        Self {
            url,
            pending,
            task: Some(task),
        }
    }
    async fn submit(&self, tx: &Transaction) -> Value {
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(&self.url)
            .timeout(Duration::from_secs(20))
            .json(&json!({
                "jsonrpc":"2.0", "id":17, "method":"octra_submit",
                "params":[serde_json::from_slice::<Value>(&tx.to_json_bytes().unwrap()).unwrap()]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        response.json().await.unwrap()
    }
    async fn close(mut self) {
        let task = self.task.take().unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}

fn sign_current(mut tx: Transaction, who: u8) -> Transaction {
    // RPC drift is the actual host wall clock. Authenticated epoch time remains
    // the parent fixture's explicit local clock; intake does not rewrite either.
    tx.timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    tx.signature = STANDARD
        .encode(
            payment_host::key(who)
                .sign(&tx.signing_bytes().unwrap())
                .to_bytes(),
        )
        .into_bytes();
    tx
}
fn spawn(fixture: &Fixture) -> Transaction {
    sign_current(
        fixture.transaction(
            11,
            &fixture.factory,
            OpType::CircleCall,
            json!([STANDARD.encode(
                serde_json::to_vec(&super::super::circle_tests::payload(&fixture.payment_code))
                    .unwrap()
            )]),
            0,
            b"deploy_payments".to_vec(),
        ),
        11,
    )
}
fn account(fixture: &Fixture, who: u8) -> Account {
    account_store::load(
        &StateBatch::from_snapshot(fixture.node.snapshot().unwrap().state().clone()),
        payment_host::address(who).as_bytes(),
    )
    .unwrap()
    .unwrap()
}
async fn draft(fixture: &Fixture) -> Arc<crate::proposal::Draft> {
    Arc::new(
        fixture
            .node
            .proposal_draft(
                &fixture.graph,
                Policy {
                    protocol: fixture.protocol,
                    genesis_time: Some(GENESIS_SECONDS),
                },
                payment_host::address(1).as_bytes(),
                fixture.now + 10.,
            )
            .await
            .unwrap(),
    )
}
fn assert_accepted(response: &Value, tx: &Transaction) {
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(response["result"]["status"], "accepted");
    assert_eq!(
        response["result"]["tx_hash"],
        hex::encode(tx.hash().unwrap())
    );
}

#[tokio::test]
async fn signed_circle_rpc_queues_without_execution_then_qc_publishes_bound_spawn() {
    let mut fixture = Box::pin(Fixture::with_application(None, Application::Circle)).await;
    let rpc = Rpc::open(&fixture, fixture.native.clone()).await;
    let tx = spawn(&fixture);
    let hash = hex::encode(tx.hash().unwrap());
    let before = fixture.node.snapshot().unwrap();
    let sender = account(&fixture, 11);
    assert_accepted(&rpc.submit(&tx).await, &tx);
    assert_eq!(rpc.pending.transactions().unwrap(), vec![tx.clone()]);
    assert_eq!(fixture.node.snapshot().unwrap().head(), before.head());
    assert_eq!(
        fixture.node.snapshot().unwrap().state().root().unwrap(),
        before.state().root().unwrap()
    );
    assert_eq!(
        fixture
            .node
            .snapshot()
            .unwrap()
            .state()
            .child_count(&[b"circles"]),
        before.state().child_count(&[b"circles"])
    );
    assert_eq!(account(&fixture, 11), sender);
    assert!(fixture
        .node
        .store
        .vm_receipt(before.head(), hash.as_bytes())
        .await
        .unwrap()
        .is_none());

    let built = fixture
        .native
        .build_proposal(draft(&fixture).await, rpc.pending.transactions().unwrap())
        .await
        .unwrap();
    assert!(built.refused().is_empty() && built.held().is_empty());
    assert_eq!(built.execution().transactions.len(), 1);
    let bindings = built
        .bundle()
        .receipts_json
        .iter()
        .filter_map(|raw| match transaction_outcome::parse(raw, true).unwrap() {
            transaction_outcome::Item::Preverify(raw) => Some(Receipt::parse(&raw).unwrap()),
            transaction_outcome::Item::Rejection(_) => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(bindings.len(), 1);
    assert!(bindings[0].ok);
    assert_eq!(bindings[0].tx_hash, hash.as_bytes());
    let Binding::Circle(binding) = &bindings[0].binding else {
        panic!("ordered Circle execution omitted its state/code binding");
    };
    assert_eq!(
        binding.snapshot_hash,
        octra_node_protocol::preverify_receipt::state_hash(before.head().ledger_root.as_bytes())
    );
    let info = circle_store::info(before.state(), fixture.factory.as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(binding.circle_id, fixture.factory.as_bytes());
    assert_eq!(binding.code_hash, info.code_hash);
    assert_eq!(binding.stable_root, info.stable_root);
    let expected: Value = serde_json::from_slice(&built.execution().vm_receipts[&hash]).unwrap();
    assert_eq!(expected["success"], true);
    let child = expected["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["event"] == "PaymentsCircleDeployed")
        .unwrap()["values"][0]
        .as_str()
        .unwrap();
    assert_ne!(child, fixture.program);
    assert!(circle_store::info(before.state(), child.as_bytes())
        .unwrap()
        .is_none());
    assert!(
        circle_store::info(fixture.node.snapshot().unwrap().state(), child.as_bytes())
            .unwrap()
            .is_none()
    );
    assert_eq!(account(&fixture, 11), sender);

    let receipt = fixture.publish(rpc.pending.transactions().unwrap()).await;
    assert_eq!(receipt, expected);
    let after = fixture.node.snapshot().unwrap();
    assert_eq!(
        after.head().cursor.epoch.0,
        before.head().cursor.epoch.0 + 1
    );
    assert_eq!(account(&fixture, 11).nonce, sender.nonce.successor());
    let child_info = circle_store::info(after.state(), child.as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(child_info.owner, fixture.factory.as_bytes());
    assert_eq!(
        after
            .state()
            .get(&[b"circles", child.as_bytes(), b"origin", b"owner_mode"]),
        Some(b"parent".as_slice())
    );
    let retained: Value = serde_json::from_slice(
        &fixture
            .node
            .store
            .vm_receipt(after.head(), hash.as_bytes())
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(retained, expected);
    rpc.close().await;
    fixture.node.shutdown().await.unwrap();
}

fn configured(fixture: &Fixture, profile: Profile) -> executor::Native {
    executor::Native::new(
        executor::Config {
            graph: fixture.graph.clone(),
            protocol: fixture.protocol,
            profile,
            payload: octra_node_protocol::transaction_payload::Limits::default(),
            bundle: executor::Limits::new(128, 50_000_000, 10_000_000_000_u64.into()),
            validators: octra_node_protocol::validator::policy::Policy::Inactive,
            emission: epoch_footer::Policy {
                emission_guard: true,
                schedule: octra_node_protocol::emission::Schedule::Inactive,
                legacy_total: None,
            },
            sender_key_activation: Some(0),
            private_result_activation: 0,
            max_fhe: 32,
            max_stealth: 32,
            max_multi_exec_calls: 8,
            ready_max_lag: 10,
            pvac_dir: fixture.directory.path().join("unused-pvac"),
            migration: None,
        },
        circle_host::runtime(),
        fixture.node.history(),
    )
    .unwrap()
}

#[tokio::test]
async fn circle_rpc_keeps_signature_profile_resource_nonce_and_lease_guards() {
    let fixture = Box::pin(Fixture::with_application(None, Application::Circle)).await;
    let rpc = Rpc::open(&fixture, fixture.native.clone()).await;
    let before = fixture.node.snapshot().unwrap();
    let sender = account(&fixture, 11);
    let tx = spawn(&fixture);
    let mut forged = tx.clone();
    forged.signature = STANDARD.encode([0; 64]).into_bytes();
    assert_eq!(rpc.submit(&forged).await["error"]["code"], 101);
    let mut oversized = tx.clone();
    oversized.ou = 20_000_001.into();
    oversized = sign_current(oversized, 11);
    let refusal = rpc.submit(&oversized).await;
    assert_eq!(refusal["error"]["code"], 105, "{refusal}");
    assert!(refusal.to_string().contains("circle resource limit: ou"));
    let mut invalid_params = tx.clone();
    invalid_params.message = Some(serde_json::to_vec(&json!(["<script>"])).unwrap());
    invalid_params = sign_current(invalid_params, 11);
    let refusal = rpc.submit(&invalid_params).await;
    assert_eq!(refusal["error"]["code"], 105, "{refusal}");
    assert!(refusal
        .to_string()
        .contains("contract call params contain invalid characters"));
    let mut used_nonce = tx.clone();
    used_nonce.nonce = sender.nonce;
    used_nonce = sign_current(used_nonce, 11);
    assert_eq!(rpc.submit(&used_nonce).await["error"]["code"], 102);

    let disabled = Rpc::open(&fixture, configured(&fixture, Profile::default())).await;
    assert_eq!(disabled.submit(&tx).await["error"]["code"], 116);
    assert!(disabled.pending.transactions().unwrap().is_empty());
    disabled.close().await;

    let captured = Arc::new(
        fixture
            .node
            .admission_capture(
                &fixture.graph,
                Policy {
                    protocol: fixture.protocol,
                    genesis_time: Some(GENESIS_SECONDS),
                },
                payment_host::address(1).as_bytes(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64(),
            )
            .await
            .unwrap(),
    );
    fixture.node.suspend("RPC lease regression");
    assert_eq!(rpc.submit(&tx).await["error"]["code"], 110);
    assert!(fixture.node.resume().await.unwrap());
    assert!(fixture
        .native
        .submit_native(captured, &rpc.pending, tx.clone())
        .await
        .is_err());
    assert!(rpc.pending.transactions().unwrap().is_empty());
    assert_eq!(fixture.node.snapshot().unwrap().head(), before.head());
    assert_eq!(
        fixture.node.snapshot().unwrap().state().root().unwrap(),
        before.state().root().unwrap()
    );
    assert_eq!(account(&fixture, 11), sender);
    assert_accepted(&rpc.submit(&tx).await, &tx);
    rpc.close().await;
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn circle_cell_rpc_admission_is_not_a_proposal_proof_or_state_transition() {
    let fixture = Box::pin(Fixture::with_application(None, Application::Circle)).await;
    let before = fixture.node.snapshot().unwrap();
    let sender = account(&fixture, 11);
    for operation in [OpType::CircleBalanceCellPut, OpType::CircleRegisterCellPut] {
        let rpc = Rpc::open(&fixture, fixture.native.clone()).await;
        let mut tx = fixture.transaction(11, &fixture.factory, operation, json!({}), 0, vec![]);
        // Structurally admissible signed envelope, deliberately no ciphertext
        // or proof. The actual proposal prove_cell must reject it, not mint a
        // receipt because queue intake accepted the transaction.
        tx.encrypted_data = None;
        tx = sign_current(tx, 11);
        assert_accepted(&rpc.submit(&tx).await, &tx);
        assert_eq!(rpc.pending.transactions().unwrap(), vec![tx.clone()]);
        let Err(executor::ProposalError::Invalid(reason)) = fixture
            .native
            .build_proposal(draft(&fixture).await, rpc.pending.transactions().unwrap())
            .await
        else {
            panic!("missing cell proof did not fail exact proposal preverification");
        };
        assert_eq!(reason, "local_preverify_mismatch");
        assert!(fixture
            .node
            .store
            .vm_receipt(before.head(), hex::encode(tx.hash().unwrap()).as_bytes())
            .await
            .unwrap()
            .is_none());
        assert_eq!(fixture.node.snapshot().unwrap().head(), before.head());
        assert_eq!(
            fixture.node.snapshot().unwrap().state().root().unwrap(),
            before.state().root().unwrap()
        );
        assert_eq!(account(&fixture, 11), sender);
        rpc.close().await;
    }
    fixture.node.shutdown().await.unwrap();
}
