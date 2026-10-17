//! Positive qualification of the public payment reader through real canonical
//! publication. Fixed validator keys, funded genesis accounts and the public
//! Circle asset are explicit local fixtures. Payment code is deployed after
//! genesis, executed by Native, and published only with signed native QCs.
//! No payment state, epoch clock or Plan lease is fabricated by these tests.
//! This does not qualify public networking, packet forwarding or key custody.
use super::{application_domain, network_domain, Application, Config, Payments, Plan};
use crate::{executor, Host, Node, Status};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::Signer;
use octra_browser::application::UnavailableHost;
use octra_exex::{sqlite::SqliteCheckpoints, ChainIdentity, StateRoot};
use octra_node_protocol::{
    circles::{self, AssetMeta, LocatorMode, MetadataMode, ResourceMode},
    consensus::{
        codec::Wire, hash, policy::Protocol, Finalize, Validator, ValidatorSet, Vote, VoteType,
    },
    contract, epoch_index,
    rules::{Graph, IsolatedApplicationProfile},
    state::Account,
    transaction::{self, OpType, RuleMode, Transaction},
    transaction_policy::{Profile, ReleaseProfile},
};
use octra_node_runtime::{
    account_store,
    canonical::{CanonicalStore, Head, ReliefSource},
    epoch_footer,
    finality::{proposal::Policy, EpochRules, ReceiptRules, ValidatorHistory},
    state_batch::StateBatch,
};
use octravpn_core::{
    parse_native_address,
    payments::{SignedUsage, Tariff, TrafficClass, Usage},
    KeyPair,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::test_host::{self as payment_host, common as circle_host};

const CHAIN: &str = "octra-rust-local-7061796d656e7473";
const GENESIS_SECONDS: f64 = 1_800_000_000.;
const GENESIS_BALANCE: u64 = 1_000_000_000_000;

#[derive(Clone)]
struct Authority {
    chain: ChainIdentity,
}
fn validators() -> ValidatorSet {
    ValidatorSet::unweighted(
        (1..=4)
            .map(|id| Validator {
                address: payment_host::address(id).into_bytes(),
                pubkey: payment_host::key(id).verifying_key().to_bytes().to_vec(),
            })
            .collect(),
    )
}
#[async_trait::async_trait]
impl ValidatorHistory for Authority {
    async fn resolve(
        &self,
        parent: &Head,
        epoch: u64,
        relief: ReliefSource,
    ) -> Result<EpochRules, String> {
        if epoch != parent.cursor.epoch.0 + 1
            || (epoch == 1 && self.chain.genesis_root() != Some(parent.cursor.state_root))
            || matches!(relief, ReliefSource::Committed(Some(_)))
        {
            return Err("local payment fixture authority binding differs".into());
        }
        Ok(EpochRules {
            validators: validators(),
            receipts: ReceiptRules {
                required: false,
                crypto_active: false,
                stealth_minimum: 5000.into(),
            },
            relief: None,
        })
    }
}
impl Host for Authority {
    fn check_views(&self, _: &Head) -> Result<(), String> {
        Ok(())
    }
}

fn genesis(tariff: &Tariff, expires: Option<i64>) -> StateBatch {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    for id in 11..=14 {
        account_store::set(
            &mut state,
            payment_host::address(id).as_bytes(),
            &Account {
                balance: GENESIS_BALANCE.into(),
                public_key: Some(
                    STANDARD
                        .encode(payment_host::key(id).verifying_key().to_bytes())
                        .into_bytes(),
                ),
                ..Account::default()
            },
            RuleMode::Active,
        )
        .unwrap();
    }
    for (key, value) in [
        (b"last_epoch".as_slice(), "0".to_owned()),
        (b"emission_remaining", "0".to_owned()),
        (b"total_supply", (4 * GENESIS_BALANCE).to_string()),
    ] {
        state.set(&[b"meta", key], value.into_bytes()).unwrap();
    }
    let profile = IsolatedApplicationProfile::BftDevnet;
    state
        .set(
            &[b"meta", profile.metadata_key()],
            serde_json::to_vec(&json!({
                "activated_applications":true,
                "chain_id":CHAIN,
                "profile":String::from_utf8(profile.name().to_vec()).unwrap()
            }))
            .unwrap(),
        )
        .unwrap();
    let circle = payment_host::address(14);
    // The existing public Circle fixture supplies canonical metadata and the
    // compiled counter. Its tariff is an immutable, hash-addressed genesis asset.
    circle_host::install_counter(&mut state, circle.as_bytes(), b"0");
    let bytes = tariff.canonical_bytes().unwrap();
    let hash = tariff.hash_hex().unwrap();
    let path = format!("/offers/{hash}/tariff.json");
    let path_key = circles::path_key(path.as_bytes());
    let metadata = AssetMeta {
        path_key: path_key.as_bytes().to_vec(),
        canonical_path: path.as_bytes().to_vec(),
        content_type: b"application/json".to_vec(),
        encoding: b"identity".to_vec(),
        size_bytes: i64::try_from(bytes.len()).unwrap(),
        blob_hash: hash.as_bytes().to_vec(),
        body_mode: ResourceMode::Public,
        plaintext_hash: None,
        key_id: None,
        padding_class: None,
        resource_key: circles::resource_key(circle.as_bytes(), path.as_bytes()).into_bytes(),
        locator_mode: LocatorMode::Path,
        slot_ref: None,
        activate_after_epoch: None,
        expire_after_epoch: expires,
        metadata_mode: MetadataMode::Reveal,
    };
    for (field, value) in [
        (b"meta".as_slice(), metadata.to_json_bytes()),
        (b"body_b64".as_slice(), STANDARD.encode(bytes).into_bytes()),
    ] {
        state
            .set(
                &[
                    b"circles",
                    circle.as_bytes(),
                    b"assets",
                    b"by_hash",
                    path_key.as_bytes(),
                    field,
                ],
                value,
            )
            .unwrap();
    }
    state
        .set(
            &[b"circles", circle.as_bytes(), b"browser", b"mode"],
            b"gateway_allowed".to_vec(),
        )
        .unwrap();
    state
        .set(
            &[b"circles", circle.as_bytes(), b"resources", b"mode"],
            b"public_resources".to_vec(),
        )
        .unwrap();
    state
}

struct Fixture {
    node: Node<Authority>,
    native: executor::Native,
    graph: Graph,
    protocol: Protocol,
    domain: String,
    tariff: Tariff,
    now: f64,
    factory: String,
    program: String,
    application: Application,
    payment_code: Vec<u8>,
    factory_code: Vec<u8>,
    _directory: tempfile::TempDir,
}
impl Fixture {
    async fn new(expires: Option<i64>) -> Self {
        Self::with_application(expires, Application::Program).await
    }
    async fn with_application(expires: Option<i64>, application: Application) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let operator = parse_native_address(&payment_host::address(11)).unwrap();
        let tariff = Tariff::new(
            operator,
            vec![
                TrafficClass {
                    name: "default".into(),
                    rate_ou_per_mib: 10,
                },
                TrafficClass {
                    name: "premium".into(),
                    rate_ou_per_mib: 100,
                },
            ],
            vec![],
        )
        .unwrap();
        let state = genesis(&tariff, expires);
        let (_, index) =
            epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
                .unwrap();
        let root = epoch_index::folded_state_root(
            hex::encode(state.root().unwrap()).as_bytes(),
            hex::encode(index).as_bytes(),
        )
        .unwrap();
        let chain = ChainIdentity::genesis(CHAIN, StateRoot(root));
        let domain = application_domain(&chain, application);
        let (payment_code, factory_code) = match application {
            Application::Program => payment_host::binaries().clone(),
            Application::Circle => (
                STANDARD
                    .decode(
                        super::build::compile(&domain, 200_000_000, payment_host::STAKE).unwrap()
                            ["bytecode"]
                            .as_str()
                            .unwrap(),
                    )
                    .unwrap(),
                octra_node_protocol::aml::source::compile(
                    include_bytes!("../../../../../program/octranet-payments-circle-factory.aml"),
                    octra_node_protocol::aml::source::Syntax::Source,
                    true,
                )
                .unwrap()
                .octb,
            ),
        };
        let graph = Graph::isolated_applications(CHAIN.as_bytes().to_vec(), None, root).unwrap();
        let store = CanonicalStore::create(
            &directory.path().join("node.db"),
            chain.clone(),
            state.snapshot(),
            0,
        )
        .await
        .unwrap();
        let runtime = circle_host::runtime();
        let checkpoints = Arc::new(
            SqliteCheckpoints::open(&directory.path().join("exex.db"))
                .await
                .unwrap(),
        );
        let node = Node::open(
            store,
            Authority { chain },
            runtime.clone(),
            Arc::new(UnavailableHost),
            checkpoints,
        )
        .await
        .unwrap();
        let node = if application == Application::Circle {
            node.with_view_graph(graph.clone()).unwrap()
        } else {
            node
        };
        let protocol = Protocol::new(2).unwrap();
        let native = executor::Native::new(
            executor::Config {
                graph: graph.clone(),
                protocol,
                profile: Profile {
                    release: ReleaseProfile::DevnetFullV1,
                    ..Profile::default()
                },
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
                pvac_dir: directory.path().join("unused-pvac"),
                migration: None,
            },
            runtime,
            node.history(),
        )
        .unwrap();
        assert!(node.resume().await.unwrap());
        let mut fixture = Self {
            node,
            native,
            graph,
            protocol,
            domain,
            tariff,
            now: GENESIS_SECONDS,
            factory: String::new(),
            program: String::new(),
            application,
            payment_code,
            factory_code,
            _directory: directory,
        };
        fixture.deploy_and_fund().await;
        fixture
    }

    #[allow(clippy::needless_pass_by_value)] // Fixture call sites use owned JSON literals.
    fn transaction(
        &self,
        who: u8,
        target: &str,
        op_type: OpType,
        params: Value,
        amount: u64,
        data: Vec<u8>,
    ) -> Transaction {
        let view = self.node.snapshot().unwrap();
        let account = account_store::load(
            &StateBatch::from_snapshot(view.state().clone()),
            payment_host::address(who).as_bytes(),
        )
        .unwrap()
        .unwrap();
        let mut tx = Transaction {
            from: payment_host::address(who).into_bytes(),
            to: target.as_bytes().to_vec(),
            amount: amount.into(),
            nonce: account.nonce.successor(),
            ou: payment_host::FEE.into(),
            timestamp: self.now + 10.,
            signature: vec![],
            public_key: Some(
                STANDARD
                    .encode(payment_host::key(who).verifying_key().to_bytes())
                    .into_bytes(),
            ),
            message: Some(serde_json::to_vec(&params).unwrap()),
            encrypted_data: Some(data),
            op_type,
        };
        tx.signature = STANDARD
            .encode(
                payment_host::key(who)
                    .sign(&tx.signing_bytes().unwrap())
                    .to_bytes(),
            )
            .into_bytes();
        let normalized = transaction::normalize_envelope(&tx, tx.public_key.as_deref()).unwrap();
        assert_eq!(normalized, tx);
        assert!(tx.verify(tx.public_key.as_ref().unwrap()));
        tx
    }

    async fn publish(&mut self, inputs: Vec<Transaction>) -> Value {
        self.publish_at(inputs, self.now + 10.).await
    }
    async fn publish_at(&mut self, inputs: Vec<Transaction>, seconds: f64) -> Value {
        let parent = self.node.snapshot().unwrap().head().clone();
        let hashes = inputs
            .iter()
            .map(|tx| hex::encode(tx.hash().unwrap()))
            .collect::<Vec<_>>();
        let draft = Arc::new(
            self.node
                .proposal_draft(
                    &self.graph,
                    Policy {
                        protocol: self.protocol,
                        genesis_time: Some(GENESIS_SECONDS),
                    },
                    payment_host::address(1).as_bytes(),
                    seconds,
                )
                .await
                .unwrap(),
        );
        let built = self.native.build_proposal(draft, inputs).await.unwrap();
        assert!(
            built.refused().is_empty(),
            "unexpected rejected fixture transaction"
        );
        assert!(
            built.held().is_empty(),
            "unexpected deferred fixture transaction"
        );
        assert_eq!(built.execution().transactions.len(), hashes.len());
        let receipt = hashes.first().map_or(Value::Null, |hash| {
            serde_json::from_slice(&built.execution().vm_receipts[hash]).unwrap()
        });
        if !hashes.is_empty() {
            assert_eq!(receipt["success"], true, "native Program failed: {receipt}");
        }
        assert!(built.execution().epoch_observation.is_some());
        let mut finalized = Finalize {
            chain_id: CHAIN.as_bytes().to_vec(),
            epoch_id: built.plan().header.epoch_id,
            commit_round: 0,
            header: built.plan().header.clone(),
            proposal_id: vec![],
            precommits: vec![],
            parent_commit: built.plan().parent_commit.clone(),
        };
        finalized.proposal_id = hash::proposal_id(&finalized.header).unwrap().to_vec();
        finalized.precommits = (1..=3)
            .map(|id| {
                let mut vote = Vote {
                    chain_id: CHAIN.as_bytes().to_vec(),
                    epoch_id: finalized.epoch_id,
                    round: 0,
                    vote_type: VoteType::Precommit,
                    proposal_id: finalized.proposal_id.clone(),
                    validator: payment_host::address(id).into_bytes(),
                    signature: vec![],
                };
                vote.signature = payment_host::key(id)
                    .sign(&hash::vote_sign_bytes(&vote).unwrap())
                    .to_bytes()
                    .to_vec();
                vote
            })
            .collect();
        let published = self
            .node
            .publish(
                &parent,
                &finalized.encode().unwrap(),
                built.execution().clone(),
            )
            .await
            .unwrap();
        assert!(matches!(published.services, Status::Serving(_)));
        self.now = seconds;
        receipt
    }

    async fn call(&mut self, who: u8, method: &str, params: Value, amount: u64) -> Value {
        let tx = self.transaction(
            who,
            &self.program,
            self.application.call(),
            params,
            amount,
            method.as_bytes().to_vec(),
        );
        self.publish(vec![tx]).await
    }

    async fn deploy_and_fund(&mut self) {
        let initial = self.node.snapshot().unwrap();
        assert_eq!(initial.head().cursor.epoch.0, 0);
        let operator = payment_host::address(11);
        let nonce = account_store::load(
            &StateBatch::from_snapshot(initial.state().clone()),
            operator.as_bytes(),
        )
        .unwrap()
        .unwrap()
        .nonce
        .successor();
        if self.application == Application::Circle {
            let payload = super::circle_tests::payload(&self.factory_code);
            let parsed = octra_node_protocol::circle_program::Deploy::from_document(
                &octra_node_protocol::native_json::Document::parse(
                    &serde_json::to_vec(&payload).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            self.factory = String::from_utf8(parsed.id(operator.as_bytes(), nonce)).unwrap();
            let tx = self.transaction(11, &self.factory, OpType::CircleDeploy, payload, 0, vec![]);
            self.publish(vec![tx]).await;
            let tx = self.transaction(
                11,
                &self.factory,
                OpType::CircleCall,
                json!([STANDARD.encode(
                    serde_json::to_vec(&super::circle_tests::payload(&self.payment_code)).unwrap()
                )]),
                0,
                b"deploy_payments".to_vec(),
            );
            let receipt = self.publish(vec![tx]).await;
            self.program = receipt["events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|event| event["event"] == "PaymentsCircleDeployed")
                .unwrap()["values"][0]
                .as_str()
                .unwrap()
                .to_owned();
            // Separate finalized initialization: the native spawn is deferred.
            self.call(14, "initialize", json!([]), 0).await;
        } else {
            self.factory = String::from_utf8(contract::address(
                &self.factory_code,
                operator.as_bytes(),
                nonce.get(),
            ))
            .unwrap();
            let tx = self.transaction(
                11,
                &self.factory,
                OpType::ContractDeploy,
                json!([]),
                0,
                STANDARD.encode(&self.factory_code).into_bytes(),
            );
            self.publish(vec![tx]).await;
            let tx = self.transaction(
                11,
                &self.factory,
                OpType::ContractCall,
                json!([
                    STANDARD.encode(&self.payment_code),
                    self.domain,
                    200_000_000,
                    payment_host::STAKE
                ]),
                0,
                b"deploy_payments".to_vec(),
            );
            let receipt = self.publish(vec![tx]).await;
            self.program = receipt["events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|event| event["event"] == "PaymentsDeployed")
                .unwrap()["values"][0]
                .as_str()
                .unwrap()
                .to_owned();
        }
        self.call(11, "bond_operator", json!([]), payment_host::STAKE)
            .await;
        let registration = format!(
            "Octranet register v1|{}|{}|{}|1",
            self.domain,
            self.program,
            payment_host::address(12)
        );
        self.call(
            12,
            "register",
            json!([
                STANDARD.encode(payment_host::key(21).verifying_key().to_bytes()),
                payment_host::sign(21, &registration)
            ]),
            0,
        )
        .await;
        self.call(
            12,
            "fund",
            json!([payment_host::address(12)]),
            payment_host::FUND,
        )
        .await;
        self.call(
            11,
            "create_offer",
            json!([self.tariff.hash_hex().unwrap()]),
            0,
        )
        .await;
        self.call(11, "append_class", json!([0, 10]), 0).await;
        self.call(11, "append_class", json!([0, 100]), 0).await;
        self.call(11, "seal_offer", json!([0]), 0).await;
        self.call(12, "open_plan", json!([0, 1000]), 0).await;
        assert_eq!(
            self.node.snapshot().unwrap().head().cursor.epoch.0,
            10 + u64::from(self.application == Application::Circle)
        );
    }

    fn payments(&self) -> Payments {
        self.node
            .payments(
                Config {
                    application: self.application,
                    program: self.program.clone(),
                    code_hash: hex::encode(Sha256::digest(&self.payment_code)),
                    factory: self.factory.clone(),
                    factory_code_hash: hex::encode(Sha256::digest(&self.factory_code)),
                    domain: self.domain.clone(),
                    operator_circle: payment_host::address(14),
                    offer: 0,
                },
                parse_native_address(&payment_host::address(11)).unwrap(),
            )
            .unwrap()
    }
}

fn receipt(plan: &Plan, bytes: u64) -> SignedUsage {
    SignedUsage::sign(
        Usage {
            deployment: plan.deployment.clone(),
            payer: plan.payer.clone(),
            generation: plan.generation,
            plan: plan.plan,
            offer: plan.offer,
            manifest_hash: plan.manifest_hash.clone(),
            traffic_class: 1,
            sequence: 1,
            total_bytes: bytes,
        },
        &KeyPair::from_secret_bytes(&[21; 32]),
    )
    .unwrap()
}

#[tokio::test]
async fn public_payment_grant_uses_post_genesis_deployment_and_authenticated_epoch_clock() {
    let mut fixture = Box::pin(Fixture::new(None)).await;
    let reader = fixture.payments();
    let granted = reader.plan(0).await.unwrap();
    assert!(granted.admissible() && granted.claimable());
    assert_eq!(granted.tariff, fixture.tariff);
    assert_eq!(granted.original_budget_ou, 1000);
    assert_eq!(granted.remaining_ou, 1000);
    assert_eq!(
        granted.canonical_ms,
        u64::try_from(
            octra_node_protocol::consensus::policy::time_of_seconds(fixture.now).unwrap()
        )
        .unwrap()
    );
    assert_eq!(granted.opened_ms, granted.canonical_ms);
    let signed = receipt(&granted, 1_048_576);
    assert_eq!(granted.claim_increment(&signed).unwrap(), 100);

    fixture
        .node
        .suspend("fixture lost canonical synchronization");
    assert!(!granted.admissible() && !granted.claimable());
    assert!(granted.claim_increment(&signed).is_err());
    assert!(reader.plan(0).await.is_err());
    assert!(fixture.node.resume().await.unwrap());
    let resumed = reader.plan(0).await.unwrap();
    assert!(resumed.admissible());
    assert!(!granted.admissible(), "resume cannot revive an old grant");

    // Buy while the connection is open. A later exit cannot charge a held
    // signature for additional, unusable capacity after the connection closes.
    fixture
        .call(13, "claim", signed.claim_params().unwrap(), 0)
        .await;
    let purchased = reader.plan(0).await.unwrap();
    assert_eq!(purchased.remaining_ou, 900);
    assert_eq!(purchased.redeemed_bytes, [0, 1_048_576]);
    assert!(purchased.admissible() && purchased.claimable());
    let held = receipt(&purchased, 2 * 1_048_576);
    fixture.call(12, "request_exit", json!([]), 0).await;
    assert!(!resumed.admissible() && !purchased.admissible());
    let exiting = reader.plan(0).await.unwrap();
    assert!(!exiting.admissible() && !exiting.claimable());
    assert!(exiting.claim_increment(&held).is_err());
    exiting.validate_usage(&signed).unwrap();
    assert!(exiting.redeemed_bytes[1] >= signed.usage.total_bytes);
    let deadline = exiting.claim_deadline_ms.unwrap();
    assert_eq!(deadline, exiting.canonical_ms);
    fixture.call(12, "withdraw_remaining", json!([]), 0).await;
    let withdrawn = reader.plan(0).await.unwrap();
    assert!(!withdrawn.admissible() && !withdrawn.claimable());
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn public_payment_grant_revokes_new_purchases_on_unstake_and_releases_unspent_immediately() {
    let mut fixture = Box::pin(Fixture::new(None)).await;
    let reader = fixture.payments();
    let active = reader.plan(0).await.unwrap();
    fixture
        .call(11, "request_operator_unstake", json!([]), 0)
        .await;
    assert!(!active.admissible() && !active.claimable());
    let stopped = reader.plan(0).await.unwrap();
    assert!(!stopped.admissible() && !stopped.claimable());
    assert!(stopped
        .claim_increment(&receipt(&stopped, 1_048_576))
        .is_err());
    let cutoff = stopped.claim_deadline_ms.unwrap();
    assert_eq!(cutoff, stopped.canonical_ms);
    fixture
        .call(11, "request_operator_unstake", json!([]), 0)
        .await;
    assert_eq!(
        reader.plan(0).await.unwrap().claim_deadline_ms,
        Some(cutoff)
    );
    fixture
        .call(12, "release_stopped_plan", json!([0]), 0)
        .await;
    let released = reader.plan(0).await.unwrap();
    assert_eq!(released.remaining_ou, 0);
    assert!(!released.admissible() && !released.claimable());
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn public_payment_grant_checks_canonical_circle_asset_expiry() {
    // Public Circle reads evaluate visibility at the next epoch. The offer
    // asset is visible at captured epoch10 and expires at policy epoch12.
    let mut fixture = Box::pin(Fixture::new(Some(12))).await;
    let reader = fixture.payments();
    let active = reader.plan(0).await.unwrap();
    assert!(active.admissible());
    let signed = receipt(&active, 1_048_576);
    fixture.publish(vec![]).await;
    assert!(!active.admissible());
    let error = reader.plan(0).await.unwrap_err();
    assert_eq!(error.to_string(), "Circle asset is not published");
    let debt = reader.claim_plan(0).await.unwrap();
    assert!(!debt.admissible() && debt.claimable());
    assert_eq!(debt.claim_increment(&signed).unwrap(), 100);
    fixture
        .call(13, "claim", signed.claim_params().unwrap(), 0)
        .await;
    let paid = reader.claim_plan(0).await.unwrap();
    assert!(!paid.admissible() && paid.claimable());
    assert_eq!(paid.remaining_ou, 900);
    assert_eq!(paid.redeemed_bytes, [0, 1_048_576]);
    assert!(reader.plan(0).await.is_err());
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn packet_capability_checks_actual_canonical_publication_at_handoff() {
    use octravpn_core::payments::PlanBinding;
    let mut fixture = Box::pin(Fixture::new(None)).await;
    let reader = fixture.payments();
    let plan = reader.plan(0).await.unwrap();
    let binding = PlanBinding {
        deployment: plan.deployment.clone(),
        payer: plan.payer.clone(),
        generation: plan.generation,
        plan: plan.plan,
        offer: plan.offer,
        manifest_hash: plan.manifest_hash.clone(),
    };
    let granted = octravpn_node::payments::Authority::plan(&reader, &binding)
        .await
        .unwrap();
    let mut writes = 0;
    granted
        .guard
        .current(&mut || {
            writes += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(writes, 1);
    fixture.node.suspend("packet fixture lost synchronization");
    assert!(!granted.guard.live());
    assert!(granted
        .guard
        .current(&mut || {
            writes += 1;
            Ok(())
        })
        .is_err());
    assert_eq!(writes, 1);
    fixture.node.resume().await.unwrap();
    assert!(granted
        .guard
        .current(&mut || {
            writes += 1;
            Ok(())
        })
        .is_err());
    let refreshed = <Payments as octravpn_node::payments::Authority>::plan(&reader, &binding)
        .await
        .unwrap();
    refreshed
        .guard
        .current(&mut || {
            writes += 1;
            Ok(())
        })
        .unwrap();
    fixture
        .call(11, "request_operator_unstake", json!([]), 0)
        .await;
    assert!(refreshed
        .guard
        .current(&mut || {
            writes += 1;
            Ok(())
        })
        .is_err());
    let stopped = <Payments as octravpn_node::payments::Authority>::plan(&reader, &binding)
        .await
        .unwrap();
    assert!(!stopped.admissible && stopped.guard.live());
    assert!(stopped
        .guard
        .current(&mut || {
            writes += 1;
            Ok(())
        })
        .is_err());
    assert_eq!(writes, 2);
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn canonical_replacement_notice_preserves_purchased_traffic_and_admits_successor_lineage() {
    let mut fixture = Box::pin(Fixture::new(None)).await;
    let reader = fixture.payments();
    let original = reader.plan(0).await.unwrap();
    let purchased = receipt(&original, 1_048_576);
    fixture
        .call(13, "claim", purchased.claim_params().unwrap(), 0)
        .await;
    fixture
        .call(
            11,
            "create_rate_change",
            json!([0, original.manifest_hash]),
            0,
        )
        .await;
    for class in original.tariff.classes() {
        fixture
            .call(11, "append_class", json!([1, class.rate_ou_per_mib]), 0)
            .await;
    }
    fixture.call(11, "seal_offer", json!([1]), 0).await;
    let notice = reader.plan(0).await.unwrap();
    let activation = notice.offer_end_ms;
    assert_eq!(activation, notice.canonical_ms + 86_400_000);
    assert!(notice.admissible() && notice.claimable());
    #[allow(clippy::cast_precision_loss)]
    // Canonical fixture milliseconds fit f64's exact integer range.
    let activation_seconds = activation as f64 / 1000.;
    fixture.publish_at(vec![], activation_seconds).await;
    let retired = reader.plan(0).await.unwrap();
    assert!(retired.admissible());
    assert!(!retired.claimable());
    assert_eq!(retired.claim_deadline_ms, None);
    assert_eq!(retired.redeemed_bytes, [0, 1_048_576]);
    retired.validate_usage(&purchased).unwrap();
    assert!(retired
        .claim_increment(&receipt(&retired, 2 * 1_048_576))
        .is_err());
    let binding = purchased.usage.binding();
    let granted = <Payments as octravpn_node::payments::Authority>::plan(&reader, &binding)
        .await
        .unwrap();
    assert!(granted.admissible && granted.guard.live());
    let mut called = false;
    granted
        .guard
        .current(&mut || {
            called = true;
            Ok(())
        })
        .unwrap();
    assert!(called, "retiring a quote cannot revoke purchased traffic");
    fixture.call(12, "open_plan", json!([1, 1000]), 0).await;
    let successor = reader.plan(1).await.unwrap();
    assert_eq!(successor.offer, 1);
    assert!(successor.admissible() && successor.claimable());
    assert_eq!(successor.offer_start_ms, activation);
    assert_eq!(successor.tariff, original.tariff);
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn canonical_partial_withdrawal_revokes_existing_transport_generation_immediately() {
    let mut fixture = Box::pin(Fixture::new(None)).await;
    let reader = fixture.payments();
    let original = reader.plan(0).await.unwrap();
    let purchased = receipt(&original, 1_048_576);
    fixture
        .call(13, "claim", purchased.claim_params().unwrap(), 0)
        .await;
    let binding = purchased.usage.binding();
    let granted = <Payments as octravpn_node::payments::Authority>::plan(&reader, &binding)
        .await
        .unwrap();
    assert!(granted.admissible && granted.guard.live());
    fixture.call(12, "withdraw_channel", json!([1]), 0).await;
    assert!(!granted.guard.live());
    let revoked = <Payments as octravpn_node::payments::Authority>::plan(&reader, &binding)
        .await
        .unwrap();
    assert!(!revoked.admissible && revoked.guard.live());
    assert!(revoked.guard.current(&mut || Ok(())).is_err());
    let closed = reader.claim_plan(0).await.unwrap();
    closed.validate_usage(&purchased).unwrap();
    assert!(!closed.admissible() && !closed.claimable());
    assert_eq!(closed.redeemed_bytes, [0, 1_048_576]);
    fixture.call(12, "withdraw_remaining", json!([]), 0).await;
    let withdrawn = reader.claim_plan(0).await.unwrap();
    withdrawn.validate_usage(&purchased).unwrap();
    assert!(!withdrawn.admissible() && !withdrawn.claimable());
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn circle_prepaid_authority_uses_real_qc_storage_clock_and_refuses_program_replay() {
    let mut fixture = Box::pin(Fixture::with_application(None, Application::Circle)).await;
    let reader = fixture.payments();
    let active = reader.plan(0).await.unwrap();
    assert!(active.admissible() && active.claimable());
    assert_eq!(active.tariff, fixture.tariff);
    assert_eq!(
        active.deployment.domain,
        application_domain(fixture.node.store.chain(), Application::Circle)
    );
    assert_ne!(
        active.deployment.domain,
        network_domain(fixture.node.store.chain())
    );
    let signed = receipt(&active, 1_048_576);
    let mut wrong = signed.usage.clone();
    wrong.deployment.domain = network_domain(fixture.node.store.chain());
    let cross_kind = SignedUsage::sign(wrong, &KeyPair::from_secret_bytes(&[21; 32])).unwrap();
    assert!(active.validate_usage(&cross_kind).is_err());
    fixture
        .call(13, "claim", signed.claim_params().unwrap(), 0)
        .await;
    assert!(!active.admissible());
    let purchased = reader.plan(0).await.unwrap();
    assert_eq!(purchased.redeemed_bytes, [0, 1_048_576]);
    assert_eq!(purchased.remaining_ou, 900);
    assert!(purchased.admissible());
    let view = fixture.node.snapshot().unwrap();
    assert!(view
        .state()
        .get(&[
            b"contracts",
            fixture.program.as_bytes(),
            b"storage",
            b"domain"
        ])
        .is_none());
    assert_eq!(view.head().cursor.epoch.0, 12);
    fixture
        .node
        .suspend("Circle fixture lost canonical availability");
    assert!(!purchased.admissible());
    assert!(reader.plan(0).await.is_err());
    assert!(fixture.node.resume().await.unwrap());
    assert!(reader.plan(0).await.unwrap().admissible());
    fixture.call(12, "withdraw_remaining", json!([]), 0).await;
    let withdrawn = reader.plan(0).await.unwrap();
    assert!(!withdrawn.admissible() && !withdrawn.claimable());
    fixture.node.shutdown().await.unwrap();
}
