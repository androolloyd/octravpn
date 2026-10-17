//! Full local service path with real WASM, signed QCs, HTTP and WireGuard.
//! Validators, genesis funding and the settlement reader are explicit fixtures.
//! This is not a public consensus driver or an executed VPN money application.
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use boringtun::noise::{Tunn, TunnResult};
use ed25519_dalek::{Signer, SigningKey};
use octra_browser::application::UnavailableHost;
use octra_exex::{
    native_history::{ArchiveProof, NativeTransaction},
    sqlite::SqliteCheckpoints,
    ChainIdentity, CommittedEpoch, ExEx, ExtensionStatus, StateRoot,
};
use octra_node::{import::Executor, vpn::Settlement, Committed, Host, Node, Status};
use octra_node_protocol::{
    circles::{self, AssetMeta, LocatorMode, MetadataMode, ResourceMode},
    consensus::{
        codec::Wire, hash, CatchupEpochRecord, CatchupFinality, EpochHeader, Finalize,
        RewardMember, RewardSource, ValidatorSet,
    },
    state::Account,
    transaction::{self, Nonce, OpType, RuleMode, Transaction},
};
use octra_node_runtime::{
    account_store,
    canonical::{CanonicalStore, Head, ReliefSource},
    circle::WasmRules,
    circle_transaction,
    consensus_bundle::{RawBundle, Replay, Rules as BundleRules},
    finality::{EpochRules, ExecutedEpoch, ValidatorHistory},
    state_batch::StateBatch,
};
use octravpn_core::{
    address::Address,
    control::{
        announce_opener_binding_payload, announce_signing_payload, AnnounceSessionRequest,
        SessionStateResponse,
    },
    onion::{build_onion, HopBuildInput},
    receipt::ReceiptContext,
    session::SessionId,
    sig::KeyPair,
    tunnel_frame,
};
use octravpn_node::{
    admission::{FundedSession, RelayLifecycle, SessionAuthority},
    embedded::Config,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{net::UdpSocket, sync::watch};
use x25519_dalek::{PublicKey, StaticSecret};

#[path = "../../octra-node-runtime/tests/common/bundle_peer.rs"]
mod bundle_peer;
#[path = "../../octra-node-runtime/tests/common/circle_host.rs"]
mod circle_host;
#[path = "../../octra-node-runtime/tests/common/finality_host.rs"]
mod finality_host;

fn rules() -> WasmRules {
    WasmRules {
        wasm_float: false,
        proof_exec: false,
        math: false,
    }
}
struct Authority {
    finality: finality_host::Authority,
    fail_views: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl ValidatorHistory for Authority {
    async fn resolve(
        &self,
        parent: &Head,
        epoch: u64,
        relief: ReliefSource,
    ) -> Result<EpochRules, String> {
        self.finality.resolve(parent, epoch, relief).await
    }
}

impl Host for Authority {
    fn check_views(&self, _: &Head) -> Result<(), String> {
        if self.fail_views.load(Ordering::SeqCst) {
            Err("fixture activation history unavailable".into())
        } else {
            Ok(())
        }
    }
}

struct FixtureSettlement {
    session: FundedSession,
}
#[async_trait::async_trait]
impl Settlement for FixtureSettlement {
    async fn session(
        &self,
        view: &Committed,
        _: &AnnounceSessionRequest,
        domain: &ReceiptContext,
    ) -> Result<Option<FundedSession>> {
        if domain != &self.session.domain {
            return Ok(None);
        }
        let mut session = self.session.clone();
        session.current_epoch = view.head().cursor.epoch.0;
        // Deliberately synthetic funded state; production needs the pinned
        // settlement application's actual escrow and opening transaction reader.
        session.escrow_ou =
            std::str::from_utf8(view.state().get(&[b"fixture", b"escrow"]).unwrap())?.parse()?;
        Ok(Some(session))
    }
    async fn lifecycle(
        &self,
        view: &Committed,
        session: &SessionId,
        domain: &ReceiptContext,
    ) -> Result<RelayLifecycle> {
        anyhow::ensure!(
            domain == &self.session.domain && session == &self.session.session_id,
            "wrong domain/session"
        );
        Ok(if view.head().cursor.epoch.0 < self.session.expires_epoch {
            RelayLifecycle::Open
        } else {
            RelayLifecycle::Terminal(2)
        })
    }
}
fn announce() -> (AnnounceSessionRequest, Arc<FixtureSettlement>) {
    let opener = KeyPair::from_secret_bytes(&[11; 32]);
    let client = KeyPair::from_secret_bytes(&[21; 32]);
    let wg = PublicKey::from(&StaticSecret::from([51; 32])).to_bytes();
    let sid = SessionId::from_u64(73);
    let hash = "ab".repeat(32);
    let request = AnnounceSessionRequest {
        client_sig: client.sign(&announce_signing_payload(&sid, &client.public, &wg, &hash)),
        opener_sig: opener.sign(&announce_opener_binding_payload(
            &sid,
            &client.public,
            &wg,
            &hash,
        )),
        session_id: sid.clone(),
        client_pubkey: client.public,
        client_wg_pubkey: wg,
        open_tx_hash: hash.clone(),
        opener_pubkey: opener.public,
    };
    let settlement = FixtureSettlement {
        session: FundedSession {
            domain: ReceiptContext::v2(
                Address::from_pubkey(&[61; 32]),
                999,
                Address::from_pubkey(&[71; 32]),
            ),
            session_id: sid,
            opener: Address::from_pubkey(&opener.public.0),
            client_pubkey: client.public,
            client_wg_pubkey: wg,
            open_tx_hash: hash,
            current_epoch: 0,
            expires_epoch: 2,
            escrow_ou: 0,
            open: true,
        },
    };
    (request, Arc::new(settlement))
}
fn vpn_config(path: &std::path::Path, domain: &ReceiptContext) -> Config {
    Config {
        control_listen: "127.0.0.1:0".parse().unwrap(),
        tunnel_listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: path.to_owned(),
        receipt_key: Arc::new(KeyPair::from_secret_bytes(&[31; 32])),
        wireguard_secret: StaticSecret::from([41; 32]),
        receipt_context: domain.clone(),
    }
}
fn install_asset(state: &mut StateBatch, circle: &[u8]) {
    let body = b"<!doctype html><html><body>Canonical Circle</body></html>";
    let key = circles::path_key(b"/index.html");
    let meta = AssetMeta {
        path_key: key.as_bytes().to_vec(),
        canonical_path: b"/index.html".to_vec(),
        content_type: b"text/html".to_vec(),
        encoding: b"identity".to_vec(),
        size_bytes: body.len() as i64,
        blob_hash: hex::encode(Sha256::digest(body)).into_bytes(),
        body_mode: ResourceMode::Public,
        plaintext_hash: None,
        key_id: None,
        padding_class: None,
        resource_key: key.as_bytes().to_vec(),
        locator_mode: LocatorMode::Path,
        slot_ref: None,
        activate_after_epoch: None,
        expire_after_epoch: None,
        metadata_mode: MetadataMode::Reveal,
    };
    state
        .set(
            &[
                b"circles",
                circle,
                b"assets",
                b"by_hash",
                key.as_bytes(),
                b"meta",
            ],
            meta.to_json_bytes(),
        )
        .unwrap();
    state
        .set(
            &[
                b"circles",
                circle,
                b"assets",
                b"by_hash",
                key.as_bytes(),
                b"body_b64",
            ],
            STANDARD.encode(body).into_bytes(),
        )
        .unwrap();
}
fn genesis(circle: &[u8]) -> StateBatch {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    circle_host::install_counter(&mut state, circle, b"4");
    install_asset(&mut state, circle);
    for (key, value) in [
        (b"last_epoch".as_slice(), b"0".as_slice()),
        (b"emission_remaining", b"0"),
        (b"total_supply", b"10000"),
    ] {
        state.set(&[b"meta", key], value.to_vec()).unwrap();
    }
    state
        .set(&[b"fixture", b"escrow"], b"100".to_vec())
        .unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let public = STANDARD.encode(key.verifying_key().to_bytes()).into_bytes();
    account_store::set(
        &mut state,
        &transaction::address_from_public_key(&public),
        &Account {
            balance: 10_000.into(),
            public_key: Some(public),
            ..Account::default()
        },
        RuleMode::Active,
    )
    .unwrap();
    state
}
async fn open(
    path: &std::path::Path,
    checkpoints: Arc<SqliteCheckpoints>,
    chain: ChainIdentity,
    fail_views: Arc<AtomicBool>,
) -> Node<Authority> {
    Node::open(
        CanonicalStore::open(path, &chain).await.unwrap(),
        Authority {
            finality: finality_host::Authority { seed: 1, chain },
            fail_views,
        },
        circle_host::runtime(),
        Arc::new(UnavailableHost),
        checkpoints,
    )
    .await
    .unwrap()
}
fn circle_call(epoch: u64, circle: &[u8]) -> Transaction {
    let key = SigningKey::from_bytes(&[42; 32]);
    let public = STANDARD.encode(key.verifying_key().to_bytes()).into_bytes();
    let mut tx = Transaction {
        from: transaction::address_from_public_key(&public),
        to: circle.to_vec(),
        amount: 1.into(),
        nonce: Nonce::new(epoch as i64).unwrap(),
        ou: 1000.into(),
        timestamp: 1.,
        signature: vec![],
        public_key: Some(public),
        message: Some(b"[]".to_vec()),
        encrypted_data: Some(b"inc".to_vec()),
        op_type: OpType::CircleCall,
    };
    tx.signature = STANDARD
        .encode(key.sign(&tx.signing_bytes().unwrap()).to_bytes())
        .into_bytes();
    tx
}
fn execute(
    view: &Committed,
    circle: &[u8],
    authority: &finality_host::Authority,
) -> (Vec<u8>, ExecutedEpoch) {
    let epoch = view.head().cursor.epoch.0 + 1;
    let tx = circle_call(epoch, circle);
    let executed = execute_received(
        view.head(),
        StateBatch::from_snapshot(view.state().clone()),
        &[tx],
        authority,
        None,
        None,
    )
    .unwrap();
    (
        finality_host::certificate(view.head(), &executed, authority)
            .encode()
            .unwrap(),
        executed,
    )
}
fn execute_received(
    parent: &Head,
    mut state: StateBatch,
    txs: &[Transaction],
    authority: &finality_host::Authority,
    replay: Option<&Replay>,
    context: Option<&octra_node_runtime::execution_rules::Bound>,
) -> Result<ExecutedEpoch> {
    let epoch = parent.cursor.epoch.0 + 1;
    let fallback;
    let context = if let Some(context) = context {
        context
    } else {
        fallback = octra_node_runtime::execution_rules::Bound::resolve(
            &octra_node_protocol::rules::Graph::new(
                authority.chain.chain_id.as_bytes().to_vec(),
                None,
            ),
            epoch as i64,
            None,
            &[],
            &|_| octra_node_protocol::rules::RootRead::Missing,
        )?;
        &fallback
    };
    state.begin().unwrap();
    let mut ledger = account_store::ledger(&state).unwrap();
    let envelope = octra_node_protocol::transaction_outcome::Rules {
        envelope: RuleMode::Active,
        compute: RuleMode::Prior,
        settle: RuleMode::Prior,
    };
    let partition = replay.map(Replay::partition);
    let bundle = replay.map(Replay::bundle);
    let txs = partition.map_or(txs, |p| p.transactions());
    for tx in txs {
        octra_node_runtime::admission::signature(
            tx,
            ledger
                .account(&tx.from)
                .and_then(|a| a.public_key.as_deref()),
        )
        .unwrap();
    }
    transaction::check_envelopes(RuleMode::Active, txs).unwrap();
    let root = parent.ledger_root.clone();
    let receipts = bundle
        .map(|bundle| octra_node_protocol::transaction_outcome::split(&bundle.receipts_json, true))
        .transpose()?;
    let gate = receipts
        .as_ref()
        .map(|receipts| octra_node_protocol::preverify_commit::Gate::parse(&receipts.preverify))
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let verification = gate
        .as_ref()
        .map_or(circle_transaction::Verification::Capture, |gate| {
            circle_transaction::Verification::Consume {
                root: root.as_bytes(),
                gate,
            }
        });
    let runtime = circle_host::runtime();
    let mut calls = circle_transaction::Calls::new(
        &runtime,
        context.circle,
        epoch as i64,
        f64::from(u32::try_from(epoch).unwrap()) * 10.,
        hex::encode(parent.cursor.state_root.0).as_bytes(),
        verification,
    );
    use octra_node_runtime::{epoch_execution, epoch_footer, validator_epoch};
    let reward = finality_host::reward(authority.seed);
    let minimum = 5000.into();
    let emission = epoch_footer::Policy {
        emission_guard: true,
        schedule: octra_node_protocol::emission::Schedule::Inactive,
        legacy_total: None,
    };
    let committed = state.snapshot();
    let previous = hex::encode(parent.cursor.state_root.0);
    let request = epoch_execution::Request {
        validators: validator_epoch::Request {
            chain: authority.chain.chain_id.as_bytes(),
            epoch: epoch as i64,
            policy: &octra_node_protocol::validator::policy::Policy::Inactive,
            legacy_members: &[],
            previous_root: previous.as_bytes(),
            committed_head: Some(&committed),
        },
        envelope,
        sender_key_activation: Some(0),
        preverification: gate.as_ref().map(|gate| epoch_execution::Preverification {
            gate,
            crypto_active: false,
            minimum: &minimum,
        }),
        emission: &emission,
        reward: &reward,
        validator_keys: &[],
    };
    let fold = &context.fold;
    let batch = if let Some(partition) = &partition {
        partition.execute(
            &request,
            fold,
            &mut ledger,
            &mut state,
            |tx, ledger, state| calls.process(tx, ledger, state),
        )?
    } else {
        epoch_execution::execute(
            &request,
            fold,
            txs,
            &mut ledger,
            &mut state,
            |tx, ledger, state| calls.process(tx, ledger, state),
        )?
    };
    anyhow::ensure!(
        batch.artifacts.rejected.is_empty(),
        "unexpected fixture rejection"
    );
    let txs = batch
        .artifacts
        .confirmed
        .iter()
        .map(|(index, _)| &txs[*index])
        .collect::<Vec<_>>();
    let preverify = txs
        .iter()
        .map(|tx| {
            use octra_node_protocol::preverify_receipt::{Binding, Receipt};
            let binding = Binding::Circle(
                calls.bindings()[&hex::encode(tx.hash().unwrap())].at_snapshot(root.as_bytes()),
            );
            Receipt::for_tx(
                tx,
                binding.clone(),
                binding.input_hash(tx).unwrap(),
                binding.output_hash(tx, b"ok").unwrap(),
                true,
                vec![],
                &5000.into(),
            )
            .unwrap()
            .canonical()
        })
        .collect::<Vec<_>>();
    let consensus_receipts = octra_node_protocol::transaction_outcome::encode(
        &preverify,
        bundle.map_or(&[], |b| b.rejections.as_slice()),
    )?;
    assert_eq!(batch.artifacts.confirmed_fees, (1000 * txs.len()).into());
    let transactions = txs
        .iter()
        .enumerate()
        .map(|(index, tx)| {
            let hash = hex::encode(tx.hash().unwrap());
            let identity = tx.identity_bytes().unwrap();
            NativeTransaction {
                txid: parent.txid_hi + 1 + index as i64,
                hash: hash.clone(),
                identity: identity.clone(),
                transaction: identity,
                proof: ArchiveProof::Exact,
                receipt: Some(calls.receipts()[&hash].clone()),
            }
        })
        .collect();
    Ok(ExecutedEpoch {
        epoch_observation: None,
        metrics: octra_node_protocol::metrics::Epoch::default(),
        vm_receipts: std::collections::BTreeMap::default(),
        reward_source: finality_host::reward_source(authority.seed),
        state: state.snapshot(),
        transactions,
        consensus_receipts,
        date: epoch as i64,
        message: b"local integration".to_vec(),
    })
}

fn add_rejected_call(view: &Committed, executed: &mut ExecutedEpoch) {
    use octra_node_runtime::epoch_execution::Effect;
    let confirmed = executed
        .transactions
        .iter()
        .map(|tx| {
            Transaction::from_document(
                &octra_node_protocol::native_json::Document::parse(&tx.transaction).unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mut rejected = confirmed[0].clone();
    rejected.nonce = Nonce::new(rejected.nonce.get() + 1).unwrap();
    rejected.amount = 0.into();
    rejected.encrypted_data = Some(b"missing_method".to_vec());
    rejected.signature = STANDARD
        .encode(
            SigningKey::from_bytes(&[42; 32])
                .sign(&rejected.signing_bytes().unwrap())
                .to_bytes(),
        )
        .into_bytes();
    // Execute the actual failing WASM call in a disposable preview. It pays its
    // fee here, but the finalized epoch excludes both that fee and its nonce.
    let mut state = StateBatch::from_snapshot(executed.state.clone());
    state.begin().unwrap();
    let mut ledger = account_store::ledger(&state).unwrap();
    let balance = ledger.account(&rejected.from).unwrap().balance.clone();
    let runtime = circle_host::runtime();
    let mut calls = circle_transaction::Calls::new(
        &runtime,
        circle_transaction::Rules {
            manifest: octra_node_runtime::circle::WasmProfile::Compute,
            update_policy: false,
            wasm: rules(),
            inspect: true,
            storage_proof: true,
            fhe_work: false,
            object_cost: false,
        },
        view.head().cursor.epoch.0 as i64 + 1,
        1.,
        hex::encode(view.head().cursor.state_root.0).as_bytes(),
        circle_transaction::Verification::Direct,
    );
    let Effect::RejectedAfterFee { fee, refusal } =
        calls.process(&rejected, &mut ledger, &mut state).unwrap()
    else {
        panic!("missing method must produce a charged VM preview failure");
    };
    assert_eq!(fee, rejected.ou);
    assert_eq!(
        ledger.account(&rejected.from).unwrap().balance,
        balance - fee
    );
    let inputs = confirmed
        .iter()
        .cloned()
        .chain([rejected.clone()])
        .collect::<Vec<_>>();
    let rejections = octra_node_protocol::transaction_outcome::build(
        &inputs,
        &[(rejected, refusal.error_type, refusal.reason)],
        &[],
    )
    .unwrap();
    executed.consensus_receipts =
        octra_node_protocol::transaction_outcome::encode(&executed.consensus_receipts, &rejections)
            .unwrap();
}
struct ImportExecutor {
    native: octra_node::executor::Native,
    fail: AtomicBool,
    corrupt: AtomicBool,
}
impl ImportExecutor {
    fn new(authority: &finality_host::Authority, node: &Node<Authority>) -> Self {
        Self::with_protocol(
            authority,
            node,
            octra_node_protocol::consensus::policy::Protocol::default(),
        )
    }
    fn with_protocol(
        authority: &finality_host::Authority,
        node: &Node<Authority>,
        protocol: octra_node_protocol::consensus::policy::Protocol,
    ) -> Self {
        use octra_node::executor::{Config, Limits, Native};
        use octra_node_protocol::transaction_policy::Profile;
        let config = Config {
            graph: octra_node_protocol::rules::Graph::new(
                authority.chain.chain_id.as_bytes().to_vec(),
                None,
            ),
            protocol,
            profile: Profile {
                admit_ops: b"circle_call".to_vec(),
                ..Profile::default()
            },
            payload: octra_node_protocol::transaction_payload::Limits::default(),
            bundle: Limits::new(100_000, 50_000_000, 10_000_000_000_u64.into()),
            validators: octra_node_protocol::validator::policy::Policy::Inactive,
            emission: octra_node_runtime::epoch_footer::Policy {
                emission_guard: true,
                schedule: octra_node_protocol::emission::Schedule::Inactive,
                legacy_total: None,
            },
            sender_key_activation: Some(0),
            private_result_activation: 0,
            max_fhe: 32,
            max_stealth: 32,
            max_multi_exec_calls: 8,
            migration: None,
            ready_max_lag: 10,
            pvac_dir: std::path::PathBuf::from("unused-public-fixture-pvac"),
        };
        Self {
            native: Native::new(config, circle_host::runtime(), node.history()).unwrap(),
            fail: AtomicBool::new(false),
            corrupt: AtomicBool::new(false),
        }
    }
}
#[async_trait::async_trait]
impl Executor for ImportExecutor {
    fn graph(&self) -> octra_node_protocol::rules::Graph {
        self.native.graph()
    }
    fn rules(
        &self,
        parent: &Head,
        header: &EpochHeader,
        context: &octra_node_runtime::execution_rules::Bound,
    ) -> Result<BundleRules> {
        self.native.rules(parent, header, context)
    }
    async fn execute(&self, request: octra_node::import::Execution<'_>) -> Result<ExecutedEpoch> {
        anyhow::ensure!(
            !self.fail.load(Ordering::SeqCst),
            "fixture execution unavailable"
        );
        let mut executed = self.native.execute(request).await?;
        if self.corrupt.load(Ordering::SeqCst) {
            let mut state = StateBatch::from_snapshot(executed.state);
            state.begin().unwrap();
            state
                .set(&[b"fixture", b"corrupt"], b"yes".to_vec())
                .unwrap();
            executed.state = state.snapshot();
        }
        Ok(executed)
    }
}
fn network_bundle(executed: &ExecutedEpoch) -> RawBundle {
    RawBundle {
        tx_hashes: executed
            .transactions
            .iter()
            .map(|tx| tx.hash.as_bytes().to_vec())
            .collect(),
        txs_json: executed
            .transactions
            .iter()
            .map(|tx| tx.transaction.clone())
            .collect(),
        receipts_json: executed.consensus_receipts.clone(),
    }
}

fn same_consensus_head(actual: &Head, expected: &Head) {
    // Irmin commit metadata is local: independent implementations may label
    // commits differently while reproducing identical consensus commitments.
    assert_eq!(actual.cursor, expected.cursor);
    assert_eq!(actual.ledger_root, expected.ledger_root);
    assert_eq!(actual.index_root, expected.index_root);
    assert_eq!(actual.index_hash, expected.index_hash);
    assert_eq!(actual.txid_hi, expected.txid_hi);
}
fn network_record(
    finalized: &Finalize,
    executed: &ExecutedEpoch,
    set: ValidatorSet,
) -> CatchupEpochRecord {
    let header = &finalized.header;
    CatchupEpochRecord {
        epoch_id: finalized.epoch_id,
        prev_state_root: header.prev_state_root.clone(),
        state_root: header.proposed_state_root.clone(),
        tx_list_hash: header.tx_list_hash.clone(),
        tx_hashes: executed
            .transactions
            .iter()
            .map(|tx| tx.hash.as_bytes().to_vec())
            .collect(),
        txs_json: executed
            .transactions
            .iter()
            .map(|tx| tx.transaction.clone())
            .collect(),
        receipt_root: header.receipt_root.clone(),
        receipts_json: executed.consensus_receipts.clone(),
        epoch_ts: header.ts,
        creator_addr: header.creator_addr.clone(),
        commit_round: finalized.commit_round,
        reward_source: Some(RewardSource {
            reward_proposer_addr: header.creator_addr.clone(),
            reward_proposer_public_key: set.public_key(&header.creator_addr).map(<[u8]>::to_vec),
            reward_members: set
                .validators
                .iter()
                .map(|v| RewardMember {
                    reward_address: v.address.clone(),
                    reward_public_key: Some(v.pubkey.clone()),
                    reward_weight: 1.into(),
                })
                .collect(),
        }),
        finality: Some(CatchupFinality {
            finalize: finalized.clone(),
            validator_set: set,
        }),
    }
}
async fn acquire_certificate(
    reader: &bundle_peer::Node,
    server: &bundle_peer::Node,
    finalized: &Finalize,
    executed: &ExecutedEpoch,
    proof: bool,
) -> Vec<u8> {
    server.authority.ranges.lock().unwrap().insert(
        finalized.epoch_id,
        network_record(finalized, executed, server.authority.validators.clone()),
    );
    let roots = [octra_node_runtime::epoch_roots::Response {
        responder_addr: server.authority.address.clone(),
        responder_head_epoch: finalized.epoch_id,
        state_root: Some(finalized.header.proposed_state_root.clone()),
    }];
    if proof {
        reader
            .finality
            .request_proof(finalized.epoch_id, &roots)
            .await
            .unwrap()
            .unwrap();
    } else {
        reader
            .finality
            .request(finalized.epoch_id, &roots)
            .await
            .unwrap()
            .unwrap();
    }
    bundle_peer::wait_for(|| !reader.authority.finalities.lock().unwrap().is_empty()).await;
    reader
        .authority
        .finalities
        .lock()
        .unwrap()
        .remove(0)
        .encode()
        .unwrap()
}
struct Recorder(Arc<Mutex<Vec<u64>>>);
impl ExEx<NativeTransaction> for Recorder {
    fn name(&self) -> &'static str {
        "integration"
    }
    async fn on_epoch(&mut self, epoch: &CommittedEpoch<NativeTransaction>) -> Result<(), String> {
        assert_eq!(epoch.events.len(), 1);
        epoch.events[0].validate().map_err(|e| e.to_string())?;
        self.0.lock().unwrap().push(epoch.cursor.sequence.0);
        Ok(())
    }
}

type PauseHook = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;
struct PausingHost {
    authority: Authority,
    hook: PauseHook,
}
#[async_trait::async_trait]
impl ValidatorHistory for PausingHost {
    async fn resolve(
        &self,
        parent: &Head,
        epoch: u64,
        relief: ReliefSource,
    ) -> Result<EpochRules, String> {
        self.authority.resolve(parent, epoch, relief).await
    }
}

impl Host for PausingHost {
    fn check_views(&self, head: &Head) -> Result<(), String> {
        if let Some(hook) = self.hook.lock().unwrap().take() {
            hook();
        }
        self.authority.check_views(head)
    }
}

#[tokio::test]
async fn newer_pause_cannot_be_undone_and_cancellation_releases_services() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.db");
    let circle = format!("oct{}", "1".repeat(44));
    let state = genesis(circle.as_bytes());
    let chain = ChainIdentity::genesis(
        "node-cancellation-fixture",
        StateRoot(finality_host::root(None, &state, &[])),
    );
    let store = CanonicalStore::create(&path, chain.clone(), state.snapshot(), 0)
        .await
        .unwrap();
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&directory.path().join("checkpoints.db"))
            .await
            .unwrap(),
    );
    let finality = finality_host::Authority {
        seed: 1,
        chain: chain.clone(),
    };
    let hook: PauseHook = Arc::new(Mutex::new(None));
    let node = Arc::new(
        Node::open(
            store,
            PausingHost {
                authority: Authority {
                    finality: finality.clone(),
                    fail_views: Arc::new(AtomicBool::new(false)),
                },
                hook: hook.clone(),
            },
            circle_host::runtime(),
            Arc::new(UnavailableHost),
            checkpoints.clone(),
        )
        .await
        .unwrap(),
    );
    assert!(
        Node::open(
            CanonicalStore::open(&path, &chain).await.unwrap(),
            Authority {
                finality,
                fail_views: Arc::new(AtomicBool::new(false))
            },
            circle_host::runtime(),
            Arc::new(UnavailableHost),
            checkpoints,
        )
        .await
        .is_err(),
        "only one canonical coordinator may own the database"
    );
    let weak = Arc::downgrade(&node);
    *hook.lock().unwrap() = Some(Box::new(move || {
        weak.upgrade().unwrap().suspend("newer catch-up request");
    }));
    assert!(
        !node.resume().await.unwrap(),
        "a newer suspension invalidates the activation ticket"
    );
    assert_eq!(
        node.status(),
        Status::Suspended("newer catch-up request".into())
    );
    assert!(node.resume().await.unwrap());
    let (request, settlement) = announce();
    let domain = &settlement.session.domain;
    let authority = node.vpn_authority(settlement.clone());
    let permit = authority
        .authorize(&request, domain)
        .await
        .unwrap()
        .unwrap();
    let vpn_path = directory.path().join("vpn");
    assert!(node
        .bind(
            "0.0.0.0:0".parse().unwrap(),
            vpn_config(&vpn_path, domain),
            settlement.clone()
        )
        .await
        .is_err());
    let services = node
        .bind(
            "127.0.0.1:0".parse().unwrap(),
            vpn_config(&vpn_path, domain),
            settlement.clone(),
        )
        .await
        .unwrap();
    let browser = services.browser_addr().unwrap();
    let (_stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(services.run(shutdown));
    let http = reqwest::Client::new();
    assert_eq!(
        http.get(format!("http://{browser}/"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(!permit.live());
    assert!(node.snapshot().is_err());
    assert!(authority.authorize(&request, domain).await.is_err());
    // Receipt handles and the bound socket are owned by the cancelled future.
    // Rebinding the same directories and browser port must be possible.
    let services = node
        .bind(browser, vpn_config(&vpn_path, domain), settlement.clone())
        .await
        .unwrap();
    assert!(node.resume().await.unwrap());
    assert!(!permit.live(), "old permits stay revoked after resume");
    drop(node);
    assert!(
        authority.authorize(&request, domain).await.is_err(),
        "service handles do not keep a dropped node eligible"
    );
    drop(services);
}
async fn reached(node: &Node<Authority>, sequence: u64) {
    let mut status = node.extension_status("integration").await.unwrap();
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            if matches!(*status.borrow_and_update(),ExtensionStatus::Running { checkpoint } if checkpoint.sequence.0==sequence) { break; }
            status.changed().await.unwrap();
        }
    }).await.unwrap();
}
async fn view(http: &reqwest::Client, base: &str, scope: &str, circle: &str) -> String {
    let html = http
        .get(format!("{base}/view/{scope}/{circle}/index.html"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    html.split("data-token=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}
async fn counter(http: &reqwest::Client, base: &str, token: &str) -> reqwest::Response {
    http.post(format!("{base}/app/request"))
        .header("origin", base)
        .header("x-octra-session", token)
        .json(&json!({"method":"program.view","params":{"method":"get_counter","params":[]}}))
        .send()
        .await
        .unwrap()
}
async fn handshake(endpoint: std::net::SocketAddr) -> (Tunn, UdpSocket) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(endpoint).await.unwrap();
    let mut tunnel = Tunn::new(
        StaticSecret::from([51; 32]),
        PublicKey::from(&StaticSecret::from([41; 32])),
        None,
        None,
        0,
        None,
    );
    let mut bytes = vec![0; 65536];
    let mut work = vec![0; 65536];
    let TunnResult::WriteToNetwork(packet) = tunnel.format_handshake_initiation(&mut bytes, false)
    else {
        panic!("handshake");
    };
    socket.send(packet).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let TunnResult::WriteToNetwork(packet) = tunnel.decapsulate(None, &bytes[..n], &mut work)
    else {
        panic!("server response did not authenticate the WireGuard handshake");
    };
    assert_eq!(&packet[..4], &[4, 0, 0, 0]);
    socket.send(packet).await.unwrap();
    (tunnel, socket)
}
async fn send(tunnel: &mut Tunn, socket: &UdpSocket, frame: &[u8]) {
    let mut bytes = vec![0; 65536];
    let TunnResult::WriteToNetwork(packet) = tunnel.encapsulate(frame, &mut bytes) else {
        panic!("encrypt");
    };
    assert_eq!(
        &packet[..4],
        &[4, 0, 0, 0],
        "expected authenticated transport"
    );
    socket.send(packet).await.unwrap();
}
async fn metered(
    http: &reqwest::Client,
    base: &str,
    request: &AnnounceSessionRequest,
) -> SessionStateResponse {
    http.get(format!("{base}/session/{}", request.session_id.to_hex()))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn peer_import_drives_browser_wireguard_exex_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.db");
    let circle = format!("oct{}", "1".repeat(44));
    let state = genesis(circle.as_bytes());
    let chain = ChainIdentity::genesis(
        "node-integration-fixture",
        StateRoot(finality_host::root(None, &state, &[])),
    );
    CanonicalStore::create(&path, chain.clone(), state.snapshot(), 0)
        .await
        .unwrap()
        .close()
        .await;
    let authority = finality_host::Authority {
        seed: 1,
        chain: chain.clone(),
    };
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&directory.path().join("checkpoints.db"))
            .await
            .unwrap(),
    );
    let fail_views = Arc::new(AtomicBool::new(false));
    let node = open(
        &path,
        checkpoints.clone(),
        chain.clone(),
        fail_views.clone(),
    )
    .await;
    let seen = Arc::new(Mutex::new(vec![]));
    node.register(Recorder(seen.clone())).await.unwrap();
    let (request, settlement) = announce();
    let domain = &settlement.session.domain;
    let admission = node.vpn_authority(settlement.clone());
    let service = node
        .bind(
            "127.0.0.1:0".parse().unwrap(),
            vpn_config(&directory.path().join("vpn"), domain),
            settlement.clone(),
        )
        .await
        .unwrap();
    let browser = format!("http://{}", service.browser_addr().unwrap());
    let control = format!("http://{}", service.control_addr().unwrap());
    let endpoint = service.tunnel_addr();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(service.run(shutdown));
    let http = reqwest::Client::new();
    assert_eq!(http.get(&browser).send().await.unwrap().status(), 503);
    assert_eq!(
        http.post(format!("{control}/session"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    assert!(node.resume().await.unwrap());
    let old = node.snapshot().unwrap();
    let scope = old.provenance().id();
    let token = view(&http, &browser, &scope, &circle).await;
    assert_eq!(
        counter(&http, &browser, &token)
            .await
            .json::<Value>()
            .await
            .unwrap(),
        json!({"result":{"result":"4"}})
    );
    let asset = format!("{browser}/asset/{scope}/{circle}/index.html");
    assert!(http
        .get(&asset)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
        .contains("Canonical Circle"));
    assert_eq!(
        http.post(format!("{control}/session"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let permit = admission
        .authorize(&request, domain)
        .await
        .unwrap()
        .unwrap();
    assert!(permit.live());
    let (mut tunnel, socket) = handshake(endpoint).await;
    // Exercise authenticated WireGuard/onion input while refusing local egress.
    // Rejected traffic must not increase a billable receipt.
    let onion = build_onion(
        &[HopBuildInput {
            static_pubkey: PublicKey::from(&StaticSecret::from([41; 32])).to_bytes(),
            endpoint: endpoint.to_string(),
        }],
        &[127, 0, 0, 1, 0, 9, 17],
    )
    .unwrap();
    let frame = tunnel_frame::encode(&request.session_id, &onion).unwrap();
    send(&mut tunnel, &socket, &frame).await;
    let before = metered(&http, &control, &request).await;
    assert_eq!(before.bytes_served, 0);
    assert!(tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let r = metered(&http, &control, &request).await;
            assert_eq!(
                r.bytes_served, before.bytes_served,
                "denied local egress was billed"
            );
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_err());
    let (_, mut executed) = execute(&old, circle.as_bytes(), &authority);
    add_rejected_call(&old, &mut executed);
    let certificate = finality_host::certificate(old.head(), &executed, &authority)
        .encode()
        .unwrap();
    let archived_bundle = network_bundle(&executed);
    let set = authority.validators(old.head(), 1).unwrap();
    let reader = bundle_peer::node(
        chain.chain_id.as_bytes(),
        b"validator-0".to_vec(),
        SigningKey::from_bytes(&[1; 32]),
        set.clone(),
        vec![],
    )
    .await;
    let server = bundle_peer::node(
        chain.chain_id.as_bytes(),
        b"validator-1".to_vec(),
        SigningKey::from_bytes(&[2; 32]),
        set,
        vec![reader.endpoint.clone()],
    )
    .await;
    bundle_peer::wait_for(|| reader.swarm.peers().len() == 1).await;
    let executor = ImportExecutor::new(&authority, &node);
    let mut forged = Finalize::decode(&certificate).unwrap();
    forged.precommits[0].signature[0] ^= 1;
    let forged = acquire_certificate(&reader, &server, &forged, &executed, false).await;
    assert!(node
        .import_finalized(&forged, &reader.bundles, &executor, 1.)
        .await
        .is_err());
    assert!(permit.live());
    assert_eq!(node.head().await.unwrap(), *old.head());
    assert!(seen.lock().unwrap().is_empty());
    assert!(
        server.authority.requests.lock().unwrap().is_empty(),
        "bad QC must not query peers"
    );
    let received = acquire_certificate(
        &reader,
        &server,
        &Finalize::decode(&certificate).unwrap(),
        &executed,
        true,
    )
    .await;
    assert_eq!(received, certificate);
    let certificate = received;
    assert!(node
        .import_finalized(&certificate, &reader.bundles, &executor, 0.15)
        .await
        .unwrap()
        .is_none());
    assert!(permit.live());
    assert_eq!(node.head().await.unwrap(), *old.head());
    assert!(seen.lock().unwrap().is_empty());
    let id = hash::proposal_id(&Finalize::decode(&certificate).unwrap().header).unwrap();
    server
        .authority
        .cached
        .lock()
        .unwrap()
        .insert(id, network_bundle(&executed));
    // Cancelling an import while its reply is held cannot publish or revoke
    // current browser/VPN capabilities.
    reader.gate.send_replace(false);
    let prior_queries = server.authority.requests.lock().unwrap().len();
    let mut interrupted =
        Box::pin(node.import_finalized(&certificate, &reader.bundles, &executor, 3.));
    tokio::select! {
        result = &mut interrupted => panic!("held query completed: {}", result.is_ok()),
        () = bundle_peer::wait_for(|| server.authority.requests.lock().unwrap().len() > prior_queries) => (),
    }
    drop(interrupted);
    reader.gate.send_replace(true);
    assert!(permit.live());
    assert_eq!(server.authority.address, b"validator-1");
    assert_eq!(node.head().await.unwrap(), *old.head());
    for failure in [&executor.fail, &executor.corrupt] {
        failure.store(true, Ordering::SeqCst);
        assert!(node
            .import_finalized(&certificate, &reader.bundles, &executor, 3.)
            .await
            .is_err());
        failure.store(false, Ordering::SeqCst);
        assert!(permit.live());
        assert_eq!(node.head().await.unwrap(), *old.head());
        assert!(seen.lock().unwrap().is_empty());
    }
    let published = node
        .import_finalized(&certificate, &reader.bundles, &executor, 3.)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(published.services, Status::Serving(_)));
    assert!(!permit.live());
    reached(&node, 1).await;
    assert_eq!(*seen.lock().unwrap(), vec![1]);
    assert_eq!(
        node.history().bundle(&id).await.unwrap(),
        Some(archived_bundle.clone())
    );
    let first_id = id;
    assert_eq!(http.get(&asset).send().await.unwrap().status(), 400);
    assert_eq!(counter(&http, &browser, &token).await.status(), 400);
    let current = node.snapshot().unwrap();
    let token = view(&http, &browser, &current.provenance().id(), &circle).await;
    assert_eq!(
        counter(&http, &browser, &token)
            .await
            .json::<Value>()
            .await
            .unwrap(),
        json!({"result":{"result":"5"}})
    );
    node.suspend("catching up");
    assert!(admission.authorize(&request, domain).await.is_err());
    assert_eq!(http.get(&browser).send().await.unwrap().status(), 503);
    send(&mut tunnel, &socket, &frame).await;
    assert_eq!(
        metered(&http, &control, &request).await.bytes_served,
        before.bytes_served
    );
    assert!(node.resume().await.unwrap());
    let renewed = admission
        .authorize(&request, domain)
        .await
        .unwrap()
        .unwrap();
    assert!(renewed.live());
    let (certificate, executed) = execute(&current, circle.as_bytes(), &authority);
    let received = acquire_certificate(
        &reader,
        &server,
        &Finalize::decode(&certificate).unwrap(),
        &executed,
        false,
    )
    .await;
    assert_eq!(received, certificate);
    let certificate = received;
    fail_views.store(true, Ordering::SeqCst);
    let id = hash::proposal_id(&Finalize::decode(&certificate).unwrap().header).unwrap();
    server
        .authority
        .cached
        .lock()
        .unwrap()
        .insert(id, network_bundle(&executed));
    let published = node
        .import_finalized(&certificate, &reader.bundles, &executor, 3.)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(published.head.cursor.epoch.0, 2);
    assert!(matches!(published.services, Status::Suspended(_)));
    assert!(!renewed.live());
    reached(&node, 2).await;
    assert_eq!(*seen.lock().unwrap(), vec![1, 2]);
    assert!(node.resume().await.is_err());
    fail_views.store(false, Ordering::SeqCst);
    assert!(node.resume().await.unwrap());
    assert!(admission
        .authorize(&request, domain)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        admission
            .lifecycle(&request.session_id, domain)
            .await
            .unwrap(),
        RelayLifecycle::Terminal(2)
    );
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    node.shutdown().await.unwrap();
    drop(node);

    let node = open(&path, checkpoints.clone(), chain, fail_views).await;
    assert_eq!(
        node.history().bundle(&first_id).await.unwrap(),
        Some(archived_bundle)
    );
    assert!(matches!(node.status(), Status::Suspended(_)));
    assert!(node.snapshot().is_err());
    node.register(Recorder(seen.clone())).await.unwrap();
    reached(&node, 2).await;
    assert_eq!(
        *seen.lock().unwrap(),
        vec![1, 2],
        "durable checkpoint must avoid replay"
    );
    let service = node
        .bind(
            "127.0.0.1:0".parse().unwrap(),
            vpn_config(&directory.path().join("vpn"), domain),
            settlement.clone(),
        )
        .await
        .unwrap();
    let browser = format!("http://{}", service.browser_addr().unwrap());
    let control = format!("http://{}", service.control_addr().unwrap());
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(service.run(shutdown));
    assert_eq!(http.get(&browser).send().await.unwrap().status(), 503);
    assert!(node.resume().await.unwrap());
    assert_eq!(
        http.post(format!("{control}/session"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let scope = node.snapshot().unwrap().provenance().id();
    let token = view(&http, &browser, &scope, &circle).await;
    assert_eq!(
        counter(&http, &browser, &token)
            .await
            .json::<Value>()
            .await
            .unwrap(),
        json!({"result":{"result":"6"}})
    );
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn resume_reauthenticates_earlier_finality_after_raw_storage_change() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.db");
    let circle = format!("oct{}", "1".repeat(44));
    let state = genesis(circle.as_bytes());
    let chain = ChainIdentity::genesis(
        "resume-full-audit-fixture",
        StateRoot(finality_host::root(None, &state, &[])),
    );
    CanonicalStore::create(&path, chain.clone(), state.snapshot(), 0)
        .await
        .unwrap()
        .close()
        .await;
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&directory.path().join("checkpoints.db"))
            .await
            .unwrap(),
    );
    let authority = finality_host::Authority {
        seed: 1,
        chain: chain.clone(),
    };
    let node = open(&path, checkpoints, chain, Arc::default()).await;
    assert!(node.resume().await.unwrap());
    for _ in 0..2 {
        let view = node.snapshot().unwrap();
        let (certificate, executed) = execute(&view, circle.as_bytes(), &authority);
        node.publish(view.head(), &certificate, executed)
            .await
            .unwrap();
    }
    // Prime an in-process audited prefix before changing an earlier row.
    node.suspend("checking retained history");
    assert!(node.resume().await.unwrap());
    let head = node.head().await.unwrap();
    assert_eq!(head.cursor.sequence.0, 2);

    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    let original: Vec<u8> =
        sqlx::query_scalar("SELECT certificate FROM node_epochs WHERE sequence=1")
            .fetch_one(&db)
            .await
            .unwrap();
    sqlx::query("UPDATE node_epochs SET certificate=? WHERE sequence=1")
        .bind([0_u8].as_slice())
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(node.head().await.unwrap(), head);
    node.suspend("checking retained history");
    assert!(node.resume().await.is_err());
    assert!(matches!(node.status(), Status::Suspended(_)));
    assert!(node.snapshot().is_err());

    sqlx::query("UPDATE node_epochs SET certificate=? WHERE sequence=1")
        .bind(original)
        .execute(&db)
        .await
        .unwrap();
    assert!(node.resume().await.unwrap());
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn empty_finalized_import_needs_no_peer_and_rejects_wrong_parent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("empty.db");
    let state = genesis(format!("oct{}", "1".repeat(44)).as_bytes());
    let chain = ChainIdentity::genesis(
        "empty-import-fixture",
        StateRoot(finality_host::root(None, &state, &[])),
    );
    CanonicalStore::create(&path, chain.clone(), state.snapshot(), 0)
        .await
        .unwrap()
        .close()
        .await;
    let authority = finality_host::Authority {
        seed: 1,
        chain: chain.clone(),
    };
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&directory.path().join("checkpoints.db"))
            .await
            .unwrap(),
    );
    let node = open(
        &path,
        checkpoints,
        chain.clone(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    let parent = node.head().await.unwrap();
    let executed = execute_received(
        &parent,
        StateBatch::from_snapshot(state.snapshot()),
        &[],
        &authority,
        None,
        None,
    )
    .unwrap();
    let certificate = finality_host::certificate(&parent, &executed, &authority);
    let reader = bundle_peer::node(
        chain.chain_id.as_bytes(),
        b"validator-0".to_vec(),
        SigningKey::from_bytes(&[1; 32]),
        authority.validators(&parent, 1).unwrap(),
        vec![],
    )
    .await;
    let executor = ImportExecutor::new(&authority, &node);
    let mut wrong = certificate.clone();
    wrong.header.prev_state_root[0] ^= 1;
    finality_host::sign(&mut wrong, authority.seed);
    let result = node
        .import_finalized(&wrong.encode().unwrap(), &reader.bundles, &executor, 0.)
        .await;
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("previous root mismatch"));
    assert_eq!(node.head().await.unwrap(), parent);
    let committed = node
        .import_finalized(
            &certificate.encode().unwrap(),
            &reader.bundles,
            &executor,
            0.,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.head.cursor.epoch.0, 1);
    assert!(matches!(committed.services, Status::Suspended(_)));
    // This fixture records Host.lookup calls, including the explicit local
    // cache read; it does not record network requests. The wrong-parent
    // certificate was refused before lookup, and the valid empty import made
    // exactly one local lookup without needing a connected peer.
    assert!(reader.swarm.peers().is_empty());
    assert_eq!(
        reader.authority.requests.lock().unwrap().as_slice(),
        &[hash::proposal_id(&certificate.header).unwrap()]
    );
    node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consecutive_peer_recovery_resumes_after_missing_bundle_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.db");
    let path = directory.path().join("recover.db");
    let circle = format!("oct{}", "1".repeat(44));
    let state = genesis(circle.as_bytes());
    let chain = ChainIdentity::genesis(
        "node-recovery-fixture",
        StateRoot(finality_host::root(None, &state, &[])),
    );
    for path in [&source_path, &path] {
        CanonicalStore::create(path, chain.clone(), state.snapshot(), 0)
            .await
            .unwrap()
            .close()
            .await;
    }
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&directory.path().join("recover-checkpoints.db"))
            .await
            .unwrap(),
    );
    let source_checkpoints = Arc::new(
        SqliteCheckpoints::open(&directory.path().join("source-checkpoints.db"))
            .await
            .unwrap(),
    );
    let source = open(
        &source_path,
        source_checkpoints.clone(),
        chain.clone(),
        Arc::default(),
    )
    .await;
    source.resume().await.unwrap();
    let authority = finality_host::Authority {
        seed: 1,
        chain: chain.clone(),
    };
    let set = authority
        .validators(&source.head().await.unwrap(), 1)
        .unwrap();
    let reader = bundle_peer::node(
        chain.chain_id.as_bytes(),
        b"validator-0".to_vec(),
        SigningKey::from_bytes(&[1; 32]),
        set.clone(),
        vec![],
    )
    .await;
    let server = bundle_peer::node(
        chain.chain_id.as_bytes(),
        b"validator-1".to_vec(),
        SigningKey::from_bytes(&[2; 32]),
        set.clone(),
        vec![reader.endpoint.clone()],
    )
    .await;
    let stale = bundle_peer::node(
        chain.chain_id.as_bytes(),
        b"validator-2".to_vec(),
        SigningKey::from_bytes(&[3; 32]),
        set.clone(),
        vec![reader.endpoint.clone()],
    )
    .await;
    bundle_peer::wait_for(|| reader.swarm.peers().len() == 2).await;
    let mut ids = vec![];
    for _ in 1..=3 {
        let view = source.snapshot().unwrap();
        let (certificate, executed) = execute(&view, circle.as_bytes(), &authority);
        let finalized = Finalize::decode(&certificate).unwrap();
        let id = hash::proposal_id(&finalized.header).unwrap();
        ids.push(id);
        source
            .publish(view.head(), &certificate, executed)
            .await
            .unwrap();
    }
    let target = source.head().await.unwrap();
    source.shutdown().await.unwrap();
    drop(source);
    let source = open(
        &source_path,
        source_checkpoints,
        chain.clone(),
        Arc::default(),
    )
    .await;
    *server.authority.history.lock().unwrap() = Some(source.history());
    assert!(server.authority.cached.lock().unwrap().is_empty());
    assert!(server.authority.ranges.lock().unwrap().is_empty());
    source.shutdown().await.unwrap();
    drop(source);
    server.authority.withheld.lock().unwrap().insert(ids[1]);

    let peers = octra_node::sync::Peers {
        roots: &reader.roots,
        finality: &reader.finality,
        bundles: &reader.bundles,
    };
    let node = open(&path, checkpoints.clone(), chain.clone(), Arc::default()).await;
    let executor = ImportExecutor::new(&authority, &node);
    let seen = Arc::new(Mutex::new(vec![]));
    node.register(Recorder(seen.clone())).await.unwrap();
    node.resume().await.unwrap();
    let (request, settlement) = announce();
    let admission = node.vpn_authority(settlement.clone());
    let permit = admission
        .authorize(&request, &settlement.session.domain)
        .await
        .unwrap()
        .unwrap();
    let range = node
        .catch_up_range(3, &reader.finality, &executor, 5.)
        .await
        .unwrap();
    assert!(!range.reached);
    assert_eq!(range.head.cursor.epoch.0, 0);
    assert!(stale
        .authority
        .range_requests
        .lock()
        .unwrap()
        .iter()
        .any(|(epoch, _)| *epoch == 1));
    assert!(server
        .authority
        .range_requests
        .lock()
        .unwrap()
        .iter()
        .any(|(epoch, _)| *epoch == 1));
    reader
        .authority
        .range_plan_error
        .store(true, Ordering::SeqCst);
    let unavailable = node
        .catch_up_range(3, &reader.finality, &executor, 5.)
        .await
        .unwrap();
    assert!(!unavailable.reached);
    assert_eq!(unavailable.head, range.head);
    reader
        .authority
        .range_plan_error
        .store(false, Ordering::SeqCst);
    let progress = node.catch_up(3, &peers, &executor, 10.).await.unwrap();
    assert!(!progress.reached);
    assert_eq!(progress.head.cursor.epoch.0, 1);
    assert!(matches!(node.status(), Status::Suspended(_)));
    assert!(!permit.live());
    assert!(node.snapshot().is_err());
    assert!(reader
        .seen
        .lock()
        .unwrap()
        .iter()
        .any(|f| f.message == 0x35));
    bundle_peer::wait_for(|| *seen.lock().unwrap() == vec![1]).await;
    reached(&node, 1).await;
    node.shutdown().await.unwrap();
    drop(node);

    let node = open(&path, checkpoints, chain, Arc::default()).await;
    assert_eq!(node.head().await.unwrap(), progress.head);
    let seen = Arc::new(Mutex::new(vec![]));
    node.register(Recorder(seen.clone())).await.unwrap();
    server.authority.withheld.lock().unwrap().remove(&ids[1]);
    // Stop while the next certificate is in flight. Neither a concurrent
    // resume nor a late reply may expose or publish an intermediate view.
    reader.gate.send(false).unwrap();
    let requested = server.authority.range_requests.lock().unwrap().len();
    let received = reader
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|f| f.message == 0x3b)
        .count();
    let mut recovering = Box::pin(node.catch_up(3, &peers, &executor, 10.));
    tokio::select! {
        result = &mut recovering => panic!("unexpected recovery completion: {:?}", result.err()),
        () = bundle_peer::wait_for(|| server.authority.range_requests.lock().unwrap().len() > requested) => (),
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), node.resume())
            .await
            .is_err()
    );
    drop(recovering);
    reader.gate.send(true).unwrap();
    bundle_peer::wait_for(|| {
        reader
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.message == 0x3b)
            .count()
            > received
    })
    .await;
    assert_eq!(node.head().await.unwrap(), progress.head);
    assert!(matches!(node.status(), Status::Suspended(_)));
    executor.corrupt.store(true, Ordering::SeqCst);
    assert!(matches!(
        node.catch_up(3, &peers, &executor, 1.).await,
        Err(octra_node::sync::PeerCatchUpError::Invalid(_))
    ));
    assert_eq!(node.head().await.unwrap(), progress.head);
    assert!(seen.lock().unwrap().is_empty());
    executor.corrupt.store(false, Ordering::SeqCst);
    let progress = node.catch_up(3, &peers, &executor, 1.).await.unwrap();
    assert!(progress.reached);
    same_consensus_head(&progress.head, &target);
    assert!(matches!(node.status(), Status::Suspended(_)));
    bundle_peer::wait_for(|| *seen.lock().unwrap() == vec![2, 3]).await;
    reached(&node, 3).await;
    let service = node
        .bind(
            "127.0.0.1:0".parse().unwrap(),
            vpn_config(
                &directory.path().join("vpn-recovery"),
                &settlement.session.domain,
            ),
            settlement,
        )
        .await
        .unwrap();
    let browser = format!("http://{}", service.browser_addr().unwrap());
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(service.run(shutdown));
    let http = reqwest::Client::new();
    assert_eq!(http.get(&browser).send().await.unwrap().status(), 503);
    node.resume().await.unwrap();
    let token = view(
        &http,
        &browser,
        &node.snapshot().unwrap().provenance().id(),
        &circle,
    )
    .await;
    assert_eq!(
        counter(&http, &browser, &token)
            .await
            .json::<Value>()
            .await
            .unwrap(),
        json!({"result":{"result":"7"}})
    );
    let requests = server.authority.range_requests.lock().unwrap().len();
    assert!(
        node.catch_up(3, &peers, &executor, 0.)
            .await
            .unwrap()
            .reached
    );
    assert_eq!(
        server.authority.range_requests.lock().unwrap().len(),
        requests
    );
    assert!(matches!(node.status(), Status::Serving(_)));
    assert!(node
        .catch_up(u64::MAX, &peers, &executor, 1.)
        .await
        .is_err());
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agreed_ranges_recover_canonical_services_and_exex_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("range-source.db");
    let path = directory.path().join("range-target.db");
    let circle = format!("oct{}", "1".repeat(44));
    let state = genesis(circle.as_bytes());
    let chain = ChainIdentity::genesis(
        "node-range-fixture",
        StateRoot(finality_host::root(None, &state, &[])),
    );
    for path in [&source_path, &path] {
        CanonicalStore::create(path, chain.clone(), state.snapshot(), 0)
            .await
            .unwrap()
            .close()
            .await;
    }
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&directory.path().join("range-checkpoints.db"))
            .await
            .unwrap(),
    );
    let source_checkpoints = Arc::new(
        SqliteCheckpoints::open(&directory.path().join("range-source-checkpoints.db"))
            .await
            .unwrap(),
    );
    let source = open(
        &source_path,
        source_checkpoints.clone(),
        chain.clone(),
        Arc::default(),
    )
    .await;
    source.resume().await.unwrap();
    let authority = finality_host::Authority {
        seed: 1,
        chain: chain.clone(),
    };
    let set = authority
        .validators(&source.head().await.unwrap(), 1)
        .unwrap();
    let reader = bundle_peer::node(
        chain.chain_id.as_bytes(),
        b"validator-0".to_vec(),
        SigningKey::from_bytes(&[1; 32]),
        set.clone(),
        vec![],
    )
    .await;
    let first = bundle_peer::node(
        chain.chain_id.as_bytes(),
        b"validator-1".to_vec(),
        SigningKey::from_bytes(&[2; 32]),
        set.clone(),
        vec![reader.endpoint.clone()],
    )
    .await;
    let second = bundle_peer::node(
        chain.chain_id.as_bytes(),
        b"validator-2".to_vec(),
        SigningKey::from_bytes(&[3; 32]),
        set,
        vec![reader.endpoint.clone()],
    )
    .await;
    bundle_peer::wait_for(|| reader.swarm.peers().len() == 2).await;
    let initial_view = source.snapshot().unwrap();
    let (certificate, executed) = execute(&initial_view, circle.as_bytes(), &authority);
    source
        .publish(initial_view.head(), &certificate, executed)
        .await
        .unwrap();
    drop(initial_view);
    for server in [&first, &second] {
        *server.authority.history.lock().unwrap() = Some(source.history());
    }

    let node = open(&path, checkpoints.clone(), chain.clone(), Arc::default()).await;
    let executor = ImportExecutor::new(&authority, &node);
    let seen = Arc::new(Mutex::new(vec![]));
    node.register(Recorder(seen.clone())).await.unwrap();
    node.resume().await.unwrap();
    let octra_node_runtime::finality_queries::Range::Found { records, .. } =
        source.history().range(1, 1).await.unwrap()
    else {
        panic!("source history missing");
    };
    let initial_head = node.head().await.unwrap();
    executor.fail.store(true, Ordering::SeqCst);
    for variant in 0..6 {
        let mut forged = records[0].clone();
        match variant {
            0 => forged.epoch_ts += 1.,
            1 => {
                forged.finality.as_mut().unwrap().validator_set =
                    octra_node_protocol::consensus::ValidatorSet::unweighted(vec![]);
            }
            2 => forged.reward_source.as_mut().unwrap().reward_members[0].reward_weight = 0.into(),
            3 => forged.txs_json[0] = b"{}".to_vec(),
            4 => forged.prev_state_root[0] ^= 1,
            _ => forged.tx_hashes.push(vec![0; 32]),
        }
        let error = node.import_record(&forged, &executor).await.err().unwrap();
        assert!(
            !format!("{error:#}").contains("fixture execution unavailable"),
            "record variant {variant} reached execution before authentication"
        );
        assert_eq!(node.head().await.unwrap(), initial_head);
    }
    executor.fail.store(false, Ordering::SeqCst);
    let (request, settlement) = announce();
    let admission = node.vpn_authority(settlement.clone());
    let permit = admission
        .authorize(&request, &settlement.session.domain)
        .await
        .unwrap()
        .unwrap();
    // Both authenticated sources have only a one-epoch committed prefix.
    let progress = node
        .catch_up_range(3, &reader.finality, &executor, 5.)
        .await
        .unwrap();
    assert!(!progress.reached);
    assert_eq!(progress.head.cursor.epoch.0, 1);
    assert!(!permit.live());
    assert!(node.snapshot().is_err());
    bundle_peer::wait_for(|| *seen.lock().unwrap() == vec![1]).await;
    reached(&node, 1).await;
    for server in [&first, &second] {
        assert!(server.authority.cached.lock().unwrap().is_empty());
        assert!(server.authority.ranges.lock().unwrap().is_empty());
        assert!(
            server.authority.requests.lock().unwrap().is_empty(),
            "range import refetched bundles"
        );
    }
    node.shutdown().await.unwrap();
    drop(node);
    source.shutdown().await.unwrap();
    drop(source);
    let source = open(
        &source_path,
        source_checkpoints,
        chain.clone(),
        Arc::default(),
    )
    .await;
    source.resume().await.unwrap();
    for _ in 2..=3 {
        let view = source.snapshot().unwrap();
        let (certificate, executed) = execute(&view, circle.as_bytes(), &authority);
        source
            .publish(view.head(), &certificate, executed)
            .await
            .unwrap();
    }
    let target = source.head().await.unwrap();
    for server in [&first, &second] {
        *server.authority.history.lock().unwrap() = Some(source.history());
    }
    source.shutdown().await.unwrap();
    drop(source);
    let node = open(&path, checkpoints, chain, Arc::default()).await;
    assert_eq!(node.head().await.unwrap(), progress.head);
    let seen = Arc::new(Mutex::new(vec![]));
    node.register(Recorder(seen.clone())).await.unwrap();
    reader.gate.send(false).unwrap();
    let requests = first.authority.range_requests.lock().unwrap().len();
    let replies = reader
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|f| f.message == 0x3b)
        .count();
    let mut recovering = Box::pin(node.catch_up_range(3, &reader.finality, &executor, 10.));
    tokio::select! {
        result=&mut recovering => panic!("unexpected recovery completion: {:?}",result.err()),
        ()=bundle_peer::wait_for(||first.authority.range_requests.lock().unwrap().len()>requests) => (),
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), node.resume())
            .await
            .is_err()
    );
    drop(recovering);
    reader.gate.send(true).unwrap();
    bundle_peer::wait_for(|| {
        reader
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.message == 0x3b)
            .count()
            >= replies + 2
    })
    .await;
    assert_eq!(node.head().await.unwrap(), progress.head);
    assert!(node.snapshot().is_err());
    executor.corrupt.store(true, Ordering::SeqCst);
    assert!(node
        .catch_up_range(3, &reader.finality, &executor, 2.)
        .await
        .is_err());
    assert_eq!(node.head().await.unwrap(), progress.head);
    assert!(seen.lock().unwrap().is_empty());
    executor.corrupt.store(false, Ordering::SeqCst);
    let progress = node
        .catch_up_range(3, &reader.finality, &executor, 2.)
        .await
        .unwrap();
    assert!(progress.reached);
    same_consensus_head(&progress.head, &target);
    assert!(matches!(node.status(), Status::Suspended(_)));
    bundle_peer::wait_for(|| *seen.lock().unwrap() == vec![2, 3]).await;
    reached(&node, 3).await;
    let service = node
        .bind(
            "127.0.0.1:0".parse().unwrap(),
            vpn_config(
                &directory.path().join("range-vpn"),
                &settlement.session.domain,
            ),
            settlement,
        )
        .await
        .unwrap();
    let browser = format!("http://{}", service.browser_addr().unwrap());
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(service.run(shutdown));
    let http = reqwest::Client::new();
    assert_eq!(http.get(&browser).send().await.unwrap().status(), 503);
    node.resume().await.unwrap();
    let token = view(
        &http,
        &browser,
        &node.snapshot().unwrap().provenance().id(),
        &circle,
    )
    .await;
    assert_eq!(
        counter(&http, &browser, &token)
            .await
            .json::<Value>()
            .await
            .unwrap(),
        json!({"result":{"result":"7"}})
    );
    assert!(
        node.catch_up_range(3, &reader.finality, &executor, 0.)
            .await
            .unwrap()
            .reached
    );
    assert!(matches!(node.status(), Status::Serving(_)));
    assert!(node
        .catch_up_range(u64::MAX, &reader.finality, &executor, 1.)
        .await
        .is_err());
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    node.shutdown().await.unwrap();
}

#[path = "services/cancellation.rs"]
mod cancellation;
#[path = "services/gateway.rs"]
mod gateway;
#[path = "services/http_join.rs"]
mod http_join;
#[path = "services/live.rs"]
mod live;
#[path = "services/local_bundles.rs"]
mod local_bundles;
#[path = "services/pending.rs"]
mod pending;
#[path = "services/proposals.rs"]
mod proposals;
#[path = "services/root_quarantine.rs"]
mod root_quarantine;
