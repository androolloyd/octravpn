//! Real native execution using the launcher's own genesis, execution policy and
//! checkpoint-open path. No fabricated application state or finality is used.
use super::*;
use crate::{bootstrap, executor::Native, Node};
use ed25519_dalek::Signer;
use octra_browser::application::UnavailableHost;
use octra_exex::{
    native_history::NativeTransaction, sqlite::SqliteCheckpoints, CommittedEpoch, Cursor, ExEx,
};
use octra_node_protocol::{
    aml::source::{self, Syntax},
    circle_program::Deploy,
    consensus::{codec::Wire, hash, Finalize, Vote, VoteType},
    native_json::Document,
    state_sync::{anchor, roots},
    transaction::{OpType, Transaction},
};
use octra_node_runtime::{
    canonical::CanonicalStore, circle_assets::CanonicalAssets, circle_query::Query, circle_view,
    finality::proposal::Policy, validator_history::Authority,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
fn runtime() -> CircleRuntime {
    CircleRuntime::isolated(
        octra_node_runtime::crypto_worker::Pool::open(
            &std::env::current_exe().unwrap(),
            octra_node_runtime::crypto_worker::Limits::from_values(|_| None),
        )
        .unwrap(),
    )
}
struct Seen(Arc<Mutex<Vec<Cursor>>>);
impl ExEx<NativeTransaction> for Seen {
    fn name(&self) -> &'static str {
        "private-launch"
    }
    async fn on_epoch(
        &mut self,
        epoch: &CommittedEpoch<NativeTransaction>,
    ) -> std::result::Result<(), String> {
        self.0.lock().unwrap().push(epoch.cursor);
        Ok(())
    }
}
struct Rig {
    node: Arc<Node<Authority>>,
    native: Native,
    graph: Graph,
    config: Config,
    keys: Vec<SigningKey>,
    seen: Arc<Mutex<Vec<Cursor>>>,
}
impl Rig {
    async fn open(config: Config, keys: Vec<SigningKey>) -> Self {
        let (store, graph) = recovery::open(&config).await.unwrap();
        let environment = Environment {
            current: Some(config.genesis.validators.join(",").into_bytes()),
            ..Environment::default()
        };
        let host = Authority::new(
            store.reader(),
            environment,
            ReceiptPolicy::new(
                Some(b"0"),
                &Profile::from_values(Some(b"devnet_full_v1"), None, None),
                None,
            ),
            JournalOwner::open(&config.data).unwrap(),
        );
        let node = Arc::new(
            Node::open(
                store,
                host,
                runtime(),
                Arc::new(UnavailableHost),
                Arc::new(
                    SqliteCheckpoints::open(&config.data.join("exex.db"))
                        .await
                        .unwrap(),
                ),
            )
            .await
            .unwrap()
            .with_view_graph(graph.clone())
            .unwrap(),
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        node.register(Seen(seen.clone())).await.unwrap();
        assert!(node.resume().await.unwrap());
        let native = Native::new(
            execution(&config, graph.clone(), Protocol::new(2).unwrap()),
            node.runtime.clone(),
            node.history(),
        )
        .unwrap();
        Self {
            node,
            native,
            graph,
            config,
            keys,
            seen,
        }
    }
    fn next_time(&self, epoch: u64) -> f64 {
        f64::from(u32::try_from(epoch + 1).unwrap()).mul_add(10., self.config.genesis.time)
    }
    async fn wait_exex(&self, cursor: Cursor) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.seen.lock().unwrap().last() != Some(&cursor) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    fn transaction(
        &self,
        target: &str,
        op_type: OpType,
        method: &[u8],
        parameters: &Value,
    ) -> Transaction {
        let key = read_key(&self.config.faucet).unwrap();
        let from = address(&key);
        let head = self.node.snapshot().unwrap();
        let nonce = account_store::load(&StateBatch::from_snapshot(head.state().clone()), &from)
            .unwrap()
            .unwrap()
            .nonce
            .successor();
        let mut tx = Transaction {
            from,
            to: target.as_bytes().to_vec(),
            amount: 0.into(),
            nonce,
            ou: 5_000_000.into(),
            timestamp: self.next_time(head.head().cursor.epoch.0),
            op_type,
            encrypted_data: Some(method.to_vec()),
            message: Some(serde_json::to_vec(parameters).unwrap()),
            public_key: Some(public(&key).into_bytes()),
            signature: vec![],
        };
        tx.signature = STANDARD
            .encode(key.sign(&tx.signing_bytes().unwrap()).to_bytes())
            .into_bytes();
        tx
    }
    async fn publish(&self, inputs: Vec<Transaction>) {
        let parent = self.node.snapshot().unwrap().head().clone();
        let draft = Arc::new(
            self.node
                .proposal_draft(
                    &self.graph,
                    Policy {
                        protocol: Protocol::new(2).unwrap(),
                        genesis_time: Some(self.config.genesis.time),
                    },
                    &address(&self.keys[0]),
                    self.next_time(parent.cursor.epoch.0),
                )
                .await
                .unwrap(),
        );
        let built = self.native.build_proposal(draft, inputs).await.unwrap();
        assert!(built.refused().is_empty());
        assert!(built.held().is_empty());
        for receipt in built.execution().vm_receipts.values() {
            let result: Value = serde_json::from_slice(receipt).unwrap();
            assert_eq!(result["success"], true, "{result}");
        }
        let mut finalized = Finalize {
            chain_id: self.config.genesis.chain.chain_id.as_bytes().to_vec(),
            epoch_id: built.plan().header.epoch_id,
            commit_round: 0,
            header: built.plan().header.clone(),
            proposal_id: vec![],
            precommits: vec![],
            parent_commit: built.plan().parent_commit.clone(),
        };
        finalized.proposal_id = hash::proposal_id(&finalized.header).unwrap().to_vec();
        finalized.precommits = self
            .keys
            .iter()
            .take(3)
            .map(|key| {
                let mut vote = Vote {
                    chain_id: finalized.chain_id.clone(),
                    epoch_id: finalized.epoch_id,
                    round: 0,
                    vote_type: VoteType::Precommit,
                    proposal_id: finalized.proposal_id.clone(),
                    validator: address(key),
                    signature: vec![],
                };
                vote.signature = key
                    .sign(&hash::vote_sign_bytes(&vote).unwrap())
                    .to_bytes()
                    .to_vec();
                vote
            })
            .collect();
        self.node
            .publish(
                &parent,
                &finalized.encode().unwrap(),
                built.execution().clone(),
            )
            .await
            .unwrap();
    }
    async fn count(&self, circle: &str) -> Value {
        let assets = CanonicalAssets::capture(&self.node.store).await.unwrap();
        let profile =
            circle_view::canonical_with_graph(&assets, &self.graph, self.node.history().as_ref())
                .await
                .unwrap();
        assert!(profile.math);
        let result = Query::committed(&assets, &profile)
            .unwrap()
            .with_runtime(&self.node.runtime)
            .circle(
                circle.as_bytes(),
                b"get",
                &Document::parse(b"[]").unwrap(),
                &address(&self.keys[0]),
                1_000_000,
            )
            .unwrap();
        assert!(result.success);
        serde_json::from_slice(&result.response.unwrap().result_json()).unwrap()
    }
}
async fn config(directory: &Path, apps: bool) -> (Config, Vec<SigningKey>) {
    let paths = init_with_applications(&directory.join("genesis"), 24000, apps)
        .await
        .unwrap();
    let keys = paths
        .iter()
        .map(|p| read_key(&read(p).unwrap().key).unwrap())
        .collect();
    let mut config = read(&paths[0]).unwrap();
    config.genesis.time -= 1800.;
    config.genesis.chain.origin = octra_exex::ChainOrigin::Genesis {
        state_root: root(&state(&config.genesis).unwrap()).unwrap(),
    };
    (config, keys)
}
#[cfg(feature = "private-payments-experimental")]
#[tokio::test]
async fn remote_private_observer_peers_never_relax_listeners_or_validator_scope() {
    let directory = tempfile::tempdir().unwrap();
    let (mut config, _) = config(directory.path(), true).await;
    config.peers = vec!["93.184.216.11:20870".parse().unwrap()];
    config.voting = false;
    assert!(validate_sockets(&config).is_err());
    config.private_route = Some(
        crate::vpn::payments::shielded::payer::startup::route::Config {
            id: [1; 32],
            hops: vec![],
            chain_dns: std::collections::BTreeMap::default(),
        },
    );
    // This tests only socket policy. Ordinary route validation independently
    // refuses the placeholder; the separate-kernel fixture supplies real jobs.
    assert!(validate_sockets(&config).is_ok());
    assert!(validate_shielded(&config).is_err());
    config.voting = true;
    assert!(validate_sockets(&config).is_err());
    config.voting = false;
    config.genesis.activated_applications = false;
    assert!(validate_sockets(&config).is_err());
    config.genesis.activated_applications = true;
    config.rpc = "0.0.0.0:19901".parse().unwrap();
    assert!(validate_sockets(&config).is_err());
}

#[tokio::test]
async fn private_launcher_preserves_native_circle_execution_and_exex_across_trusted_checkpoint_reopen(
) {
    let temp = tempfile::tempdir().unwrap();
    let (config, keys) = config(temp.path(), true).await;
    let rig = Rig::open(config.clone(), keys.clone()).await;
    assert!(rig.graph.has_proven_application_opt_in());
    let code=source::compile(b"program PrivateCounter { state { count: uint } fn initialize() { self.count = 0 } fn inc(): uint { self.count = self.count + 1 return self.count } view fn get(): uint { return self.count } }",Syntax::Source,true).unwrap().octb;
    let payload = json!({"runtime":"octb","privacy_class":"public","browser_mode":"gateway_allowed","resource_mode":"public_resources","code_b64":STANDARD.encode(code),"limits":{"max_stable_bytes":"33554432","max_assets_bytes":"33554432","max_inline_value":"65536","max_wasm_bytes":"33554432"}});
    let preliminary = rig.transaction("", OpType::CircleDeploy, b"", &payload);
    let circle = String::from_utf8(
        Deploy::from_document(&Document::parse(&serde_json::to_vec(&payload).unwrap()).unwrap())
            .unwrap()
            .id(&preliminary.from, preliminary.nonce),
    )
    .unwrap();
    rig.publish(vec![rig.transaction(
        &circle,
        OpType::CircleDeploy,
        b"",
        &payload,
    )])
    .await;
    rig.publish(vec![rig.transaction(
        &circle,
        OpType::CircleCall,
        b"initialize",
        &json!([]),
    )])
    .await;
    rig.publish(vec![rig.transaction(
        &circle,
        OpType::CircleCall,
        b"inc",
        &json!([]),
    )])
    .await;
    assert_eq!(rig.count(&circle).await, json!("1"));
    while rig.node.snapshot().unwrap().head().cursor.epoch.0 <= roots::WIDTH as u64 {
        rig.publish(vec![]).await;
    }
    let head = rig.node.snapshot().unwrap().head().clone();
    rig.wait_exex(head.cursor).await;
    assert_eq!(rig.seen.lock().unwrap().last(), Some(&head.cursor));
    let network = bootstrap::Network {
        identity: config.genesis.chain.clone(),
        config_hash: hex::encode(Sha256::digest(serde_json::to_vec(&config.genesis).unwrap())),
        validators: config.genesis.validators.clone(),
        exporters: vec![config.genesis.validators[0].clone()],
        minimum_epoch: 0,
        migration_root: None,
    };
    let authority = bootstrap::Authority::new(network.clone()).unwrap();
    let finality = anchor::Anchor {
        steps: vec![],
        finalize: Finalize::decode(
            &rig.node
                .store
                .certificate(head.cursor.sequence)
                .await
                .unwrap(),
        )
        .unwrap(),
        validator_set: anchor::raw_validator_set(authority.trust().validators).unwrap(),
    };
    let image = temp.path().join("snapshot");
    let finality_path = temp.path().join("finality.oce1");
    std::fs::write(&finality_path, finality.encode().unwrap()).unwrap();
    let ledger = bootstrap::export::ledger(
        &authority,
        &config.data,
        &temp.path().join("private.ledger"),
        octra_node_runtime::ledger_image::Limits::default(),
    )
    .await
    .unwrap();
    assert_eq!(ledger.epoch, head.cursor.epoch.0);
    assert_eq!(ledger.ledger.root, head.ledger_root);
    bootstrap::export::prepare(
        &authority,
        &config.data,
        &image,
        bootstrap::export::Prepare {
            finality: finality_path,
            chunk_size: 1_048_576,
            valid_for: 86_400,
            limits: octra_node_runtime::ledger_image::Limits::default(),
        },
    )
    .await
    .unwrap();
    bootstrap::export::assemble(
        &authority,
        &image,
        bootstrap::export::Assemble {
            exporter_key: Some(config.key.clone()),
            exporter_signatures: vec![],
            checkpoint_signatures: vec![],
            limits: octra_node_runtime::ledger_image::Limits::default(),
        },
    )
    .unwrap();
    let raw = std::fs::read(image.join("snapshot.certificate.json")).unwrap();
    let window = std::fs::read(image.join("ready_roots")).unwrap();
    let state = rig.node.store.reader().snapshot_at(&head).await.unwrap();
    let target = temp.path().join("restored");
    std::fs::create_dir(&target).unwrap();
    let imported = CanonicalStore::create_from_checkpoint(
        &target.join("canonical.sqlite"),
        config.genesis.chain.clone(),
        state,
        &raw,
        &window,
        &authority.trust(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    )
    .await
    .unwrap();
    imported.close().await;
    let mut recovered = config.clone();
    recovered.data = target;
    assert!(recovery::open(&recovered).await.is_err());
    assert!(!recovered.data.join("canonical.db").exists());
    recovered.checkpoint_trust = Some(network.clone());
    for change in 0..3 {
        let mut bad = recovered.clone();
        let trust = bad.checkpoint_trust.as_mut().unwrap();
        match change {
            0 => trust.config_hash = "ff".repeat(32),
            1 => {
                trust.validators.remove(0);
            }
            _ => trust.identity.chain_id = "other".into(),
        }
        assert!(recovery::open(&bad).await.is_err());
    }
    rig.node.shutdown().await.unwrap();
    drop(rig);
    let restored = Rig::open(recovered.clone(), keys.clone()).await;
    assert_eq!(restored.node.store.anchor().cursor.epoch, head.cursor.epoch);
    assert!(restored
        .node
        .store
        .reader()
        .head_for_epoch(0)
        .await
        .is_err());
    assert!(restored.graph.has_proven_application_opt_in());
    assert_eq!(restored.count(&circle).await, json!("1"));
    restored
        .publish(vec![restored.transaction(
            &circle,
            OpType::CircleCall,
            b"inc",
            &json!([]),
        )])
        .await;
    assert_eq!(restored.count(&circle).await, json!("2"));
    let current = restored.node.snapshot().unwrap().head().cursor;
    restored.wait_exex(current).await;
    assert_eq!(restored.seen.lock().unwrap().last(), Some(&current));
    restored.node.shutdown().await.unwrap();
    drop(restored);
    let restarted = Rig::open(recovered.clone(), keys).await;
    assert_eq!(restarted.count(&circle).await, json!("2"));
    restarted.node.shutdown().await.unwrap();
    drop(restarted);
    std::fs::write(recovered.data.join("canonical.db"), []).unwrap();
    assert!(recovery::open(&recovered).await.is_err());
}

#[tokio::test]
async fn private_launcher_never_treats_flags_or_downloaded_trust_as_genesis_authority() {
    let temp = tempfile::tempdir().unwrap();
    let (config, _) = config(temp.path(), false).await;
    let (store, graph) = recovery::open(&config).await.unwrap();
    assert!(!graph.has_proven_application_opt_in());
    store.close().await;
    let mut altered = config.clone();
    altered.genesis.activated_applications = true;
    assert!(recovery::open(&altered).await.is_err());
    let mut public = config.clone();
    public.genesis.chain.chain_id = "octra-mainnet".into();
    public.genesis.activated_applications = true;
    public.genesis.chain.origin = octra_exex::ChainOrigin::Genesis {
        state_root: root(&state(&public.genesis).unwrap()).unwrap(),
    };
    assert!(recovery::open(&public).await.is_err());
    let mut absent = config.clone();
    absent.data = temp.path().join("missing");
    absent.checkpoint_trust = Some(bootstrap::Network {
        identity: config.genesis.chain.clone(),
        config_hash: "aa".repeat(32),
        validators: config.genesis.validators.clone(),
        exporters: vec![config.genesis.validators[0].clone()],
        minimum_epoch: 0,
        migration_root: None,
    });
    assert!(recovery::open(&absent).await.is_err());
    assert!(!absent.data.exists());
    let old = serde_json::to_value(&config).unwrap();
    assert!(old.get("checkpoint_trust").is_none());
    let mut relative = config.clone();
    relative.data = "node-0".into();
    relative.key = "node-0/validator.key".into();
    relative.faucet = "faucet.key".into();
    let file = temp.path().join("genesis/config.json");
    std::fs::write(&file, serde_json::to_vec(&relative).unwrap()).unwrap();
    let read = read(&file).unwrap();
    assert_eq!(read.data, config.data);
    assert_eq!(read.key, config.key);
    assert_eq!(read.faucet, config.faucet);
    let mut public_genesis = config.genesis.clone();
    public_genesis.chain.chain_id = "octra-mainnet".into();
    let public_state = state(&public_genesis).unwrap();
    public_genesis.chain.origin = octra_exex::ChainOrigin::Genesis {
        state_root: root(&public_state).unwrap(),
    };
    let mut public_network = absent.checkpoint_trust.unwrap();
    public_network.identity = public_genesis.chain.clone();
    let public_authority = bootstrap::Authority::new(public_network).unwrap();
    let public_source = temp.path().join("public-source");
    std::fs::create_dir(&public_source).unwrap();
    let ordinary = CanonicalStore::create(
        &public_source.join("canonical.db"),
        public_genesis.chain,
        public_state.snapshot(),
        0,
    )
    .await
    .unwrap();
    ordinary.close().await;
    let output = temp.path().join("refused-public.ledger");
    assert!(bootstrap::export::ledger(
        &public_authority,
        &public_source,
        &output,
        octra_node_runtime::ledger_image::Limits::default()
    )
    .await
    .is_err());
    assert!(!output.exists());
}
