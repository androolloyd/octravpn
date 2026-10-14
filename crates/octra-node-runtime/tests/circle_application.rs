use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use octra_browser::{
    application::{ApplicationHost, Context, ReadMethod, ReadRequest},
    Error,
};
use octra_exex::{
    native_history::{ArchiveProof, NativeTransaction},
    sqlite::SqliteCheckpoints,
    ChainIdentity, CommittedEpoch, CommittedEpochSource, ExEx, ExExManager, Sequence, StateRoot,
};
use octra_node_protocol::{
    consensus::codec::Wire,
    epoch_index,
    state::Account,
    transaction::{self, Nonce, OpType, RuleMode, Transaction},
    transaction_payload::Limits,
    transaction_policy::Profile,
};
use octra_node_runtime::{
    account_store,
    admission::{self, Postcheck, Precheck},
    circle_transaction,
    execution::{Completion, Outcome},
    finality::{ExecutedEpoch, Publisher},
};
use std::sync::Arc;
#[path = "common/finality_host.rs"]
mod finality_host;
use octra_node_runtime::{
    canonical::CanonicalStore, circle::WasmRules, circle_application::CanonicalApplications,
    circle_assets::CanonicalAssets, state_batch::StateBatch,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[path = "common/circle_host.rs"]
mod common;

async fn create(path: &std::path::Path, state: &StateBatch) -> CanonicalStore {
    let index = epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
        .unwrap()
        .1;
    let root = epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap();
    CanonicalStore::create(
        path,
        ChainIdentity {
            chain_id: "circle-view-test".into(),
            genesis_root: StateRoot(root),
        },
        state.snapshot(),
        0,
    )
    .await
    .unwrap()
}
async fn host(store: &CanonicalStore, profile: WasmRules) -> CanonicalApplications {
    let assets = CanonicalAssets::capture(store).await.unwrap();
    let profile = common::view_profile(&assets, profile);
    CanonicalApplications::new(assets, common::runtime(), profile)
}
fn profile() -> WasmRules {
    WasmRules {
        wasm_float: false,
        proof_exec: false,
        math: false,
    }
}
fn request(host: &CanonicalApplications, circle: &str, method: &str, params: Value) -> ReadRequest {
    let mut arguments = json!({"method":method});
    arguments["params"] = params;
    ReadRequest {
        context: Context {
            circle_id: circle.into(),
            provenance: host.provenance(),
        },
        method: ReadMethod::ProgramView,
        params: arguments,
    }
}
fn result(result: Result<Value, Error>) -> Value {
    match result {
        Ok(v) => v,
        Err(Error::Invalid(e) | Error::Unavailable(e)) => json!({"error":e}),
        Err(e) => panic!("unexpected error: {e}"),
    }
}
#[tokio::test]
async fn real_wasm_views_match_complete_native_host_outcomes() {
    let fixture = common::fixture();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inventory: Value = serde_json::from_slice(
        &std::fs::read(root.join("docs/rust-node/source-map.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(
            std::fs::read(root.join("scripts/node-port/circle-view-oracle.ml")).unwrap()
        ))
    );
    let wasm = STANDARD
        .decode(fixture["wasm_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(fixture["wasm_sha256"], hex::encode(Sha256::digest(&wasm)));
    let dir = tempfile::tempdir().unwrap();
    for (i, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let circle = input["circle"].as_str().unwrap();
        let mut state = StateBatch::default();
        state.begin().unwrap();
        for entry in input["entries"].as_array().unwrap() {
            let path = entry["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| STANDARD.decode(v.as_str().unwrap()).unwrap())
                .collect::<Vec<_>>();
            state
                .set(
                    &path.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                    STANDARD.decode(entry["value"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
        }
        state
            .set(
                &[b"circles", circle.as_bytes(), b"program", b"code_b64"],
                STANDARD.encode(&wasm).into_bytes(),
            )
            .unwrap();
        state
            .set(
                &[b"circles", circle.as_bytes(), b"code_hash"],
                hex::encode(Sha256::digest(&wasm)).into_bytes(),
            )
            .unwrap();
        assert_eq!(hex::encode(state.root().unwrap()), case["expected"]["root"]);
        let store = create(&dir.path().join(format!("case-{i}.db")), &state).await;
        let host = host(
            &store,
            WasmRules {
                wasm_float: input["float"].as_bool().unwrap(),
                proof_exec: input["proof"].as_bool().unwrap(),
                math: input["math"].as_bool().unwrap(),
            },
        )
        .await;
        let request = request(
            &host,
            circle,
            input["method"].as_str().unwrap(),
            input["params"].clone(),
        );
        assert_eq!(
            result(host.read(request).await),
            case["expected"]["found"],
            "native case {i}"
        );
        assert_eq!(
            hex::encode(store.snapshot().await.unwrap().1.root().unwrap()),
            case["expected"]["root"],
            "view mutated state"
        );
        store.close().await;
    }
}

#[tokio::test]
async fn signed_circle_transactions_reach_canonical_views_and_exex_through_restart() {
    signed_counter(false).await;
}
#[tokio::test]
async fn signed_octb_transactions_reach_canonical_views_and_exex_through_restart() {
    signed_counter(true).await;
}
async fn signed_counter(octb: bool) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.db");
    let mut state = StateBatch::default();
    state.begin().unwrap();
    state.set(&[b"meta", b"last_epoch"], b"0".to_vec()).unwrap();
    let circle = format!("oct{}", "1".repeat(44));
    if octb {
        common::install_octb_counter(&mut state, circle.as_bytes());
    } else {
        common::install_counter(&mut state, circle.as_bytes(), b"4");
    }
    // Public deterministic development wallet, confined to this temporary chain.
    let key = SigningKey::from_bytes(&[42; 32]);
    let public_key = STANDARD.encode(key.verifying_key().to_bytes()).into_bytes();
    let sender = transaction::address_from_public_key(&public_key);
    let account = Account {
        balance: 10_000.into(),
        public_key: Some(public_key.clone()),
        ..Account::default()
    };
    account_store::set(&mut state, &sender, &account, RuleMode::Active).unwrap();
    let mut ledger = account_store::ledger(&state).unwrap();
    state
        .set(&[b"meta", b"emission_remaining"], b"0".to_vec())
        .unwrap();
    state
        .set(&[b"meta", b"total_supply"], b"10000".to_vec())
        .unwrap();
    for circle in [b"private".as_slice(), b"bad-code", b"octb"] {
        common::install_counter(&mut state, circle, b"77");
    }
    state
        .set(
            &[b"circles", b"private", b"privacy", b"class"],
            b"sealed".to_vec(),
        )
        .unwrap();
    state
        .set(&[b"circles", b"bad-code", b"code_hash"], b"bad".to_vec())
        .unwrap();
    state
        .set(&[b"circles", b"octb", b"runtime"], b"octb".to_vec())
        .unwrap();
    let store = Arc::new(create(&path, &state).await);
    let authority = finality_host::Authority {
        seed: 1,
        chain: store.chain().clone(),
    };
    let publisher = Publisher::open(store.clone(), authority.clone())
        .await
        .unwrap();
    let old = host(&store, profile()).await;
    let base = store.head().await.unwrap();
    assert_eq!(
        old.read(request(&old, &circle, "get_counter", json!([])))
            .await
            .unwrap(),
        json!({"result":"4"})
    );
    assert!(matches!(
        old.read(request(&old, "private", "get_counter", json!([])))
            .await,
        Err(Error::Sealed)
    ));
    assert_eq!(
        result(
            old.read(request(&old, "bad-code", "get_counter", json!([])))
                .await
        ),
        json!({"error":"circle code hash mismatch"})
    );
    assert!(matches!(
        old.read(request(&old, "octb", "get_counter", json!([])))
            .await,
        Err(Error::Invalid(_))
    ));
    if !octb {
        assert!(matches!(
            old.read(request(&old, &circle, "fhe_encrypt_of", json!([])))
                .await,
            Err(Error::Unavailable(_))
        ));
    }
    let mut info = request(&old, &circle, "unused", json!([]));
    info.method = ReadMethod::ProgramInfo;
    info.params = json!({});
    let info = old.read(info).await.unwrap();
    assert_eq!(info["has_program"], true);
    assert!(info["code_b64"].is_null());
    assert!(info["methods"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["name"] == "get_counter"));
    let mut wallet = request(&old, &circle, "unused", json!([]));
    wallet.method = ReadMethod::WalletInfo;
    assert!(matches!(old.read(wallet).await, Err(Error::Unavailable(_))));
    let mut next = store.snapshot().await.unwrap().1;
    next.begin().unwrap();
    // Native signing bytes and RPC admission precede the sender/savepoint loop.
    // The independently signed QC uses fixture validators, not a peer driver.
    let release = Profile::from_values(Some(b"devnet_full_v1"), None, None);
    let pre = Precheck {
        now: 1.,
        max_timestamp_drift: 60.,
        observer: false,
        bft: true,
        profile: &release,
        duty: None,
        limits: Limits::default(),
    };
    let post = Postcheck {
        preverify_has_capacity: true,
        preverify_pending: Nonce::default(),
        preverify_pending_max: Nonce::new(100).unwrap(),
        bft: true,
        confirmed_nonce: Nonce::default(),
        bft_window: Nonce::new(100).unwrap(),
    };
    let transactions = (1..=5)
        .map(|n| {
            let mut tx = Transaction {
                from: sender.clone(),
                to: circle.as_bytes().to_vec(),
                amount: 1.into(),
                nonce: Nonce::new(n).unwrap(),
                ou: 1000.into(),
                timestamp: 1.,
                signature: vec![],
                public_key: Some(public_key.clone()),
                message: Some(b"[]".to_vec()),
                encrypted_data: Some(b"inc".to_vec()),
                op_type: OpType::CircleCall,
            };
            tx.signature = STANDARD
                .encode(key.sign(&tx.signing_bytes().unwrap()).to_bytes())
                .into_bytes();
            let mut forged = tx.clone();
            forged.amount += 1;
            assert!(admission::submit(forged, &ledger, &pre, post).is_err());
            octra_node_protocol::transaction_policy::staging_admission(
                &tx,
                &3000.into(),
                &1.into(),
            )
            .unwrap();
            admission::submit(tx, &ledger, &pre, post)
                .unwrap()
                .into_transaction()
        })
        .collect::<Vec<_>>();
    transaction::check_envelopes(RuleMode::Active, &transactions).unwrap();
    let batch = circle_transaction::execute(
        &common::runtime(),
        circle_transaction::Rules {
            manifest: octra_node_runtime::circle::WasmProfile::Compute,
            update_policy: false,
            wasm: profile(),
            inspect: true,
            storage_proof: true,
            fhe_work: false,
        },
        1,
        123.5,
        &transactions,
        &mut ledger,
        &mut next,
    )
    .unwrap();
    assert_eq!(batch.fees, 5000.into());
    assert_eq!(batch.receipts.len(), 5);
    assert_eq!(batch.outcomes.len(), 5);
    assert!(batch
        .outcomes
        .iter()
        .all(|e| matches!(e.outcome, Outcome::Completed(Completion::Confirmed { .. }))));
    assert_eq!(ledger.account(&sender).unwrap().balance, 4995.into());
    assert_eq!(
        ledger.account(&sender).unwrap().nonce,
        Nonce::new(5).unwrap()
    );
    assert_eq!(ledger.account(circle.as_bytes()).unwrap().balance, 5.into());
    let footer = octra_node_runtime::epoch_footer::apply(
        &octra_node_runtime::epoch_footer::Policy {
            emission_guard: true,
            schedule: octra_node_protocol::emission::Schedule::Inactive,
            legacy_total: None,
        },
        &octra_node_runtime::epoch_footer::Request {
            epoch: 1,
            reward: &finality_host::reward(authority.seed),
            validator_keys: &[],
            confirmed_fees: batch.fees.clone(),
        },
        &mut ledger,
        &mut next,
    )
    .unwrap();
    assert_eq!(footer.plan.total_reward, 5000.into());
    assert_eq!(footer.plan.fees_burned, 0.into());
    assert_eq!(ledger.total_supply(), &10000.into());
    assert_eq!(ledger.account(b"validator-0").unwrap().balance, 3875.into());
    assert_eq!(ledger.account(b"validator-1").unwrap().balance, 375.into());
    account_store::flush_dirty(&mut ledger, &mut next, RuleMode::Active).unwrap();
    let archive = transactions
        .iter()
        .enumerate()
        .map(|(index, tx)| {
            let hash = hex::encode(tx.hash().unwrap());
            let identity = tx.identity_bytes().unwrap();
            let item = NativeTransaction {
                txid: i64::try_from(index).unwrap(),
                proof: ArchiveProof::Exact,
                identity: identity.clone(),
                transaction: identity,
                receipt: Some(batch.receipts[&hash].clone()),
                hash,
            };
            item.validate().unwrap();
            item
        })
        .collect::<Vec<_>>();
    next.set(&[b"meta", b"last_epoch"], b"1".to_vec()).unwrap();
    let executed = ExecutedEpoch {
        reward_source: finality_host::reward_source(authority.seed),
        state: next.snapshot(),
        transactions: archive.clone(),
        consensus_receipts: vec![], // Local fixture has preverification disabled.
        date: 1,
        message: b"advance counter snapshot".to_vec(),
    };
    let certificate = finality_host::certificate(&base, &executed, &authority)
        .encode()
        .unwrap();
    let prepared = publisher
        .prepare(&base, &certificate, executed)
        .await
        .unwrap();
    assert_eq!(host(&store, profile()).await.provenance(), old.provenance());
    assert!(store.source().load(Sequence(1)).await.unwrap().is_none());
    let published = prepared.commit().await.unwrap();
    assert_eq!(
        store
            .source()
            .load(Sequence(1))
            .await
            .unwrap()
            .unwrap()
            .events,
        archive
    );
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&dir.path().join("extension.db"))
            .await
            .unwrap(),
    );
    let mut manager = ExExManager::new(store.source(), checkpoints.clone()).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager.register(Recorder(tx)).await.unwrap();
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivered.cursor, published.cursor);
    assert_eq!(delivered.events, archive);
    assert_eq!(
        manager.stop("circle-integration").await.unwrap(),
        published.cursor
    );
    drop(manager);
    let new = host(&store, profile()).await;
    assert_eq!(store.source().head().await.unwrap().epoch.0, 1);
    assert_eq!(
        new.read(request(&new, &circle, "get_counter", json!([])))
            .await
            .unwrap(),
        json!({"result":"9"})
    );
    assert!(matches!(
        new.read(request(&old, &circle, "get_counter", json!([])))
            .await,
        Err(Error::SnapshotChanged)
    ));
    assert_eq!(
        old.read(request(&old, &circle, "get_counter", json!([])))
            .await
            .unwrap(),
        json!({"result":"4"})
    );
    let chain = store.chain().clone();
    publisher.audit().await.unwrap();
    drop(publisher);
    Arc::try_unwrap(store).ok().unwrap().close().await;
    let reopened = Arc::new(CanonicalStore::open(&path, &chain).await.unwrap());
    let publisher = Publisher::open(reopened.clone(), authority).await.unwrap();
    let recovered = host(&reopened, profile()).await;
    assert_eq!(new.provenance(), recovered.provenance());
    assert_eq!(
        recovered
            .read(request(&recovered, &circle, "get_counter", json!([])))
            .await
            .unwrap(),
        json!({"result":"9"})
    );
    let state = reopened.snapshot().await.unwrap().1;
    let recovered_ledger = account_store::ledger(&state).unwrap();
    assert_eq!(recovered_ledger.accounts(), ledger.accounts());
    assert_eq!(recovered_ledger.total_supply(), ledger.total_supply());
    assert_eq!(
        account_store::load(&state, &sender).unwrap(),
        ledger.account(&sender).cloned()
    );
    assert_eq!(
        account_store::load(&state, circle.as_bytes()).unwrap(),
        ledger.account(circle.as_bytes()).cloned()
    );
    assert_eq!(
        reopened
            .source()
            .load(Sequence(1))
            .await
            .unwrap()
            .unwrap()
            .events,
        archive
    );
    let mut manager = ExExManager::new(reopened.source(), checkpoints).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager.register(Recorder(tx)).await.unwrap();
    manager.notify_commit();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
            .await
            .is_err()
    );
    assert_eq!(
        manager.stop("circle-integration").await.unwrap(),
        published.cursor
    );
    drop(manager);
    drop(publisher);
    Arc::try_unwrap(reopened).ok().unwrap().close().await;
}

struct Recorder(tokio::sync::mpsc::UnboundedSender<CommittedEpoch<NativeTransaction>>);
impl ExEx<NativeTransaction> for Recorder {
    fn name(&self) -> &'static str {
        "circle-integration"
    }
    fn on_epoch(
        &mut self,
        epoch: &CommittedEpoch<NativeTransaction>,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send {
        let result = self.0.send(epoch.clone()).map_err(|e| e.to_string());
        async move { result }
    }
}
