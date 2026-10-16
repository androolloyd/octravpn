//! Actual stored genesis/provenance and real Circle engine integration. The
//! private fixture graph never changes public graph defaults or voting rules.
use async_trait::async_trait;
use octra_browser::{
    application::{ApplicationHost, Context, ReadMethod, ReadRequest},
    AssetResolver,
};
use octra_exex::{ChainIdentity, StateRoot};
use octra_node_protocol::{epoch_index, rules::Graph, transaction::RuleMode};
use octra_node_runtime::{
    canonical::{AppliedEpoch, CanonicalStore, Head},
    circle_application::CanonicalApplications,
    circle_assets::CanonicalAssets,
    circle_view,
    consensus_bundle::RawBundle,
    finality::{self, history::History},
    finality_queries::Range,
    state_batch::StateBatch,
};
use serde_json::json;
#[path = "common/circle_host.rs"]
mod common;
const CHAIN: &str = "octra-rust-local-0123456789abcdef";
struct Roots<'a> {
    store: &'a CanonicalStore,
    wrong: bool,
}
#[async_trait]
impl History for Roots<'_> {
    async fn head(&self) -> Result<Head, finality::Error> {
        Ok(self.store.head().await?)
    }
    async fn root(&self, epoch: i64) -> Result<Option<Vec<u8>>, finality::Error> {
        let Ok(epoch) = u64::try_from(epoch) else {
            return Ok(None);
        };
        Ok(self
            .store
            .reader()
            .head_for_epoch_opt(epoch)
            .await?
            .map(|head| {
                if self.wrong {
                    vec![9; 32]
                } else {
                    head.cursor.state_root.0.to_vec()
                }
            }))
    }
    async fn range(&self, _: i64, _: i64) -> Result<Range, finality::Error> {
        Err(finality::Error::Unavailable("no finality fixture".into()))
    }
    async fn bundle(&self, _: &[u8; 32]) -> Result<Option<RawBundle>, finality::Error> {
        Err(finality::Error::Unavailable("no finality fixture".into()))
    }
}
fn root(state: &StateBatch, base: Option<&Head>) -> [u8; 32] {
    let previous = base.map_or_else(
        || hex::encode(epoch_index::genesis_root()),
        |h| h.index_root.clone(),
    );
    let epoch = base.map_or(0, |h| i64::try_from(h.cursor.epoch.0).unwrap() + 1);
    let index = epoch_index::next_root(previous.as_bytes(), epoch, &[])
        .unwrap()
        .1;
    epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap()
}
fn make_state(opt_in: bool) -> StateBatch {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    state.set(&[b"meta", b"last_epoch"], b"0".to_vec()).unwrap();
    state.set(&[b"meta",b"local_devnet"],serde_json::to_vec(&json!({"chain_id":CHAIN,"profile":"devnet_full_v1","activated_applications":opt_in})).unwrap()).unwrap();
    common::install_counter(&mut state, b"circle", b"4");
    state
}
async fn create_store(path: &std::path::Path, state: &StateBatch) -> CanonicalStore {
    CanonicalStore::create(
        path,
        ChainIdentity::genesis(CHAIN, StateRoot(root(state, None))),
        state.snapshot(),
        0,
    )
    .await
    .unwrap()
}
#[tokio::test]
async fn captured_execution_graph_reaches_real_circle_view_and_default_remains_prior() {
    let dir = tempfile::tempdir().unwrap();
    let state = make_state(true);
    let store = create_store(&dir.path().join("chain.db"), &state).await;
    let assets = CanonicalAssets::capture(&store).await.unwrap();
    let graph = Graph::isolated_applications(
        CHAIN.as_bytes().to_vec(),
        None,
        store.chain().genesis_root().unwrap().0,
    )
    .unwrap();
    let history = Roots {
        store: &store,
        wrong: false,
    };
    let old = circle_view::canonical(&assets, &history).await.unwrap();
    assert!(!old.math && !old.point_ops);
    assert_eq!(old.proof_exec, RuleMode::Prior);
    let profile = circle_view::canonical_with_graph(&assets, &graph, &history)
        .await
        .unwrap();
    assert!(profile.math && profile.point_ops && profile.object_cost && profile.int_work);
    assert_eq!(profile.proof_exec, RuleMode::Active);
    assert_eq!(profile.fhe_work, RuleMode::Active);
    assert_eq!(profile.wasm_float, RuleMode::Prior);
    let before = store.head().await.unwrap();
    let provenance = assets.provenance();
    let host = CanonicalApplications::new(assets, common::runtime(), profile);
    let reply = host
        .read(ReadRequest {
            context: Context {
                circle_id: "circle".into(),
                provenance,
            },
            method: ReadMethod::ProgramView,
            params: json!({"method":"get_counter","params":[]}),
        })
        .await
        .unwrap();
    assert_eq!(reply, json!({"result":"4"}));
    assert_eq!(store.head().await.unwrap(), before);
    store.close().await;
}
#[tokio::test]
async fn captured_graph_rejects_wrong_identity_anchor_and_unreadable_original_opt_in() {
    let dir = tempfile::tempdir().unwrap();
    let state = make_state(true);
    let store = create_store(&dir.path().join("chain.db"), &state).await;
    let assets = CanonicalAssets::capture(&store).await.unwrap();
    let good = Graph::isolated_applications(
        CHAIN.as_bytes().to_vec(),
        None,
        store.chain().genesis_root().unwrap().0,
    )
    .unwrap();
    let wrong = Graph::isolated_applications(CHAIN.as_bytes().to_vec(), None, [9; 32]).unwrap();
    let history = Roots {
        store: &store,
        wrong: false,
    };
    assert!(circle_view::canonical_with_graph(&assets, &wrong, &history)
        .await
        .unwrap_err()
        .to_string()
        .contains("anchor differs"));
    let foreign = Graph::new(b"foreign-chain".to_vec(), None);
    assert!(
        circle_view::canonical_with_graph(&assets, &foreign, &history)
            .await
            .unwrap_err()
            .to_string()
            .contains("chain differs")
    );
    let history = Roots {
        store: &store,
        wrong: true,
    };
    assert!(circle_view::canonical_with_graph(&assets, &good, &history)
        .await
        .is_err());
    store.close().await;
    for (name, raw) in [
        ("malformed", b"not-json".to_vec()),
        ("oversized", vec![b'x'; 65537]),
    ] {
        let mut state = StateBatch::from_snapshot(state.snapshot());
        state.begin().unwrap();
        state.set(&[b"meta", b"local_devnet"], raw).unwrap();
        let store = create_store(&dir.path().join(format!("{name}.db")), &state).await;
        let assets = CanonicalAssets::capture(&store).await.unwrap();
        let graph = Graph::isolated_applications(
            CHAIN.as_bytes().to_vec(),
            None,
            store.chain().genesis_root().unwrap().0,
        )
        .unwrap();
        assert!(circle_view::canonical_with_graph(
            &assets,
            &graph,
            &Roots {
                store: &store,
                wrong: false
            }
        )
        .await
        .is_err());
        store.close().await;
    }
}
#[tokio::test]
async fn later_opt_in_cannot_activate_a_genesis_that_did_not_commit_it() {
    let dir = tempfile::tempdir().unwrap();
    let initial = make_state(false);
    let store = create_store(&dir.path().join("chain.db"), &initial).await;
    let graph = Graph::isolated_applications(
        CHAIN.as_bytes().to_vec(),
        None,
        store.chain().genesis_root().unwrap().0,
    )
    .unwrap();
    let history = Roots {
        store: &store,
        wrong: false,
    };
    let assets = CanonicalAssets::capture(&store).await.unwrap();
    assert!(circle_view::canonical_with_graph(&assets, &graph, &history)
        .await
        .is_err());
    let before = store.head().await.unwrap();
    let mut later = StateBatch::from_snapshot(store.snapshot().await.unwrap().1.snapshot());
    later.begin().unwrap();
    later.set(&[b"meta", b"last_epoch"], b"1".to_vec()).unwrap();
    later
        .set(
            &[b"meta", b"local_devnet"],
            serde_json::to_vec(
                &json!({"chain_id":CHAIN,"profile":"devnet_full_v1","activated_applications":true}),
            )
            .unwrap(),
        )
        .unwrap();
    let prepared = store
        .prepare(
            &before,
            AppliedEpoch {
                epoch: 1,
                state: later.snapshot(),
                expected_root: StateRoot(root(&later, Some(&before))),
                transactions: vec![],
                certificate: b"storage fixture only; no finality claim".to_vec(),
                date: 1,
                message: b"later flag".to_vec(),
            },
        )
        .await
        .unwrap();
    prepared.commit().await.unwrap();
    let assets = CanonicalAssets::capture(&store).await.unwrap();
    assert!(circle_view::canonical_with_graph(&assets, &graph, &history)
        .await
        .unwrap_err()
        .to_string()
        .contains("opt-in differs"));
    store.close().await;
}

#[tokio::test]
async fn private_single_application_genesis_reaches_real_circle_view_and_rejects_wrong_profile() {
    const SINGLE: &str = "octra-single-local-0123456789abcdef";
    let dir = tempfile::tempdir().unwrap();
    for (name, profile, opt_in) in [
        ("valid", "single_applications_v1", true),
        ("wrong-profile", "devnet_full_v1", true),
        ("disabled", "single_applications_v1", false),
    ] {
        let mut state = make_state(false);
        state
            .set(
                &[b"meta", b"local_single"],
                serde_json::to_vec(
                    &json!({"chain_id":SINGLE,"profile":profile,"activated_applications":opt_in}),
                )
                .unwrap(),
            )
            .unwrap();
        let store = CanonicalStore::create(
            &dir.path().join(format!("{name}.db")),
            ChainIdentity::genesis(SINGLE, StateRoot(root(&state, None))),
            state.snapshot(),
            0,
        )
        .await
        .unwrap();
        let assets = CanonicalAssets::capture(&store).await.unwrap();
        let graph = Graph::isolated_single_applications(
            SINGLE.as_bytes().to_vec(),
            None,
            store.chain().genesis_root().unwrap().0,
        )
        .unwrap();
        let history = Roots {
            store: &store,
            wrong: false,
        };
        let resolved = circle_view::canonical_with_graph(&assets, &graph, &history).await;
        if name == "valid" {
            let profile = resolved.unwrap();
            assert!(profile.math && profile.point_ops && profile.object_cost && profile.int_work);
            assert_eq!(profile.proof_exec, RuleMode::Active);
            assert_eq!(profile.fhe_work, RuleMode::Active);
            assert_eq!(profile.wasm_float, RuleMode::Prior);
            let before = store.head().await.unwrap();
            let provenance = assets.provenance();
            let host = CanonicalApplications::new(assets, common::runtime(), profile);
            assert_eq!(
                host.read(ReadRequest {
                    context: Context {
                        circle_id: "circle".into(),
                        provenance
                    },
                    method: ReadMethod::ProgramView,
                    params: json!({"method":"get_counter","params":[]})
                })
                .await
                .unwrap(),
                json!({"result":"4"})
            );
            assert_eq!(store.head().await.unwrap(), before);
        } else {
            assert!(resolved.unwrap_err().to_string().contains("opt-in differs"));
        }
        store.close().await;
    }
}
