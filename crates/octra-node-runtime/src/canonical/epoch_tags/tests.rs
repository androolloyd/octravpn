use super::*;
use crate::{canonical::AppliedEpoch, state_batch::StateBatch};
use octra_exex::{ChainIdentity, EpochId, Sequence, StateRoot};
use octra_node_protocol::{epoch_index, irmin};
use serde_json::Value;
use sha2::{Digest, Sha256};

async fn fixture(meta: Option<&[u8]>) -> (tempfile::TempDir, CanonicalStore) {
    fixture_with_retention(meta, EpochTagRetention::capture().unwrap()).await
}

async fn fixture_with_retention(
    meta: Option<&[u8]>,
    retention: EpochTagRetention,
) -> (tempfile::TempDir, CanonicalStore) {
    let directory = tempfile::tempdir().unwrap();
    let mut state = StateBatch::default();
    state.begin().unwrap();
    if let Some(raw) = meta {
        state.set(&[b"meta", b"last_epoch"], raw.to_vec()).unwrap();
    }
    state.set(&[b"value"], b"genesis".to_vec()).unwrap();
    let index = epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
        .unwrap()
        .1;
    let root = epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap();
    let store = CanonicalStore::create_with_retention(
        &directory.path().join("chain.db"),
        ChainIdentity::genesis("epoch-tag-storage-fixture", StateRoot(root)),
        state.snapshot(),
        0,
        retention,
    )
    .await
    .unwrap();
    (directory, store)
}

async fn prepare(store: &CanonicalStore) -> super::super::PreparedCommit {
    let (head, mut state) = store.snapshot().await.unwrap();
    let epoch = head.cursor.epoch.0 + 1;
    state.begin().unwrap();
    state
        .set(&[b"meta", b"last_epoch"], epoch.to_string().into_bytes())
        .unwrap();
    state.set(&[b"value"], b"successor".to_vec()).unwrap();
    let snapshot = state.snapshot();
    let expected_root = super::super::execution_root(&head, epoch, &snapshot, &[]).unwrap();
    store
        .prepare(
            &head,
            AppliedEpoch {
                epoch,
                state: snapshot,
                expected_root,
                transactions: vec![],
                certificate: b"trusted storage fixture, not a QC".to_vec(),
                date: epoch as i64,
                message: b"epoch tag fixture".to_vec(),
            },
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn publication_and_rollback_keep_tag_history_and_outbox_atomic() {
    let (directory, store) = fixture(Some(b"0")).await;
    let reader = store.reader();
    let initial = store.head().await.unwrap();
    assert_eq!(reader.epoch_tag(0).await.unwrap(), Some(initial.clone()));
    let before = reader.epoch_tag_stats().await.unwrap();
    let abandoned = prepare(&store).await;
    assert_eq!(reader.epoch_tag_stats().await.unwrap(), before);
    assert!(reader.epoch_tag(1).await.unwrap().is_none());
    drop(abandoned);
    assert_eq!(store.head().await.unwrap(), initial);
    assert_eq!(reader.epoch_tag_stats().await.unwrap(), before);

    let committed = prepare(&store).await.commit().await.unwrap();
    assert_eq!(reader.epoch_tag(0).await.unwrap(), Some(initial));
    assert_eq!(reader.epoch_tag(1).await.unwrap(), Some(committed.clone()));
    let stats = reader.epoch_tag_stats().await.unwrap();
    assert_eq!((stats.count, stats.min_epoch, stats.max_epoch), (2, 0, 1));
    assert!(!stats.gc_enabled && !stats.gc_running);
    assert!(stats.split_epoch.is_none() && stats.gc_need.is_none());
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM exex_committed_epoch")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
    let chain = store.chain().clone();
    store.close().await;
    let reopened = CanonicalStore::open(&directory.path().join("chain.db"), &chain)
        .await
        .unwrap();
    assert_eq!(reopened.reader().epoch_tag_stats().await.unwrap(), stats);
    assert_eq!(
        reopened.reader().epoch_tag(1).await.unwrap(),
        Some(committed)
    );
    reopened.close().await;
}

#[tokio::test]
async fn migration_seeds_only_current_checkpoint_and_authenticates_its_binding() {
    let (directory, store) = fixture(None).await;
    assert_eq!(store.reader().epoch_tag_stats().await.unwrap().count, 0);
    let head = prepare(&store).await.commit().await.unwrap();
    sqlx::query("DROP TABLE node_epoch_tags")
        .execute(&store.pool)
        .await
        .unwrap();
    let chain = store.chain().clone();
    store.close().await;
    let path = directory.path().join("chain.db");
    let store = CanonicalStore::open(&path, &chain).await.unwrap();
    let stats = store.reader().epoch_tag_stats().await.unwrap();
    assert_eq!((stats.count, stats.min_epoch, stats.max_epoch), (1, 1, 1));
    assert_eq!(
        store.reader().epoch_tag(1).await.unwrap(),
        Some(head.clone())
    );
    assert!(store.reader().epoch_tag(0).await.unwrap().is_none());
    assert_eq!(
        store
            .reader()
            .head_at(Sequence(0))
            .await
            .unwrap()
            .cursor
            .epoch,
        EpochId(0)
    );

    sqlx::query("DELETE FROM node_epoch_tags")
        .execute(&store.pool)
        .await
        .unwrap();
    store.close().await;
    let store = CanonicalStore::open(&path, &chain).await.unwrap();
    assert_eq!(store.reader().epoch_tag_stats().await.unwrap(), stats);
    assert_eq!(store.reader().epoch_tag(1).await.unwrap(), Some(head));
    sqlx::query("UPDATE node_epoch_tags SET root=zeroblob(64)")
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(store.reader().epoch_tag(1).await.is_err());
    assert_eq!(store.head().await.unwrap().cursor.epoch, EpochId(1));
    store.close().await;
}

fn native() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/epoch-tags-native.json"
    ))
    .unwrap()
}

#[test]
fn captured_keep_and_successor_schedule_match_unchanged_native() {
    let oracle = native();
    assert_eq!(
        oracle["upstream_commit"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    let mapping: Value = serde_json::from_str(include_str!(
        "../../../../../docs/rust-node/source-map.json"
    ))
    .unwrap();
    assert_eq!(oracle["source_sha256"], mapping["files"]);
    assert_eq!(
        oracle["builder_image"],
        "sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95"
    );
    assert_eq!(oracle["compiler"], "4.14.2");
    assert_eq!(
        oracle["source_map_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../../../docs/rust-node/source-map.json"
        )))
    );
    assert_eq!(
        oracle["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../../../scripts/node-port/epoch-tags-native.ml"
        )))
    );
    let generator = include_str!("../../../../../scripts/node-port/epoch-tags-fixtures.py");
    assert_eq!(
        oracle["generator_sha256"],
        hex::encode(Sha256::digest(generator.as_bytes()))
    );
    let worker = generator
        .split_once("WORKER = r'''")
        .unwrap()
        .1
        .split_once("'''")
        .unwrap()
        .0;
    assert_eq!(
        oracle["worker_sha256"],
        hex::encode(Sha256::digest(worker.as_bytes()))
    );
    assert_eq!(oracle["retagged_value"], "100");
    for case in oracle["keep_cases"].as_array().unwrap() {
        let actual = keep_of(case["raw"].as_str().map(str::as_bytes)).ok();
        assert_eq!(actual, case["expected"].as_i64(), "{case}");
    }
    for case in oracle["schedule_cases"].as_array().unwrap() {
        let applied = case["applied"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            cleanup_floor(applied, DEFAULT_KEEP),
            case["floor"].as_i64(),
            "{case}"
        );
    }
    for case in oracle["initial_cases"].as_array().unwrap() {
        let result = initial_label(
            case["empty"].as_bool().unwrap(),
            case["raw"].as_str().map(str::as_bytes),
        );
        assert_eq!(result.is_err(), case["error"].as_bool().unwrap(), "{case}");
        if let Ok(label) = result {
            assert_eq!(label, case["label"].as_i64(), "{case}");
        }
    }
    assert!(keep_of(Some(b"many")).is_err());
    assert_eq!(keep_of(Some(b"4096")).unwrap(), 4096);
    assert_eq!(keep_of(Some(b"65536")).unwrap(), 65536);
}

#[tokio::test]
async fn initial_labels_and_captured_retention_do_not_reinterpret_history() {
    let (directory, mut store) = fixture(Some(b"7")).await;
    let original = store.head().await.unwrap();
    assert_eq!(
        store.reader().epoch_tag(7).await.unwrap(),
        Some(store.head().await.unwrap())
    );
    assert!(store.reader().epoch_tag(0).await.unwrap().is_none());
    store.epoch_tag_keep = 4096;
    let captured = store.reader();
    store.epoch_tag_keep = 65536;
    assert_eq!(captured.epoch_tag_stats().await.unwrap().keep_epochs, 4096);
    assert_eq!(
        store.reader().epoch_tag_stats().await.unwrap().keep_epochs,
        65536
    );
    assert_eq!(store.head().await.unwrap().cursor.epoch, EpochId(0));
    let mut last = original.clone();
    for _ in 0..7 {
        last = prepare(&store).await.commit().await.unwrap();
    }
    assert_eq!(last.cursor.epoch, EpochId(7));
    assert_eq!(
        store.reader().epoch_tag(7).await.unwrap(),
        Some(last.clone())
    );
    assert_eq!(store.reader().epoch_tag_stats().await.unwrap().count, 7);
    assert_eq!(store.reader().head_at(Sequence(0)).await.unwrap(), original);
    let chain = store.chain().clone();
    store.close().await;
    let reopened = CanonicalStore::open(&directory.path().join("chain.db"), &chain)
        .await
        .unwrap();
    assert_eq!(reopened.reader().epoch_tag(7).await.unwrap(), Some(last));
    assert_eq!(reopened.reader().epoch_tag_stats().await.unwrap().count, 7);
    assert_eq!(
        reopened.reader().head_at(Sequence(0)).await.unwrap(),
        original
    );
    reopened.close().await;
}

/// Sparse tag insertion is a storage-policy fixture, not a consecutive BFT
/// chain. Each row retains a real validated commit preimage and object root.
async fn tagged_head(store: &CanonicalStore, epoch: u64, lifecycle: bool) -> Head {
    let base = store.head().await.unwrap();
    let mut head = base.clone();
    head.cursor.sequence = Sequence(base.cursor.sequence.0 + 1);
    head.cursor.epoch = EpochId(epoch);
    head.parent_commit = Some(base.irmin_commit.clone());
    head.date = epoch as i64;
    head.message = b"sparse epoch-tag policy fixture".to_vec();
    head.irmin_commit = hex::encode(irmin::commit_hash(
        &hex_hash(&head.ledger_root).unwrap(),
        &[hex_hash(&base.irmin_commit).unwrap()],
        head.date,
        b"octra",
        &head.message,
    ));
    let mut tx = store.pool.begin().await.unwrap();
    super::super::write_head(&mut tx, &head, b"tag policy fixture")
        .await
        .unwrap();
    if lifecycle {
        record(&mut tx, &head, DEFAULT_KEEP).await.unwrap();
    } else {
        insert(&mut tx, epoch as i64, &head).await.unwrap();
    }
    tx.commit().await.unwrap();
    head
}

#[tokio::test]
async fn exact_native_prune_boundaries_preserve_immutable_rows() {
    let (_directory, store) = fixture(Some(b"0")).await;
    for epoch in [1, 7, 8, 99, 100] {
        tagged_head(&store, epoch, false).await;
    }
    let oracle = native();
    for step in oracle["lifecycle"].as_array().unwrap() {
        let epoch = step["applied"].as_u64().unwrap();
        tagged_head(&store, epoch, true).await;
        let stats = store.reader().epoch_tag_stats().await.unwrap();
        assert_eq!(stats.count, step["count"].as_i64().unwrap());
        assert_eq!(stats.min_epoch, step["min_epoch"].as_i64().unwrap());
        assert_eq!(stats.max_epoch, step["max_epoch"].as_i64().unwrap());
        let tags: Vec<i64> = sqlx::query_scalar("SELECT epoch FROM node_epoch_tags ORDER BY epoch")
            .fetch_all(&store.pool)
            .await
            .unwrap();
        assert_eq!(serde_json::to_value(tags).unwrap(), step["tags"]);
        assert!(store
            .reader()
            .epoch_tag(epoch as i64)
            .await
            .unwrap()
            .is_some());
    }
    assert!(store.reader().epoch_tag(0).await.unwrap().is_none());
    assert_eq!(
        store
            .reader()
            .head_at(Sequence(0))
            .await
            .unwrap()
            .cursor
            .epoch,
        EpochId(0)
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM node_epochs")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        rows,
        6 + oracle["lifecycle"].as_array().unwrap().len() as i64
    );
    assert_eq!(oracle["storage_backend"], "irmin-pack");
    assert_eq!(oracle["pack_collection_invoked"], false);
    let gc = &oracle["readonly_pack_status"];
    // The unchanged native getter reports Store.Gc.is_allowed, including for
    // readonly repositories. This is an observed Irmin-pack capability, not
    // an inference that readonly disables GC and not a SQLite GC property.
    assert!(gc["pack_gc_enabled"].is_boolean());
    assert!(gc["pack_gc_running"].is_boolean());
    assert!(gc["split_epoch"].is_null() || gc["split_epoch"].is_i64());
    assert!(
        gc["pack_gc_need_bytes"].is_null()
            || gc["pack_gc_need_bytes"]
                .as_str()
                .is_some_and(|raw| raw.parse::<i64>().is_ok())
    );
    let stats = store.reader().epoch_tag_stats().await.unwrap();
    // This backend has no physical Irmin pack collector. Its capability must
    // remain honest even when the source-native repository reports enabled.
    assert_eq!(
        (
            stats.split_epoch,
            stats.gc_enabled,
            stats.gc_running,
            stats.gc_need
        ),
        (None, false, false, None)
    );
    store.close().await;
}

#[tokio::test]
async fn explicit_retention_is_used_by_real_create_and_reopen() {
    let retention = EpochTagRetention::from_value(Some(b"4096")).unwrap();
    let (directory, store) = fixture_with_retention(Some(b"0"), retention).await;
    let chain = store.chain().clone();
    let head = store.head().await.unwrap();
    assert_eq!(
        store.reader().epoch_tag_stats().await.unwrap().keep_epochs,
        4096
    );
    store.close().await;
    for (raw, expected) in [(Some(b"65536".as_slice()), 65536), (None, 8192)] {
        let store = CanonicalStore::open_with_retention(
            &directory.path().join("chain.db"),
            &chain,
            EpochTagRetention::from_value(raw).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            store.reader().epoch_tag_stats().await.unwrap().keep_epochs,
            expected
        );
        assert_eq!(store.head().await.unwrap(), head);
        assert_eq!(
            store.reader().epoch_tag(0).await.unwrap(),
            Some(head.clone())
        );
        store.close().await;
    }
    for raw in [b"4095".as_slice(), b"65537", b"invalid"] {
        assert!(EpochTagRetention::from_value(Some(raw)).is_err());
    }
}
