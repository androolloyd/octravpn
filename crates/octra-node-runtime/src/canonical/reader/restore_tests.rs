use super::{restore, RESTORE_EDGES};
use crate::{
    canonical::CanonicalStore,
    state_batch::{Snapshot, StateBatch},
};
use futures::TryStreamExt;
use octra_exex::{ChainIdentity, StateRoot};
use octra_node_protocol::{epoch_index, irmin::Hash};
use sqlx::{sqlite::SqliteConnectOptions, sqlite::SqlitePoolOptions, Row, SqlitePool};
use std::{collections::BTreeSet, time::Instant};

const OLD_EDGES: &str = "WITH RECURSIVE reachable(hash) AS (SELECT ? UNION SELECT child FROM node_edges JOIN reachable ON parent=reachable.hash) SELECT e.parent,e.child FROM node_edges e JOIN reachable r ON e.parent=r.hash";

fn state() -> Snapshot {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    // Native inodes and flat directories, including repeated contents hashes.
    for index in 0u16..769 {
        state
            .set(
                &[b"accounts", &index.to_be_bytes(), b"data"],
                (index % 11).to_be_bytes().to_vec(),
            )
            .unwrap();
    }
    state.snapshot()
}

async fn store(path: &std::path::Path, state: Snapshot) -> CanonicalStore {
    let (_, index) =
        epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
            .unwrap();
    let root = epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap();
    CanonicalStore::create(
        path,
        ChainIdentity::genesis("indexed-restore", StateRoot(root)),
        state,
        0,
    )
    .await
    .unwrap()
}

async fn edges(pool: &SqlitePool, sql: &str, root: Hash) -> BTreeSet<(Hash, Hash)> {
    let mut result = BTreeSet::new();
    let mut rows = sqlx::query(sql).bind(root.as_slice()).fetch(pool);
    while let Some(row) = rows.try_next().await.unwrap() {
        let parent: Vec<u8> = row.get("parent");
        let child: Vec<u8> = row.get("child");
        assert!(result.insert((parent.try_into().unwrap(), child.try_into().unwrap())));
    }
    result
}

#[tokio::test]
async fn indexed_restore_preserves_shared_inodes_and_ignores_unreachable_history() {
    let dir = tempfile::tempdir().unwrap();
    let state = state();
    let store = store(&dir.path().join("state.sqlite"), state.clone()).await;
    let head = store.head().await.unwrap();
    // An unreachable, malformed historical object must not be read as state.
    sqlx::query("INSERT INTO node_objects VALUES(?,0,?)")
        .bind([42u8; 64].as_slice())
        .bind(b"unreachable".as_slice())
        .execute(&store.pool)
        .await
        .unwrap();
    let expected = edges(&store.pool, OLD_EDGES, state.root().unwrap()).await;
    assert_eq!(
        edges(&store.pool, RESTORE_EDGES, state.root().unwrap()).await,
        expected
    );
    let restored = restore(&store.pool, &head).await.unwrap();
    assert_eq!(restored.root().unwrap(), state.root().unwrap());
    assert_eq!(
        restored.get(&[b"accounts", &768u16.to_be_bytes(), b"data"]),
        state.get(&[b"accounts", &768u16.to_be_bytes(), b"data"])
    );
    store.close().await;
}

#[tokio::test]
async fn indexed_restore_rejects_missing_edges_and_terminates_corrupt_cycles() {
    let dir = tempfile::tempdir().unwrap();
    let state = state();
    let root = state.root().unwrap();
    let store = store(&dir.path().join("state.sqlite"), state).await;
    let head = store.head().await.unwrap();
    let child: Vec<u8> = sqlx::query_scalar("SELECT child FROM node_edges WHERE parent=? LIMIT 1")
        .bind(root.as_slice())
        .fetch_one(&store.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM node_edges WHERE parent=? AND child=?")
        .bind(root.as_slice())
        .bind(&child)
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(restore(&store.pool, &head).await.is_err());
    sqlx::query("INSERT INTO node_edges VALUES(?,?)")
        .bind(root.as_slice())
        .bind(&child)
        .execute(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        restore(&store.pool, &head).await.unwrap().root().unwrap(),
        root
    );
    sqlx::query("INSERT INTO node_edges VALUES(?,?)")
        .bind(root.as_slice())
        .bind(root.as_slice())
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(tokio::time::timeout(
        std::time::Duration::from_secs(5),
        restore(&store.pool, &head)
    )
    .await
    .unwrap()
    .is_err());
    store.close().await;
}

#[tokio::test]
async fn indexed_restore_looks_up_edges_by_parent_instead_of_scanning_history() {
    let dir = tempfile::tempdir().unwrap();
    let state = state();
    let root = state.root().unwrap();
    let store = store(&dir.path().join("state.sqlite"), state).await;
    let rows = sqlx::query(&format!("EXPLAIN QUERY PLAN {RESTORE_EDGES}"))
        .bind(root.as_slice())
        .fetch_all(&store.pool)
        .await
        .unwrap();
    let plan = rows
        .iter()
        .map(|r| r.get::<String, _>("detail"))
        .collect::<Vec<_>>();
    assert!(
        plan.iter()
            .any(|p| p.starts_with("SEARCH e ") && p.contains("parent=?")),
        "{plan:?}"
    );
    assert!(!plan.iter().any(|p| p.starts_with("SCAN e")), "{plan:?}");
    store.close().await;
}

/// Run only against an explicitly supplied, stopped database copy. The bounded
/// edge set checks exact row equality; this measures SQL reads, not full state
/// restoration, certificate authentication, or public-network qualification.
#[tokio::test]
#[ignore = "requires OCTRA_RESTORE_BENCHMARK_DB pointing to a stopped database copy"]
async fn retained_edge_query_benchmark() {
    let path = std::env::var_os("OCTRA_RESTORE_BENCHMARK_DB").expect("stopped database copy");
    let mut reports = Vec::new();
    let mut expected = None;
    for (name, sql, cache) in [
        ("historical_scan", OLD_EDGES, -2000),
        ("parent_index", RESTORE_EDGES, -2000),
        ("parent_index_32m", RESTORE_EDGES, -32768),
    ] {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(std::path::PathBuf::from(&path))
                    .read_only(true)
                    .create_if_missing(false)
                    .immutable(true)
                    .pragma("query_only", "ON")
                    .pragma("cache_size", cache.to_string()),
            )
            .await
            .unwrap();
        let version: String = sqlx::query_scalar("SELECT sqlite_version()")
            .fetch_one(&pool)
            .await
            .unwrap();
        let root: Vec<u8> =
            sqlx::query_scalar("SELECT root FROM node_epochs ORDER BY sequence DESC LIMIT 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        let started = Instant::now();
        let result = edges(&pool, sql, root.try_into().unwrap()).await;
        reports.push(serde_json::json!({"name":name,"sqlite":version,"rows":result.len(),"elapsed_seconds":started.elapsed().as_secs_f64(),"cache_kib":-cache}));
        if let Some(ref expected) = expected {
            assert_eq!(&result, expected);
        } else {
            expected = Some(result);
        }
        pool.close().await;
        eprintln!("{}", reports.last().unwrap());
    }
    eprintln!(
        "exact_row_sets_equal=true reports={}",
        serde_json::to_string(&reports).unwrap()
    );
}
