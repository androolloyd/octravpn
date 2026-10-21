//! Differential subtree reads and raw-storage negative controls.
use super::*;
use crate::{canonical::CanonicalStore, state_batch::StateBatch};
use octra_exex::{ChainIdentity, StateRoot};
use octra_node_protocol::{epoch_index, irmin};

struct Fixture {
    _root: tempfile::TempDir,
    store: CanonicalStore,
    head: Head,
    snapshot: Snapshot,
}
async fn fixture(wide: bool) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let mut state = StateBatch::default();
    state.begin().unwrap();
    state.set(&[b"meta", b"last_epoch"], b"0".to_vec()).unwrap();
    state.set(&[b"kept", b"value"], b"small".to_vec()).unwrap();
    state
        .set(&[b"unrelated", b"large"], vec![77; 2 * 1024 * 1024])
        .unwrap();
    if wide {
        for index in 0_u16..2048 {
            state
                .set(
                    &[b"wide", format!("key-{index:04}").as_bytes(), b"value"],
                    index.to_be_bytes().to_vec(),
                )
                .unwrap();
        }
    }
    let snapshot = state.snapshot();
    let index = epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
        .unwrap()
        .1;
    let folded = epoch_index::folded_state_root(
        hex::encode(snapshot.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap();
    let store = CanonicalStore::create(
        &root.path().join("chain.db"),
        ChainIdentity::genesis("subtree-reader-fixture", StateRoot(folded)),
        snapshot.clone(),
        0,
    )
    .await
    .unwrap();
    let head = store.head().await.unwrap();
    Fixture {
        _root: root,
        store,
        head,
        snapshot,
    }
}

async fn matches(f: &Fixture, path: &[&[u8]]) {
    let read = f
        .store
        .reader()
        .read_tree_at(&f.head, path, 16384)
        .await
        .unwrap();
    let encoded = STANDARD.encode(read.proof);
    let expected = f.snapshot.subtree(path);
    assert_eq!(
        proof::verify_tree(f.head.ledger_root.as_bytes(), path, encoded.as_bytes()).unwrap(),
        expected.as_ref().map(|tree| tree.root().unwrap())
    );
    assert_eq!(
        read.tree.as_ref().map(|tree| tree.root().unwrap()),
        expected.as_ref().map(|tree| tree.root().unwrap())
    );
    if let Some(tree) = read.tree {
        assert_eq!(tree.get(&[b"value"]), expected.unwrap().get(&[b"value"]));
        let raw = f
            .store
            .reader()
            .prove_tree_at(&f.head, path, &tree, &[&[b"value"]], 16384)
            .await
            .unwrap();
        let mut full = path.to_vec();
        full.push(b"value");
        assert_eq!(
            raw,
            f.snapshot.read_proof_paths(&[&full]).unwrap(),
            "selected contents proof must match the full-tree producer byte for byte"
        );
    }
}

#[tokio::test]
async fn bounded_projection_does_not_load_or_reveal_an_unrelated_tree() {
    let f = fixture(false).await;
    let reader = f.store.reader();
    let big = irmin::contents_hash(&vec![77; 2 * 1024 * 1024]);
    sqlx::query("UPDATE node_objects SET data=zeroblob(8388608) WHERE hash=?")
        .bind(big.as_slice())
        .execute(&reader.pool)
        .await
        .unwrap();
    matches(&f, &[b"kept"]).await;
    matches(&f, &[b"absent"]).await;
    assert!(
        super::super::restore(&reader.pool, &f.head).await.is_err(),
        "negative control must traverse the corrupt unrelated object"
    );
    assert!(reader
        .read_tree_at(&f.head, &[b"unrelated"], 4096)
        .await
        .is_err());
    assert!(
        reader
            .read_tree_at(&f.head, &[b"kept", b"value"], 4096)
            .await
            .is_err(),
        "a contents value must not become a subtree"
    );
    f.store.close().await;
}

#[tokio::test]
async fn inode_and_legacy_paths_prove_the_same_subtrees_and_absences() {
    let f = fixture(true).await;
    for name in [
        b"key-0000".as_slice(),
        b"key-1025",
        b"key-2047",
        b"not-present",
    ] {
        matches(&f, &[b"wide", name]).await;
    }
    let wide = f.snapshot.subtree(&[b"wide"]).unwrap();
    let hash = wide.root().unwrap();
    let entries = wide
        .child_names(&[])
        .map(|name| {
            (
                name.to_vec(),
                false,
                wide.hash_at(&[name]).unwrap().unwrap().to_vec(),
            )
        })
        .collect::<Vec<_>>();
    let reader = f.store.reader();
    let mut write = reader.pool.begin().await.unwrap();
    sqlx::query("UPDATE node_objects SET data=? WHERE hash=?")
        .bind(serde_json::to_vec(&entries).unwrap())
        .bind(hash.as_slice())
        .execute(&mut *write)
        .await
        .unwrap();
    sqlx::query("DELETE FROM node_edges WHERE parent=?")
        .bind(hash.as_slice())
        .execute(&mut *write)
        .await
        .unwrap();
    for (_, _, child) in &entries {
        sqlx::query("INSERT OR IGNORE INTO node_edges(parent,child) VALUES(?,?)")
            .bind(hash.as_slice())
            .bind(child)
            .execute(&mut *write)
            .await
            .unwrap();
    }
    write.commit().await.unwrap();
    for name in [
        b"key-0000".as_slice(),
        b"key-1025",
        b"key-2047",
        b"not-present",
    ] {
        matches(&f, &[b"wide", name]).await;
    }
    assert!(reader
        .read_tree_at(&f.head, &[b"wide"], 1024)
        .await
        .is_err());
    f.store.close().await;
}

#[tokio::test]
async fn selected_corruption_missing_edges_and_mismatched_heads_refuse() {
    let f = fixture(false).await;
    let reader = f.store.reader();
    let mut wrong = f.head.clone();
    wrong.date += 1;
    assert!(reader.read_tree_at(&wrong, &[b"kept"], 4096).await.is_err());
    let hash = irmin::contents_hash(b"small");
    sqlx::query("UPDATE node_objects SET data=? WHERE hash=?")
        .bind(b"bad".as_slice())
        .bind(hash.as_slice())
        .execute(&reader.pool)
        .await
        .unwrap();
    assert!(reader
        .read_tree_at(&f.head, &[b"kept"], 4096)
        .await
        .is_err());
    sqlx::query("UPDATE node_objects SET data=? WHERE hash=?")
        .bind(b"small".as_slice())
        .bind(hash.as_slice())
        .execute(&reader.pool)
        .await
        .unwrap();
    let parent = f.snapshot.subtree(&[b"kept"]).unwrap().root().unwrap();
    sqlx::query("DELETE FROM node_edges WHERE parent=? AND child=?")
        .bind(parent.as_slice())
        .bind(hash.as_slice())
        .execute(&reader.pool)
        .await
        .unwrap();
    assert!(reader
        .read_tree_at(&f.head, &[b"kept"], 4096)
        .await
        .is_err());
    f.store.close().await;
}

/// Explicit performance/format diagnostic for a stopped, already authenticated
/// deployment. Metadata alone supplies no independent finality or grant.
#[tokio::test]
#[ignore = "requires explicit stopped-store path, expected head and public subtree paths"]
async fn stopped_retained_store_subtrees_stay_bounded() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    println!("opening stopped-store diagnostic");
    let path = std::env::var("OCTRA_TREE_DATABASE").unwrap();
    let expected = std::env::var("OCTRA_TREE_HEAD").unwrap();
    let paths: Vec<Vec<String>> =
        serde_json::from_str(&std::env::var("OCTRA_TREE_PATHS").unwrap()).unwrap();
    assert!((1..=8).contains(&paths.len()));
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .read_only(true)
                .create_if_missing(false)
                .pragma("query_only", "ON"),
        )
        .await
        .unwrap();
    println!("stopped-store connection opened");
    let identity = sqlx::query("SELECT chain,anchor FROM node_identity WHERE id=0")
        .fetch_one(&pool)
        .await
        .unwrap();
    let chain: ChainIdentity = serde_json::from_slice(identity.get("chain")).unwrap();
    let anchor: Head = serde_json::from_slice(identity.get("anchor")).unwrap();
    let row =
        sqlx::query("SELECT sequence,head,root FROM node_epochs ORDER BY sequence DESC LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    let head = decode_head(&row).unwrap();
    println!("stopped-store head read");
    assert_eq!(hex::encode(head.cursor.state_root.0), expected);
    let reader = Reader::new(
        pool.clone(),
        chain,
        anchor.cursor,
        std::sync::Arc::default(),
        0,
        None,
    );
    let mut results = Vec::new();
    for path in paths {
        println!("reading stopped-store subtree {path:?}");
        let selected = path.iter().map(String::as_bytes).collect::<Vec<_>>();
        let read = reader
            .read_tree_at(&head, &selected, 8 * 1024 * 1024)
            .await
            .unwrap();
        println!("bounded subtree proof bytes={}", read.proof.len());
        results.push(
            serde_json::json!({"path":path,"proof_bytes":read.proof.len(),
            "subtree_root":read.tree.as_ref().map(|tree| hex::encode(tree.root().unwrap()))}),
        );
    }
    println!(
        "{}",
        serde_json::json!({"epoch":head.cursor.epoch.0,"state_root":expected,
        "scope":"Stopped local storage diagnostic; no independent finality or admission authority",
        "subtrees":results})
    );
    pool.close().await;
}
