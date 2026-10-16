use crate::{
    canonical::{execution_root, AppliedEpoch, CanonicalStore, Head, Result},
    state_batch::{
        storage::{self, test_support::legacy},
        Snapshot, StateBatch,
    },
};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_exex::{ChainIdentity, StateRoot};
use octra_node_protocol::{
    epoch_index,
    irmin::{self, page::Page, Hash},
};
use sqlx::{Connection, Row, SqlitePool};

async fn fixture(count: u32, shared: bool) -> (tempfile::TempDir, CanonicalStore) {
    let dir = tempfile::tempdir().unwrap();
    let mut state = StateBatch::default();
    state.begin().unwrap();
    state.set(&[b"meta", b"last_epoch"], b"0".to_vec()).unwrap();
    for index in 0..count {
        let mut value = vec![0; 128];
        value[..4].copy_from_slice(&index.to_le_bytes());
        if shared {
            value = b"shared".to_vec();
        }
        state
            .set(&[b"accounts", &index.to_be_bytes()], value)
            .unwrap();
    }
    let index = epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
        .unwrap()
        .1;
    let root = epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap();
    let store = CanonicalStore::create(
        &dir.path().join("chain.db"),
        ChainIdentity::genesis("inode-fixture", StateRoot(root)),
        state.snapshot(),
        0,
    )
    .await
    .unwrap();
    (dir, store)
}
async fn advance(store: &CanonicalStore, edit: impl FnOnce(&mut StateBatch)) -> Result<Head> {
    let (head, mut state) = store.snapshot().await?;
    state.begin().unwrap();
    edit(&mut state);
    let epoch = head.cursor.epoch.0 + 1;
    state
        .set(&[b"meta", b"last_epoch"], epoch.to_string().into_bytes())
        .unwrap();
    let snapshot = state.snapshot();
    let expected_root = execution_root(&head, epoch, &snapshot, &[])?;
    store
        .prepare(
            &head,
            AppliedEpoch {
                epoch,
                state: snapshot,
                expected_root,
                transactions: vec![],
                certificate: b"trusted-storage-fixture".to_vec(),
                date: epoch as i64,
                message: b"next".to_vec(),
            },
        )
        .await?
        .commit()
        .await
}
async fn install_legacy(pool: &SqlitePool, snapshot: &Snapshot) {
    let objects = legacy(snapshot);
    let mut connection = pool.acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *connection)
        .await
        .unwrap();
    let mut tx = connection.begin().await.unwrap();
    sqlx::query("DELETE FROM node_edges")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM node_objects")
        .execute(&mut *tx)
        .await
        .unwrap();
    for object in objects {
        sqlx::query("INSERT INTO node_objects(hash,contents,data) VALUES(?,?,?)")
            .bind(object.hash.as_slice())
            .bind(object.contents)
            .bind(object.data)
            .execute(&mut *tx)
            .await
            .unwrap();
        for child in object.children {
            sqlx::query("INSERT INTO node_edges(parent,child) VALUES(?,?) ON CONFLICT DO NOTHING")
                .bind(object.hash.as_slice())
                .bind(child.as_slice())
                .execute(&mut *tx)
                .await
                .unwrap();
        }
    }
    assert!(sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(&mut *tx)
        .await
        .unwrap()
        .is_empty());
    tx.commit().await.unwrap();
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&mut *connection)
        .await
        .unwrap();
}
async fn data(pool: &SqlitePool, hash: &Hash) -> Vec<u8> {
    sqlx::query_scalar("SELECT data FROM node_objects WHERE hash=?")
        .bind(hash.as_slice())
        .fetch_one(pool)
        .await
        .unwrap()
}
async fn accounting(pool: &SqlitePool) -> (i64, i64, i64, i64) {
    let row = sqlx::query(
        "SELECT count(*) AS n,COALESCE(sum(length(data)),0) AS bytes FROM node_objects",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let edges: i64 = sqlx::query_scalar("SELECT count(*) FROM node_edges")
        .fetch_one(pool)
        .await
        .unwrap();
    let pages: i64 = sqlx::query_scalar("PRAGMA page_count")
        .fetch_one(pool)
        .await
        .unwrap();
    let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
        .fetch_one(pool)
        .await
        .unwrap();
    (
        row.get("n"),
        row.get("bytes"),
        edges,
        pages.checked_mul(page_size).unwrap(),
    )
}
async fn image(pool: &SqlitePool) -> (Vec<(Vec<u8>, bool, Vec<u8>)>, Vec<(Vec<u8>, Vec<u8>)>) {
    let objects = sqlx::query("SELECT hash,contents,data FROM node_objects ORDER BY hash")
        .fetch_all(pool)
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.get("hash"), row.get("contents"), row.get("data")))
        .collect();
    let edges = sqlx::query("SELECT parent,child FROM node_edges ORDER BY parent,child")
        .fetch_all(pool)
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.get("parent"), row.get("child")))
        .collect();
    (objects, edges)
}
async fn root_at(store: &CanonicalStore, path: &[&[u8]]) -> Hash {
    store
        .snapshot()
        .await
        .unwrap()
        .1
        .snapshot()
        .hash_at(path)
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn legacy_same_hash_reuse_is_immutable_and_mixed_history_reopens() {
    let (dir, store) = fixture(513, false).await;
    let initial = store.snapshot().await.unwrap().1.snapshot();
    let old_head = store.head().await.unwrap();
    let root = initial.hash_at(&[b"accounts"]).unwrap().unwrap();
    let original = initial
        .get(&[b"accounts", &7u32.to_be_bytes()])
        .unwrap()
        .to_vec();
    let chain = store.chain().clone();
    install_legacy(&store.pool, &initial).await;
    let old_data = data(&store.pool, &root).await;
    let old_edges = image(&store.pool).await.1;
    assert!(!old_data.starts_with(storage::MAGIC));
    store.close().await;
    let store = CanonicalStore::open(&dir.path().join("chain.db"), &chain)
        .await
        .unwrap();
    assert_eq!(
        store
            .reader()
            .read_at(&old_head, &[b"accounts", &7u32.to_be_bytes()])
            .await
            .unwrap(),
        Some(original.clone())
    );
    let first = advance(&store, |state| {
        state
            .set(&[b"accounts", &7u32.to_be_bytes()], b"changed".to_vec())
            .unwrap();
    })
    .await
    .unwrap();
    let paged = root_at(&store, &[b"accounts"]).await;
    assert!(data(&store.pool, &paged).await.starts_with(storage::MAGIC));
    let second = advance(&store, |state| {
        state
            .set(&[b"accounts", &7u32.to_be_bytes()], original.clone())
            .unwrap();
    })
    .await
    .unwrap();
    assert_eq!(root_at(&store, &[b"accounts"]).await, root);
    assert_eq!(data(&store.pool, &root).await, old_data);
    let now = image(&store.pool).await.1;
    assert_eq!(
        now.iter()
            .filter(|(parent, _)| parent.as_slice() == root)
            .cloned()
            .collect::<Vec<_>>(),
        old_edges
            .into_iter()
            .filter(|(parent, _)| parent.as_slice() == root)
            .collect::<Vec<_>>()
    );
    store.close().await;
    let reopened = CanonicalStore::open(&dir.path().join("chain.db"), &chain)
        .await
        .unwrap();
    assert_eq!(reopened.head().await.unwrap(), second);
    assert_eq!(
        reopened
            .reader()
            .read_at(&first, &[b"accounts", &7u32.to_be_bytes()])
            .await
            .unwrap(),
        Some(b"changed".to_vec())
    );
    assert_eq!(
        reopened
            .reader()
            .read_at(&old_head, &[b"accounts", &7u32.to_be_bytes()])
            .await
            .unwrap(),
        Some(original)
    );
}
#[tokio::test]
async fn durable_growth_tracks_changed_inode_paths_instead_of_directory_width() {
    let (_dir, store) = fixture(0, false).await;
    let account_key = |index: u32| {
        let mut public = [0; 32];
        public[..4].copy_from_slice(&index.to_le_bytes());
        let address = octra_node_protocol::transaction::address_from_public_key(
            STANDARD.encode(public).as_bytes(),
        );
        assert!(octra_node_protocol::transaction::is_valid_address(&address));
        address
    };
    advance(&store, |state| {
        for index in 0u32..32_768 {
            let mut value = vec![0; 128];
            value[..4].copy_from_slice(&index.to_le_bytes());
            state
                .set(&[b"accounts", &account_key(index)], value)
                .unwrap();
        }
    })
    .await
    .unwrap();
    let snapshot = store.snapshot().await.unwrap().1.snapshot();
    let root = snapshot.hash_at(&[b"accounts"]).unwrap().unwrap();
    let legacy_directory_bytes = legacy(&snapshot)
        .into_iter()
        .find(|object| object.hash == root)
        .unwrap()
        .data
        .len();
    assert!(
        legacy_directory_bytes > 16 * 65_536,
        "the old full-directory representation must exceed the changed-path budget"
    );
    eprintln!("inode-growth accounts=32768 native_address_bytes=47 old_directory_bytes={legacy_directory_bytes}");
    let initial = accounting(&store.pool).await;
    let mut previous = initial;
    for epoch in 0u32..8 {
        advance(&store, |state| {
            state
                .set(
                    &[b"accounts", &account_key(epoch * 4093)],
                    format!("updated-{epoch}").into_bytes(),
                )
                .unwrap();
        })
        .await
        .unwrap();
        let next = accounting(&store.pool).await;
        let delta = (
            next.0 - previous.0,
            next.1 - previous.1,
            next.2 - previous.2,
            next.3 - previous.3,
        );
        eprintln!(
            "inode-growth update={epoch} objects={} data_bytes={} edges={} database_page_bytes={}",
            delta.0, delta.1, delta.2, delta.3
        );
        assert!(delta.0 <= 16, "new physical objects: {delta:?}");
        assert!(
            delta.1 <= 65_536,
            "persisted bytes must be bounded per changed native path: {delta:?}"
        );
        assert!(delta.2 <= 512, "new edges: {delta:?}");
        assert!(
            delta.3 <= 1_048_576,
            "logical database allocation must also stay within the changed-path budget: {delta:?}"
        );
        previous = next;
    }
    assert!(previous.1 - initial.1 <= 8 * 65_536);
}
#[tokio::test]
async fn threshold_crossings_keep_old_flat_and_new_native_roots_readable() {
    let (_dir, store) = fixture(256, false).await;
    let first = store.head().await.unwrap();
    let original = root_at(&store, &[b"accounts"]).await;
    assert!(!data(&store.pool, &original)
        .await
        .starts_with(storage::MAGIC));
    let wide = advance(&store, |state| {
        state
            .set(&[b"accounts", &256u32.to_be_bytes()], b"extra".to_vec())
            .unwrap();
    })
    .await
    .unwrap();
    let wide_root = root_at(&store, &[b"accounts"]).await;
    assert!(data(&store.pool, &wide_root)
        .await
        .starts_with(storage::MAGIC));
    let small = advance(&store, |state| {
        state.remove(&[b"accounts", &256u32.to_be_bytes()]).unwrap();
    })
    .await
    .unwrap();
    assert_eq!(root_at(&store, &[b"accounts"]).await, original);
    assert_eq!(
        store
            .reader()
            .read_at(&wide, &[b"accounts", &256u32.to_be_bytes()])
            .await
            .unwrap(),
        Some(b"extra".to_vec())
    );
    for head in [first, small] {
        assert_eq!(
            store
                .reader()
                .read_at(&head, &[b"accounts", &256u32.to_be_bytes()])
                .await
                .unwrap(),
            None
        );
    }
}
#[tokio::test]
async fn corrupt_legacy_same_hash_collision_rolls_back_all_new_physical_pages() {
    let (_dir, store) = fixture(513, false).await;
    let initial = store.snapshot().await.unwrap().1.snapshot();
    let root = initial.hash_at(&[b"accounts"]).unwrap().unwrap();
    let original = initial
        .get(&[b"accounts", &7u32.to_be_bytes()])
        .unwrap()
        .to_vec();
    install_legacy(&store.pool, &initial).await;
    let head = advance(&store, |state| {
        state
            .set(&[b"accounts", &7u32.to_be_bytes()], b"changed".to_vec())
            .unwrap();
    })
    .await
    .unwrap();
    let raw = data(&store.pool, &root).await;
    sqlx::query("UPDATE node_objects SET data=? WHERE hash=?")
        .bind(b"corrupted-legacy".as_slice())
        .bind(root.as_slice())
        .execute(&store.pool)
        .await
        .unwrap();
    let before = image(&store.pool).await;
    let error = advance(&store, |state| {
        state
            .set(&[b"accounts", &7u32.to_be_bytes()], original)
            .unwrap();
    })
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("conflicting persisted state object"));
    assert_eq!(image(&store.pool).await, before);
    assert_eq!(store.head().await.unwrap(), head);
    sqlx::query("UPDATE node_objects SET data=? WHERE hash=?")
        .bind(raw)
        .bind(root.as_slice())
        .execute(&store.pool)
        .await
        .unwrap();
}
#[tokio::test]
async fn existing_native_edge_conflict_is_not_repaired_or_silently_extended() {
    let (_dir, store) = fixture(513, false).await;
    let root = root_at(&store, &[b"accounts"]).await;
    let extra = irmin::contents_hash(b"0");
    sqlx::query("INSERT INTO node_edges(parent,child) VALUES(?,?)")
        .bind(root.as_slice())
        .bind(extra.as_slice())
        .execute(&store.pool)
        .await
        .unwrap();
    let before = image(&store.pool).await;
    let snapshot = store.snapshot().await.unwrap().1.snapshot();
    let mut tx = store.pool.begin().await.unwrap();
    let error = super::super::write_snapshot(&mut tx, &snapshot, None)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("conflicting persisted state edges"));
    tx.rollback().await.unwrap();
    assert_eq!(image(&store.pool).await, before);
}
#[tokio::test]
async fn full_restore_detects_missing_edges_even_when_child_is_reachable_elsewhere() {
    for extra in [false, true] {
        let (dir, store) = fixture(513, true).await;
        let chain = store.chain().clone();
        let snapshot = store.snapshot().await.unwrap().1.snapshot();
        let objects = snapshot.objects().unwrap();
        let (hash, page) = objects
            .iter()
            .find(|(_, object)| {
                matches!(
                    storage::decode(&object.hash, &object.data),
                    Ok(storage::Directory::Inode(Page::Values(_)))
                )
            })
            .unwrap();
        let child = page.children[0];
        if extra {
            let other = irmin::contents_hash(b"0");
            sqlx::query("INSERT INTO node_edges(parent,child) VALUES(?,?)")
                .bind(hash.as_slice())
                .bind(other.as_slice())
                .execute(&store.pool)
                .await
                .unwrap();
        } else {
            sqlx::query("DELETE FROM node_edges WHERE parent=? AND child=?")
                .bind(hash.as_slice())
                .bind(child.as_slice())
                .execute(&store.pool)
                .await
                .unwrap();
        }
        let reachable: i64 = sqlx::query_scalar("SELECT count(*) FROM node_edges WHERE child=?")
            .bind(child.as_slice())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert!(
            reachable > 0,
            "the shared child remains otherwise reachable"
        );
        store.close().await;
        let error = CanonicalStore::open(&dir.path().join("chain.db"), &chain)
            .await
            .err()
            .expect("corrupt graph must not reopen");
        assert!(
            error.to_string().contains("state object edges differ"),
            "{error}"
        );
    }
}
#[tokio::test]
async fn selected_path_refuses_corrupt_pages_kind_missing_objects_and_selected_edges() {
    for mode in ["bytes", "kind", "missing", "edge"] {
        let (_dir, store) = fixture(513, false).await;
        let head = store.head().await.unwrap();
        let root = root_at(&store, &[b"accounts"]).await;
        let storage::Directory::Inode(Page::Branch { children, .. }) =
            storage::decode(&root, &data(&store.pool, &root).await).unwrap()
        else {
            panic!("native root")
        };
        let slot = irmin::page::slot(&7u32.to_be_bytes(), 0).unwrap();
        let child = children.iter().find(|(index, _)| *index == slot).unwrap().1;
        match mode {
            "bytes" => {
                let mut raw = data(&store.pool, &child).await;
                raw[5] ^= 1;
                sqlx::query("UPDATE node_objects SET data=? WHERE hash=?")
                    .bind(raw)
                    .bind(child.as_slice())
                    .execute(&store.pool)
                    .await
                    .unwrap();
            }
            "kind" => {
                sqlx::query("UPDATE node_objects SET contents=1 WHERE hash=?")
                    .bind(child.as_slice())
                    .execute(&store.pool)
                    .await
                    .unwrap();
            }
            "edge" => {
                sqlx::query("DELETE FROM node_edges WHERE parent=? AND child=?")
                    .bind(root.as_slice())
                    .bind(child.as_slice())
                    .execute(&store.pool)
                    .await
                    .unwrap();
            }
            "missing" => {
                let mut connection = store.pool.acquire().await.unwrap();
                sqlx::query("PRAGMA foreign_keys=OFF")
                    .execute(&mut *connection)
                    .await
                    .unwrap();
                sqlx::query("DELETE FROM node_objects WHERE hash=?")
                    .bind(child.as_slice())
                    .execute(&mut *connection)
                    .await
                    .unwrap();
                sqlx::query("PRAGMA foreign_keys=ON")
                    .execute(&mut *connection)
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            store
                .reader()
                .read_at(&head, &[b"accounts", &7u32.to_be_bytes()])
                .await
                .is_err(),
            "{mode}"
        );
    }
}
