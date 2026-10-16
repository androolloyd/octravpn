//! Compare bounded edge writes with the exact pre-batching writer.
use super::{connect, error, write_snapshot, Result};
use crate::state_batch::{Snapshot, StateBatch, StoredObject};
use octra_node_protocol::irmin::Hash;
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::{collections::BTreeMap, path::Path};

#[derive(Debug, PartialEq)]
struct Image {
    objects: Vec<(Vec<u8>, bool, Vec<u8>)>,
    edges: Vec<(Vec<u8>, Vec<u8>)>,
}
async fn database(path: &Path) -> SqlitePool {
    drop(std::fs::File::create(path).unwrap());
    let pool = connect(path).await.unwrap();
    for statement in [
        "CREATE TABLE node_objects(hash BLOB PRIMARY KEY CHECK(length(hash)=64), contents INTEGER NOT NULL CHECK(contents IN (0,1)), data BLOB NOT NULL)",
        "CREATE TABLE node_edges(parent BLOB NOT NULL REFERENCES node_objects(hash), child BLOB NOT NULL REFERENCES node_objects(hash), PRIMARY KEY(parent,child))",
    ] {
        sqlx::query(statement).execute(&pool).await.unwrap();
    }
    let enabled: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(enabled, 1);
    pool
}
async fn image(pool: &SqlitePool) -> Image {
    Image {
        objects: sqlx::query("SELECT hash,contents,data FROM node_objects ORDER BY hash")
            .fetch_all(pool)
            .await
            .unwrap()
            .into_iter()
            .map(|r| (r.get("hash"), r.get("contents"), r.get("data")))
            .collect(),
        edges: sqlx::query("SELECT parent,child FROM node_edges ORDER BY parent,child")
            .fetch_all(pool)
            .await
            .unwrap()
            .into_iter()
            .map(|r| (r.get("parent"), r.get("child")))
            .collect(),
    }
}
fn restore(root: Hash, image: &Image) -> Snapshot {
    Snapshot::restore_owned(
        root,
        image
            .objects
            .iter()
            .map(|(hash, contents, data)| {
                let hash = hash.as_slice().try_into().unwrap();
                (
                    hash,
                    StoredObject {
                        hash,
                        contents: *contents,
                        data: data.clone(),
                        children: image
                            .edges
                            .iter()
                            .filter(|(parent, _)| parent.as_slice() == hash.as_slice())
                            .map(|(_, child)| child.as_slice().try_into().unwrap())
                            .collect(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
    )
    .unwrap()
}
fn wide() -> Snapshot {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    // A wide native root, with repeated child hashes across page boundaries.
    for index in 0u16..769 {
        let value = if index.is_multiple_of(3) {
            b"shared".to_vec()
        } else {
            index.to_be_bytes().to_vec()
        };
        state
            .set(&[b"accounts", &index.to_be_bytes()], value)
            .unwrap();
    }
    state.snapshot()
}

#[tokio::test]
async fn batched_objects_edges_and_reopen_match_original_writer() {
    let dir = tempfile::tempdir().unwrap();
    let old_path = dir.path().join("original.db");
    let new_path = dir.path().join("batched.db");
    let old = database(&old_path).await;
    let new = database(&new_path).await;
    let base = wide();
    let mut old_tx = old.begin().await.unwrap();
    write_snapshot_before_batching(&mut old_tx, &base, None)
        .await
        .unwrap();
    old_tx.commit().await.unwrap();
    let mut new_tx = new.begin().await.unwrap();
    write_snapshot(&mut new_tx, &base, None).await.unwrap();
    new_tx.commit().await.unwrap();
    let expected = image(&old).await;
    assert_eq!(image(&new).await, expected);
    let physical_edges = base
        .objects()
        .unwrap()
        .into_values()
        .flat_map(|object| {
            object
                .children
                .into_iter()
                .map(move |child| (object.hash, child))
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        expected.edges.len(),
        physical_edges.len(),
        "every physical native page edge persists exactly once"
    );
    assert_eq!(
        restore(base.root().unwrap(), &expected).root().unwrap(),
        base.root().unwrap()
    );

    let mut state = StateBatch::from_snapshot(base.clone());
    state.begin().unwrap();
    state
        .set(
            &[b"accounts", &17u16.to_be_bytes()],
            b"replacement".to_vec(),
        )
        .unwrap();
    state.remove(&[b"accounts", &768u16.to_be_bytes()]).unwrap();
    let next = state.snapshot();
    let mut old_tx = old.begin().await.unwrap();
    write_snapshot_before_batching(&mut old_tx, &next, Some(&base))
        .await
        .unwrap();
    old_tx.commit().await.unwrap();
    let mut new_tx = new.begin().await.unwrap();
    write_snapshot(&mut new_tx, &next, Some(&base))
        .await
        .unwrap();
    new_tx.commit().await.unwrap();
    let expected = image(&old).await;
    assert_eq!(image(&new).await, expected);
    // Existing objects must still compare exactly and duplicate edges stay idempotent.
    let mut tx = new.begin().await.unwrap();
    write_snapshot(&mut tx, &next, None).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(image(&new).await, expected);
    old.close().await;
    new.close().await;
    let reopened = connect(&new_path).await.unwrap();
    let stored = image(&reopened).await;
    assert_eq!(stored, expected);
    let restored = restore(next.root().unwrap(), &stored);
    assert_eq!(restored.root().unwrap(), next.root().unwrap());
    assert_eq!(
        restored.get(&[b"accounts", &17u16.to_be_bytes()]),
        Some(b"replacement".as_slice())
    );
    assert_eq!(restored.get(&[b"accounts", &768u16.to_be_bytes()]), None);
    reopened.close().await;
}

#[tokio::test]
async fn conflicting_existing_type_or_bytes_rollback_all_prior_inserts() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = wide();
    let objects = snapshot.objects().unwrap();
    let root = objects.get(&snapshot.root().unwrap()).unwrap();
    assert!(!root.contents);
    for (name, contents, data) in [
        ("wrong-type", true, root.data.clone()),
        ("wrong-bytes", false, b"corrupted".to_vec()),
    ] {
        let path = dir.path().join(format!("{name}.db"));
        let pool = database(&path).await;
        sqlx::query("INSERT INTO node_objects(hash,contents,data) VALUES(?,?,?)")
            .bind(root.hash.as_slice())
            .bind(contents)
            .bind(data)
            .execute(&pool)
            .await
            .unwrap();
        let before = image(&pool).await;
        let mut tx = pool.begin().await.unwrap();
        let error = write_snapshot(&mut tx, &snapshot, None).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "canonical store: conflicting persisted state object"
        );
        tx.rollback().await.unwrap();
        assert_eq!(image(&pool).await, before);
        pool.close().await;
        let reopened = connect(&path).await.unwrap();
        assert_eq!(image(&reopened).await, before);
        reopened.close().await;
    }
}

#[tokio::test]
async fn batched_edges_cannot_reference_missing_reused_children() {
    let dir = tempfile::tempdir().unwrap();
    let pool = database(&dir.path().join("foreign-key.db")).await;
    let base = wide();
    let mut setup = pool.begin().await.unwrap();
    write_snapshot(&mut setup, &base, None).await.unwrap();
    setup.commit().await.unwrap();
    let root = base.hash_at(&[b"accounts"]).unwrap().unwrap();
    let objects = base.objects().unwrap();
    let crate::state_batch::storage::Directory::Inode(
        octra_node_protocol::irmin::page::Page::Branch { children, .. },
    ) = crate::state_batch::storage::decode(&root, &objects[&root].data).unwrap()
    else {
        panic!("wide native parent");
    };
    let changed_slot = octra_node_protocol::irmin::page::slot(&17u16.to_be_bytes(), 0).unwrap();
    let missing = children
        .iter()
        .find(|(slot, _)| *slot != changed_slot)
        .unwrap()
        .1;
    // Corrupt an already authenticated prefix. The writer must keep actual FK
    // enforcement when a new parent reuses an unchanged physical child.
    let mut connection = pool.acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("DELETE FROM node_objects WHERE hash=?")
        .bind(missing.as_slice())
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    let before = image(&pool).await;
    let mut state = StateBatch::from_snapshot(base.clone());
    state.begin().unwrap();
    state
        .set(
            &[b"accounts", &17u16.to_be_bytes()],
            b"replacement".to_vec(),
        )
        .unwrap();
    let next = state.snapshot();
    let mut tx = pool.begin().await.unwrap();
    // The persisted root exists, but its reused child does not; require the real FK error.
    let error = write_snapshot(&mut tx, &next, Some(&base))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("FOREIGN KEY constraint failed"),
        "{error}"
    );
    tx.rollback().await.unwrap();
    assert_eq!(image(&pool).await, before);
    pool.close().await;
}

// Exact original writer, retained only as the differential regression oracle.
#[tokio::test]
async fn native_page_reuse_requires_an_existing_persisted_parent() {
    let dir = tempfile::tempdir().unwrap();
    let pool = database(&dir.path().join("missing-parent.db")).await;
    let base = wide();
    let mut state = StateBatch::from_snapshot(base.clone());
    state.begin().unwrap();
    state
        .set(
            &[b"accounts", &17u16.to_be_bytes()],
            b"replacement".to_vec(),
        )
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    let error = write_snapshot(&mut tx, &state.snapshot(), Some(&base))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no rows returned"), "{error}");
    tx.rollback().await.unwrap();
    assert_eq!(
        image(&pool).await,
        Image {
            objects: vec![],
            edges: vec![]
        }
    );
}

async fn write_snapshot_before_batching(
    tx: &mut Transaction<'_, Sqlite>,
    snapshot: &Snapshot,
    base: Option<&Snapshot>,
) -> Result<()> {
    for object in snapshot.object_stream(base).map_err(error)? {
        let object = object.map_err(error)?;
        sqlx::query(
            "INSERT INTO node_objects(hash,contents,data) VALUES(?,?,?) ON CONFLICT DO NOTHING",
        )
        .bind(object.hash.as_slice())
        .bind(object.contents)
        .bind(&object.data)
        .execute(&mut **tx)
        .await
        .map_err(error)?;
        let row = sqlx::query("SELECT contents,data FROM node_objects WHERE hash=?")
            .bind(object.hash.as_slice())
            .fetch_one(&mut **tx)
            .await
            .map_err(error)?;
        if row.try_get::<bool, _>("contents").map_err(error)? != object.contents
            || row.try_get::<Vec<u8>, _>("data").map_err(error)? != object.data
        {
            return Err(error("conflicting persisted state object"));
        }
        // The stream visits children first, so all edge targets already exist.
        for child in &object.children {
            sqlx::query("INSERT INTO node_edges(parent,child) VALUES(?,?) ON CONFLICT DO NOTHING")
                .bind(object.hash.as_slice())
                .bind(child.as_slice())
                .execute(&mut **tx)
                .await
                .map_err(error)?;
        }
    }
    Ok(())
}
