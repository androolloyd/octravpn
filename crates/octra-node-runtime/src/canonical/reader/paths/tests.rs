//! Trusted raw-storage fixtures; finality signatures are covered separately.
use crate::{
    canonical::{execution_root, AppliedEpoch, CanonicalStore, Head},
    state_batch::StateBatch,
};
use octra_exex::{ChainIdentity, StateRoot};
use octra_node_protocol::{epoch_index, irmin::Hash, validator::update};
use sqlx::SqlitePool;

type Links = Vec<(Vec<u8>, bool, Vec<u8>)>;
const ACTIVE: &[&[u8]] = &[b"meta", update::ACTIVE_KEY];
const PENDING: &[&[u8]] = &[b"meta", update::PENDING_KEY];

#[tokio::test]
async fn bounded_selected_contents_refuse_oversize_before_hash_and_verify_accepted_bytes() {
    let f = fixture().await;
    let reader = f.store.reader();
    assert_eq!(
        reader
            .read_at_bounded(&f.head, ACTIVE, 64)
            .await
            .unwrap()
            .unwrap(),
        b"active-v0"
    );
    let limited = reader
        .read_at_bounded(&f.head, ACTIVE, 4)
        .await
        .unwrap_err();
    assert!(limited
        .to_string()
        .contains("selected contents exceeds read limit"));
    let hash = octra_node_protocol::irmin::contents_hash(b"active-v0");
    sqlx::query("UPDATE node_objects SET data=zeroblob(1048576) WHERE hash=?")
        .bind(hash.as_slice())
        .execute(&reader.pool)
        .await
        .unwrap();
    let limited = reader
        .read_at_bounded(&f.head, ACTIVE, 64)
        .await
        .unwrap_err();
    assert!(limited
        .to_string()
        .contains("selected contents exceeds read limit"));
    sqlx::query("UPDATE node_objects SET data=? WHERE hash=?")
        .bind(b"corrupted".as_slice())
        .bind(hash.as_slice())
        .execute(&reader.pool)
        .await
        .unwrap();
    let invalid = reader
        .read_at_bounded(&f.head, ACTIVE, 64)
        .await
        .unwrap_err();
    assert!(invalid
        .to_string()
        .contains("state object commitment differs"));
    f.store.close().await;
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: CanonicalStore,
    head: Head,
}
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut state = StateBatch::default();
    state.begin().unwrap();
    for (path, value) in [
        (ACTIVE, b"active-v0".as_slice()),
        (PENDING, b"pending-v0".as_slice()),
        (&[b"meta".as_slice(), b"last_epoch"], b"0".as_slice()),
        (
            &[b"unrelated".as_slice(), b"account"],
            b"old-account".as_slice(),
        ),
    ] {
        state.set(path, value.to_vec()).unwrap();
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
        ChainIdentity::genesis("read-at-fixture", StateRoot(root)),
        state.snapshot(),
        0,
    )
    .await
    .unwrap();
    let head = store.head().await.unwrap();
    Fixture {
        _dir: dir,
        store,
        head,
    }
}
async fn advance(f: &Fixture) -> Head {
    let (_, mut state) = f.store.snapshot().await.unwrap();
    state.begin().unwrap();
    state.set(ACTIVE, b"active-v1".to_vec()).unwrap();
    state.set(PENDING, b"pending-v1".to_vec()).unwrap();
    state.set(&[b"meta", b"last_epoch"], b"1".to_vec()).unwrap();
    state
        .set(&[b"unrelated", b"account"], b"new-account".to_vec())
        .unwrap();
    let snapshot = state.snapshot();
    let expected_root = execution_root(&f.head, 1, &snapshot, &[]).unwrap();
    f.store
        .prepare(
            &f.head,
            AppliedEpoch {
                epoch: 1,
                state: snapshot,
                expected_root,
                transactions: vec![],
                certificate: b"trusted-storage-fixture".to_vec(),
                date: 1,
                message: b"next".to_vec(),
            },
        )
        .await
        .unwrap()
        .commit()
        .await
        .unwrap()
}
async fn hash_at(pool: &SqlitePool, head: &Head, path: &[&[u8]]) -> Hash {
    let mut hash: Hash = hex::decode(&head.ledger_root).unwrap().try_into().unwrap();
    for name in path {
        let raw: Vec<u8> = sqlx::query_scalar("SELECT data FROM node_objects WHERE hash=?")
            .bind(hash.as_slice())
            .fetch_one(pool)
            .await
            .unwrap();
        let links: Links = serde_json::from_slice(&raw).unwrap();
        hash = links
            .iter()
            .find(|(n, _, _)| n.as_slice() == *name)
            .unwrap()
            .2
            .as_slice()
            .try_into()
            .unwrap();
    }
    hash
}
async fn set_data(pool: &SqlitePool, hash: &Hash, data: Vec<u8>) {
    sqlx::query("UPDATE node_objects SET data=? WHERE hash=?")
        .bind(data)
        .bind(hash.as_slice())
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn retained_values_and_authenticated_absence_match_snapshot_reads() {
    let f = fixture().await;
    let latest = advance(&f).await;
    let reader = f.store.reader();
    for (head, path, expected) in [
        (&f.head, ACTIVE, Some(b"active-v0".to_vec())),
        (&f.head, PENDING, Some(b"pending-v0".to_vec())),
        (&latest, ACTIVE, Some(b"active-v1".to_vec())),
        (&latest, PENDING, Some(b"pending-v1".to_vec())),
        (&f.head, &[b"meta".as_slice(), b"absent"], None),
        (&f.head, &[b"absent".as_slice(), b"child"], None),
        (&f.head, &[b"meta".as_slice()], None),
        (
            &f.head,
            &[b"meta".as_slice(), update::ACTIVE_KEY, b"child"],
            None,
        ),
        (&f.head, &[], None),
    ] {
        assert_eq!(reader.read_at(head, path).await.unwrap(), expected);
        let tree = reader.snapshot_at(head).await.unwrap();
        assert_eq!(tree.get(path).map(<[u8]>::to_vec), expected);
    }
}

#[tokio::test]
async fn selected_metadata_does_not_restore_unrelated_historical_payload() {
    let f = fixture().await;
    advance(&f).await;
    let unrelated = hash_at(&f.store.pool, &f.head, &[b"unrelated", b"account"]).await;
    set_data(&f.store.pool, &unrelated, b"corrupt-old-account".to_vec()).await;
    let reader = f.store.reader();
    assert_eq!(
        reader.read_at(&f.head, ACTIVE).await.unwrap(),
        Some(b"active-v0".to_vec())
    );
    assert!(
        reader.snapshot_at(&f.head).await.is_err(),
        "full historical restore still authenticates the corrupted unrelated object"
    );
    assert!(
        f.store.snapshot().await.is_ok(),
        "latest authenticated tree remains intact"
    );
}

#[tokio::test]
async fn forged_head_cannot_select_a_path_even_when_the_path_is_absent() {
    let f = fixture().await;
    let mut forged = f.head.clone();
    forged.message.push(b'!');
    let error = f
        .store
        .reader()
        .read_at(&forged, &[b"absent"])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("historical head differs"));
}

#[tokio::test]
async fn altered_directory_leaf_and_selected_kind_are_rejected() {
    for mode in ["directory", "leaf", "type"] {
        let f = fixture().await;
        let meta = hash_at(&f.store.pool, &f.head, &[b"meta"]).await;
        let leaf = hash_at(&f.store.pool, &f.head, ACTIVE).await;
        match mode {
            "directory" => {
                let raw: Vec<u8> = sqlx::query_scalar("SELECT data FROM node_objects WHERE hash=?")
                    .bind(meta.as_slice())
                    .fetch_one(&f.store.pool)
                    .await
                    .unwrap();
                let mut links: Links = serde_json::from_slice(&raw).unwrap();
                links[0].2[0] ^= 1;
                set_data(&f.store.pool, &meta, serde_json::to_vec(&links).unwrap()).await;
            }
            "leaf" => set_data(&f.store.pool, &leaf, b"tampered".to_vec()).await,
            "type" => {
                sqlx::query("UPDATE node_objects SET contents=0 WHERE hash=?")
                    .bind(leaf.as_slice())
                    .execute(&f.store.pool)
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let error = f.store.reader().read_at(&f.head, ACTIVE).await.unwrap_err();
        assert!(
            error.to_string().contains(if mode == "type" {
                "invalid tree child"
            } else {
                "state object commitment differs"
            }),
            "{mode}: {error}"
        );
    }
}

#[tokio::test]
async fn duplicate_names_and_short_child_hashes_cannot_prove_absence() {
    for duplicate in [true, false] {
        let f = fixture().await;
        let meta = hash_at(&f.store.pool, &f.head, &[b"meta"]).await;
        let raw: Vec<u8> = sqlx::query_scalar("SELECT data FROM node_objects WHERE hash=?")
            .bind(meta.as_slice())
            .fetch_one(&f.store.pool)
            .await
            .unwrap();
        let mut links: Links = serde_json::from_slice(&raw).unwrap();
        if duplicate {
            links.push(links[0].clone());
        } else {
            links[0].2.pop();
        }
        set_data(&f.store.pool, &meta, serde_json::to_vec(&links).unwrap()).await;
        let error = f
            .store
            .reader()
            .read_at(&f.head, &[b"meta", b"absent"])
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains(if duplicate {
                "invalid tree child"
            } else {
                "invalid child hash"
            }),
            "{error}"
        );
    }
}

#[tokio::test]
async fn missing_selected_edge_is_unavailable_even_when_object_exists() {
    let f = fixture().await;
    let meta = hash_at(&f.store.pool, &f.head, &[b"meta"]).await;
    let leaf = hash_at(&f.store.pool, &f.head, ACTIVE).await;
    sqlx::query("DELETE FROM node_edges WHERE parent=? AND child=?")
        .bind(meta.as_slice())
        .bind(leaf.as_slice())
        .execute(&f.store.pool)
        .await
        .unwrap();
    let error = f.store.reader().read_at(&f.head, ACTIVE).await.unwrap_err();
    assert!(error.to_string().contains("missing state edge"));
}

#[tokio::test]
async fn missing_selected_object_is_an_error_instead_of_authenticated_absence() {
    let f = fixture().await;
    let leaf = hash_at(&f.store.pool, &f.head, ACTIVE).await;
    let mut connection = f.store.pool.acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("DELETE FROM node_objects WHERE hash=?")
        .bind(leaf.as_slice())
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    let error = f.store.reader().read_at(&f.head, ACTIVE).await.unwrap_err();
    assert!(error.to_string().contains("missing state object"));
}
