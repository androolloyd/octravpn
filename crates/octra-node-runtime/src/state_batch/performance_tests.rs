use super::{storage::test_support::legacy, work, Node, Snapshot, StateBatch, StoredObject};
use octra_node_protocol::irmin::{self, Entry, Hash, Kind};
use std::{collections::BTreeMap, sync::Arc};

fn wide(count: u32) -> StateBatch {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    for index in 0..count {
        state
            .set(
                &[b"accounts", &index.to_be_bytes()],
                index.to_le_bytes().to_vec(),
            )
            .unwrap();
    }
    state.root().unwrap();
    state
}

// The independent, pre-cache batch commitment algorithm is small enough to
// serve as a reference for these shallow ledgers and every intermediate edit.
fn reference(node: &Node) -> Hash {
    match node {
        Node::Contents(value, _) => irmin::contents_hash(value),
        Node::Tree(children, _) => irmin::node_hash(
            &children
                .iter()
                .map(|(name, child)| Entry {
                    name: name.clone(),
                    kind: if matches!(child.as_ref(), Node::Contents(_, _)) {
                        Kind::Contents
                    } else {
                        Kind::Node
                    },
                    hash: reference(child),
                })
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    }
}

fn insert_stream(
    objects: &mut BTreeMap<Hash, StoredObject>,
    stream: impl Iterator<Item = Result<StoredObject, super::Error>>,
) -> usize {
    let mut count = 0;
    for object in stream {
        let object = object.unwrap();
        assert!(
            object
                .children
                .iter()
                .all(|hash| objects.contains_key(hash)),
            "a parent cannot reference an absent physical or logical child"
        );
        if let Some(old) = objects.get(&object.hash) {
            assert_eq!(old.contents, object.contents);
            if old.data != object.data {
                assert!(super::storage::compatible(&object.hash, &old.data, &object.data).unwrap());
                continue; // Existing legacy representation and edges stay immutable.
            }
        }
        objects.insert(object.hash, object);
        count += 1;
    }
    count
}

#[test]
fn sparse_hot_edits_do_not_scan_the_ledger_width() {
    for width in [512, 4096, 32_768] {
        let mut state = wide(width);
        let mut previous = state.snapshot();
        let mut objects = previous.objects().unwrap();
        for epoch in 1u32..=8 {
            work::reset();
            state
                .set(
                    &[b"accounts", &(width / 2).to_be_bytes()],
                    epoch.to_be_bytes().to_vec(),
                )
                .unwrap();
            let next = state.snapshot();
            let grants = next.previous_wide_roots(&previous).unwrap();
            let emitted = insert_stream(
                &mut objects,
                next.object_stream_reusing(Some(&previous), grants).unwrap(),
            );
            let counts = work::snapshot();
            eprintln!("sparse width={width} epoch={epoch}: {counts:?}, emitted={emitted}");
            assert!(
                counts.child_visits < 1024,
                "full-width traversal: {counts:?}"
            );
            assert!(
                counts.encoded_objects <= 16,
                "full-page regeneration: {counts:?}"
            );
            assert!(emitted <= 16);
            assert_eq!(next.root().unwrap(), reference(next.tree.as_ref()));
            previous = next;
        }
        let restored = Snapshot::restore_owned(previous.root().unwrap(), objects).unwrap();
        assert_eq!(restored.root().unwrap(), previous.root().unwrap());
        assert_eq!(
            restored.get(&[b"accounts", &(width / 2).to_be_bytes()]),
            Some(8u32.to_be_bytes().as_slice())
        );
    }
}

#[test]
fn unchanged_mutations_keep_cached_snapshots_and_require_an_active_batch() {
    let mut state = wide(4096);
    let base = state.snapshot();
    work::reset();
    state
        .set(
            &[b"accounts", &12u32.to_be_bytes()],
            12u32.to_le_bytes().to_vec(),
        )
        .unwrap();
    state.remove(&[b"accounts", b"missing"]).unwrap();
    state.remove(&[b"missing", b"child"]).unwrap();
    state.graft(&[], &base).unwrap();
    let unchanged = state.snapshot();
    assert!(Arc::ptr_eq(&base.tree, &unchanged.tree));
    assert_eq!(unchanged.root().unwrap(), base.root().unwrap());
    assert!(unchanged.previous_wide_roots(&base).unwrap().is_empty());
    assert!(unchanged
        .object_stream(Some(&base))
        .unwrap()
        .next()
        .is_none());
    let counts = work::snapshot();
    assert!(
        counts.child_visits < 16,
        "no-op traversed descendants: {counts:?}"
    );
    assert_eq!(counts.encoded_objects, 0);
    state.acknowledge_commit().unwrap();
    assert!(state
        .set(
            &[b"accounts", &12u32.to_be_bytes()],
            12u32.to_le_bytes().to_vec()
        )
        .is_err());
    assert!(state.remove(&[b"missing"]).is_err());
    assert!(state.graft(&[], &unchanged).is_err());
}

#[test]
fn repeated_cached_versions_do_not_retain_old_ledger_nodes() {
    let mut state = wide(1025);
    for version in 1u32..=128 {
        let previous = state.snapshot();
        let Node::Tree(children, _) = previous.tree.as_ref() else {
            unreachable!()
        };
        let Node::Tree(accounts, _) = children.get(b"accounts".as_slice()).unwrap().as_ref() else {
            unreachable!()
        };
        let old = Arc::downgrade(accounts.get(0u32.to_be_bytes().as_slice()).unwrap());
        state
            .set(
                &[b"accounts", &0u32.to_be_bytes()],
                version.to_le_bytes().to_vec(),
            )
            .unwrap();
        state.root().unwrap();
        assert!(
            old.upgrade().is_some(),
            "the live snapshot must keep its leaf"
        );
        drop(previous);
        assert!(
            old.upgrade().is_none(),
            "cache lineage retained an obsolete contents node"
        );
    }
    assert_eq!(
        state.root().unwrap(),
        reference(state.snapshot().tree.as_ref())
    );
}

#[test]
fn savepoint_restore_and_kind_changes_match_independent_commitments() {
    let mut state = wide(257);
    state.set_stealth_counter(9);
    let saved = state.save().unwrap();
    let original = state.snapshot();
    for key in [0u32, 1] {
        state.remove(&[b"accounts", &key.to_be_bytes()]).unwrap();
        assert_eq!(
            state.root().unwrap(),
            reference(state.snapshot().tree.as_ref())
        );
    }
    state.set_stealth_counter(23);
    state.restore(saved).unwrap();
    assert_eq!(state.stealth_counter(), 9);
    assert_eq!(state.root().unwrap(), original.root().unwrap());
    state
        .set(
            &[b"accounts", &17u32.to_be_bytes(), b"nested"],
            b"value".to_vec(),
        )
        .unwrap();
    assert_eq!(
        state.root().unwrap(),
        reference(state.snapshot().tree.as_ref())
    );
    state
        .set(
            &[b"accounts", &17u32.to_be_bytes()],
            b"contents again".to_vec(),
        )
        .unwrap();
    state.remove(&[b"accounts", &18u32.to_be_bytes()]).unwrap();
    assert_eq!(
        state.root().unwrap(),
        reference(state.snapshot().tree.as_ref())
    );
    state
        .set(&[b"accounts", b"new-key"], b"new".to_vec())
        .unwrap();
    assert_eq!(
        state.root().unwrap(),
        reference(state.snapshot().tree.as_ref())
    );
    assert_eq!(original.child_count(&[b"accounts"]), 257);
    assert_eq!(
        original.get(&[b"accounts", &17u32.to_be_bytes()]),
        Some(17u32.to_le_bytes().as_slice())
    );
}

#[test]
fn physical_reuse_needs_a_persisted_native_grant() {
    let mut state = wide(4096);
    let base = state.snapshot();
    let mut native = base.objects().unwrap();
    let mut legacy_image = legacy(&base)
        .into_iter()
        .map(|object| (object.hash, object))
        .collect::<BTreeMap<_, _>>();
    state
        .set(&[b"accounts", &17u32.to_be_bytes()], b"changed".to_vec())
        .unwrap();
    let next = state.snapshot();
    let grants = next.previous_wide_roots(&base).unwrap();
    assert!(!grants.is_empty());
    let reused = insert_stream(
        &mut native,
        next.object_stream_reusing(Some(&base), grants).unwrap(),
    );
    let rebuilt = insert_stream(&mut legacy_image, next.object_stream(Some(&base)).unwrap());
    assert!(reused <= 16);
    assert!(
        rebuilt > reused * 4,
        "a legacy-only target must receive unchanged physical pages"
    );
    for objects in [native, legacy_image] {
        let reopened = Snapshot::restore_owned(next.root().unwrap(), objects).unwrap();
        assert_eq!(reopened.root().unwrap(), next.root().unwrap());
    }
}

#[test]
fn authenticated_restore_has_a_warm_sparse_successor() {
    let base = wide(8192).snapshot();
    let objects = base.objects().unwrap();
    let restored = Snapshot::restore(base.root().unwrap(), &objects).unwrap();
    let mut state = StateBatch::from_snapshot(restored.clone());
    state.begin().unwrap();
    work::reset();
    state
        .set(&[b"accounts", &17u32.to_be_bytes()], b"changed".to_vec())
        .unwrap();
    let next = state.snapshot();
    let grants = next.previous_wide_roots(&restored).unwrap();
    let emitted = next
        .object_stream_reusing(Some(&restored), grants)
        .unwrap()
        .map(Result::unwrap)
        .count();
    let counts = work::snapshot();
    eprintln!("restored width=8192: {counts:?}, emitted={emitted}");
    assert!(
        counts.child_visits < 1024,
        "restore discarded the authenticated cache: {counts:?}"
    );
    assert!(counts.encoded_objects <= 16);
    assert_eq!(next.root().unwrap(), reference(next.tree.as_ref()));
}

#[test]
fn cross_store_graft_emits_every_required_foreign_page() {
    let foreign = wide(1025).snapshot().subtree(&[b"accounts"]).unwrap();
    let mut target = StateBatch::default();
    target.begin().unwrap();
    target.set(&[b"local"], b"local".to_vec()).unwrap();
    let base = target.snapshot();
    let mut objects = base.objects().unwrap();
    target.graft(&[b"foreign"], &foreign).unwrap();
    let next = target.snapshot();
    let grants = next.previous_wide_roots(&base).unwrap();
    assert!(grants.is_empty());
    assert!(
        insert_stream(
            &mut objects,
            next.object_stream_reusing(Some(&base), grants).unwrap()
        ) > 1025
    );
    let reopened = Snapshot::restore_owned(next.root().unwrap(), objects).unwrap();
    assert_eq!(reopened.root().unwrap(), reference(next.tree.as_ref()));
    assert_eq!(reopened.child_count(&[b"foreign"]), 1025);
}
