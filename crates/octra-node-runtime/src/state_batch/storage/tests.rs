use super::{decode, pages, Directory, MAGIC};
use crate::state_batch::{Snapshot, StateBatch, StoredObject};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::irmin::{self, page::Page, Entry, Hash, Kind};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn wide(count: u32) -> Snapshot {
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
    state.snapshot()
}
#[test]
fn fresh_native_operations_reopen_identical_roots_across_every_threshold() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/native-inode.json")).unwrap();
    assert_eq!(
        fixture["upstream_commit"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    assert_eq!(fixture["instrumentation"], serde_json::json!({}));
    let map: Value = serde_json::from_str(include_str!(
        "../../../../../docs/rust-node/source-map.json"
    ))
    .unwrap();
    assert_eq!(fixture["source_sha256"], map["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../../../scripts/node-port/storage-oracle.ml"
        )))
    );
    assert_eq!(
        fixture["runner_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../../../scripts/node-port/native-oracle.py"
        )))
    );
    assert_eq!(
        fixture["generator_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../../../scripts/node-port/native-inode-fixtures.py"
        )))
    );
    assert_eq!(
        fixture["builder_image"],
        "sha256:65dee9f250107983aaadbf8d4aa762848bebaa3d531ad1e8e362e01cfff4fd0d"
    );
    for (case_index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let mut state = StateBatch::default();
        state.begin().unwrap();
        let mut persisted = BTreeMap::new();
        let mut previous = state.snapshot();
        for object in previous.object_stream(None).unwrap() {
            let object = object.unwrap();
            persisted.insert(object.hash, object);
        }
        assert_eq!(hex::encode(previous.root().unwrap()), case["expected"][0]);
        for (index, operation) in case["input"]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let names = operation["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| STANDARD.decode(value.as_str().unwrap()).unwrap())
                .collect::<Vec<_>>();
            let path = names.iter().map(Vec::as_slice).collect::<Vec<_>>();
            if operation["op"] == "set" {
                state
                    .set(
                        &path,
                        STANDARD
                            .decode(operation["value"].as_str().unwrap())
                            .unwrap(),
                    )
                    .unwrap();
            } else {
                state.remove(&path).unwrap();
            }
            let next = state.snapshot();
            let expected = case["expected"][index + 1].as_str().unwrap();
            assert_eq!(
                hex::encode(next.root().unwrap()),
                expected,
                "case{case_index}/op{index}"
            );
            let reusable = next.previous_wide_roots(&previous).unwrap();
            for object in next
                .object_stream_reusing(Some(&previous), reusable)
                .unwrap()
            {
                let object = object.unwrap();
                assert!(
                    object
                        .children
                        .iter()
                        .all(|hash| persisted.contains_key(hash)),
                    "child before parent"
                );
                if let Some(old) = persisted.get(&object.hash) {
                    assert_eq!(old.data, object.data);
                    assert_eq!(old.contents, object.contents);
                }
                persisted.insert(object.hash, object);
            }
            let restored = Snapshot::restore(next.root().unwrap(), &persisted).unwrap();
            assert_eq!(hex::encode(restored.root().unwrap()), expected);
            previous = next;
        }
    }
}
#[test]
fn legacy_native_and_mixed_images_restore_without_changing_commitments() {
    let state = wide(1025);
    let legacy = super::test_support::legacy(&state)
        .into_iter()
        .map(|object| (object.hash, object))
        .collect::<BTreeMap<_, _>>();
    let native = state.objects().unwrap();
    assert_ne!(legacy.len(), native.len());
    for objects in [legacy.clone(), native.clone()] {
        let restored = Snapshot::restore_owned(state.root().unwrap(), objects).unwrap();
        assert_eq!(restored.root().unwrap(), state.root().unwrap());
    }
    let legacy_root = state.hash_at(&[b"accounts"]).unwrap().unwrap();
    let mut mixed = native;
    mixed.extend(legacy);
    assert!(matches!(
        decode(&legacy_root, &mixed[&legacy_root].data).unwrap(),
        Directory::Flat(_)
    ));
    assert_eq!(
        Snapshot::restore_owned(state.root().unwrap(), mixed)
            .unwrap()
            .root()
            .unwrap(),
        state.root().unwrap()
    );
}
#[test]
fn inode_corruption_kind_missing_and_edge_changes_refuse_full_restore() {
    let state = wide(1025);
    let original = state.objects().unwrap();
    let page_hash = *original
        .iter()
        .find(|(_, object)| object.data.starts_with(MAGIC))
        .unwrap()
        .0;
    for mode in ["bytes", "kind", "missing", "edge", "extra-edge"] {
        let mut objects = original.clone();
        match mode {
            "bytes" => objects.get_mut(&page_hash).unwrap().data[5] ^= 1,
            "kind" => objects.get_mut(&page_hash).unwrap().contents = true,
            "missing" => {
                objects.remove(&page_hash);
            }
            "edge" => {
                objects.get_mut(&page_hash).unwrap().children.pop();
            }
            "extra-edge" => objects.get_mut(&page_hash).unwrap().children.push([99; 64]),
            _ => unreachable!(),
        }
        assert!(
            Snapshot::restore_owned(state.root().unwrap(), objects).is_err(),
            "{mode}"
        );
    }
}
fn object(page: &Page) -> StoredObject {
    let hash = page.hash().unwrap();
    let mut data = MAGIC.to_vec();
    data.extend(page.encode().unwrap());
    StoredObject {
        hash,
        contents: false,
        data,
        children: page.children(),
    }
}
#[test]
fn contextual_root_depth_routing_and_declared_length_are_authenticated() {
    let entry = Entry {
        name: b"leaf".to_vec(),
        kind: Kind::Contents,
        hash: irmin::contents_hash(b"value"),
    };
    let value = StoredObject {
        hash: entry.hash,
        contents: true,
        data: b"value".to_vec(),
        children: vec![],
    };
    let leaf = object(&Page::Values(vec![entry.clone()]));
    assert!(
        Snapshot::restore_owned(
            leaf.hash,
            BTreeMap::from([(leaf.hash, leaf.clone()), (value.hash, value.clone())])
        )
        .is_err(),
        "inode leaf cannot masquerade as logical root"
    );
    let root_slot = irmin::page::slot(&entry.name, 0).unwrap();
    let child_slot = irmin::page::slot(&entry.name, 1).unwrap();
    for (case, depth, length, slot, expected) in [
        (
            "depth",
            2,
            257,
            child_slot,
            "invalid inode branch depth or length",
        ),
        ("length", 1, 257, child_slot, "inode length differs"),
        (
            "routing",
            1,
            33,
            (child_slot + 1) % 32,
            "inode entry routing differs",
        ),
    ] {
        let child = object(&Page::Branch {
            depth,
            length,
            children: vec![(slot, leaf.hash)],
        });
        let root = object(&Page::Branch {
            depth: 0,
            length: 257,
            children: vec![(root_slot, child.hash)],
        });
        let objects = BTreeMap::from([
            (root.hash, root.clone()),
            (child.hash, child),
            (leaf.hash, leaf.clone()),
            (value.hash, value.clone()),
        ]);
        assert_eq!(
            Snapshot::restore_owned(root.hash, objects).unwrap_err(),
            crate::state_batch::Error(expected),
            "{case}"
        );
    }
    assert!(pages(&[entry]).unwrap().is_empty());
}

fn reject_both(root: Hash, objects: BTreeMap<Hash, StoredObject>, reason: &'static str) {
    assert_eq!(
        Snapshot::restore(root, &objects).unwrap_err(),
        crate::state_batch::Error(reason)
    );
    assert_eq!(
        Snapshot::restore_owned(root, objects).unwrap_err(),
        crate::state_batch::Error(reason)
    );
}

#[test]
fn valid_contents_and_directory_objects_cannot_use_another_requested_key() {
    let contents = StoredObject {
        hash: irmin::contents_hash(b"actual contents"),
        contents: true,
        data: b"actual contents".to_vec(),
        children: vec![],
    };
    let wrong = irmin::contents_hash(b"another requested key");
    assert_ne!(wrong, contents.hash);
    reject_both(
        wrong,
        BTreeMap::from([(wrong, contents)]),
        "state object key differs",
    );

    let state = wide(257);
    let directory = state.hash_at(&[b"accounts"]).unwrap().unwrap();
    let legacy = super::test_support::legacy(&state)
        .into_iter()
        .map(|object| (object.hash, object))
        .collect::<BTreeMap<_, _>>();
    for mut objects in [legacy, state.objects().unwrap()] {
        let object = objects.remove(&directory).unwrap();
        // Both representations have a valid commitment under their own key.
        decode(&object.hash, &object.data).unwrap();
        assert_ne!(wrong, object.hash);
        objects.insert(wrong, object);
        reject_both(wrong, objects, "state object key differs");
    }
}

#[test]
fn authenticated_directory_children_cannot_alias_other_valid_contents() {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    state
        .set(&[b"leaf"], b"expected contents".to_vec())
        .unwrap();
    let state = state.snapshot();
    let root = state.root().unwrap();
    let expected = irmin::contents_hash(b"expected contents");
    let mut objects = state.objects().unwrap();
    let other = StoredObject {
        hash: irmin::contents_hash(b"other valid contents"),
        contents: true,
        data: b"other valid contents".to_vec(),
        children: vec![],
    };
    assert_eq!(irmin::contents_hash(&other.data), other.hash);
    assert_ne!(expected, other.hash);
    objects.insert(expected, other);
    reject_both(root, objects, "state object key differs");

    let mut objects = state.objects().unwrap();
    objects.get_mut(&expected).unwrap().data.push(0);
    reject_both(root, objects, "state object commitment differs");
}

#[test]
fn physical_inode_pages_bind_the_requested_key_to_the_object_hash() {
    let state = wide(1025);
    let original = state.objects().unwrap();
    let root = state.root().unwrap();
    let directory = state.hash_at(&[b"accounts"]).unwrap().unwrap();
    let Directory::Inode(Page::Branch { children, .. }) =
        decode(&directory, &original[&directory].data).unwrap()
    else {
        panic!("expected native inode branch");
    };
    assert!(children.len() >= 2);
    let first = children[0].1;
    let second = children[1].1;
    assert_ne!(first, second);
    let other = original[&second].clone();
    decode(&other.hash, &other.data).unwrap();
    let mut objects = original.clone();
    objects.insert(first, other);
    reject_both(root, objects, "state object key differs");

    // The bytes still authenticate under the requested key, but the stored
    // object's identity metadata must not be silently ignored.
    let mut objects = original;
    objects.get_mut(&first).unwrap().hash = second;
    reject_both(root, objects, "state object key differs");
}
