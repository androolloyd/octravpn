//! Existing exact native Irmin corpus, replayed with cached directories at each
//! logical node. The reference fixture includes wide and colliding hash paths.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
use sha2::{Digest, Sha256};

enum Tree {
    Contents(Vec<u8>),
    Node(BTreeMap<Vec<u8>, Self>, Directory),
}
impl Default for Tree {
    fn default() -> Self {
        Self::Node(BTreeMap::new(), Directory::from_entries(&[]).unwrap())
    }
}
impl Tree {
    fn hash(&self) -> Hash {
        match self {
            Self::Contents(value) => irmin::contents_hash(value),
            Self::Node(_, directory) => directory.hash(),
        }
    }
    fn entry(&self, name: &[u8]) -> Entry {
        Entry {
            name: name.to_vec(),
            hash: self.hash(),
            kind: if matches!(self, Self::Contents(_)) {
                Kind::Contents
            } else {
                Kind::Node
            },
        }
    }
    fn set(&mut self, path: &[Vec<u8>], value: Vec<u8>) {
        let Some((name, rest)) = path.split_first() else {
            *self = Self::Contents(value);
            return;
        };
        if !matches!(self, Self::Node(..)) {
            *self = Self::default();
        }
        let Self::Node(children, directory) = self else {
            unreachable!()
        };
        let child = children.entry(name.clone()).or_default();
        child.set(rest, value);
        *directory = directory.set(child.entry(name)).unwrap();
    }
    fn remove(&mut self, path: &[Vec<u8>]) {
        let Some((name, rest)) = path.split_first() else {
            *self = Self::default();
            return;
        };
        let Self::Node(children, directory) = self else {
            return;
        };
        let Some(child) = children.get_mut(name) else {
            return;
        };
        child.remove(rest);
        if matches!(child,Self::Node(children,_) if children.is_empty()) {
            children.remove(name);
            *directory = directory.remove(name).unwrap();
        } else {
            *directory = directory.set(child.entry(name)).unwrap();
        }
    }
}
fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}

#[test]
fn cached_directory_tree_updates_replay_adopted_native_storage_corpus() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../octra-node-runtime/tests/fixtures/irmin-storage.json"
    ))
    .unwrap();
    let pin: Value = serde_json::from_str(include_str!(
        "../../../../../../docs/rust-node/upstream.json"
    ))
    .unwrap();
    assert_eq!(fixture["upstream_commit"], pin["commit"]);
    let source: Value = serde_json::from_str(include_str!(
        "../../../../../../docs/rust-node/source-map.json"
    ))
    .unwrap();
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../../../../scripts/node-port/storage-oracle.ml"
        )))
    );
    let mut cases = 0;
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        if case["input"]["op"] != "tree" {
            continue;
        }
        cases += 1;
        let mut tree = Tree::default();
        let expected = case["expected"].as_array().unwrap();
        assert_eq!(hex::encode(tree.hash()), expected[0]);
        for (offset, operation) in case["input"]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let path = operation["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(bytes)
                .collect::<Vec<_>>();
            if operation["op"] == "set" {
                tree.set(&path, bytes(&operation["value"]));
            } else {
                tree.remove(&path);
            }
            assert_eq!(
                hex::encode(tree.hash()),
                expected[offset + 1],
                "native case{index} operation{offset}: {operation}"
            );
        }
    }
    assert!(cases >= 90);
}
