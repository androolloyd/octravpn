//! Pinned native Node/Tree diagnostic bytes, signatures and shared finalize table.
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    legacy_tree::{self, Node, Tree},
    transaction::Nonce,
};
use serde_json::Value;

fn bytes(value: &Value, field: &str) -> Vec<u8> {
    STANDARD.decode(value[field].as_str().unwrap()).unwrap()
}

#[test]
fn native_diagnostic_hashes_signatures_and_shallow_finalize_match_exactly() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/legacy-tree.json")).unwrap();
    assert_eq!(
        fixture["upstream_commit"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    let inputs = fixture["inputs"].as_array().unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(inputs.len(), cases.len());
    for (index, (input, expected)) in inputs.iter().zip(cases).enumerate() {
        let node = Node::decode(&bytes(input, "node_b64")).unwrap();
        if input["operation"] == "node" {
            assert_eq!(
                node.encode().unwrap(),
                bytes(expected, "encoded_b64"),
                "node JSON case {index}"
            );
            assert_eq!(
                node.hash(),
                expected["hash"].as_str().unwrap().as_bytes(),
                "node hash case {index}"
            );
            assert_eq!(
                legacy_tree::string_of_float(node.metrics.score()),
                expected["score"].as_str().unwrap().as_bytes(),
                "native float score case {index}"
            );
            let key = STANDARD.encode([9; 32]);
            assert_eq!(
                node.sign(key.as_bytes()).unwrap(),
                expected["signature"].as_str().unwrap().as_bytes(),
                "native signature case {index}"
            );
        } else {
            let epoch = input["epoch"].as_str().unwrap().parse().unwrap();
            let mut tree = Tree::create(Nonce::new(epoch).unwrap(), b"prior\0commit".to_vec());
            assert_eq!(
                tree.add_node(node.clone()).unwrap(),
                expected["first"].as_bool().unwrap()
            );
            assert_eq!(
                tree.add_node(node.clone()).unwrap(),
                expected["duplicate"].as_bool().unwrap()
            );
            tree.add_commit_signature(b"z".to_vec(), b"first".to_vec());
            tree.add_commit_signature(b"a".to_vec(), b"second".to_vec());
            tree.add_commit_signature(b"z".to_vec(), b"ignored".to_vec());
            assert_eq!(
                tree.encode().unwrap(),
                bytes(expected, "before_b64"),
                "tree before case {index}"
            );
            let finalized = tree
                .finalized(b"validator-final".to_vec(), vec![], None)
                .unwrap();
            assert_eq!(
                finalized.encode().unwrap(),
                bytes(expected, "final_b64"),
                "tree finalize case {index}"
            );
            let mut child = node.clone();
            child.id = b"child".to_vec();
            child.parent = Some(node.hash());
            assert_eq!(
                tree.add_node(child).unwrap(),
                expected["child"].as_bool().unwrap()
            );
            let mut root = node;
            root.id = b"later-root".to_vec();
            root.parent = None;
            assert_eq!(
                tree.add_node(root).unwrap(),
                expected["root"].as_bool().unwrap()
            );
            assert_eq!(
                finalized.encode().unwrap(),
                bytes(expected, "shared_final_b64"),
                "shared finalized table case {index}"
            );
            assert_eq!(
                tree.encode().unwrap(),
                bytes(expected, "after_b64"),
                "original tree case {index}"
            );
            assert_eq!(
                finalized.hash().unwrap(),
                expected["final_hash"].as_str().unwrap().as_bytes(),
                "final hash case {index}"
            );
            assert_eq!(
                tree.root_count().get(),
                expected["original_roots"].as_i64().unwrap()
            );
            assert_eq!(
                finalized.root_count().get(),
                expected["final_roots"].as_i64().unwrap()
            );
        }
    }
}
