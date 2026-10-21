use super::{Node, Snapshot};
use octra_node_protocol::{
    irmin::{proof::produce, Entry, Kind},
    oce1::Error,
};
impl Snapshot {
    /// Unvisited values and inode branches remain blinded. Missing paths open
    /// their searched bucket, proving absence rather than missing coverage.
    pub fn read_proof(&self, path: &[&[u8]], subtree: bool) -> Result<Vec<u8>, Error> {
        self.prove(&[path], subtree)
    }
    /// Multi-read proofs reveal only the values actually requested, even when
    /// a packed account references many ciphertext parts.
    pub fn read_proof_paths(&self, paths: &[&[&[u8]]]) -> Result<Vec<u8>, Error> {
        self.prove(paths, false)
    }
    fn prove(&self, paths: &[&[&[u8]]], subtree: bool) -> Result<Vec<u8>, Error> {
        if !matches!(self.tree.as_ref(), Node::Tree(_, _)) {
            return Err("proof root is not a node".into());
        }
        // Hashing fills immutable-node caches once. Reusing those commitments
        // avoids walking every blinded subtree for each authenticated read.
        let root = self.tree.hash().map_err(|e| Error::from(e.to_string()))?;
        struct Child<'a> {
            name: &'a [u8],
            node: &'a Node,
            proof: Option<usize>,
        }
        enum Work<'a> {
            Visit {
                id: usize,
                node: &'a Node,
                depth: usize,
                queries: Vec<usize>,
            },
            Finish {
                id: usize,
                children: Vec<Child<'a>>,
                names: Vec<&'a [u8]>,
            },
        }
        let mut pending = vec![Work::Visit {
            id: 0,
            node: self.tree.as_ref(),
            depth: 0,
            queries: (0..paths.len()).collect(),
        }];
        let mut proofs: Vec<Option<Vec<u8>>> = vec![None];
        while let Some(work) = pending.pop() {
            match work {
                Work::Visit {
                    id,
                    node,
                    depth,
                    queries,
                } => match node {
                    Node::Contents(value, _) => proofs[id] = Some(produce::contents(value)),
                    Node::Tree(children, _) => {
                        let full = subtree && queries.iter().any(|q| paths[*q].len() <= depth);
                        let names = queries
                            .iter()
                            .filter_map(|q| paths[*q].get(depth).copied())
                            .collect::<Vec<_>>();
                        let mut leaves = Vec::with_capacity(children.len());
                        let mut visits = Vec::new();
                        for (name, child) in children {
                            let selected = queries
                                .iter()
                                .copied()
                                .filter(|q| {
                                    full || paths[*q]
                                        .get(depth)
                                        .is_some_and(|step| *step == name.as_slice())
                                })
                                .collect::<Vec<_>>();
                            let proof = if full || !selected.is_empty() {
                                let child_id = proofs.len();
                                proofs.push(None);
                                visits.push(Work::Visit {
                                    id: child_id,
                                    node: child.as_ref(),
                                    depth: depth + 1,
                                    queries: selected,
                                });
                                Some(child_id)
                            } else {
                                None
                            };
                            leaves.push(Child {
                                name,
                                node: child.as_ref(),
                                proof,
                            });
                        }
                        pending.push(Work::Finish {
                            id,
                            children: leaves,
                            names,
                        });
                        pending.extend(visits.into_iter().rev());
                    }
                },
                Work::Finish {
                    id,
                    children,
                    names,
                } => {
                    let entries = children
                        .into_iter()
                        .map(|child| {
                            let proof = child
                                .proof
                                .map(|id| {
                                    proofs[id]
                                        .take()
                                        .ok_or_else(|| Error::from("selected read proof missing"))
                                })
                                .transpose()?;
                            Ok((
                                Entry {
                                    name: child.name.to_vec(),
                                    kind: if matches!(child.node, Node::Contents(_, _)) {
                                        Kind::Contents
                                    } else {
                                        Kind::Node
                                    },
                                    hash: *child.node.cache().get().ok_or_else(|| {
                                        Error::from("read proof child commitment missing")
                                    })?,
                                },
                                proof,
                            ))
                        })
                        .collect::<Result<Vec<_>, Error>>()?;
                    proofs[id] = Some(produce::directory_for_reads(&entries, &names)?);
                }
            }
        }
        let tree = proofs[0]
            .take()
            .ok_or_else(|| Error::from("missing read proof root"))?;
        Ok(produce::read(&root, &tree))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_batch::StateBatch;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use std::sync::Arc;

    #[test]
    fn subtree_commitment_proofs_keep_unrelated_values_blinded_and_prove_absence() {
        let mut state = StateBatch::default();
        state.begin().unwrap();
        state
            .set(&[b"public", b"value"], b"visible".to_vec())
            .unwrap();
        state
            .set(&[b"private", b"value"], b"hidden".to_vec())
            .unwrap();
        let snapshot = state.snapshot();
        let root = hex::encode(snapshot.root().unwrap());
        let raw = STANDARD.encode(snapshot.read_proof(&[b"public"], false).unwrap());
        assert_eq!(
            octra_node_protocol::irmin::proof::verify_tree(
                root.as_bytes(),
                &[b"public"],
                raw.as_bytes()
            )
            .unwrap(),
            Some(snapshot.subtree(&[b"public"]).unwrap().root().unwrap())
        );
        assert!(octra_node_protocol::irmin::proof::verify(
            root.as_bytes(),
            &[b"private", b"value"],
            raw.as_bytes()
        )
        .is_err());
        let raw = STANDARD.encode(snapshot.read_proof(&[b"absent"], false).unwrap());
        assert!(octra_node_protocol::irmin::proof::verify_tree(
            root.as_bytes(),
            &[b"absent"],
            raw.as_bytes()
        )
        .unwrap()
        .is_none());
        let raw = STANDARD.encode(snapshot.read_proof(&[b"public", b"value"], false).unwrap());
        assert!(octra_node_protocol::irmin::proof::verify_tree(
            root.as_bytes(),
            &[b"public", b"value"],
            raw.as_bytes()
        )
        .is_err());
        assert!(octra_node_protocol::irmin::proof::verify_tree(
            b"bad",
            &[b"public"],
            raw.as_bytes()
        )
        .is_err());
    }

    #[test]
    fn cached_read_proof_does_not_walk_blinded_descendants() {
        let mut state = StateBatch::default();
        state.begin().unwrap();
        state
            .set(&[b"public", b"value"], b"visible".to_vec())
            .unwrap();
        state
            .set(&[b"private", b"value"], b"hidden".to_vec())
            .unwrap();
        let mut snapshot = state.snapshot();
        let root = hex::encode(snapshot.root().unwrap());
        let selected = [b"public".as_slice(), b"value".as_slice()];
        let expected = snapshot.read_proof(&selected, false).unwrap();
        drop(state);

        // Evict only a blinded descendant's memo. The immutable bytes and the
        // already established parent commitments remain exactly the same.
        let Node::Tree(children, _) = Arc::get_mut(&mut snapshot.tree).unwrap() else {
            panic!("directory root");
        };
        let Node::Tree(children, _) =
            Arc::get_mut(children.get_mut(b"private".as_slice()).unwrap()).unwrap()
        else {
            panic!("private directory");
        };
        Arc::get_mut(children.get_mut(b"value".as_slice()).unwrap())
            .unwrap()
            .invalidate();

        let proof = snapshot.read_proof(&selected, false).unwrap();
        assert_eq!(
            proof, expected,
            "cache reuse preserves the exact proof bytes"
        );
        assert!(
            snapshot
                .tree
                .at(&[b"private", b"value"])
                .unwrap()
                .cache()
                .get()
                .is_none(),
            "a blinded descendant must not be visited just to collect hashes"
        );
        let encoded = STANDARD.encode(proof);
        assert_eq!(
            octra_node_protocol::irmin::proof::verify(
                root.as_bytes(),
                &selected,
                encoded.as_bytes()
            )
            .unwrap(),
            Some(b"visible".to_vec())
        );
        assert!(
            octra_node_protocol::irmin::proof::verify(
                root.as_bytes(),
                &[b"private", b"value"],
                encoded.as_bytes()
            )
            .is_err(),
            "an unrequested value remains blinded"
        );
    }
}
