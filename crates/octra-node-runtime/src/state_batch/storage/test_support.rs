//! Exact existing logical Links JSON image for legacy migration controls.
use crate::state_batch::{Node, Snapshot, StoredObject};
use std::collections::BTreeSet;
pub(crate) fn legacy(snapshot: &Snapshot) -> Vec<StoredObject> {
    snapshot.root().unwrap();
    let mut pending = vec![(snapshot.tree.as_ref(), false)];
    let mut seen = BTreeSet::new();
    let mut objects = Vec::new();
    while let Some((node, finish)) = pending.pop() {
        let hash = *node.cache().get().unwrap();
        if seen.contains(&hash) {
            continue;
        }
        let object = match node {
            Node::Contents(value, _) => StoredObject {
                hash,
                contents: true,
                data: value.clone(),
                children: vec![],
            },
            Node::Tree(children, _) if !finish => {
                pending.push((node, true));
                pending.extend(children.values().rev().map(|child| (child.as_ref(), false)));
                continue;
            }
            Node::Tree(children, _) => {
                let links = children
                    .iter()
                    .map(|(name, child)| {
                        (
                            name.clone(),
                            matches!(child.as_ref(), Node::Contents(_, _)),
                            child.cache().get().unwrap().to_vec(),
                        )
                    })
                    .collect::<super::Links>();
                StoredObject {
                    hash,
                    contents: false,
                    data: serde_json::to_vec(&links).unwrap(),
                    children: children
                        .values()
                        .map(|child| *child.cache().get().unwrap())
                        .collect(),
                }
            }
        };
        seen.insert(hash);
        objects.push(object);
    }
    objects
}
