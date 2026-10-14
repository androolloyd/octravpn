//! Persistent object tree and transaction savepoints used by execution.
//! Directory commitments use the native Irmin hash layout. An active batch is
//! speculative until the durable host publishes it.
use octra_node_protocol::irmin::{self, Entry, Hash, Kind, MaxDepth};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Tree(BTreeMap<Vec<u8>, Arc<Self>>),
    Contents(Vec<u8>),
}
impl Default for Node {
    fn default() -> Self {
        Self::Tree(BTreeMap::new())
    }
}
impl Node {
    fn hashes(&self) -> Result<BTreeMap<*const Self, Hash>, MaxDepth> {
        let mut hashes = BTreeMap::new();
        let mut pending = vec![(self, false)];
        while let Some((node, finish)) = pending.pop() {
            let key = std::ptr::from_ref(node);
            if hashes.contains_key(&key) {
                continue;
            }
            match node {
                Self::Contents(value) => {
                    hashes.insert(key, irmin::contents_hash(value));
                }
                Self::Tree(children) if !finish => {
                    pending.push((node, true));
                    pending.extend(children.values().rev().map(|child| (child.as_ref(), false)));
                }
                Self::Tree(children) => {
                    let entries = children
                        .iter()
                        .map(|(name, child)| Entry {
                            name: name.clone(),
                            kind: if matches!(child.as_ref(), Self::Contents(_)) {
                                Kind::Contents
                            } else {
                                Kind::Node
                            },
                            hash: hashes[&std::ptr::from_ref(child.as_ref())],
                        })
                        .collect::<Vec<_>>();
                    hashes.insert(key, irmin::node_hash(&entries)?);
                }
            }
        }
        Ok(hashes)
    }

    fn hash(&self) -> Result<Hash, MaxDepth> {
        Ok(self.hashes()?[&std::ptr::from_ref(self)])
    }

    fn at(&self, path: &[&[u8]]) -> Option<&Self> {
        let mut node = self;
        for step in path {
            let Self::Tree(children) = node else {
                return None;
            };
            node = children.get(*step)?.as_ref();
        }
        Some(node)
    }

    fn remove(&mut self, path: &[&[u8]]) {
        let mut current = std::mem::take(self);
        let mut ancestors = Vec::new();
        let mut depth = 0;
        while depth < path.len() {
            let Self::Tree(children) = &mut current else {
                break;
            };
            let Some(child) = children.remove(path[depth]) else {
                break;
            };
            ancestors.push((path[depth].to_vec(), std::mem::take(children)));
            current = Arc::try_unwrap(child).unwrap_or_else(|node| node.as_ref().clone());
            depth += 1;
        }
        if depth == path.len() {
            current = Self::default();
        }
        while let Some((name, mut siblings)) = ancestors.pop() {
            if !matches!(&current,Self::Tree(children) if children.is_empty()) {
                siblings.insert(name, Arc::new(current));
            }
            current = Self::Tree(siblings);
        }
        *self = current;
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        let Self::Tree(children) = self else {
            return;
        };
        let mut pending = std::mem::take(children).into_values().collect::<Vec<_>>();
        while let Some(child) = pending.pop() {
            if let Ok(Self::Tree(children)) = Arc::try_unwrap(child).as_mut() {
                pending.extend(std::mem::take(children).into_values());
            }
        }
    }
}
#[derive(Clone, Debug)]
pub struct Savepoint {
    tree: Arc<Node>,
    stealth_counter: i64,
}

/// An immutable execution snapshot. Holding one never changes the published HEAD.
#[derive(Clone, Debug)]
pub struct Snapshot {
    tree: Arc<Node>,
    stealth_counter: i64,
}

pub(crate) struct StoredObject {
    pub hash: Hash,
    pub contents: bool,
    pub data: Vec<u8>,
    pub children: Vec<Hash>,
}

type Links = Vec<(Vec<u8>, bool, Vec<u8>)>;

impl Snapshot {
    /// Immutable subtree view; descendants remain shared across snapshots.
    pub fn subtree(&self, path: &[&[u8]]) -> Option<Self> {
        let mut node = &self.tree;
        for step in path {
            let Node::Tree(children) = node.as_ref() else {
                return None;
            };
            node = children.get(*step)?;
        }
        Some(Self {
            tree: node.clone(),
            stealth_counter: 0,
        })
    }
    pub fn root(&self) -> Result<Hash, MaxDepth> {
        self.tree.hash()
    }

    pub fn get(&self, path: &[&[u8]]) -> Option<&[u8]> {
        match self.tree.at(path)? {
            Node::Contents(value) => Some(value),
            Node::Tree(_) => None,
        }
    }

    pub fn contains_tree(&self, path: &[&[u8]]) -> bool {
        self.tree.at(path).is_some()
    }

    pub fn hash_at(&self, path: &[&[u8]]) -> Result<Option<Hash>, MaxDepth> {
        self.tree.at(path).map(Node::hash).transpose()
    }

    pub fn child_count(&self, path: &[&[u8]]) -> usize {
        match self.tree.at(path) {
            Some(Node::Tree(children)) => children.len(),
            _ => 0,
        }
    }

    /// Immediate names in native byte-key order, including subtrees.
    pub fn child_names<'a>(&'a self, path: &[&[u8]]) -> impl DoubleEndedIterator<Item = &'a [u8]> {
        let children = match self.tree.at(path) {
            Some(Node::Tree(children)) => Some(children),
            _ => None,
        };
        children
            .into_iter()
            .flat_map(|children| children.keys().map(Vec::as_slice))
    }

    /// Immediate contents in native byte-key order. Nested trees are not values.
    pub fn entries<'a>(&'a self, path: &[&[u8]]) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
        let children = match self.tree.at(path) {
            Some(Node::Tree(children)) => Some(children),
            _ => None,
        };
        children
            .into_iter()
            .flat_map(|children| children.iter())
            .filter_map(|(key, node)| match node.as_ref() {
                Node::Contents(value) => Some((key.as_slice(), value.as_slice())),
                Node::Tree(_) => None,
            })
    }

    pub(crate) fn objects(&self) -> Result<BTreeMap<Hash, StoredObject>, Error> {
        let hashes = self
            .tree
            .hashes()
            .map_err(|_| Error("Irmin inode depth exhausted"))?;
        let mut out = BTreeMap::new();
        let mut pending = vec![self.tree.as_ref()];
        while let Some(node) = pending.pop() {
            let hash = hashes[&std::ptr::from_ref(node)];
            if out.contains_key(&hash) {
                continue;
            }
            let (contents, data, children) = match node {
                Node::Contents(value) => (true, value.clone(), Vec::new()),
                Node::Tree(children) => {
                    let links = children
                        .iter()
                        .map(|(name, child)| {
                            (
                                name.clone(),
                                matches!(child.as_ref(), Node::Contents(_)),
                                hashes[&std::ptr::from_ref(child.as_ref())].to_vec(),
                            )
                        })
                        .collect::<Links>();
                    let child_hashes = children
                        .values()
                        .map(|child| hashes[&std::ptr::from_ref(child.as_ref())])
                        .collect();
                    pending.extend(children.values().map(Arc::as_ref));
                    (
                        false,
                        serde_json::to_vec(&links).map_err(|_| Error("object encoding failed"))?,
                        child_hashes,
                    )
                }
            };
            out.insert(
                hash,
                StoredObject {
                    hash,
                    contents,
                    data,
                    children,
                },
            );
        }
        Ok(out)
    }

    pub(crate) fn restore(
        root: Hash,
        objects: &BTreeMap<Hash, StoredObject>,
    ) -> Result<Self, Error> {
        enum Visit {
            Enter(Hash),
            Finish(Hash, Links),
        }
        let mut pending = vec![Visit::Enter(root)];
        let mut active = BTreeSet::new();
        let mut cache = BTreeMap::<Hash, Arc<Node>>::new();
        while let Some(task) = pending.pop() {
            match task {
                Visit::Enter(hash) => {
                    if cache.contains_key(&hash) {
                        continue;
                    }
                    if !active.insert(hash) {
                        return Err(Error("cyclic state object graph"));
                    }
                    let object = objects.get(&hash).ok_or(Error("missing state object"))?;
                    if object.contents {
                        if irmin::contents_hash(&object.data) != hash {
                            return Err(Error("state object commitment differs"));
                        }
                        cache.insert(hash, Arc::new(Node::Contents(object.data.clone())));
                        active.remove(&hash);
                    } else {
                        let links: Links = serde_json::from_slice(&object.data)
                            .map_err(|_| Error("invalid tree object"))?;
                        let hashes = links
                            .iter()
                            .map(|(_, _, raw)| {
                                raw.as_slice()
                                    .try_into()
                                    .map_err(|_| Error("invalid child hash"))
                            })
                            .collect::<Result<Vec<Hash>, Error>>()?;
                        pending.push(Visit::Finish(hash, links));
                        pending.extend(hashes.into_iter().rev().map(Visit::Enter));
                    }
                }
                Visit::Finish(hash, links) => {
                    let mut children = BTreeMap::new();
                    let mut entries = Vec::with_capacity(links.len());
                    for (name, contents, raw_hash) in links {
                        let hash: Hash = raw_hash
                            .as_slice()
                            .try_into()
                            .map_err(|_| Error("invalid child hash"))?;
                        let child = cache
                            .get(&hash)
                            .ok_or(Error("missing child object"))?
                            .clone();
                        if contents != matches!(child.as_ref(), Node::Contents(_))
                            || children.insert(name.clone(), child).is_some()
                        {
                            return Err(Error("invalid tree child"));
                        }
                        entries.push(Entry {
                            name,
                            kind: if contents { Kind::Contents } else { Kind::Node },
                            hash,
                        });
                    }
                    if irmin::node_hash(&entries)
                        .map_err(|_| Error("Irmin inode depth exhausted"))?
                        != hash
                    {
                        return Err(Error("state object commitment differs"));
                    }
                    cache.insert(hash, Arc::new(Node::Tree(children)));
                    active.remove(&hash);
                }
            }
        }
        let tree = cache.remove(&root).ok_or(Error("missing state root"))?;
        let stealth_counter = match tree.at(&[b"index", b"stealth_counter"]) {
            Some(Node::Contents(raw)) => octra_node_protocol::native_integer::parse_int64(raw)
                .ok_or(Error("corrupt stealth counter"))?,
            _ => 0,
        };
        Ok(Self {
            tree,
            stealth_counter,
        })
    }
}
#[derive(Clone, Debug, Default)]
pub struct StateBatch {
    published: Arc<Node>,
    batch: Option<Arc<Node>>,
    stealth_counter: i64,
}
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub &'static str);
impl StateBatch {
    pub fn from_snapshot(snapshot: Snapshot) -> Self {
        Self {
            published: snapshot.tree,
            batch: None,
            stealth_counter: snapshot.stealth_counter,
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            tree: self.batch.as_ref().unwrap_or(&self.published).clone(),
            stealth_counter: self.stealth_counter,
        }
    }
    /// Native `read_tree` also succeeds when this path holds contents.
    pub fn contains_tree(&self, path: &[&[u8]]) -> bool {
        let mut node = self.batch.as_ref().unwrap_or(&self.published).as_ref();
        for step in path {
            let Node::Tree(children) = node else {
                return false;
            };
            let Some(child) = children.get(*step) else {
                return false;
            };
            node = child.as_ref();
        }
        true
    }

    /// Commitment of the visible tree, including any active speculative batch.
    pub fn root(&self) -> Result<Hash, MaxDepth> {
        self.batch.as_ref().unwrap_or(&self.published).hash()
    }

    pub fn published_root(&self) -> Result<Hash, MaxDepth> {
        self.published.hash()
    }

    pub fn begin(&mut self) -> Result<(), Error> {
        if self.batch.is_some() {
            return Err(Error("store epoch batch is already active"));
        }
        self.batch = Some(self.published.clone());
        Ok(())
    }
    pub fn is_active(&self) -> bool {
        self.batch.is_some()
    }
    pub fn save(&self) -> Result<Savepoint, Error> {
        Ok(Savepoint {
            tree: self
                .batch
                .as_ref()
                .ok_or(Error("store batch is not active"))?
                .clone(),
            stealth_counter: self.stealth_counter,
        })
    }
    pub fn restore(&mut self, savepoint: Savepoint) -> Result<(), Error> {
        if self.batch.is_none() {
            return Err(Error("store batch is not active"));
        }
        self.batch = Some(savepoint.tree);
        self.stealth_counter = savepoint.stealth_counter;
        Ok(())
    }
    /// Publish only after the durable host has validated and committed this tree.
    pub fn acknowledge_commit(&mut self) -> Result<(), Error> {
        self.published = self
            .batch
            .take()
            .ok_or(Error("store batch is not active"))?;
        Ok(())
    }
    pub fn abort(&mut self) {
        self.batch = None;
    }
    pub const fn stealth_counter(&self) -> i64 {
        self.stealth_counter
    }
    pub fn set_stealth_counter(&mut self, value: i64) {
        self.stealth_counter = value;
    }
    pub fn get(&self, path: &[&[u8]]) -> Option<&[u8]> {
        let mut node = self.batch.as_ref().unwrap_or(&self.published).as_ref();
        for step in path {
            let Node::Tree(children) = node else {
                return None;
            };
            node = children.get(*step)?.as_ref();
        }
        match node {
            Node::Contents(value) => Some(value),
            Node::Tree(_) => None,
        }
    }
    pub fn set(&mut self, path: &[&[u8]], value: Vec<u8>) -> Result<(), Error> {
        self.set_node(path, Arc::new(Node::Contents(value)))
    }
    /// Native add_tree semantics, including removal when grafting an empty tree.
    pub fn graft(&mut self, path: &[&[u8]], source: &Snapshot) -> Result<(), Error> {
        if matches!(source.tree.as_ref(),Node::Tree(children) if children.is_empty()) {
            self.remove(path)
        } else {
            self.set_node(path, source.tree.clone())
        }
    }
    fn set_node(&mut self, path: &[&[u8]], value: Arc<Node>) -> Result<(), Error> {
        let mut current = self
            .batch
            .as_mut()
            .ok_or(Error("store batch is not active"))?;
        for step in path {
            let node = Arc::make_mut(current);
            if !matches!(node, Node::Tree(_)) {
                *node = Node::default();
            }
            let Node::Tree(children) = node else {
                unreachable!()
            };
            current = children.entry(step.to_vec()).or_default();
        }
        *current = value;
        Ok(())
    }

    pub fn remove(&mut self, path: &[&[u8]]) -> Result<(), Error> {
        let current = self
            .batch
            .as_mut()
            .ok_or(Error("store batch is not active"))?;
        Arc::make_mut(current).remove(path);
        Ok(())
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[test]
    fn deep_object_graph_hash_restore_remove_and_drop_do_not_recurse() {
        let mut state = StateBatch::default();
        state.begin().unwrap();
        let path = vec![b"child".as_slice(); 30_000];
        state.set(&path, b"leaf".to_vec()).unwrap();
        let snapshot = state.snapshot();
        let root = snapshot.root().unwrap();
        let objects = snapshot.objects().unwrap();
        let restored = Snapshot::restore(root, &objects).unwrap();
        assert_eq!(restored.get(&path), Some(b"leaf".as_slice()));
        assert_eq!(restored.root().unwrap(), root);
        state.remove(&path).unwrap();
        assert_eq!(state.root().unwrap(), StateBatch::default().root().unwrap());
    }

    #[test]
    fn cyclic_corrupt_objects_refuse_before_constructing_a_tree() {
        let hash = [7; 64];
        let links: Links = vec![(b"loop".to_vec(), false, hash.to_vec())];
        let mut objects = BTreeMap::new();
        objects.insert(
            hash,
            StoredObject {
                hash,
                contents: false,
                data: serde_json::to_vec(&links).unwrap(),
                children: vec![hash],
            },
        );
        assert_eq!(
            Snapshot::restore(hash, &objects).unwrap_err(),
            Error("cyclic state object graph")
        );
    }

    #[test]
    fn restart_counter_comes_from_committed_tree_not_volatile_cache() {
        let mut state = StateBatch::default();
        state.begin().unwrap();
        state
            .set(&[b"index", b"stealth_counter"], b"0x7f".to_vec())
            .unwrap();
        state.set_stealth_counter(10000);
        let snapshot = state.snapshot();
        let restored =
            Snapshot::restore(snapshot.root().unwrap(), &snapshot.objects().unwrap()).unwrap();
        assert_eq!(StateBatch::from_snapshot(restored).stealth_counter(), 127);
        state
            .set(&[b"index", b"stealth_counter"], b"bad".to_vec())
            .unwrap();
        let snapshot = state.snapshot();
        assert!(Snapshot::restore(snapshot.root().unwrap(), &snapshot.objects().unwrap()).is_err());
    }
}
