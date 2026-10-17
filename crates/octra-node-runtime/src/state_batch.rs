//! Persistent object tree and transaction savepoints used by execution.
//! Directory commitments use the native Irmin hash layout. An active batch is
//! speculative until the durable host publishes it.
use octra_node_protocol::irmin::{self, directory::Directory, Entry, Hash, Kind, MaxDepth};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, OnceLock},
};
#[cfg(test)]
mod performance_tests;
mod proof;
pub(crate) mod storage;
#[cfg(test)]
mod work;
type Children = imbl::OrdMap<Vec<u8>, Arc<Node>>;
#[derive(Clone, Debug, Default)]
struct TreeCache {
    hash: OnceLock<Hash>,
    directory: OnceLock<Directory>,
    previous: Option<Directory>,
    dirty: imbl::OrdSet<Vec<u8>>,
}
impl TreeCache {
    fn changed(&mut self, name: &[u8]) {
        if let Some(directory) = self.directory.take() {
            self.previous = Some(directory);
            self.dirty.clear();
        }
        self.hash.take();
        if self.previous.is_some() {
            self.dirty.insert(name.to_vec());
        }
    }
}
#[derive(Clone, Debug)]
enum Node {
    Tree(Children, TreeCache),
    Contents(Vec<u8>, OnceLock<Hash>),
}
// Persistent-map diff must never compare ledger descendants recursively.
impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(test)]
        work::visit_child();
        std::ptr::eq(self, other)
            || (std::mem::discriminant(self) == std::mem::discriminant(other)
                && self
                    .cache()
                    .get()
                    .is_some_and(|hash| other.cache().get() == Some(hash)))
    }
}
impl Default for Node {
    fn default() -> Self {
        Self::tree(Children::new())
    }
}
impl Node {
    fn tree(children: Children) -> Self {
        Self::Tree(children, TreeCache::default())
    }
    fn contents(value: Vec<u8>) -> Self {
        Self::Contents(value, OnceLock::new())
    }
    fn cache(&self) -> &OnceLock<Hash> {
        match self {
            Self::Tree(_, cache) => &cache.hash,
            Self::Contents(_, cache) => cache,
        }
    }
    #[cfg(test)]
    fn invalidate(&mut self) {
        match self {
            Self::Tree(_, cache) => *cache = TreeCache::default(),
            Self::Contents(_, cache) => {
                cache.take();
            }
        }
    }
    fn hash(&self) -> Result<Hash, MaxDepth> {
        let mut pending = vec![(self, false)];
        while let Some((node, finish)) = pending.pop() {
            if node.cache().get().is_some() {
                continue;
            }
            let hash = match node {
                Self::Contents(value, _) => irmin::contents_hash(value),
                Self::Tree(children, cache) if !finish => {
                    pending.push((node, true));
                    if cache.previous.is_some() {
                        pending.extend(cache.dirty.iter().filter_map(|name| {
                            #[cfg(test)]
                            work::visit_child();
                            children
                                .get(name)
                                .filter(|child| child.cache().get().is_none())
                                .map(|child| (child.as_ref(), false))
                        }));
                    } else {
                        pending.extend(children.values().rev().filter_map(|child| {
                            #[cfg(test)]
                            work::visit_child();
                            child
                                .cache()
                                .get()
                                .is_none()
                                .then_some((child.as_ref(), false))
                        }));
                    }
                    continue;
                }
                Self::Tree(children, cache) => {
                    let directory = if let Some(previous) = &cache.previous {
                        let mut directory = previous.clone();
                        for name in &cache.dirty {
                            #[cfg(test)]
                            work::visit_child();
                            directory = match children.get(name) {
                                Some(child) => directory.set(entry(name, child))?,
                                None => directory.remove(name)?,
                            };
                        }
                        directory
                    } else {
                        Directory::from_entries(&storage::entries(children))?
                    };
                    let hash = directory.hash();
                    let _ = cache.directory.set(directory);
                    hash
                }
            };
            let _ = node.cache().set(hash);
        }
        Ok(*self.cache().get().expect("finished immutable root"))
    }

    fn at(&self, path: &[&[u8]]) -> Option<&Self> {
        let mut node = self;
        for step in path {
            let Self::Tree(children, _) = node else {
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
            let Self::Tree(children, cache) = &mut current else {
                break;
            };
            let Some(child) = children.remove(path[depth]) else {
                break;
            };
            cache.changed(path[depth]);
            ancestors.push((
                path[depth].to_vec(),
                std::mem::take(children),
                std::mem::take(cache),
            ));
            current = Arc::try_unwrap(child).unwrap_or_else(|node| node.as_ref().clone());
            depth += 1;
        }
        if depth == path.len() {
            current = Self::default();
        }
        while let Some((name, mut siblings, cache)) = ancestors.pop() {
            if !matches!(&current,Self::Tree(children, _) if children.is_empty()) {
                siblings.insert(name, Arc::new(current));
            }
            current = Self::Tree(siblings, cache);
        }
        *self = current;
    }
}

fn entry(name: &[u8], child: &Node) -> Entry {
    Entry {
        name: name.to_vec(),
        kind: if matches!(child, Node::Contents(_, _)) {
            Kind::Contents
        } else {
            Kind::Node
        },
        hash: *child.cache().get().expect("hashed immutable child"),
    }
}

fn changed_children<'a>(
    children: &'a Children,
    previous: Option<&'a Children>,
) -> impl Iterator<Item = (&'a Arc<Node>, Option<&'a Arc<Node>>)> {
    let changes = previous
        .into_iter()
        .flat_map(move |old| old.diff(children))
        .filter_map(|change| {
            #[cfg(test)]
            work::visit_child();
            match change {
                imbl::ordmap::DiffItem::Add(_, child) => Some((child, None)),
                imbl::ordmap::DiffItem::Update {
                    old: (_, old),
                    new: (_, child),
                } => Some((child, Some(old))),
                imbl::ordmap::DiffItem::Remove(_, _) => None,
            }
        });
    changes.chain(
        previous
            .is_none()
            .then(|| children.values().rev())
            .into_iter()
            .flatten()
            .map(|child| {
                #[cfg(test)]
                work::visit_child();
                (child, None)
            }),
    )
}
thread_local! {
    // Let the persistent map free only unshared B+tree branches. Nested ledger
    // directories join this worklist rather than recursively dropping a path.
    static DROPS: RefCell<Option<Vec<Children>>> = const { RefCell::new(None) };
}

// TLS destructors can still own ledger trees after DROPS itself has closed.
// A shared deferred queue handles concurrent final-Arc races without recursing.
static FINAL_DROPS: std::sync::Mutex<Option<Vec<Children>>> = std::sync::Mutex::new(None);
fn drop_after_tls(children: Children) {
    let mut queue = FINAL_DROPS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(queue) = queue.as_mut() {
        queue.push(children);
        return;
    }
    *queue = Some(vec![children]);
    drop(queue);
    loop {
        let next = {
            let mut queue = FINAL_DROPS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(next) = queue.as_mut().expect("active final tree drop").pop() {
                next
            } else {
                *queue = None;
                return;
            }
        };
        drop(next);
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        let Self::Tree(children, _) = self else {
            return;
        };
        if children.is_empty() {
            return;
        }
        let children = std::mem::take(children);
        let mut children = Some(children);
        let queued = DROPS.try_with(|drops| {
            let children = children.take().expect("tree drop ownership");
            let mut queue = drops.borrow_mut();
            if let Some(queue) = queue.as_mut() {
                queue.push(children);
                return;
            }
            *queue = Some(Vec::new());
            drop(queue);
            drop(children);
            loop {
                let next = drops.borrow_mut().as_mut().expect("active tree drop").pop();
                let Some(next) = next else {
                    *drops.borrow_mut() = None;
                    break;
                };
                drop(next);
            }
        });
        if queued.is_err() {
            drop_after_tls(children.take().expect("unregistered tree drop"));
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

#[derive(Clone)]
pub(crate) struct StoredObject {
    pub hash: Hash,
    pub contents: bool,
    pub data: Vec<u8>,
    pub children: Vec<Hash>,
}

type Links = Vec<(Vec<u8>, bool, Vec<u8>)>;

pub(crate) struct Objects<'a> {
    pending: Vec<(&'a Node, Option<&'a Node>, bool)>,
    seen: BTreeSet<Hash>,
    physical: Option<irmin::directory::Pages>,
    reusable_roots: BTreeSet<Hash>,
}
impl Iterator for Objects<'_> {
    type Item = Result<StoredObject, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((hash, page)) = self.physical.as_mut().and_then(Iterator::next) {
                if self.seen.contains(&hash) {
                    continue;
                }
                let object = match storage::encode_page(hash, &page) {
                    Ok(object) => object,
                    Err(error) => return Some(Err(error)),
                };
                if self.seen.insert(object.hash) {
                    return Some(Ok(object));
                }
                continue;
            }
            let (node, previous, finish) = self.pending.pop()?;
            let hash = *node.cache().get().expect("hashed immutable object");
            if self.seen.contains(&hash) || previous.is_some_and(|old| node == old) {
                continue;
            }
            let (contents, data, children) = match node {
                Node::Contents(value, _) => (true, value.clone(), Vec::new()),
                Node::Tree(children, _) if !finish => {
                    self.pending.push((node, previous, true));
                    let old = match previous {
                        Some(Node::Tree(children, _)) => Some(children),
                        _ => None,
                    };
                    self.pending.extend(changed_children(children, old).map(
                        |(child, previous)| (child.as_ref(), previous.map(Arc::as_ref), false),
                    ));
                    continue;
                }
                Node::Tree(children, cache) if children.len() > 256 => {
                    let base = match previous {
                        Some(Node::Tree(_, cache))
                            if cache
                                .hash
                                .get()
                                .is_some_and(|hash| self.reusable_roots.contains(hash)) =>
                        {
                            cache.directory.get()
                        }
                        _ => None,
                    };
                    self.physical = Some(
                        cache
                            .directory
                            .get()
                            .expect("hashed immutable directory")
                            .pages_since(base),
                    );
                    continue;
                }
                Node::Tree(children, _) => {
                    let mut links = Links::with_capacity(children.len());
                    let mut hashes = Vec::with_capacity(children.len());
                    for (name, child) in children {
                        #[cfg(test)]
                        work::visit_child();
                        let hash = *child.cache().get().expect("hashed immutable child");
                        links.push((
                            name.clone(),
                            matches!(child.as_ref(), Node::Contents(_, _)),
                            hash.to_vec(),
                        ));
                        hashes.push(hash);
                    }
                    let Ok(data) = serde_json::to_vec(&links) else {
                        return Some(Err(Error("object encoding failed")));
                    };
                    (false, data, hashes)
                }
            };
            #[cfg(test)]
            work::encode_object();
            self.seen.insert(hash);
            return Some(Ok(StoredObject {
                hash,
                contents,
                data,
                children,
            }));
        }
    }
}

impl Snapshot {
    pub(crate) fn with_persisted_counter(mut self) -> Result<Self, Error> {
        self.stealth_counter = match self.get(&[b"index", b"stealth_counter"]) {
            Some(raw) => octra_node_protocol::native_integer::parse_int64(raw)
                .ok_or(Error("corrupt stealth counter"))?,
            None => 0,
        };
        Ok(self)
    }
    /// Immutable subtree view; descendants remain shared across snapshots.
    pub fn subtree(&self, path: &[&[u8]]) -> Option<Self> {
        let mut node = &self.tree;
        for step in path {
            let Node::Tree(children, _) = node.as_ref() else {
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
            Node::Contents(value, _) => Some(value),
            Node::Tree(_, _) => None,
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
            Some(Node::Tree(children, _)) => children.len(),
            _ => 0,
        }
    }

    /// Preorder native byte-key traversal, excluding the root itself. Iterator
    /// state grows with depth rather than the width of a ledger directory.
    pub(crate) fn walk(&self) -> impl Iterator<Item = (Vec<&[u8]>, Option<&[u8]>)> {
        let mut frames = match self.tree.as_ref() {
            Node::Tree(children, _) => vec![children.iter()],
            Node::Contents(_, _) => vec![],
        };
        let mut path = Vec::new();
        std::iter::from_fn(move || loop {
            let depth = frames.len();
            let Some((name, child)) = frames.last_mut()?.next() else {
                frames.pop();
                continue;
            };
            path.truncate(depth - 1);
            path.push(name.as_slice());
            let value = match child.as_ref() {
                Node::Contents(value, _) => Some(value.as_slice()),
                Node::Tree(children, _) => {
                    frames.push(children.iter());
                    None
                }
            };
            return Some((path.clone(), value));
        })
    }

    /// Immediate names in native byte-key order, including subtrees.
    pub fn child_names<'a>(&'a self, path: &[&[u8]]) -> impl DoubleEndedIterator<Item = &'a [u8]> {
        let children = match self.tree.at(path) {
            Some(Node::Tree(children, _)) => Some(children),
            _ => None,
        };
        children
            .into_iter()
            .flat_map(|children| children.keys().map(Vec::as_slice))
    }

    /// Immediate contents in native byte-key order. Nested trees are not values.
    pub fn entries<'a>(&'a self, path: &[&[u8]]) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
        let children = match self.tree.at(path) {
            Some(Node::Tree(children, _)) => Some(children),
            _ => None,
        };
        children
            .into_iter()
            .flat_map(|children| children.iter())
            .filter_map(|(key, node)| match node.as_ref() {
                Node::Contents(value, _) => Some((key.as_slice(), value.as_slice())),
                Node::Tree(_, _) => None,
            })
    }

    #[cfg(test)]
    pub(crate) fn objects(&self) -> Result<BTreeMap<Hash, StoredObject>, Error> {
        self.objects_since(None)
    }
    /// Only an authenticated persisted parent may supply the reusable prefix.
    /// Shared subtrees remain immutable; their bytes need no repeated encoding.
    #[cfg(test)]
    pub(crate) fn objects_since(
        &self,
        base: Option<&Self>,
    ) -> Result<BTreeMap<Hash, StoredObject>, Error> {
        self.object_stream(base)?
            .map(|object| object.map(|object| (object.hash, object)))
            .collect()
    }

    /// Children precede their parents; only one object's encoded bytes are held
    /// by a streaming persistence caller, including during the initial import.
    #[cfg(test)]
    pub(crate) fn object_stream<'a>(
        &'a self,
        base: Option<&'a Self>,
    ) -> Result<Objects<'a>, Error> {
        self.object_stream_reusing(base, BTreeSet::new())
    }

    /// Only the canonical writer may grant old physical-page reuse after
    /// confirming the persisted parent uses this representation.
    pub(crate) fn object_stream_reusing<'a>(
        &'a self,
        base: Option<&'a Self>,
        reusable_roots: BTreeSet<Hash>,
    ) -> Result<Objects<'a>, Error> {
        self.root()
            .map_err(|_| Error("Irmin inode depth exhausted"))?;
        if let Some(base) = base {
            base.root()
                .map_err(|_| Error("Irmin inode depth exhausted"))?;
        }
        Ok(Objects {
            pending: vec![(
                self.tree.as_ref(),
                base.map(|base| base.tree.as_ref()),
                false,
            )],
            seen: BTreeSet::new(),
            physical: None,
            reusable_roots,
        })
    }

    /// Old wide roots whose changed successor may reuse authenticated native
    /// physical pages. Unchanged logical subtrees need no storage lookup.
    pub(crate) fn previous_wide_roots(&self, base: &Self) -> Result<BTreeSet<Hash>, Error> {
        self.root()
            .map_err(|_| Error("Irmin inode depth exhausted"))?;
        base.root()
            .map_err(|_| Error("Irmin inode depth exhausted"))?;
        let mut roots = BTreeSet::new();
        let mut pending = vec![(self.tree.as_ref(), base.tree.as_ref())];
        while let Some((node, old)) = pending.pop() {
            if node == old {
                continue;
            }
            let (Node::Tree(children, _), Node::Tree(previous, cache)) = (node, old) else {
                continue;
            };
            if children.len() > 256 && previous.len() > 256 {
                roots.insert(*cache.hash.get().expect("hashed parent directory"));
            }
            pending.extend(
                changed_children(children, Some(previous))
                    .filter_map(|(child, old)| old.map(|old| (child.as_ref(), old.as_ref()))),
            );
        }
        Ok(roots)
    }

    #[cfg(test)]
    pub(crate) fn restore(
        root: Hash,
        objects: &BTreeMap<Hash, StoredObject>,
    ) -> Result<Self, Error> {
        Self::restore_objects(root, |hash| objects.get(hash).cloned())
    }

    pub(crate) fn restore_owned(
        root: Hash,
        mut objects: BTreeMap<Hash, StoredObject>,
    ) -> Result<Self, Error> {
        Self::restore_objects(root, |hash| objects.remove(hash))
    }

    fn restore_objects(
        root: Hash,
        mut take: impl FnMut(&Hash) -> Option<StoredObject>,
    ) -> Result<Self, Error> {
        enum Visit {
            Enter(Hash),
            Finish(storage::VerifiedDirectory),
        }
        let mut pending = vec![Visit::Enter(root)];
        let mut active = BTreeSet::new();
        let mut cache = BTreeMap::<Hash, Arc<Node>>::new();
        let mut resolver = storage::Resolver::default();
        while let Some(task) = pending.pop() {
            match task {
                Visit::Enter(hash) => {
                    if cache.contains_key(&hash) {
                        continue;
                    }
                    if !active.insert(hash) {
                        return Err(Error("cyclic state object graph"));
                    }
                    let object = take(&hash).ok_or(Error("missing state object"))?;
                    if object.hash != hash {
                        return Err(Error("state object key differs"));
                    }
                    match resolver.logical(object, &mut take)? {
                        storage::Logical::Contents(value) => {
                            let node = Node::contents(value);
                            let _ = node.cache().set(hash);
                            cache.insert(hash, Arc::new(node));
                            active.remove(&hash);
                        }
                        storage::Logical::Directory(directory) => {
                            // Finish owns entries; copy child work before moving that ownership.
                            #[allow(clippy::needless_collect)]
                            let hashes = directory
                                .entries()
                                .iter()
                                .map(|entry| entry.hash)
                                .collect::<Vec<_>>();
                            pending.push(Visit::Finish(directory));
                            pending.extend(hashes.into_iter().rev().map(Visit::Enter));
                        }
                    }
                }
                Visit::Finish(directory) => {
                    let (hash, links) = directory.into_parts();
                    let directory = Directory::from_entries(&links)
                        .map_err(|_| Error("Irmin inode depth exhausted"))?;
                    if directory.hash() != hash {
                        return Err(Error("state object commitment differs"));
                    }
                    let mut children = Children::new();
                    for entry in links {
                        let child = cache
                            .get(&entry.hash)
                            .ok_or(Error("missing child object"))?
                            .clone();
                        if (entry.kind == Kind::Contents)
                            != matches!(child.as_ref(), Node::Contents(_, _))
                            || children.insert(entry.name.clone(), child).is_some()
                        {
                            return Err(Error("invalid tree child"));
                        }
                    }
                    let node = Node::Tree(
                        children,
                        TreeCache {
                            hash: OnceLock::from(hash),
                            directory: OnceLock::from(directory),
                            ..TreeCache::default()
                        },
                    );
                    cache.insert(hash, Arc::new(node));
                    active.remove(&hash);
                }
            }
        }
        let tree = cache.remove(&root).ok_or(Error("missing state root"))?;
        Self {
            tree,
            stealth_counter: 0,
        }
        .with_persisted_counter()
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
            let Node::Tree(children, _) = node else {
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
            let Node::Tree(children, _) = node else {
                return None;
            };
            node = children.get(*step)?.as_ref();
        }
        match node {
            Node::Contents(value, _) => Some(value),
            Node::Tree(_, _) => None,
        }
    }
    pub fn set(&mut self, path: &[&[u8]], value: Vec<u8>) -> Result<(), Error> {
        self.set_node(path, Arc::new(Node::contents(value)))
    }
    /// Native add_tree semantics, including removal when grafting an empty tree.
    pub fn graft(&mut self, path: &[&[u8]], source: &Snapshot) -> Result<(), Error> {
        if matches!(source.tree.as_ref(),Node::Tree(children, _) if children.is_empty()) {
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
        if current.at(path).is_some_and(|old| {
            old == value.as_ref()
                || matches!((old, value.as_ref()), (Node::Contents(old, _), Node::Contents(new, _)) if old == new)
        }) {
            return Ok(());
        }
        for step in path {
            let node = Arc::make_mut(current);
            if !matches!(node, Node::Tree(_, _)) {
                *node = Node::default();
            }
            let Node::Tree(children, cache) = node else {
                unreachable!()
            };
            cache.changed(step);
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
        if current.at(path).is_none()
            || (path.is_empty()
                && matches!(current.as_ref(), Node::Tree(children, _) if children.is_empty()))
        {
            return Ok(());
        }
        Arc::make_mut(current).remove(path);
        Ok(())
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[test]
    fn shared_deep_subtrees_drop_concurrently_after_thread_local_teardown() {
        thread_local! {
            static HELD: RefCell<Option<Snapshot>> = const { RefCell::new(None) };
        }
        let mut state = StateBatch::default();
        state.begin().unwrap();
        let path = vec![b"child".as_slice(); 30_000];
        state.set(&path, b"leaf".to_vec()).unwrap();
        let snapshot = state.snapshot();
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let mut threads = Vec::new();
        for index in 0..8 {
            let subtree = snapshot.subtree(&path[..index * 3000]).unwrap();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                HELD.with(|held| *held.borrow_mut() = Some(subtree));
                let mut trigger = StateBatch::default();
                trigger.begin().unwrap();
                trigger.set(&[b"trigger"], vec![1]).unwrap();
                drop(trigger);
                barrier.wait();
            }));
        }
        drop(snapshot);
        drop(state);
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn deep_tree_drops_after_its_thread_local_worklist_has_closed() {
        thread_local! {
            static HELD: RefCell<Option<StateBatch>> = const { RefCell::new(None) };
        }
        std::thread::spawn(|| {
            HELD.with(|held| assert!(held.borrow().is_none()));
            let mut deep = StateBatch::default();
            deep.begin().unwrap();
            deep.set(&vec![b"child".as_slice(); 30_000], b"leaf".to_vec())
                .unwrap();
            HELD.with(|held| *held.borrow_mut() = Some(deep));
            // Register the drop worklist after HELD, so TLS destruction closes
            // it before dropping the deep ledger retained by HELD.
            let mut trigger = StateBatch::default();
            trigger.begin().unwrap();
            trigger.set(&[b"trigger"], vec![1]).unwrap();
            drop(trigger);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn transaction_savepoints_share_wide_directories_without_cloning_unrelated_entries() {
        let mut state = StateBatch::default();
        state.begin().unwrap();
        for index in 0u32..4096 {
            state
                .set(&[&index.to_be_bytes()], index.to_be_bytes().to_vec())
                .unwrap();
        }
        let base = state.snapshot();
        let Node::Tree(children, _) = base.tree.as_ref() else {
            unreachable!()
        };
        let unrelated = children.get(0u32.to_be_bytes().as_slice()).unwrap();
        let owners = Arc::strong_count(unrelated);
        let savepoint = state.save().unwrap();
        state
            .set(&[&2048u32.to_be_bytes()], b"edited".to_vec())
            .unwrap();
        assert_eq!(
            Arc::strong_count(unrelated),
            owners,
            "an unrelated leaf page must stay shared"
        );
        assert_eq!(
            base.get(&[&2048u32.to_be_bytes()]),
            Some(2048u32.to_be_bytes().as_slice())
        );
        assert_eq!(
            state.get(&[&2048u32.to_be_bytes()]),
            Some(b"edited".as_slice())
        );
        state.restore(savepoint).unwrap();
        assert_eq!(
            state.get(&[&2048u32.to_be_bytes()]),
            base.get(&[&2048u32.to_be_bytes()])
        );
    }

    #[test]
    fn cached_hashes_track_edits_savepoints_removal_and_equal_replacements() {
        let mut state = StateBatch::default();
        state.begin().unwrap();
        state
            .set(&[b"accounts", b"alice"], b"one".to_vec())
            .unwrap();
        state.set(&[b"accounts", b"bob"], b"two".to_vec()).unwrap();
        let base = state.snapshot();
        let root = base.root().unwrap();
        let saved = state.save().unwrap();
        state
            .set(&[b"accounts", b"alice"], b"changed".to_vec())
            .unwrap();
        let changed = state.snapshot();
        assert_ne!(changed.root().unwrap(), root);
        let checked =
            Snapshot::restore(changed.root().unwrap(), &changed.objects().unwrap()).unwrap();
        assert_eq!(
            checked.get(&[b"accounts", b"alice"]),
            Some(b"changed".as_slice())
        );
        assert_eq!(base.root().unwrap(), root);
        state.restore(saved).unwrap();
        assert_eq!(state.root().unwrap(), root);
        state
            .set(&[b"accounts", b"alice"], b"one".to_vec())
            .unwrap();
        assert_eq!(state.root().unwrap(), root);
        assert!(state
            .snapshot()
            .objects_since(Some(&base))
            .unwrap()
            .is_empty());
        state.remove(&[b"accounts", b"bob"]).unwrap();
        let removed = state.snapshot();
        let mut objects = base.objects().unwrap();
        let delta = removed.objects_since(Some(&base)).unwrap();
        assert_eq!(
            delta.len(),
            2,
            "only the changed directory and its ancestor"
        );
        objects.extend(delta);
        let restored = Snapshot::restore_owned(removed.root().unwrap(), objects).unwrap();
        assert_eq!(
            restored.get(&[b"accounts", b"alice"]),
            Some(b"one".as_slice())
        );
        assert_eq!(restored.get(&[b"accounts", b"bob"]), None);
    }

    #[test]
    fn object_stream_persists_children_first_and_reuses_immutable_payloads() {
        let mut state = StateBatch::default();
        state.begin().unwrap();
        for index in 0u16..256 {
            state
                .set(
                    &[b"accounts", &index.to_be_bytes()],
                    vec![index as u8; 4096],
                )
                .unwrap();
        }
        let base = state.snapshot();
        let root = base.root().unwrap();
        let mut persisted = BTreeMap::new();
        for object in base.object_stream(None).unwrap() {
            let object = object.unwrap();
            assert!(object
                .children
                .iter()
                .all(|hash| persisted.contains_key(hash)));
            persisted.insert(object.hash, object);
        }
        assert_eq!(
            Snapshot::restore(root, &persisted).unwrap().root().unwrap(),
            root
        );
        state
            .set(
                &[b"accounts", &100u16.to_be_bytes()],
                b"new payload".to_vec(),
            )
            .unwrap();
        let next = state.snapshot();
        let delta = next.objects_since(Some(&base)).unwrap();
        assert_eq!(delta.len(), 3, "one leaf, its directory and root");
        persisted.extend(delta);
        let restored = Snapshot::restore_owned(next.root().unwrap(), persisted).unwrap();
        assert_eq!(
            restored.get(&[b"accounts", &100u16.to_be_bytes()]),
            Some(b"new payload".as_slice())
        );
        assert_eq!(
            restored.get(&[b"accounts", &101u16.to_be_bytes()]),
            Some(vec![101u8; 4096].as_slice())
        );
    }

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
