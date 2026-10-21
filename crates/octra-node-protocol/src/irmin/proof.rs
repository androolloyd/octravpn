//! Native Irmin 3.11 read proofs. The supplied root must already be authenticated
//! by consensus; a self-consistent proof does not establish a trusted root.
// Derived from Irmin and repr (ISC); attribution in LICENSE-IRMIN.
pub mod produce;
mod wire;

use super::{
    contents_hash, digest, flat_node_preimage, node_hash, step_hash, string, varint, Entry, Hash,
    Kind,
};
use crate::{native_base64, oce1::Error};
use std::collections::BTreeMap;
use wire::{Part, Proof};
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Key {
    kind: Kind,
    hash: Hash,
}
type Entries = BTreeMap<Vec<u8>, Key>;
#[derive(Clone)]
enum Directory {
    Values(Entries),
    Inode(usize),
}
enum InodeBody {
    Hidden,
    Values(Entries),
    Branch(Vec<(usize, usize)>),
}
struct Inode {
    hash: Hash,
    depth: usize,
    visible: usize,
    complete: bool,
    body: InodeBody,
}
#[derive(Clone, Copy)]
enum Loaded {
    Tree(Key),
    Inode(usize),
}
#[derive(Default)]
struct Environment {
    contents: BTreeMap<Hash, Vec<u8>>,
    nodes: BTreeMap<Hash, Directory>,
    inodes: Vec<Inode>,
}
fn invalid() -> Error {
    "proof mismatch: Invalid proof".into()
}
fn dangling(hash: &Hash) -> Error {
    format!(
        "Irmin_pack.Inode.of_proof@find: encountered dangling hash {}",
        hex::encode(hash)
    )
    .into()
}
fn pruned(context: &str, hash: &Hash) -> Error {
    format!("proof mismatch: verify_proof: {context} is trying to read through a blinded node or object ({})", hex::encode(hash)).into()
}
fn entries_hash(values: &Entries) -> Result<Hash> {
    node_hash(&entries(values)).map_err(|e| e.to_string().into())
}
fn entries(values: &Entries) -> Vec<Entry> {
    values
        .iter()
        .map(|(name, key)| Entry {
            name: name.clone(),
            kind: key.kind,
            hash: key.hash,
        })
        .collect()
}
impl Environment {
    fn push(&mut self, inode: Inode) -> usize {
        let id = self.inodes.len();
        self.inodes.push(inode);
        id
    }
    fn values(&mut self, depth: usize, values: Entries) -> usize {
        let mut raw = vec![0];
        varint(&mut raw, values.len());
        for (name, key) in &values {
            string(&mut raw, name);
            raw.push(u8::from(key.kind != Kind::Node));
            raw.extend_from_slice(&key.hash);
        }
        let hash = if depth == 0 {
            digest(&flat_node_preimage(&entries(&values)))
        } else {
            digest(&raw)
        };
        self.push(Inode {
            hash,
            depth,
            visible: values.len(),
            complete: true,
            body: InodeBody::Values(values),
        })
    }
    fn dense(&mut self, depth: usize, values: Entries) -> Result<usize> {
        if values.len() <= 32 {
            return Ok(self.values(depth, values));
        }
        if depth >= 10 {
            return Err(format!("Irmin_pack.Inode.Max_depth({depth})").into());
        }
        let length = values.len() as i64;
        let mut groups: [Entries; 32] = std::array::from_fn(|_| Entries::new());
        for (name, key) in values {
            let hash = step_hash(&name);
            let bit = depth * 5;
            let word = u16::from_be_bytes([hash[bit / 8], hash[bit / 8 + 1]]);
            groups[usize::from((word >> (11 - bit % 8)) & 31)].insert(name, key);
        }
        let mut children = Vec::new();
        for (index, group) in groups.into_iter().enumerate() {
            if !group.is_empty() {
                children.push((index, self.dense(depth + 1, group)?));
            }
        }
        self.branch(depth, length, children)
    }
    fn large_root_values(&mut self, values: Entries) -> Result<usize> {
        if values.len() <= 32 {
            return Err(invalid());
        }
        let id = self.dense(0, values)?;
        let InodeBody::Branch(children) = &self.inodes[id].body else {
            return Err(invalid());
        };
        let children = children.clone();
        let mut shallow = Vec::new();
        for (index, child) in children {
            let node = &self.inodes[child];
            let hash = node.hash;
            let depth = node.depth;
            let hidden = self.push(Inode {
                hash,
                depth,
                visible: 0,
                complete: false,
                body: InodeBody::Hidden,
            });
            shallow.push((index, hidden));
        }
        self.inodes[id].body = InodeBody::Branch(shallow);
        Ok(id)
    }
    fn flatten(&self, id: usize) -> Result<Entries> {
        let mut stack = vec![id];
        let mut out = Entries::new();
        while let Some(id) = stack.pop() {
            match &self.inodes[id].body {
                InodeBody::Hidden => return Err(dangling(&self.inodes[id].hash)),
                InodeBody::Values(values) => out.extend(values.clone()),
                InodeBody::Branch(children) => {
                    stack.extend(children.iter().rev().map(|(_, id)| *id));
                }
            }
        }
        Ok(out)
    }
    fn branch(
        &mut self,
        depth: usize,
        length: i64,
        children: Vec<(usize, usize)>,
    ) -> Result<usize> {
        if children.is_empty()
            || children.iter().any(|(i, _)| *i >= 32)
            || !children.windows(2).all(|w| w[0].0 < w[1].0)
        {
            return Err(invalid());
        }
        let visible = children
            .iter()
            .try_fold(0_usize, |n, (_, id)| {
                n.checked_add(self.inodes[*id].visible)
            })
            .ok_or_else(invalid)?;
        let complete = children.iter().all(|(_, id)| self.inodes[*id].complete);
        if length < 0 || visible > length as usize || (complete && visible != length as usize) {
            return Err(invalid());
        }
        let mut raw = vec![1];
        varint(&mut raw, depth);
        varint(&mut raw, length as usize);
        varint(&mut raw, children.len());
        for (index, id) in &children {
            varint(&mut raw, *index);
            raw.extend_from_slice(&self.inodes[*id].hash);
        }
        let id = self.push(Inode {
            hash: digest(&raw),
            depth,
            visible,
            complete,
            body: InodeBody::Branch(children),
        });
        if length == 0 || (depth == 0 && length <= 256) {
            self.inodes[id].hash = digest(&flat_node_preimage(&entries(&self.flatten(id)?)));
        }
        Ok(id)
    }
    fn install_inode(&mut self, id: usize) -> Result<Key> {
        if matches!(self.inodes[id].body, InodeBody::Hidden) {
            return Err(invalid());
        }
        let key = Key {
            kind: Kind::Node,
            hash: self.inodes[id].hash,
        };
        self.nodes.insert(key.hash, Directory::Inode(id));
        Ok(key)
    }
    fn load(&mut self, proof: &Proof) -> Result<Key> {
        let mut loaded = vec![None; proof.parts.len()];
        for &id in &proof.order {
            let tree = |id: usize| match loaded[id] {
                Some(Loaded::Tree(k)) => Ok(k),
                _ => Err(invalid()),
            };
            let inode = |id: usize| match loaded[id] {
                Some(Loaded::Inode(k)) => Ok(k),
                _ => Err(invalid()),
            };
            let value = match &proof.parts[id] {
                Part::Contents(value) => {
                    let hash = contents_hash(value);
                    self.contents.insert(hash, value.clone());
                    Loaded::Tree(Key {
                        kind: Kind::Contents,
                        hash,
                    })
                }
                Part::BlindedContents(hash) => Loaded::Tree(Key {
                    kind: Kind::Contents,
                    hash: *hash,
                }),
                Part::BlindedNode(hash) => Loaded::Tree(Key {
                    kind: Kind::Node,
                    hash: *hash,
                }),
                Part::Node(children) => {
                    let values = children
                        .iter()
                        .map(|(name, id)| Ok((name.clone(), tree(*id)?)))
                        .collect::<Result<Entries>>()?;
                    let key = Key {
                        kind: Kind::Node,
                        hash: entries_hash(&values)?,
                    };
                    self.nodes.insert(key.hash, Directory::Values(values));
                    Loaded::Tree(key)
                }
                Part::BlindedInode { hash, depth } => Loaded::Inode(self.push(Inode {
                    hash: *hash,
                    depth: *depth,
                    visible: 0,
                    complete: false,
                    body: InodeBody::Hidden,
                })),
                Part::Values { depth, children } => {
                    let values = children
                        .iter()
                        .map(|(name, id)| Ok((name.clone(), tree(*id)?)))
                        .collect::<Result<Entries>>()?;
                    if *depth == 0 && children.len() > 32 {
                        Loaded::Inode(self.large_root_values(values)?)
                    } else {
                        if children.is_empty()
                            || children.len() > 32
                            || !children.windows(2).all(|w| w[0].0 < w[1].0)
                        {
                            return Err(invalid());
                        }
                        Loaded::Inode(self.values(*depth, values))
                    }
                }
                Part::Inode {
                    root,
                    depth,
                    length,
                    children,
                } => {
                    let children = children
                        .iter()
                        .map(|(index, id)| Ok((*index, inode(*id)?)))
                        .collect::<Result<_>>()?;
                    let result = self.branch(*depth, *length, children)?;
                    if *root {
                        Loaded::Tree(self.install_inode(result)?)
                    } else {
                        Loaded::Inode(result)
                    }
                }
                Part::Extender {
                    root,
                    depth,
                    length,
                    segments,
                    child,
                } => {
                    let mut result = inode(*child)?;
                    for (offset, index) in segments.iter().enumerate().rev() {
                        result = self.branch(depth + offset, *length, vec![(*index, result)])?;
                    }
                    if *root {
                        Loaded::Tree(self.install_inode(result)?)
                    } else {
                        Loaded::Inode(result)
                    }
                }
                Part::Pending => return Err(invalid()),
            };
            loaded[id] = Some(value);
        }
        match loaded[0] {
            Some(Loaded::Tree(key)) => Ok(key),
            _ => Err(invalid()),
        }
    }
    fn find(&self, directory: &Directory, name: &[u8]) -> Result<Option<Key>> {
        let mut id = match directory {
            Directory::Values(values) => return Ok(values.get(name).copied()),
            Directory::Inode(id) => *id,
        };
        let hash = step_hash(name);
        let mut lookups = 0;
        loop {
            lookups += 1;
            if lookups > self.inodes.len() + 1 {
                return Err(invalid());
            }
            let node = &self.inodes[id];
            match &node.body {
                InodeBody::Values(values) => return Ok(values.get(name).copied()),
                InodeBody::Hidden => match self.nodes.get(&node.hash) {
                    Some(Directory::Values(values)) => return Ok(values.get(name).copied()),
                    Some(Directory::Inode(next)) => id = *next,
                    None => return Err(dangling(&node.hash)),
                },
                InodeBody::Branch(children) => {
                    if node.depth >= 10 {
                        return Err(format!("Irmin_pack.Inode.Max_depth({})", node.depth).into());
                    }
                    let bit = node.depth * 5;
                    let word = u16::from_be_bytes([hash[bit / 8], hash[bit / 8 + 1]]);
                    let index = usize::from((word >> (11 - bit % 8)) & 31);
                    match children.iter().find(|(i, _)| *i == index) {
                        Some((_, child)) => id = *child,
                        None => return Ok(None),
                    }
                }
            }
        }
    }
    fn at(&self, mut key: Key, path: &[&[u8]]) -> Result<Option<Key>> {
        for (i, name) in path.iter().enumerate() {
            if key.kind == Kind::Contents {
                return Ok(None);
            }
            let context = if i + 1 == path.len() {
                "find_tree.findv"
            } else {
                "find_tree.sub"
            };
            let directory = self
                .nodes
                .get(&key.hash)
                .ok_or_else(|| pruned(context, &key.hash))?;
            let Some(next) = self.find(directory, name)? else {
                return Ok(None);
            };
            key = next;
        }
        Ok(Some(key))
    }
    fn read(&self, key: Key, path: &[&[u8]]) -> Result<Option<Vec<u8>>> {
        let Some(key) = self.at(key, path)? else {
            return Ok(None);
        };
        if key.kind == Kind::Node {
            Ok(None)
        } else {
            self.contents
                .get(&key.hash)
                .cloned()
                .map(Some)
                .ok_or_else(|| pruned("find_all", &key.hash))
        }
    }
}

/// Verify a read against an authenticated ledger root. Missing values return
/// `None`; missing proof coverage is an error and never proves absence.
pub fn verify(ledger_root: &[u8], path: &[&[u8]], encoded: &[u8]) -> Result<Option<Vec<u8>>> {
    let (env, key) = open(ledger_root, encoded)?;
    env.read(key, path)
}
/// Authenticate a subtree commitment. Its contents may stay blinded here;
/// callers must independently restore an image with exactly this root.
pub fn verify_tree(ledger_root: &[u8], path: &[&[u8]], encoded: &[u8]) -> Result<Option<Hash>> {
    let (env, key) = open(ledger_root, encoded)?;
    let Some(key) = env.at(key, path)? else {
        return Ok(None);
    };
    if key.kind != Kind::Node {
        return Err("proof subtree is contents".into());
    }
    Ok(Some(key.hash))
}
fn open(ledger_root: &[u8], encoded: &[u8]) -> Result<(Environment, Key)> {
    let raw = native_base64::decode(encoded)
        .map_err(|e| Error::from(format!("invalid proof base64: {e}")))?;
    let proof = Proof::parse(&raw)?;
    if proof.before.kind != Kind::Node {
        return Err("proof root is not a node".into());
    }
    if proof.after.kind != Kind::Node
        || hex::encode(proof.before.hash).as_bytes() != ledger_root
        || proof.before != proof.after
    {
        return Err(format!("proof root mismatch: {}", hex::encode(proof.before.hash)).into());
    }
    let mut env = Environment::default();
    let key = env.load(&proof)?;
    if key != proof.before {
        return Err("proof mismatch: verify_proof: invalid before hash".into());
    }
    Ok((env, key))
}

/// Native packed-account read: verifies every referenced ciphertext part in the
/// same proof before reconstructing the account JSON witness.
pub fn verify_account(
    ledger_root: &[u8],
    address: &[u8],
    encoded: &[u8],
) -> Result<Option<crate::state::Account>> {
    let (env, key) = open(ledger_root, encoded)?;
    let Some(raw) = env.read(key, &[b"accounts", address, b"data"])? else {
        return Ok(None);
    };
    let data = crate::account_pack::data(&raw).map_err(|e| Error::from(e.to_string()))?;
    if let crate::account_pack::Data::Old(account) = data {
        return Ok(Some(account));
    }
    let meta = env.read(key, &[b"accounts", address, b"cipher", b"meta"])?;
    let parsed = meta
        .as_ref()
        .map(|v| crate::account_pack::meta(v))
        .transpose()
        .map_err(|e| Error::from(e.to_string()))?;
    let mut parts = BTreeMap::new();
    if let Some(meta) = &parsed {
        for id in &meta.parts {
            let value = env.read(key, &[b"accounts", address, b"cipher", b"parts", id])?;
            parts.insert(id.clone(), value);
        }
    }
    crate::account_pack::read(data, meta.as_deref(), |id| parts.get(id).cloned().flatten())
        .map(Some)
        .map_err(|e| Error::from(e.to_string()))
}
