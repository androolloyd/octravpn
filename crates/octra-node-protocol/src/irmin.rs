//! Irmin-pack commitments with the native node's exact storage configuration:
//! Blake2b-512, 32-way hash-bits inodes and a 256-entry stable root threshold.
//! This encodes hash preimages, not the pack-file compression format.
// Derived from Irmin (ISC); attribution and license in LICENSE-IRMIN.

use blake2::{Blake2b512, Digest};
use std::collections::BTreeMap;

pub mod directory;
pub mod page;
pub mod proof;

pub type Hash = [u8; 64];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Node,
    Contents,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: Vec<u8>,
    pub kind: Kind,
    pub hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("Irmin inode exceeds the native maximum depth ({0})")]
pub struct MaxDepth(pub usize);

fn digest(bytes: &[u8]) -> Hash {
    Blake2b512::digest(bytes).into()
}

fn varint(out: &mut Vec<u8>, mut value: usize) {
    while value >= 128 {
        out.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}

fn string(out: &mut Vec<u8>, bytes: &[u8]) {
    varint(out, bytes.len());
    out.extend_from_slice(bytes);
}

pub fn contents_preimage(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + value.len());
    out.push(b'B');
    out.extend_from_slice(value);
    out
}

pub fn contents_hash(value: &[u8]) -> Hash {
    let mut hash = Blake2b512::new();
    hash.update(b"B");
    hash.update(value);
    hash.finalize().into()
}

pub fn step_hash(value: &[u8]) -> Hash {
    digest(value)
}

/// The last duplicate name wins, as in native `Node.of_list`.
fn unique(entries: &[Entry]) -> BTreeMap<&[u8], &Entry> {
    entries
        .iter()
        .map(|entry| (entry.name.as_slice(), entry))
        .collect()
}

fn flat_preimage(entries: &[&Entry]) -> Vec<u8> {
    let mut out = vec![b'N'];
    varint(&mut out, entries.len());
    for entry in entries.iter().rev() {
        out.push(match entry.kind {
            Kind::Node => 0,
            Kind::Contents => 1,
        });
        string(&mut out, &entry.name);
        out.extend_from_slice(&entry.hash);
    }
    out
}

/// The schema's flat node encoding, even when a pack root would use inodes.
pub fn flat_node_preimage(entries: &[Entry]) -> Vec<u8> {
    flat_preimage(&unique(entries).into_values().collect::<Vec<_>>())
}

/// The root commitment used by `Store.Tree.hash` for directory nodes.
pub fn node_hash(entries: &[Entry]) -> Result<Hash, MaxDepth> {
    let entries = unique(entries).into_values().collect::<Vec<_>>();
    if entries.len() <= 256 {
        return Ok(digest(&flat_preimage(&entries)));
    }
    let entries = entries
        .into_iter()
        .map(|entry| (entry, step_hash(&entry.name)))
        .collect::<Vec<_>>();
    inode_hash(&entries, 0)
}

fn inode_hash(entries: &[(&Entry, Hash)], depth: usize) -> Result<Hash, MaxDepth> {
    let mut out = Vec::new();
    if entries.len() <= 32 {
        // Node.value has a custom encoding: Node=0, Contents=1.
        out.push(0);
        varint(&mut out, entries.len());
        for (entry, _) in entries {
            string(&mut out, &entry.name);
            out.push(match entry.kind {
                Kind::Node => 0,
                Kind::Contents => 1,
            });
            out.extend_from_slice(&entry.hash);
        }
    } else {
        if depth >= 10 {
            return Err(MaxDepth(depth));
        }
        let mut children: [Vec<(&Entry, Hash)>; 32] = std::array::from_fn(|_| Vec::new());
        for &(entry, key) in entries {
            let bit = depth * 5;
            let word = u16::from_be_bytes([key[bit / 8], key[bit / 8 + 1]]);
            let index = usize::from((word >> (11 - bit % 8)) & 31);
            children[index].push((entry, key));
        }
        out.push(1);
        varint(&mut out, depth);
        varint(&mut out, entries.len());
        varint(
            &mut out,
            children.iter().filter(|child| !child.is_empty()).count(),
        );
        for (index, child) in children
            .iter()
            .enumerate()
            .filter(|(_, child)| !child.is_empty())
        {
            varint(&mut out, index);
            out.extend_from_slice(&inode_hash(child, depth + 1)?);
        }
    }
    Ok(digest(&out))
}

pub fn commit_preimage(
    node: &Hash,
    parents: &[Hash],
    date: i64,
    author: &[u8],
    message: &[u8],
) -> Vec<u8> {
    let mut parents = parents.to_vec();
    parents.sort_unstable();
    let mut out = vec![b'C'];
    out.extend_from_slice(node);
    varint(&mut out, parents.len());
    for parent in parents {
        out.extend_from_slice(&parent);
    }
    out.extend_from_slice(&date.to_be_bytes());
    string(&mut out, author);
    string(&mut out, message);
    out
}

pub fn commit_hash(
    node: &Hash,
    parents: &[Hash],
    date: i64,
    author: &[u8],
    message: &[u8],
) -> Hash {
    digest(&commit_preimage(node, parents, date, author, message))
}
