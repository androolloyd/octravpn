//! Versioned disk envelope for exact native inode preimages. Existing logical
//! Links JSON stays readable and remains the encoding for <=256-entry roots.
use super::{Error, StoredObject};
use octra_node_protocol::irmin::{self, page::Page, Entry, Hash, Kind};
use std::collections::BTreeSet;
mod restore;
pub(super) use restore::{Logical, Resolver, VerifiedDirectory};
pub(crate) const MAGIC: &[u8] = b"OIP\x01";
type Links = Vec<(Vec<u8>, bool, Vec<u8>)>;

#[derive(Clone, Debug)]
pub(crate) enum Directory {
    Flat(Vec<Entry>),
    Inode(Page),
}
impl Directory {
    pub(crate) fn children(&self) -> Vec<Hash> {
        match self {
            Self::Flat(entries) => entries.iter().map(|entry| entry.hash).collect(),
            Self::Inode(page) => page.children(),
        }
    }
    pub(crate) fn logical_root(&self) -> Result<(), Error> {
        match self {
            Self::Flat(_) => Ok(()),
            Self::Inode(Page::Branch {
                depth: 0, length, ..
            }) if *length > 256 => Ok(()),
            Self::Inode(_) => Err(Error("inode is not a logical root")),
        }
    }
}

pub(crate) fn decode(hash: &Hash, bytes: &[u8]) -> Result<Directory, Error> {
    if let Some(raw) = bytes.strip_prefix(MAGIC) {
        let page = Page::decode(raw).map_err(|_| Error("invalid inode page"))?;
        if page.hash().map_err(|_| Error("invalid inode page"))? != *hash {
            return Err(Error("state object commitment differs"));
        }
        return Ok(Directory::Inode(page));
    }
    let links: Links = serde_json::from_slice(bytes).map_err(|_| Error("invalid tree object"))?;
    let mut names = BTreeSet::new();
    let mut entries = Vec::with_capacity(links.len());
    for (name, contents, raw) in links {
        if !names.insert(name.clone()) {
            return Err(Error("invalid tree child"));
        }
        entries.push(Entry {
            name,
            kind: if contents { Kind::Contents } else { Kind::Node },
            hash: raw
                .as_slice()
                .try_into()
                .map_err(|_| Error("invalid child hash"))?,
        });
    }
    if irmin::node_hash(&entries).map_err(|_| Error("Irmin inode depth exhausted"))? != *hash {
        return Err(Error("state object commitment differs"));
    }
    Ok(Directory::Flat(entries))
}

pub(crate) fn edges(object: &StoredObject, expected: &[Hash]) -> Result<(), Error> {
    let actual = object.children.iter().copied().collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(Error("state object edges differ"));
    }
    Ok(())
}

pub(crate) fn pages(entries: &[Entry]) -> Result<Vec<StoredObject>, Error> {
    irmin::page::directory(entries)
        .map_err(|_| Error("Irmin inode depth exhausted"))?
        .into_iter()
        .map(|(hash, page)| {
            let mut data = MAGIC.to_vec();
            data.extend(page.encode().map_err(|_| Error("invalid inode page"))?);
            Ok(StoredObject {
                hash,
                contents: false,
                data,
                children: page.children(),
            })
        })
        .collect()
}

/// Only native root pages and legacy logical directories can be two encodings
/// of one commitment. Reproduce the page from the complete authenticated legacy
/// entries; matching only the key or accepting arbitrary conflicting bytes is
/// insufficient. The caller retains the existing representation and its edges.
pub(crate) fn compatible(hash: &Hash, existing: &[u8], incoming: &[u8]) -> Result<bool, Error> {
    let old = decode(hash, existing)?;
    let new = decode(hash, incoming)?;
    match (old, new) {
        (Directory::Flat(entries), Directory::Inode(Page::Branch { depth: 0, .. })) => {
            let pages = pages(&entries)?;
            Ok(pages
                .last()
                .is_some_and(|root| root.hash == *hash && root.data == incoming))
        }
        _ => Ok(false),
    }
}

pub(super) fn entries(children: &super::Children) -> Vec<Entry> {
    children
        .iter()
        .map(|(name, child)| Entry {
            name: name.clone(),
            kind: if matches!(child.as_ref(), super::Node::Contents(_, _)) {
                Kind::Contents
            } else {
                Kind::Node
            },
            hash: *child.cache().get().expect("hashed immutable child"),
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
