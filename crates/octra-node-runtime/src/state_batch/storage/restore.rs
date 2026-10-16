use super::{decode, edges, Directory, Error, Page, StoredObject};
use octra_node_protocol::irmin::{self, page, Entry, Hash};
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::state_batch) enum Logical {
    Contents(Vec<u8>),
    Directory(VerifiedDirectory),
}

/// Constructed after the directory commitment and physical page edges have
/// been checked. Consumers must still authenticate the logical children.
pub(in crate::state_batch) struct VerifiedDirectory {
    hash: Hash,
    entries: Vec<Entry>,
}
impl VerifiedDirectory {
    pub(in crate::state_batch) fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub(in crate::state_batch) fn into_parts(self) -> (Hash, Vec<Entry>) {
        (self.hash, self.entries)
    }
}
#[derive(Default)]
pub(in crate::state_batch) struct Resolver {
    pages: BTreeMap<Hash, Page>,
}
impl Resolver {
    pub(in crate::state_batch) fn logical(
        &mut self,
        object: StoredObject,
        take: &mut impl FnMut(&Hash) -> Option<StoredObject>,
    ) -> Result<Logical, Error> {
        if object.contents {
            if irmin::contents_hash(&object.data) != object.hash {
                return Err(Error("state object commitment differs"));
            }
            edges(&object, &[])?;
            return Ok(Logical::Contents(object.data));
        }
        if object.children.contains(&object.hash) {
            return Err(Error("cyclic state object graph"));
        }
        let directory = decode(&object.hash, &object.data)?;
        directory.logical_root()?;
        edges(&object, &directory.children())?;
        let entries = match directory {
            Directory::Flat(entries) => entries,
            Directory::Inode(page) => {
                self.pages.insert(object.hash, page);
                let entries =
                    self.flatten(object.hash, 0, &mut Vec::new(), take, &mut BTreeSet::new())?;
                if irmin::node_hash(&entries).map_err(|_| Error("Irmin inode depth exhausted"))?
                    != object.hash
                {
                    return Err(Error("state object commitment differs"));
                }
                entries
            }
        };
        // Flat decoding already verifies the complete native node hash.
        Ok(Logical::Directory(VerifiedDirectory {
            hash: object.hash,
            entries,
        }))
    }

    fn page(
        &mut self,
        hash: Hash,
        take: &mut impl FnMut(&Hash) -> Option<StoredObject>,
    ) -> Result<Page, Error> {
        if let Some(page) = self.pages.get(&hash) {
            return Ok(page.clone());
        }
        let object = take(&hash).ok_or(Error("missing state object"))?;
        if object.hash != hash {
            return Err(Error("state object key differs"));
        }
        if object.contents {
            return Err(Error("invalid inode child kind"));
        }
        let Directory::Inode(page) = decode(&hash, &object.data)? else {
            return Err(Error("inode child is not a page"));
        };
        edges(&object, &page.children())?;
        self.pages.insert(hash, page.clone());
        Ok(page)
    }

    fn flatten(
        &mut self,
        hash: Hash,
        depth: usize,
        prefix: &mut Vec<u8>,
        take: &mut impl FnMut(&Hash) -> Option<StoredObject>,
        active: &mut BTreeSet<Hash>,
    ) -> Result<Vec<Entry>, Error> {
        if !active.insert(hash) {
            return Err(Error("cyclic state object graph"));
        }
        let entries = match self.page(hash, take)? {
            Page::Values(entries) => {
                if depth == 0 || depth > 10 {
                    return Err(Error("invalid inode leaf depth"));
                }
                for entry in &entries {
                    for (depth, expected) in prefix.iter().enumerate() {
                        if page::slot(&entry.name, depth)
                            .map_err(|_| Error("invalid inode depth"))?
                            != *expected
                        {
                            return Err(Error("inode entry routing differs"));
                        }
                    }
                }
                entries
            }
            Page::Branch {
                depth: stored,
                length,
                children,
            } => {
                if stored != depth || depth >= 10 || (depth == 0 && length <= 256) {
                    return Err(Error("invalid inode branch depth or length"));
                }
                let mut entries = Vec::new();
                for (slot, child) in children {
                    prefix.push(slot);
                    entries.extend(self.flatten(child, depth + 1, prefix, take, active)?);
                    prefix.pop();
                }
                if entries.len() != length {
                    return Err(Error("inode length differs"));
                }
                entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
                if !entries.windows(2).all(|w| w[0].name < w[1].name) {
                    return Err(Error("invalid tree child"));
                }
                entries
            }
        };
        active.remove(&hash);
        Ok(entries)
    }
}
