//! Immutable native directories. Warm edits copy only their hash-bit inode path.
//! A base passed to `pages_since` must have physical pages authenticated by the
//! caller's durable store; a logical directory hash alone grants no such reuse.
use super::{Entry, Hash, MaxDepth};
use std::{collections::BTreeMap, sync::Arc};
mod inode;
pub use inode::Pages;
use inode::{Inode, Routed};

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    entry_visits: usize,
    name_hashes: usize,
    page_encodes: usize,
}

#[cfg(test)]
thread_local! {
    static COUNTS: std::cell::Cell<Counts> = const {
        std::cell::Cell::new(Counts { entry_visits: 0, name_hashes: 0, page_encodes: 0 })
    };
}
macro_rules! count {
    ($field:ident, $amount:expr) => {
        #[cfg(test)]
        $crate::irmin::directory::COUNTS.with(|counter| {
            let mut value = counter.get();
            value.$field += $amount;
            counter.set(value);
        });
    };
}
pub(super) use count;

// Ten native levels consume fifty bits, including cross-byte slot boundaries.
type Route = [u8; 8];
fn route(name: &[u8]) -> Route {
    count!(name_hashes, 1);
    super::step_hash(name)[..8].try_into().expect("route width")
}
fn slot(key: Route, depth: usize) -> u8 {
    debug_assert!(depth < 10);
    let bit = depth * 5;
    let word = u16::from_be_bytes([key[bit / 8], key[bit / 8 + 1]]);
    ((word >> (11 - bit % 8)) & 31) as u8
}

#[derive(Debug)]
enum Root {
    Flat { entries: Vec<Entry>, hash: Hash },
    Wide(Arc<Inode>),
}

#[derive(Clone, Debug)]
pub struct Directory {
    root: Arc<Root>,
}
impl Directory {
    /// Last duplicate name wins, in native byte order.
    pub fn from_entries(entries: &[Entry]) -> Result<Self, MaxDepth> {
        count!(entry_visits, entries.len());
        let unique = entries
            .iter()
            .map(|entry| (entry.name.as_slice(), entry))
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .cloned()
            .collect::<Vec<_>>();
        Self::from_unique(unique)
    }
    fn from_unique(entries: Vec<Entry>) -> Result<Self, MaxDepth> {
        if entries.len() <= 256 {
            let hash = super::node_hash(&entries)?;
            Ok(Self {
                root: Arc::new(Root::Flat { entries, hash }),
            })
        } else {
            let entries = entries
                .into_iter()
                .map(|entry| Routed {
                    key: route(&entry.name),
                    entry,
                })
                .collect();
            Ok(Self {
                root: Arc::new(Root::Wide(Inode::build(entries, 0)?)),
            })
        }
    }
    pub fn hash(&self) -> Hash {
        match self.root.as_ref() {
            Root::Flat { hash, .. } => *hash,
            Root::Wide(node) => node.hash,
        }
    }
    pub fn len(&self) -> usize {
        match self.root.as_ref() {
            Root::Flat { entries, .. } => entries.len(),
            Root::Wide(node) => node.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn set(&self, entry: Entry) -> Result<Self, MaxDepth> {
        match self.root.as_ref() {
            Root::Flat { entries, .. } => {
                let found = entries.binary_search_by(|old| old.name.cmp(&entry.name));
                if found.is_ok_and(|index| entries[index] == entry) {
                    return Ok(self.clone());
                }
                count!(entry_visits, entries.len());
                let mut entries = entries.clone();
                match found {
                    Ok(index) => entries[index] = entry,
                    Err(index) => entries.insert(index, entry),
                }
                Self::from_unique(entries)
            }
            Root::Wide(node) => {
                let key = route(&entry.name);
                let changed = Inode::set(node, entry, key, 0)?;
                Ok(if Arc::ptr_eq(node, &changed) {
                    self.clone()
                } else {
                    Self {
                        root: Arc::new(Root::Wide(changed)),
                    }
                })
            }
        }
    }
    pub fn remove(&self, name: &[u8]) -> Result<Self, MaxDepth> {
        match self.root.as_ref() {
            Root::Flat { entries, .. } => {
                let Ok(index) = entries.binary_search_by(|entry| entry.name.as_slice().cmp(name))
                else {
                    return Ok(self.clone());
                };
                count!(entry_visits, entries.len());
                let mut entries = entries.clone();
                entries.remove(index);
                Self::from_unique(entries)
            }
            Root::Wide(node) => {
                let changed = Inode::remove(node, name, route(name));
                let Some(changed) = changed else {
                    return Self::from_unique(Vec::new());
                };
                if Arc::ptr_eq(node, &changed) {
                    return Ok(self.clone());
                }
                if changed.len() <= 256 {
                    let entries = changed
                        .entries()
                        .into_iter()
                        .map(|entry| entry.entry)
                        .collect();
                    Self::from_unique(entries)
                } else {
                    Ok(Self {
                        root: Arc::new(Root::Wide(changed)),
                    })
                }
            }
        }
    }
    /// Child-first native pages, pruning equal immutable paths in `base`.
    /// Stable roots (at most 256 entries) have no physical inode pages.
    pub fn pages_since(&self, base: Option<&Self>) -> Pages {
        let Root::Wide(node) = self.root.as_ref() else {
            return Pages::empty();
        };
        let base = base.and_then(|base| match base.root.as_ref() {
            Root::Wide(node) => Some(node.clone()),
            Root::Flat { .. } => None,
        });
        Pages::new(node.clone(), base)
    }
}

#[cfg(test)]
mod tests;
