use super::{count, slot, Entry, Hash, MaxDepth, Route};
use crate::irmin::{digest, page::Page};
use std::sync::Arc;

pub(super) struct Routed {
    pub(super) entry: Entry,
    pub(super) key: Route,
}
#[derive(Debug)]
pub(super) struct Inode {
    pub(super) hash: Hash,
    page: Page,
    keys: Vec<Route>,
    children: Vec<(u8, Arc<Self>)>,
}
impl Inode {
    fn value(page: Page, keys: Vec<Route>, children: Vec<(u8, Arc<Self>)>) -> Arc<Self> {
        count!(page_encodes, 1);
        let raw = page.encode().expect("constructed canonical native page");
        Arc::new(Self {
            hash: digest(&raw),
            page,
            keys,
            children,
        })
    }
    fn leaf(entries: Vec<Routed>) -> Arc<Self> {
        let (entries, keys) = entries
            .into_iter()
            .map(|entry| (entry.entry, entry.key))
            .unzip();
        Self::value(Page::Values(entries), keys, Vec::new())
    }
    fn branch(depth: usize, children: Vec<(u8, Arc<Self>)>) -> Arc<Self> {
        let length = children.iter().map(|(_, node)| node.len()).sum();
        let page = Page::Branch {
            depth,
            length,
            children: children
                .iter()
                .map(|(index, node)| (*index, node.hash))
                .collect(),
        };
        Self::value(page, Vec::new(), children)
    }
    pub(super) fn len(&self) -> usize {
        match &self.page {
            Page::Values(entries) => entries.len(),
            Page::Branch { length, .. } => *length,
        }
    }
    pub(super) fn build(entries: Vec<Routed>, depth: usize) -> Result<Arc<Self>, MaxDepth> {
        count!(entry_visits, entries.len());
        if entries.len() <= 32 {
            return Ok(Self::leaf(entries));
        }
        if depth >= 10 {
            return Err(MaxDepth(depth));
        }
        let mut groups: [Vec<Routed>; 32] = std::array::from_fn(|_| Vec::new());
        for entry in entries {
            groups[usize::from(slot(entry.key, depth))].push(entry);
        }
        let children = groups
            .into_iter()
            .enumerate()
            .filter(|(_, entries)| !entries.is_empty())
            .map(|(index, entries)| Self::build(entries, depth + 1).map(|node| (index as u8, node)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::branch(depth, children))
    }
    pub(super) fn set(
        node: &Arc<Self>,
        entry: Entry,
        key: Route,
        depth: usize,
    ) -> Result<Arc<Self>, MaxDepth> {
        match &node.page {
            Page::Values(entries) => {
                let found = entries.binary_search_by(|old| old.name.cmp(&entry.name));
                if found.is_ok_and(|index| entries[index] == entry) {
                    return Ok(node.clone());
                }
                let mut entries = node.entries();
                let value = Routed { entry, key };
                match found {
                    Ok(index) => entries[index] = value,
                    Err(index) => entries.insert(index, value),
                }
                Self::build(entries, depth)
            }
            Page::Branch { depth: actual, .. } => {
                debug_assert_eq!(depth, *actual);
                let index = slot(key, depth);
                let found = node
                    .children
                    .binary_search_by_key(&index, |(index, _)| *index);
                let child = match found {
                    Ok(position) => Self::set(&node.children[position].1, entry, key, depth + 1)?,
                    Err(_) => Self::leaf(vec![Routed { entry, key }]),
                };
                if found.is_ok_and(|position| Arc::ptr_eq(&node.children[position].1, &child)) {
                    return Ok(node.clone());
                }
                let mut children = node.children.clone();
                match found {
                    Ok(position) => children[position].1 = child,
                    Err(position) => children.insert(position, (index, child)),
                }
                Ok(Self::branch(depth, children))
            }
        }
    }
    pub(super) fn remove(node: &Arc<Self>, name: &[u8], key: Route) -> Option<Arc<Self>> {
        match &node.page {
            Page::Values(entries) => {
                let Ok(index) = entries.binary_search_by(|entry| entry.name.as_slice().cmp(name))
                else {
                    return Some(node.clone());
                };
                if entries.len() == 1 {
                    return None;
                }
                let mut entries = node.entries();
                entries.remove(index);
                Some(Self::leaf(entries))
            }
            Page::Branch { depth, .. } => {
                let index = slot(key, *depth);
                let Ok(position) = node
                    .children
                    .binary_search_by_key(&index, |(index, _)| *index)
                else {
                    return Some(node.clone());
                };
                let child = Self::remove(&node.children[position].1, name, key);
                if child
                    .as_ref()
                    .is_some_and(|child| Arc::ptr_eq(child, &node.children[position].1))
                {
                    return Some(node.clone());
                }
                let mut children = node.children.clone();
                match child {
                    Some(child) => children[position].1 = child,
                    None => {
                        children.remove(position);
                    }
                }
                let length: usize = children.iter().map(|(_, child)| child.len()).sum();
                if length == 0 {
                    None
                } else if length <= 32 {
                    if children.len() == 1 && matches!(children[0].1.page, Page::Values(_)) {
                        return Some(children.remove(0).1);
                    }
                    let mut entries = children
                        .iter()
                        .flat_map(|(_, child)| child.entries())
                        .collect::<Vec<_>>();
                    entries.sort_unstable_by(|left, right| left.entry.name.cmp(&right.entry.name));
                    Some(Self::leaf(entries))
                } else {
                    Some(Self::branch(*depth, children))
                }
            }
        }
    }
    pub(super) fn entries(&self) -> Vec<Routed> {
        match &self.page {
            Page::Values(entries) => {
                count!(entry_visits, entries.len());
                entries
                    .iter()
                    .cloned()
                    .zip(&self.keys)
                    .map(|(entry, key)| Routed { entry, key: *key })
                    .collect()
            }
            Page::Branch { .. } => {
                let mut entries = self
                    .children
                    .iter()
                    .flat_map(|(_, child)| child.entries())
                    .collect::<Vec<_>>();
                entries.sort_unstable_by(|left, right| left.entry.name.cmp(&right.entry.name));
                entries
            }
        }
    }
    fn old_child(old: &Arc<Self>, index: u8, depth: usize) -> Option<Arc<Self>> {
        match &old.page {
            Page::Branch { depth: actual, .. } if *actual == depth => old
                .children
                .binary_search_by_key(&index, |(index, _)| *index)
                .ok()
                .map(|position| old.children[position].1.clone()),
            Page::Values(_) if slot(old.keys[0], depth) == index => Some(old.clone()),
            _ => None,
        }
    }
    fn old_leaf(mut old: Arc<Self>, key: Route) -> Option<Arc<Self>> {
        loop {
            let Page::Branch { depth, .. } = &old.page else {
                return Some(old);
            };
            old = Self::old_child(&old, slot(key, *depth), *depth)?;
        }
    }
}

/// Owned streaming traversal; equal hashes/Arcs prune complete immutable paths.
pub struct Pages {
    pending: Vec<(Arc<Inode>, Option<Arc<Inode>>, bool)>,
}
impl Pages {
    pub(super) fn empty() -> Self {
        Self {
            pending: Vec::new(),
        }
    }
    pub(super) fn new(node: Arc<Inode>, base: Option<Arc<Inode>>) -> Self {
        Self {
            pending: vec![(node, base, false)],
        }
    }
}
impl Iterator for Pages {
    type Item = (Hash, Page);
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (node, mut old, finish) = self.pending.pop()?;
            if let Page::Values(_) = node.page {
                old = old.and_then(|old| Inode::old_leaf(old, node.keys[0]));
            }
            if old
                .as_ref()
                .is_some_and(|old| Arc::ptr_eq(old, &node) || old.hash == node.hash)
            {
                continue;
            }
            if !finish {
                if let Page::Branch { depth, .. } = &node.page {
                    self.pending.push((node.clone(), old.clone(), true));
                    for (index, child) in node.children.iter().rev() {
                        let base = old
                            .as_ref()
                            .and_then(|old| Inode::old_child(old, *index, *depth));
                        self.pending.push((child.clone(), base, false));
                    }
                    continue;
                }
            }
            #[cfg(test)]
            if let Page::Values(entries) = &node.page {
                count!(entry_visits, entries.len());
            }
            return Some((node.hash, node.page.clone()));
        }
    }
}
