use super::*;
use crate::irmin::{self, page::Page, Kind};
use std::collections::BTreeSet;

fn entry(index: u32) -> Entry {
    Entry {
        name: index.to_be_bytes().to_vec(),
        hash: irmin::contents_hash(&index.to_le_bytes()),
        kind: if index.is_multiple_of(3) {
            Kind::Node
        } else {
            Kind::Contents
        },
    }
}
fn reference(entries: &BTreeMap<Vec<u8>, Entry>) -> Vec<(Hash, Page)> {
    irmin::page::directory(&entries.values().cloned().collect::<Vec<_>>()).unwrap()
}
fn assert_directory(directory: &Directory, entries: &BTreeMap<Vec<u8>, Entry>) {
    let entries_vec = entries.values().cloned().collect::<Vec<_>>();
    assert_eq!(directory.hash(), irmin::node_hash(&entries_vec).unwrap());
    assert_eq!(directory.len(), entries.len());
    assert_eq!(directory.is_empty(), entries.is_empty());
    assert_eq!(
        directory.pages_since(None).collect::<Vec<_>>(),
        reference(entries)
    );
}
fn assert_delta(current: &Directory, base: Option<&Directory>) {
    let previous = base
        .map(|base| {
            base.pages_since(None)
                .map(|(hash, _)| hash)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut seen = previous.clone();
    let mut emitted = BTreeSet::new();
    for (hash, page) in current.pages_since(base) {
        assert!(!previous.contains(&hash), "unchanged physical page emitted");
        assert_eq!(page.hash().unwrap(), hash);
        if let Page::Branch { children, .. } = &page {
            assert!(
                children.iter().all(|(_, child)| seen.contains(child)),
                "parent precedes child"
            );
        }
        assert!(emitted.insert(hash));
        seen.insert(hash);
    }
    let full = current
        .pages_since(None)
        .map(|(hash, _)| hash)
        .collect::<BTreeSet<_>>();
    assert_eq!(emitted, full.difference(&previous).copied().collect());
}

#[test]
fn batch_roots_pages_duplicates_and_byte_names_match_reference() {
    for count in [0, 1, 31, 32, 33, 255, 256, 257, 1024, 8192] {
        let mut entries = (0..count).map(entry).collect::<Vec<_>>();
        entries.extend([
            Entry {
                name: Vec::new(),
                kind: Kind::Contents,
                hash: [9; 64],
            },
            Entry {
                name: vec![0, 255, 128],
                kind: Kind::Node,
                hash: [4; 64],
            },
        ]);
        let mut replacement = entries[0].clone();
        replacement.kind = Kind::Node;
        replacement.hash = [77; 64];
        entries.push(replacement);
        let directory = Directory::from_entries(&entries).unwrap();
        let expected = entries
            .into_iter()
            .map(|entry| (entry.name.clone(), entry))
            .collect();
        assert_directory(&directory, &expected);
        assert_delta(&directory, None);
    }
    let empty = Directory::from_entries(&[]).unwrap();
    assert_directory(&empty, &BTreeMap::new());
}

#[test]
fn persistent_updates_removals_and_thresholds_preserve_old_snapshots() {
    let mut expected = BTreeMap::new();
    let mut current = Directory::from_entries(&[]).unwrap();
    let mut snapshots = Vec::new();
    for index in 0..1025 {
        if matches!(index, 0 | 31 | 32 | 255 | 256 | 257 | 512) {
            snapshots.push((current.clone(), expected.clone()));
        }
        let value = entry(index);
        expected.insert(value.name.clone(), value.clone());
        let next = current.set(value).unwrap();
        assert_delta(&next, Some(&current));
        current = next;
        if matches!(index, 31 | 32 | 255 | 256 | 257 | 1024) {
            assert_directory(&current, &expected);
        }
    }
    for index in (0u32..1025).rev() {
        let name = index.to_be_bytes();
        let next = current.remove(&name).unwrap();
        expected.remove(name.as_slice());
        assert_delta(&next, Some(&current));
        current = next;
        if matches!(index, 0 | 31 | 32 | 255 | 256 | 257 | 1024) {
            assert_directory(&current, &expected);
        }
    }
    for (snapshot, expected) in snapshots {
        assert_directory(&snapshot, &expected);
    }
}

#[test]
fn randomized_edits_and_multiple_bases_match_independent_batch_construction() {
    let values = (0..513).map(entry).collect::<Vec<_>>();
    let mut expected = values
        .iter()
        .cloned()
        .map(|entry| (entry.name.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut current = Directory::from_entries(&values).unwrap();
    let mut saved = vec![current.clone()];
    let mut random = 0x1299_7765_ee11_3344u64;
    for round in 0u32..400 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let index = (random % 800) as u32;
        let name = index.to_be_bytes();
        let next = if round % 4 == 0 {
            expected.remove(name.as_slice());
            current.remove(&name).unwrap()
        } else {
            let value = Entry {
                name: name.to_vec(),
                hash: irmin::contents_hash(&random.to_be_bytes()),
                kind: if random & 1 == 0 {
                    Kind::Node
                } else {
                    Kind::Contents
                },
            };
            expected.insert(name.to_vec(), value.clone());
            current.set(value).unwrap()
        };
        assert_delta(&next, Some(&current));
        current = next;
        assert_directory(&current, &expected);
        if round.is_multiple_of(37) {
            for base in &saved {
                assert_delta(&current, Some(base));
            }
            saved.push(current.clone());
        }
    }
}

#[test]
fn moved_leaf_reuses_its_exact_native_page_across_split_and_collapse() {
    let mut old = Vec::new();
    let mut fillers = Vec::new();
    let mut new = None;
    for index in 0u32..1_000_000 {
        let value = entry(index);
        let key = route(&value.name);
        if slot(key, 0) == 0 && slot(key, 1) == 0 && old.len() < 32 {
            old.push(value);
        } else if slot(key, 0) != 0 && fillers.len() < 225 {
            fillers.push(value);
        } else if slot(key, 0) == 0 && slot(key, 1) == 1 && new.is_none() {
            new = Some(value);
        }
        if old.len() == 32 && fillers.len() == 225 && new.is_some() {
            break;
        }
    }
    assert_eq!(old.len(), 32);
    let old_leaf = Page::Values(old.clone()).hash().unwrap();
    old.extend(fillers);
    let base = Directory::from_entries(&old).unwrap();
    let new = new.unwrap();
    let split = base.set(new.clone()).unwrap();
    let pages = split.pages_since(Some(&base)).collect::<Vec<_>>();
    assert_eq!(pages.len(), 3, "only new leaf, split branch and root");
    assert!(!pages.iter().any(|(hash, _)| hash == &old_leaf));
    assert_delta(&split, Some(&base));
    let collapsed = split.remove(&new.name).unwrap();
    assert_eq!(collapsed.hash(), base.hash());
    assert_eq!(collapsed.pages_since(Some(&split)).count(), 1);
    assert_delta(&collapsed, Some(&split));
}

#[test]
fn identical_update_and_absent_remove_retain_the_exact_snapshot() {
    for count in [0, 32, 256, 257, 4096] {
        let entries = (0..count).map(entry).collect::<Vec<_>>();
        let base = Directory::from_entries(&entries).unwrap();
        let absent = base.remove(b"absent\0\xff").unwrap();
        assert!(Arc::ptr_eq(&absent.root, &base.root));
        for value in entries.iter().take(3) {
            let same = base.set(value.clone()).unwrap();
            assert!(Arc::ptr_eq(&same.root, &base.root));
            assert!(same.pages_since(Some(&base)).next().is_none());
        }
    }
}

#[test]
fn warm_mutation_work_is_bounded_by_native_path_not_directory_width() {
    for width in [4096, 131_072] {
        let entries = (0..width).map(entry).collect::<Vec<_>>();
        let base = Directory::from_entries(&entries).unwrap();
        COUNTS.with(|counts| counts.set(Counts::default()));
        let mut value = entries[width as usize / 2].clone();
        value.kind = if value.kind == Kind::Contents {
            Kind::Node
        } else {
            Kind::Contents
        };
        value.hash = [41; 64];
        let changed = base.set(value).unwrap();
        let pages = changed.pages_since(Some(&base)).count();
        let work = COUNTS.with(std::cell::Cell::get);
        eprintln!("directory-work width={width} operation=set entries={} name_hashes={} page_encodes={} emitted_pages={pages}",
            work.entry_visits,work.name_hashes,work.page_encodes);
        assert_eq!(work.name_hashes, 1, "{width}: {work:?}");
        assert!(work.entry_visits <= 128, "{width}: {work:?}");
        assert!(work.page_encodes <= 11, "{width}: {work:?}");
        assert!(pages <= 11);
        assert_ne!(changed.hash(), base.hash());
        COUNTS.with(|counts| counts.set(Counts::default()));
        let removed = changed.remove(&entries[width as usize / 2].name).unwrap();
        let pages = removed.pages_since(Some(&changed)).count();
        let work = COUNTS.with(std::cell::Cell::get);
        eprintln!("directory-work width={width} operation=remove entries={} name_hashes={} page_encodes={} emitted_pages={pages}",
            work.entry_visits,work.name_hashes,work.page_encodes);
        assert_eq!(work.name_hashes, 1, "{width}: {work:?}");
        assert!(work.entry_visits <= 128, "{width}: {work:?}");
        assert!(work.page_encodes <= 11, "{width}: {work:?}");
    }
}

#[test]
fn maximum_depth_refusal_does_not_change_the_original_inode() {
    let original = (0..32).map(entry).collect::<Vec<_>>();
    let routed = original
        .iter()
        .cloned()
        .map(|entry| inode::Routed {
            key: route(&entry.name),
            entry,
        })
        .collect();
    let leaf = inode::Inode::build(routed, 10).unwrap();
    let hash = leaf.hash;
    let extra = entry(33);
    let result = inode::Inode::set(&leaf, extra.clone(), route(&extra.name), 10);
    assert!(matches!(result, Err(MaxDepth(10))));
    assert_eq!(leaf.hash, hash);
    assert_eq!(leaf.len(), 32);
}

mod native;
