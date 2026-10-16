use super::{directory, Page};
use crate::irmin::{self, Entry, Kind};

fn entries(count: u32) -> Vec<Entry> {
    (0..count)
        .map(|index| Entry {
            name: index.to_be_bytes().to_vec(),
            hash: irmin::contents_hash(&index.to_le_bytes()),
            kind: if index.is_multiple_of(3) {
                Kind::Node
            } else {
                Kind::Contents
            },
        })
        .collect()
}
#[test]
fn pages_have_exact_native_commitments_and_canonical_child_first_preimages() {
    for count in [0, 1, 31, 32, 33, 255, 256, 257, 1024, 8192] {
        let entries = entries(count);
        let pages = directory(&entries).unwrap();
        if count <= 256 {
            assert!(pages.is_empty());
            continue;
        }
        assert_eq!(pages.last().unwrap().0, irmin::node_hash(&entries).unwrap());
        let mut seen = std::collections::BTreeSet::new();
        for (hash, page) in pages {
            let raw = page.encode().unwrap();
            assert_eq!(Page::decode(&raw).unwrap(), page);
            assert_eq!(irmin::step_hash(&raw), hash);
            if let Page::Branch { children, .. } = &page {
                assert!(children.iter().all(|(_, hash)| seen.contains(hash)));
            }
            seen.insert(hash);
        }
    }
}
#[test]
fn duplicate_input_names_keep_native_last_value_wins() {
    let mut entries = entries(257);
    let mut replacement = entries[0].clone();
    replacement.hash = [77; 64];
    entries.push(replacement);
    let pages = directory(&entries).unwrap();
    assert_eq!(pages.last().unwrap().0, irmin::node_hash(&entries).unwrap());
}
#[test]
fn malformed_order_kind_depth_count_varint_and_truncation_are_refused() {
    let values = Page::Values(entries(2));
    let raw = values.encode().unwrap();
    for cut in 0..raw.len() {
        assert!(Page::decode(&raw[..cut]).is_err());
    }
    let mut extra = raw.clone();
    extra.push(0);
    assert!(Page::decode(&extra).is_err());
    let mut nonminimal = raw.clone();
    nonminimal.splice(1..2, [0x82, 0]);
    assert!(Page::decode(&nonminimal).is_err());
    let mut wrong_kind = raw;
    wrong_kind[7] = 2;
    assert!(Page::decode(&wrong_kind).is_err());
    let mut reversed = entries(2);
    reversed.reverse();
    assert!(Page::Values(reversed).encode().is_err());
    assert!(Page::Values(entries(33)).encode().is_err());
    for (depth, length, children) in [
        (10, 257, vec![(0, [1; 64])]),
        (0, 32, vec![(0, [1; 64])]),
        (0, 257, vec![]),
        (0, 257, vec![(32, [1; 64])]),
        (0, 257, vec![(1, [1; 64]), (0, [2; 64])]),
        (0, 257, vec![(0, [1; 64]), (0, [2; 64])]),
    ] {
        assert!(Page::Branch {
            depth,
            length,
            children
        }
        .encode()
        .is_err());
    }
    for raw in [
        vec![1, 10, 0x81, 2, 1, 0],
        vec![1, 0, 32, 1, 0],
        vec![1, 0, 0x81, 2, 0],
        vec![0, 0],
        vec![2],
    ] {
        assert!(Page::decode(&raw).is_err());
    }
}
