//! Native read-proof wire production. Unvisited siblings stay blinded, including
//! inode branches, so a single account read does not disclose another value.
use super::{Error, Hash, Kind, Result};
use crate::irmin::{self, Entry};
use std::collections::BTreeMap;

pub fn contents(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0];
    irmin::string(&mut out, value);
    out
}
pub fn blinded(kind: Kind, hash: &Hash) -> Vec<u8> {
    let mut out = vec![if kind == Kind::Contents { 1 } else { 3 }];
    out.extend_from_slice(hash);
    out
}
pub fn read(root: &Hash, tree: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(130 + tree.len());
    for _ in 0..2 {
        out.push(1);
        out.extend_from_slice(root);
    }
    out.extend_from_slice(tree);
    out
}

/// Children with `None` coverage are blinded. Revealed children are already
/// native tree encodings. A caller must verify the finished proof before serving.
pub fn directory(entries: &[(Entry, Option<Vec<u8>>)]) -> Result<Vec<u8>> {
    directory_inner(entries, vec![], true)
}
/// Absence reads must open the queried inode bucket even when no entry matches.
pub fn directory_for_read(
    entries: &[(Entry, Option<Vec<u8>>)],
    name: Option<&[u8]>,
) -> Result<Vec<u8>> {
    directory_for_reads(entries, &name.into_iter().collect::<Vec<_>>())
}
pub fn directory_for_reads(
    entries: &[(Entry, Option<Vec<u8>>)],
    names: &[&[u8]],
) -> Result<Vec<u8>> {
    directory_inner(
        entries,
        names.iter().map(|name| irmin::step_hash(name)).collect(),
        false,
    )
}
fn directory_inner(
    entries: &[(Entry, Option<Vec<u8>>)],
    seek: Vec<Hash>,
    all_names: bool,
) -> Result<Vec<u8>> {
    let mut unique = BTreeMap::new();
    for (entry, proof) in entries {
        unique.insert(entry.name.as_slice(), (entry, proof.as_deref()));
    }
    let entries = unique.into_values().collect::<Vec<_>>();
    let mut out = Vec::new();
    if entries.len() <= 256 {
        out.push(2);
        names(&mut out, &entries);
    } else {
        let entries = entries
            .iter()
            .map(|(e, p)| (*e, *p, irmin::step_hash(&e.name)))
            .collect::<Vec<_>>();
        inode(&mut out, &entries, 0, true, seek, all_names)?;
    }
    Ok(out)
}
type Child<'a> = (&'a Entry, Option<&'a [u8]>, Hash);
fn names(out: &mut Vec<u8>, entries: &[(&Entry, Option<&[u8]>)]) {
    irmin::varint(out, entries.len());
    for (entry, proof) in entries {
        irmin::string(out, &entry.name);
        match proof {
            Some(proof) => out.extend_from_slice(proof),
            None => out.extend(blinded(entry.kind, &entry.hash)),
        }
    }
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn inode(
    out: &mut Vec<u8>,
    entries: &[Child<'_>],
    depth: usize,
    root: bool,
    seek: Vec<Hash>,
    all_names: bool,
) -> Result<()> {
    if !root && !all_names && seek.is_empty() && entries.iter().all(|(_, proof, _)| proof.is_none())
    {
        let hashed = entries
            .iter()
            .map(|(entry, _, key)| (*entry, *key))
            .collect::<Vec<_>>();
        let hash = irmin::inode_hash(&hashed, depth).map_err(|e| Error::from(e.to_string()))?;
        out.push(0);
        out.extend_from_slice(&hash);
        return Ok(());
    }
    if entries.len() <= 32 {
        out.push(if root { 2 } else { 1 });
        names(
            out,
            &entries.iter().map(|(e, p, _)| (*e, *p)).collect::<Vec<_>>(),
        );
        return Ok(());
    }
    if depth >= 10 {
        return Err(format!("Irmin_pack.Inode.Max_depth({depth})").into());
    }
    let mut groups: [Vec<Child<'_>>; 32] = std::array::from_fn(|_| Vec::new());
    for &(entry, proof, key) in entries {
        let bit = depth * 5;
        let word = u16::from_be_bytes([key[bit / 8], key[bit / 8 + 1]]);
        groups[usize::from((word >> (11 - bit % 8)) & 31)].push((entry, proof, key));
    }
    out.push(if root { 4 } else { 2 });
    irmin::varint(out, entries.len());
    irmin::varint(out, groups.iter().filter(|v| !v.is_empty()).count());
    for (index, group) in groups.iter().enumerate().filter(|(_, v)| !v.is_empty()) {
        irmin::varint(out, index);
        let seek = seek
            .iter()
            .filter(|key| {
                let bit = depth * 5;
                let word = u16::from_be_bytes([key[bit / 8], key[bit / 8 + 1]]);
                usize::from((word >> (11 - bit % 8)) & 31) == index
            })
            .copied()
            .collect();
        inode(out, group, depth + 1, false, seek, all_names)?;
    }
    Ok(())
}
