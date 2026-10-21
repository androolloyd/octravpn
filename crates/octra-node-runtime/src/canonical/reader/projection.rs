//! Bounded subtree images with native read proofs. A subtree is not a complete
//! canonical snapshot and cannot mint browser provenance or execution authority.
use super::{decode_head, error, hex_hash, Head, Reader, Result, Snapshot, StoredObject};
use crate::state_batch::storage::{self, Directory};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures::TryStreamExt;
use octra_node_protocol::irmin::{page, proof, Entry, Hash, Kind};
use sqlx::{Row, SqliteConnection};
use std::collections::BTreeMap;

pub struct TreeRead {
    /// Raw native read-proof wire bytes, rooted at the requested ledger hash.
    pub proof: Vec<u8>,
    /// Only the selected subtree. Its root is checked against the proof.
    pub tree: Option<Snapshot>,
}

const PATH_OBJECT_BYTES: usize = 256 * 1024 * 1024;
const REACHABLE: &str = "WITH RECURSIVE reachable(hash) AS (SELECT ? UNION SELECT e.child FROM reachable r CROSS JOIN node_edges e ON e.parent=r.hash LIMIT ?) ";
#[cfg(test)]
mod tests;

impl Reader {
    /// Authenticate one retained path and restore only its bounded subtree.
    /// Missing coverage/objects are errors; a complete searched bucket proves
    /// absence. Unvisited branches remain blinded and are never restored.
    pub async fn read_tree_at(
        &self,
        head: &Head,
        path: &[&[u8]],
        maximum: usize,
    ) -> Result<TreeRead> {
        if !(1..=32 * 1024 * 1024).contains(&maximum)
            || path.len() > 64
            || path.iter().map(|step| step.len()).sum::<usize>() > 4096
        {
            return Err(error("subtree read exceeds limits"));
        }
        let mut read = self.pool.begin().await.map_err(error)?;
        let row = sqlx::query("SELECT sequence,head,root FROM node_epochs WHERE sequence=?")
            .bind(i64::try_from(head.cursor.sequence.0).map_err(error)?)
            .fetch_one(&mut *read)
            .await
            .map_err(error)?;
        if decode_head(&row)? != *head {
            return Err(error("subtree read head differs"));
        }
        let root = hex_hash(&head.ledger_root)?;
        let (body, selected) = walk(&mut read, root, path, maximum, None).await?;
        let raw = proof::produce::read(&root, &body);
        if raw.len() > maximum {
            return Err(error("subtree proof exceeds limit"));
        }
        let encoded = STANDARD.encode(&raw);
        let verified = proof::verify_tree(head.ledger_root.as_bytes(), path, encoded.as_bytes())
            .map_err(error)?;
        if selected != verified {
            return Err(error("subtree proof result differs"));
        }
        let tree = match selected {
            Some(root) => Some(restore(&mut read, root, maximum).await?),
            None => None,
        };
        read.rollback().await.map_err(error)?;
        Ok(TreeRead { proof: raw, tree })
    }

    /// Open selected suffixes of a previously loaded subtree. Its root must
    /// still match this retained path; the proof keeps the full ledger root.
    pub async fn prove_tree_at(
        &self,
        head: &Head,
        path: &[&[u8]],
        tree: &Snapshot,
        suffixes: &[&[&[u8]]],
        maximum: usize,
    ) -> Result<Vec<u8>> {
        if !(1..=32 * 1024 * 1024).contains(&maximum)
            || path.len() > 64
            || suffixes.len() > 16_384
            || path.iter().map(|step| step.len()).sum::<usize>() > 4096
            || suffixes.iter().any(|suffix| suffix.len() > 64)
            || suffixes
                .iter()
                .flat_map(|suffix| suffix.iter())
                .map(|step| step.len())
                .sum::<usize>()
                > maximum
        {
            return Err(error("subtree proof exceeds limits"));
        }
        let subtree = tree.root().map_err(error)?;
        let local = tree.read_proof_paths(suffixes).map_err(error)?;
        let terminal = proof::produce::read_body(&subtree, &local)
            .map_err(error)?
            .to_vec();
        if terminal.len() > maximum {
            return Err(error("subtree proof exceeds limit"));
        }
        let mut read = self.pool.begin().await.map_err(error)?;
        let row = sqlx::query("SELECT sequence,head,root FROM node_epochs WHERE sequence=?")
            .bind(i64::try_from(head.cursor.sequence.0).map_err(error)?)
            .fetch_one(&mut *read)
            .await
            .map_err(error)?;
        if decode_head(&row)? != *head {
            return Err(error("subtree proof head differs"));
        }
        let root = hex_hash(&head.ledger_root)?;
        let (body, selected) =
            walk(&mut read, root, path, maximum, Some((subtree, terminal))).await?;
        if selected != Some(subtree) {
            return Err(error("subtree proof path is absent"));
        }
        let raw = proof::produce::read(&root, &body);
        if raw.len() > maximum {
            return Err(error("subtree proof exceeds limit"));
        }
        let encoded = STANDARD.encode(&raw);
        if proof::verify_tree(head.ledger_root.as_bytes(), path, encoded.as_bytes())
            .map_err(error)?
            != Some(subtree)
        {
            return Err(error("subtree proof result differs"));
        }
        read.rollback().await.map_err(error)?;
        Ok(raw)
    }
}

enum Frame {
    Flat(Vec<Entry>, Vec<u8>),
    Values(Vec<Entry>, Vec<u8>),
    Branch {
        root: bool,
        length: usize,
        children: Vec<(u8, Hash)>,
        selected: u8,
    },
}
impl Frame {
    fn finish(self, child: Option<Vec<u8>>) -> Result<Vec<u8>> {
        match self {
            Self::Flat(entries, name) => {
                let mut child = child;
                let entries = entries
                    .into_iter()
                    .map(|entry| {
                        let opened = (entry.name == name).then(|| child.take()).flatten();
                        (entry, opened)
                    })
                    .collect::<Vec<_>>();
                proof::produce::directory_for_read(&entries, Some(&name)).map_err(error)
            }
            Self::Values(mut entries, name) => {
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                let mut child = child;
                let entries = entries
                    .into_iter()
                    .map(|entry| {
                        let opened = (entry.name == name).then(|| child.take()).flatten();
                        (entry, opened)
                    })
                    .collect::<Vec<_>>();
                proof::produce::inode_values(&entries).map_err(error)
            }
            Self::Branch {
                root,
                length,
                children,
                selected,
            } => {
                let mut child = child;
                let children = children
                    .into_iter()
                    .map(|(slot, hash)| {
                        let opened = (slot == selected).then(|| child.take()).flatten();
                        (slot, hash, opened)
                    })
                    .collect::<Vec<_>>();
                proof::produce::inode_branch(root, length, &children).map_err(error)
            }
        }
    }
}

async fn edge(read: &mut SqliteConnection, parent: &Hash, child: &Hash) -> Result<()> {
    let present: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM node_edges WHERE parent=? AND child=?)")
            .bind(parent.as_slice())
            .bind(child.as_slice())
            .fetch_one(read)
            .await
            .map_err(error)?;
    if !present {
        return Err(error("missing state edge"));
    }
    Ok(())
}
async fn walk(
    read: &mut SqliteConnection,
    root: Hash,
    path: &[&[u8]],
    maximum: usize,
    mut terminal: Option<(Hash, Vec<u8>)>,
) -> Result<(Vec<u8>, Option<Hash>)> {
    let mut hash = root;
    let mut position = 0;
    let mut prefix: Option<Vec<u8>> = None;
    let mut frames = Vec::new();
    let mut selected = None;
    let mut body = loop {
        if position == path.len() {
            selected = Some(hash);
            if let Some((expected, body)) = terminal.take() {
                if expected != hash {
                    return Err(error("subtree proof source differs"));
                }
                break Some(body);
            }
            break Some(proof::produce::blinded(Kind::Node, &hash));
        }
        let row = sqlx::query("SELECT contents,length(CAST(data AS BLOB)) AS bytes,CASE WHEN length(CAST(data AS BLOB))>? THEN NULL ELSE data END AS data FROM node_objects WHERE hash=?")
            .bind(PATH_OBJECT_BYTES as i64).bind(hash.as_slice()).fetch_one(&mut *read).await.map_err(error)?;
        if row.try_get::<bool, _>("contents").map_err(error)? {
            return Err(error("selected subtree path is contents"));
        }
        if row.try_get::<i64, _>("bytes").map_err(error)? > PATH_OBJECT_BYTES as i64 {
            return Err(error("subtree path object exceeds limit"));
        }
        let data: Vec<u8> = row.try_get("data").map_err(error)?;
        let directory = storage::decode(&hash, &data).map_err(error)?;
        if prefix.is_none() {
            directory.logical_root().map_err(error)?;
        }
        let name = path[position];
        let (entries, inode) = match directory {
            Directory::Flat(entries) if prefix.is_none() => (entries, false),
            Directory::Flat(_) => return Err(error("inode child is not a page")),
            Directory::Inode(page::Page::Branch {
                depth,
                length,
                children,
            }) => {
                let mut route = prefix.take().unwrap_or_default();
                if depth != route.len() || depth >= 10 || (depth == 0 && length <= 256) {
                    return Err(error("invalid inode branch depth or length"));
                }
                let slot = page::slot(name, depth).map_err(error)?;
                let next = children
                    .iter()
                    .find(|(index, _)| *index == slot)
                    .map(|(_, hash)| *hash);
                frames.push(Frame::Branch {
                    root: depth == 0,
                    length,
                    children,
                    selected: slot,
                });
                let Some(next) = next else {
                    break None;
                };
                edge(read, &hash, &next).await?;
                route.push(slot);
                prefix = Some(route);
                hash = next;
                continue;
            }
            Directory::Inode(page::Page::Values(entries)) => {
                let route = prefix
                    .as_ref()
                    .ok_or_else(|| error("invalid inode leaf depth"))?;
                if route.is_empty() || route.len() > 10 {
                    return Err(error("invalid inode leaf depth"));
                }
                for entry in &entries {
                    for (depth, expected) in route.iter().enumerate() {
                        if page::slot(&entry.name, depth).map_err(error)? != *expected {
                            return Err(error("inode entry routing differs"));
                        }
                    }
                }
                (entries, true)
            }
        };
        let next = entries.iter().find(|entry| entry.name == name).cloned();
        frames.push(if inode {
            Frame::Values(entries, name.to_vec())
        } else {
            Frame::Flat(entries, name.to_vec())
        });
        let Some(next) = next else {
            break None;
        };
        if next.kind != Kind::Node {
            return Err(error("selected subtree is contents"));
        }
        edge(read, &hash, &next.hash).await?;
        hash = next.hash;
        position += 1;
        prefix = None;
    };
    for frame in frames.into_iter().rev() {
        let next = frame.finish(body)?;
        if next.len() > maximum {
            return Err(error("subtree proof exceeds limit"));
        }
        body = Some(next);
    }
    Ok((
        body.ok_or_else(|| error("subtree proof missing"))?,
        selected,
    ))
}

async fn restore(read: &mut SqliteConnection, root: Hash, maximum: usize) -> Result<Snapshot> {
    let count = (maximum / 16).clamp(1, 262_144);
    let query = format!("{REACHABLE} SELECT count(*) AS count,count(o.hash) AS found,coalesce(sum(length(CAST(o.data AS BLOB))),0) AS bytes FROM reachable r LEFT JOIN node_objects o ON o.hash=r.hash");
    let row = sqlx::query(&query)
        .bind(root.as_slice())
        .bind((count + 1) as i64)
        .fetch_one(&mut *read)
        .await
        .map_err(error)?;
    let actual = usize::try_from(row.try_get::<i64, _>("count").map_err(error)?).map_err(error)?;
    let bytes = usize::try_from(row.try_get::<i64, _>("bytes").map_err(error)?).map_err(error)?;
    if actual > count || bytes > maximum {
        return Err(error("selected subtree exceeds limit"));
    }
    if row.try_get::<i64, _>("found").map_err(error)? != actual as i64 {
        return Err(error("missing subtree object"));
    }
    // Keep the selected hashes on the outer side, including on SQLite versions
    // that would otherwise scan every historical object for a tiny subtree.
    let query = format!("{REACHABLE} SELECT o.hash,o.contents,o.data FROM reachable r CROSS JOIN node_objects o ON o.hash=r.hash");
    let mut rows = sqlx::query(&query)
        .bind(root.as_slice())
        .bind((count + 1) as i64)
        .fetch(&mut *read);
    let mut objects = BTreeMap::new();
    while let Some(row) = rows.try_next().await.map_err(error)? {
        let hash: Hash = row
            .try_get::<Vec<u8>, _>("hash")
            .map_err(error)?
            .try_into()
            .map_err(|_| error("invalid object hash"))?;
        objects.insert(
            hash,
            StoredObject {
                hash,
                contents: row.try_get("contents").map_err(error)?,
                data: row.try_get("data").map_err(error)?,
                children: vec![],
            },
        );
    }
    drop(rows);
    if objects.get(&root).is_none_or(|object| object.contents) {
        return Err(error("selected subtree root is not a node"));
    }
    let query = format!("{REACHABLE} SELECT e.parent,e.child FROM reachable r CROSS JOIN node_edges e ON e.parent=r.hash LIMIT ?");
    let mut rows = sqlx::query(&query)
        .bind(root.as_slice())
        .bind((count + 1) as i64)
        .bind((maximum / 16 + 1) as i64)
        .fetch(read);
    let mut edges = 0;
    while let Some(row) = rows.try_next().await.map_err(error)? {
        edges += 1;
        if edges > maximum / 16 {
            return Err(error("subtree edge count exceeds limit"));
        }
        let parent: Hash = row
            .try_get::<Vec<u8>, _>("parent")
            .map_err(error)?
            .try_into()
            .map_err(|_| error("invalid parent hash"))?;
        let child: Hash = row
            .try_get::<Vec<u8>, _>("child")
            .map_err(error)?
            .try_into()
            .map_err(|_| error("invalid child hash"))?;
        objects
            .get_mut(&parent)
            .ok_or_else(|| error("missing subtree parent"))?
            .children
            .push(child);
    }
    Snapshot::restore_owned(root, objects).map_err(error)
}
