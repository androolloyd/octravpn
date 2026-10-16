//! Authenticated selected-path reads through legacy directories and inode pages.
use super::super::{error, Result};
use crate::state_batch::storage::{self, Directory};
use octra_node_protocol::irmin::{self, page, Entry, Hash, Kind};
use sqlx::{Row, SqlitePool};

pub(super) async fn read(pool: &SqlitePool, hash: Hash, path: &[&[u8]]) -> Result<Option<Vec<u8>>> {
    read_bounded(pool, hash, path, usize::MAX).await
}

pub(super) async fn read_bounded(
    pool: &SqlitePool,
    mut hash: Hash,
    mut path: &[&[u8]],
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    let mut expected_contents = None;
    let mut prefix: Option<Vec<u8>> = None;
    loop {
        // CASE keeps an oversized terminal blob out of the returned SQLite row.
        // Include the authenticated edge kind so a corrupt stored kind cannot
        // evade the cap and allocate a large blob before the mismatch is caught.
        let row = sqlx::query("SELECT contents,length(CAST(data AS BLOB)) AS byte_len,CASE WHEN (contents OR ?) AND length(CAST(data AS BLOB))>? THEN NULL ELSE data END AS data FROM node_objects WHERE hash=?")
            .bind(expected_contents == Some(true))
            .bind(i64::try_from(max_bytes).unwrap_or(i64::MAX))
            .bind(hash.as_slice())
            .fetch_optional(pool)
            .await
            .map_err(error)?
            .ok_or_else(|| error("missing state object"))?;
        let contents: bool = row.try_get("contents").map_err(error)?;
        if expected_contents.is_some_and(|expected| contents != expected) {
            return Err(error("invalid tree child"));
        }
        if contents
            && row.try_get::<i64, _>("byte_len").map_err(error)?
                > i64::try_from(max_bytes).unwrap_or(i64::MAX)
        {
            return Err(error("selected contents exceeds read limit"));
        }
        let data: Vec<u8> = row.try_get("data").map_err(error)?;
        if contents {
            if irmin::contents_hash(&data) != hash {
                return Err(error("state object commitment differs"));
            }
            return Ok(path.is_empty().then_some(data));
        }
        let directory = storage::decode(&hash, &data).map_err(error)?;
        if prefix.is_none() {
            directory.logical_root().map_err(error)?;
        }
        let Some((step, rest)) = path.split_first() else {
            return Ok(None);
        };
        let entries = match directory {
            Directory::Flat(entries) if prefix.is_none() => entries,
            Directory::Flat(_) => return Err(error("inode child is not a page")),
            Directory::Inode(page::Page::Values(entries)) => {
                let prefix = prefix
                    .as_ref()
                    .ok_or_else(|| error("invalid inode leaf depth"))?;
                if prefix.is_empty() || prefix.len() > 10 {
                    return Err(error("invalid inode leaf depth"));
                }
                for entry in &entries {
                    for (depth, expected) in prefix.iter().enumerate() {
                        if page::slot(&entry.name, depth).map_err(error)? != *expected {
                            return Err(error("inode entry routing differs"));
                        }
                    }
                }
                entries
            }
            Directory::Inode(page::Page::Branch {
                depth,
                length,
                children,
            }) => {
                let mut route = prefix.unwrap_or_default();
                if depth != route.len() || depth >= 10 || (depth == 0 && length <= 256) {
                    return Err(error("invalid inode branch depth or length"));
                }
                let slot = page::slot(step, depth).map_err(error)?;
                let Some((_, child)) = children.iter().find(|(index, _)| *index == slot) else {
                    return Ok(None);
                };
                require_edge(pool, &hash, child).await?;
                hash = *child;
                route.push(slot);
                prefix = Some(route);
                expected_contents = Some(false);
                continue;
            }
        };
        let Some(child) = selected(&entries, step) else {
            return Ok(None);
        };
        require_edge(pool, &hash, &child.hash).await?;
        hash = child.hash;
        expected_contents = Some(child.kind == Kind::Contents);
        prefix = None;
        path = rest;
    }
}
fn selected<'a>(entries: &'a [Entry], name: &[u8]) -> Option<&'a Entry> {
    entries.iter().find(|entry| entry.name == name)
}
async fn require_edge(pool: &SqlitePool, parent: &Hash, child: &Hash) -> Result<()> {
    let present: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM node_edges WHERE parent=? AND child=?)")
            .bind(parent.as_slice())
            .bind(child.as_slice())
            .fetch_one(pool)
            .await
            .map_err(error)?;
    if !present {
        return Err(error("missing state edge"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
