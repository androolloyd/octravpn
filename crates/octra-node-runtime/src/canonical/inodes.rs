//! Physical inode persistence inside the existing canonical SQLite transaction.
use super::{error, Result};
use crate::state_batch::{storage, Snapshot, StoredObject};
use octra_node_protocol::irmin::Hash;
use sqlx::{QueryBuilder, Row, Sqlite, Transaction};
use std::collections::BTreeSet;

pub(super) async fn write(
    tx: &mut Transaction<'_, Sqlite>,
    snapshot: &Snapshot,
    base: Option<&Snapshot>,
) -> Result<()> {
    let mut reusable = BTreeSet::new();
    if let Some(base) = base {
        for hash in snapshot.previous_wide_roots(base).map_err(error)? {
            let row = sqlx::query(
                "SELECT contents,substr(data,1,?) AS magic FROM node_objects WHERE hash=?",
            )
            .bind(storage::MAGIC.len() as i64)
            .bind(hash.as_slice())
            .fetch_one(&mut **tx)
            .await
            .map_err(error)?;
            if row.try_get::<bool, _>("contents").map_err(error)? {
                return Err(error("persisted parent directory kind differs"));
            }
            if row.try_get::<Vec<u8>, _>("magic").map_err(error)? == storage::MAGIC {
                let data: Vec<u8> =
                    sqlx::query_scalar("SELECT data FROM node_objects WHERE hash=?")
                        .bind(hash.as_slice())
                        .fetch_one(&mut **tx)
                        .await
                        .map_err(error)?;
                let directory = storage::decode(&hash, &data).map_err(error)?;
                directory.logical_root().map_err(error)?;
                reusable.insert(hash);
            }
        }
    }
    for object in snapshot
        .object_stream_reusing(base, reusable)
        .map_err(error)?
    {
        insert(tx, object.map_err(error)?).await?;
    }
    Ok(())
}

async fn insert(tx: &mut Transaction<'_, Sqlite>, object: StoredObject) -> Result<()> {
    let inserted = sqlx::query(
        "INSERT INTO node_objects(hash,contents,data) VALUES(?,?,?) ON CONFLICT DO NOTHING",
    )
    .bind(object.hash.as_slice())
    .bind(object.contents)
    .bind(&object.data)
    .execute(&mut **tx)
    .await
    .map_err(error)?;
    if inserted.rows_affected() == 0 {
        let row = sqlx::query("SELECT contents,data FROM node_objects WHERE hash=?")
            .bind(object.hash.as_slice())
            .fetch_one(&mut **tx)
            .await
            .map_err(error)?;
        let contents: bool = row.try_get("contents").map_err(error)?;
        let data: Vec<u8> = row.try_get("data").map_err(error)?;
        if contents != object.contents {
            return Err(error("conflicting persisted state object"));
        }
        let expected = if data == object.data {
            object.children
        } else if !contents
            && storage::compatible(&object.hash, &data, &object.data).unwrap_or(false)
        {
            storage::decode(&object.hash, &data)
                .map_err(error)?
                .children()
        } else {
            return Err(error("conflicting persisted state object"));
        };
        let existing =
            sqlx::query_scalar::<_, Vec<u8>>("SELECT child FROM node_edges WHERE parent=?")
                .bind(object.hash.as_slice())
                .fetch_all(&mut **tx)
                .await
                .map_err(error)?
                .into_iter()
                .map(|raw| {
                    raw.as_slice()
                        .try_into()
                        .map_err(|_| error("invalid child hash"))
                })
                .collect::<Result<BTreeSet<Hash>>>()?;
        if existing != expected.into_iter().collect() {
            return Err(error("conflicting persisted state edges"));
        }
        // An existing legacy object keeps its original authenticated encoding
        // and edges. Never attach inode edges to its flat representation.
        return Ok(());
    }
    for children in object.children.chunks(256) {
        let mut query = QueryBuilder::<Sqlite>::new("INSERT INTO node_edges(parent,child) ");
        query.push_values(children, |mut row, child| {
            row.push_bind(object.hash.as_slice())
                .push_bind(child.as_slice());
        });
        query
            .push(" ON CONFLICT DO NOTHING")
            .build()
            .execute(&mut **tx)
            .await
            .map_err(error)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
