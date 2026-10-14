//! Historical reads verify the retained head and immutable object commitments.
use super::{decode_head, error, hex_hash, Head, Result, StoredObject};
use crate::state_batch::Snapshot;
use octra_exex::{ChainIdentity, Sequence};
use octra_node_protocol::{
    consensus::{relief::Mark, relief_log},
    irmin,
};
use sqlx::{Row, SqlitePool};
use std::collections::BTreeMap;

/// A committed absence is distinct from missing historical evidence. Only an
/// unpublished epoch may consult the mutable validator journal.
pub enum ReliefSource {
    Journal,
    Committed(Option<Mark>),
}

#[derive(Clone)]
pub struct Reader {
    pool: SqlitePool,
    chain: ChainIdentity,
}
impl Reader {
    pub(super) fn new(pool: SqlitePool, chain: ChainIdentity) -> Self {
        Self { pool, chain }
    }
    pub fn chain(&self) -> &ChainIdentity {
        &self.chain
    }
    pub async fn head_at(&self, sequence: Sequence) -> Result<Head> {
        let number = i64::try_from(sequence.0).map_err(error)?;
        let row = sqlx::query("SELECT sequence,head,root FROM node_epochs WHERE sequence=?")
            .bind(number)
            .fetch_one(&self.pool)
            .await
            .map_err(error)?;
        decode_head(&row)
    }
    /// Caller-provided epoch/root metadata cannot select a different tree.
    pub async fn snapshot_at(&self, head: &Head) -> Result<Snapshot> {
        let retained = self.head_at(head.cursor.sequence).await?;
        if &retained != head {
            return Err(error("historical head differs"));
        }
        restore(&self.pool, &retained).await
    }

    pub async fn relief_after(&self, parent: &Head) -> Result<ReliefSource> {
        if self.head_at(parent.cursor.sequence).await? != *parent {
            return Err(error("historical head differs"));
        }
        let next = parent
            .cursor
            .sequence
            .0
            .checked_add(1)
            .and_then(|n| i64::try_from(n).ok())
            .ok_or_else(|| error("sequence exhausted"))?;
        let row = sqlx::query("SELECT sequence,head,root FROM node_epochs WHERE sequence=?")
            .bind(next)
            .fetch_optional(&self.pool)
            .await
            .map_err(error)?;
        let Some(row) = row else {
            return Ok(ReliefSource::Journal);
        };
        let head = decode_head(&row)?;
        if head.parent_commit.as_ref() != Some(&parent.irmin_commit)
            || parent.cursor.epoch.0.checked_add(1) != Some(head.cursor.epoch.0)
        {
            return Err(error("relief history parent differs"));
        }
        // A missing table or row is unavailable history, never permission to
        // fall back to the live journal after its older proofs were pruned.
        let row =
            sqlx::query("SELECT substr(mark,1,?) AS mark FROM node_epoch_relief WHERE sequence=?")
                .bind(relief_log::MAX_WIRE_BYTES as i64 + 1)
                .bind(next)
                .fetch_one(&self.pool)
                .await
                .map_err(error)?;
        let bytes: Option<Vec<u8>> = row.try_get("mark").map_err(error)?;
        if bytes
            .as_ref()
            .is_some_and(|b| b.len() as u64 > relief_log::MAX_WIRE_BYTES)
        {
            return Err(error("relief archive exceeds native record limit"));
        }
        let mark = bytes
            .as_deref()
            .map(relief_log::decode)
            .transpose()
            .map_err(error)?;
        Ok(ReliefSource::Committed(mark))
    }
}
pub(super) async fn restore(pool: &SqlitePool, head: &Head) -> Result<Snapshot> {
    let root: irmin::Hash = hex_hash(&head.ledger_root)?;
    let rows=sqlx::query("WITH RECURSIVE reachable(hash) AS (SELECT ? UNION SELECT child FROM node_edges JOIN reachable ON parent=reachable.hash) SELECT o.hash,o.contents,o.data FROM node_objects o JOIN reachable r ON o.hash=r.hash")
        .bind(root.as_slice()).fetch_all(pool).await.map_err(error)?;
    let mut objects = BTreeMap::new();
    for row in rows {
        let hash = row
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
    Snapshot::restore(root, &objects).map_err(error)
}
