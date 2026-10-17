//! Historical reads verify the retained head and immutable object commitments.
use super::{decode_head, error, hex_hash, Head, Result, StoredObject};
use crate::state_batch::Snapshot;
use futures::TryStreamExt;
use octra_exex::{ChainIdentity, Cursor, Sequence};
use octra_node_protocol::{
    consensus::{relief::Mark, relief_log},
    irmin,
};
use sqlx::{Row, SqlitePool};
use std::{collections::BTreeMap, sync::Arc};
mod paths;

/// A committed absence is distinct from missing historical evidence. Only an
/// unpublished epoch may consult the mutable validator journal.
pub enum ReliefSource {
    Journal,
    Committed(Option<Mark>),
}

#[derive(Clone)]
pub struct Reader {
    pub(super) pool: SqlitePool,
    chain: ChainIdentity,
    anchor: Cursor,
    snapshots: Arc<super::snapshots::Cache>,
    pub(super) epoch_tag_keep: i64,
}
impl Reader {
    pub(super) fn new(
        pool: SqlitePool,
        chain: ChainIdentity,
        anchor: Cursor,
        snapshots: Arc<super::snapshots::Cache>,
        epoch_tag_keep: i64,
    ) -> Self {
        Self {
            pool,
            chain,
            anchor,
            snapshots,
            epoch_tag_keep,
        }
    }
    pub fn chain(&self) -> &ChainIdentity {
        &self.chain
    }
    pub fn anchor(&self) -> Cursor {
        self.anchor
    }
    /// Allocation preflight for one retained finality record. These lengths are
    /// operational hints, never inclusion evidence: callers must subsequently
    /// authenticate the decoded transactions, receipts, reward source and QC.
    pub async fn record_lengths(&self, head: &Head) -> Result<RecordLengths> {
        if self.head_at(head.cursor.sequence).await? != *head {
            return Err(error("record read head differs"));
        }
        let previous = head
            .cursor
            .sequence
            .0
            .checked_sub(1)
            .ok_or_else(|| error("genesis has no finality record"))?;
        let parent = self.head_at(Sequence(previous)).await?;
        let row=sqlx::query("SELECT e.sequence AS event_sequence,e.epoch AS event_epoch,e.parent_root AS event_parent,e.root AS event_root,length(e.events) AS events,length(n.certificate) AS certificate,length(r.receipts) AS receipts,length(w.source) AS reward FROM exex_committed_epoch e JOIN node_epochs n ON n.sequence=? JOIN node_consensus_receipts r ON r.sequence=n.sequence JOIN node_epoch_rewards w ON w.sequence=n.sequence WHERE e.chain_id=? AND e.genesis=? AND e.sequence=?")
            .bind(i64::try_from(head.cursor.sequence.0).map_err(error)?)
            .bind(&self.chain.chain_id).bind(self.chain.namespace_key().as_slice())
            .bind(format!("{:016x}",head.cursor.sequence.0)).fetch_one(&self.pool).await.map_err(error)?;
        if row.try_get::<String, _>("event_sequence").map_err(error)?
            != format!("{:016x}", head.cursor.sequence.0)
            || row.try_get::<String, _>("event_epoch").map_err(error)?
                != format!("{:016x}", head.cursor.epoch.0)
            || row.try_get::<Vec<u8>, _>("event_parent").map_err(error)?
                != parent.cursor.state_root.0
            || row.try_get::<Vec<u8>, _>("event_root").map_err(error)? != head.cursor.state_root.0
        {
            return Err(error("record outbox binding differs"));
        }
        let length = |name| -> Result<usize> {
            usize::try_from(row.try_get::<i64, _>(name).map_err(error)?).map_err(error)
        };
        Ok(RecordLengths {
            events: length("events")?,
            certificate: length("certificate")?,
            receipts: length("receipts")?,
            reward: length("reward")?,
        })
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
    pub async fn head_for_epoch(&self, epoch: u64) -> Result<Head> {
        let offset = epoch
            .checked_sub(self.anchor.epoch.0)
            .ok_or_else(|| error("epoch precedes retained history floor"))?;
        let head = self.head_at(Sequence(offset)).await?;
        if head.cursor.epoch.0 != epoch {
            return Err(error("historical epoch binding differs"));
        }
        Ok(head)
    }
    /// Missing retained history is an absence; storage failure or a contradictory
    /// row remains an error. Callers must still compare the requested state root.
    pub async fn head_for_epoch_opt(&self, epoch: u64) -> Result<Option<Head>> {
        let Some(offset) = epoch.checked_sub(self.anchor.epoch.0) else {
            return Ok(None);
        };
        let sequence = i64::try_from(offset).map_err(error)?;
        let row = sqlx::query("SELECT sequence,head,root FROM node_epochs WHERE sequence=?")
            .bind(sequence)
            .fetch_optional(&self.pool)
            .await
            .map_err(error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let head = decode_head(&row)?;
        if head.cursor.epoch.0 != epoch {
            return Err(error("historical epoch binding differs"));
        }
        Ok(Some(head))
    }
    /// Caller-provided epoch/root metadata cannot select a different tree.
    pub async fn snapshot_at(&self, head: &Head) -> Result<Snapshot> {
        let retained = self.head_at(head.cursor.sequence).await?;
        if &retained != head {
            return Err(error("historical head differs"));
        }
        self.snapshots.load(&self.pool, &retained).await
    }

    /// Read one contents path from an authenticated retained head. Absence is
    /// established by a complete verified directory, never a missing object.
    pub(crate) async fn read_at(&self, head: &Head, path: &[&[u8]]) -> Result<Option<Vec<u8>>> {
        if self.head_at(head.cursor.sequence).await? != *head {
            return Err(error("historical head differs"));
        }
        paths::read(&self.pool, hex_hash(&head.ledger_root)?, path).await
    }

    /// Selected-path proof with an allocation cap on the terminal contents.
    /// The length guard is an operational preflight; accepted bytes must still
    /// match the authenticated contents hash before reaching the caller.
    pub(crate) async fn read_at_bounded(
        &self,
        head: &Head,
        path: &[&[u8]],
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>> {
        if self.head_at(head.cursor.sequence).await? != *head {
            return Err(error("historical head differs"));
        }
        paths::read_bounded(&self.pool, hex_hash(&head.ledger_root)?, path, max_bytes).await
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

#[derive(Clone, Copy, Debug)]
pub struct RecordLengths {
    pub events: usize,
    pub certificate: usize,
    pub receipts: usize,
    pub reward: usize,
}
pub(super) async fn restore(pool: &SqlitePool, head: &Head) -> Result<Snapshot> {
    let root: irmin::Hash = hex_hash(&head.ledger_root)?;
    let mut rows=sqlx::query("WITH RECURSIVE reachable(hash) AS (SELECT ? UNION SELECT child FROM node_edges JOIN reachable ON parent=reachable.hash) SELECT o.hash,o.contents,o.data FROM node_objects o JOIN reachable r ON o.hash=r.hash")
        .bind(root.as_slice()).fetch(pool);
    let mut objects = BTreeMap::new();
    while let Some(row) = rows.try_next().await.map_err(error)? {
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
    let mut edges = sqlx::query("WITH RECURSIVE reachable(hash) AS (SELECT ? UNION SELECT child FROM node_edges JOIN reachable ON parent=reachable.hash) SELECT e.parent,e.child FROM node_edges e JOIN reachable r ON e.parent=r.hash")
        .bind(root.as_slice()).fetch(pool);
    while let Some(row) = edges.try_next().await.map_err(error)? {
        let parent: irmin::Hash = row
            .try_get::<Vec<u8>, _>("parent")
            .map_err(error)?
            .as_slice()
            .try_into()
            .map_err(|_| error("invalid object hash"))?;
        let child: irmin::Hash = row
            .try_get::<Vec<u8>, _>("child")
            .map_err(error)?
            .as_slice()
            .try_into()
            .map_err(|_| error("invalid child hash"))?;
        objects
            .get_mut(&parent)
            .ok_or_else(|| error("missing state object"))?
            .children
            .push(child);
    }
    Snapshot::restore_owned(root, objects).map_err(error)
}
