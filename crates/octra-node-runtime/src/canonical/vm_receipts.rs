//! Auxiliary VM receipts are local execution output, never finality or funding
//! proofs. They publish atomically with the ledger, outcome log and ExEx outbox.
use super::{error, CanonicalStore, Head, PreparedCommit, Result};
use octra_exex::{native_history::NativeTransaction, Sequence};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};
use std::collections::BTreeMap;

pub type VmReceipts = BTreeMap<String, Vec<u8>>;

pub(super) fn confirmed(transactions: &[NativeTransaction]) -> Result<VmReceipts> {
    let mut receipts = VmReceipts::new();
    for tx in transactions {
        if let Some(raw) = &tx.receipt {
            if receipts.insert(tx.hash.clone(), raw.clone()).is_some() {
                return Err(error("duplicate archived VM receipt"));
            }
        }
    }
    Ok(receipts)
}
async fn schema(tx: &mut Transaction<'_, Sqlite>) -> Result<()> {
    sqlx::query("CREATE TABLE IF NOT EXISTS node_vm_receipts(hash TEXT NOT NULL, sequence INTEGER NOT NULL REFERENCES node_epochs(sequence), raw BLOB NOT NULL, digest BLOB NOT NULL CHECK(length(digest)=32), PRIMARY KEY(hash,sequence)) WITHOUT ROWID")
        .execute(&mut **tx).await.map_err(error)?;
    sqlx::query("CREATE TABLE IF NOT EXISTS node_vm_receipt_index(id INTEGER PRIMARY KEY CHECK(id=0), version INTEGER NOT NULL CHECK(version=1), sequence INTEGER NOT NULL REFERENCES node_epochs(sequence))")
        .execute(&mut **tx).await.map_err(error)?;
    sqlx::query("INSERT OR IGNORE INTO node_vm_receipt_index VALUES(0,1,0)")
        .execute(&mut **tx)
        .await
        .map_err(error)?;
    Ok(())
}
async fn retain(
    tx: &mut Transaction<'_, Sqlite>,
    sequence: i64,
    values: &VmReceipts,
) -> Result<()> {
    for (hash, raw) in values {
        super::hex_hash::<32>(hash)?;
        let digest = Sha256::digest(raw).to_vec();
        let existing =
            sqlx::query("SELECT raw,digest FROM node_vm_receipts WHERE hash=? AND sequence=?")
                .bind(hash)
                .bind(sequence)
                .fetch_optional(&mut **tx)
                .await
                .map_err(error)?;
        if let Some(row) = existing {
            if row.try_get::<Vec<u8>, _>("raw").map_err(error)? != *raw
                || row.try_get::<Vec<u8>, _>("digest").map_err(error)? != digest
            {
                return Err(error("VM receipt differs from archived execution"));
            }
        } else {
            sqlx::query("INSERT INTO node_vm_receipts VALUES(?,?,?,?)")
                .bind(hash)
                .bind(sequence)
                .bind(raw)
                .bind(digest)
                .execute(&mut **tx)
                .await
                .map_err(error)?;
        }
    }
    Ok(())
}
impl PreparedCommit {
    pub(crate) async fn retain_vm_receipts(&mut self, values: &VmReceipts) -> Result<()> {
        let sequence = i64::try_from(self.head.cursor.sequence.0).map_err(error)?;
        retain(&mut self.transaction, sequence, values).await
    }
    pub(super) async fn advance_vm_receipts(&mut self, base: Sequence) -> Result<()> {
        let changed = sqlx::query(
            "UPDATE node_vm_receipt_index SET sequence=? WHERE id=0 AND version=1 AND sequence=?",
        )
        .bind(i64::try_from(self.head.cursor.sequence.0).map_err(error)?)
        .bind(i64::try_from(base.0).map_err(error)?)
        .execute(&mut *self.transaction)
        .await
        .map_err(error)?;
        if changed.rows_affected() != 1 {
            return Err(error("VM receipt index is behind canonical history"));
        }
        Ok(())
    }
}
impl CanonicalStore {
    /// Older stores retain confirmed receipts in the outbox. Reindex only that
    /// existing evidence, in bounded pages. Missing historical failed-call
    /// receipts cannot be reconstructed from consensus outcome messages.
    pub(super) async fn index_vm_receipts(&self) -> Result<()> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(error)?;
        schema(&mut tx).await?;
        let mut after: i64 = sqlx::query_scalar(
            "SELECT sequence FROM node_vm_receipt_index WHERE id=0 AND version=1",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(error)?;
        let head: i64 = sqlx::query_scalar("SELECT MAX(sequence) FROM node_epochs")
            .fetch_one(&mut *tx)
            .await
            .map_err(error)?;
        if after < 0 || after > head {
            return Err(error("invalid VM receipt index boundary"));
        }
        while after < head {
            let rows = sqlx::query("SELECT n.sequence,e.events FROM node_epochs n JOIN exex_committed_epoch e ON e.chain_id=? AND e.genesis=? AND e.sequence=printf('%016x',n.sequence) WHERE n.sequence>? AND n.sequence<=? ORDER BY n.sequence LIMIT 16")
                .bind(&self.chain.chain_id).bind(self.chain.namespace_key().as_slice())
                .bind(after).bind(head).fetch_all(&mut *tx).await.map_err(error)?;
            if rows.is_empty() {
                return Err(error("VM receipt recovery history missing"));
            }
            for row in rows {
                let sequence: i64 = row.try_get("sequence").map_err(error)?;
                if sequence != after + 1 {
                    return Err(error("VM receipt recovery history gap"));
                }
                let raw: Vec<u8> = row.try_get("events").map_err(error)?;
                let transactions: Vec<NativeTransaction> =
                    serde_json::from_slice(&raw).map_err(error)?;
                retain(&mut tx, sequence, &confirmed(&transactions)?).await?;
                after = sequence;
            }
        }
        sqlx::query("UPDATE node_vm_receipt_index SET sequence=? WHERE id=0")
            .bind(after)
            .execute(&mut *tx)
            .await
            .map_err(error)?;
        tx.commit().await.map_err(error)
    }
    /// Fix the read to the caller's published snapshot, even if a newer epoch
    /// commits before the query finishes. Hashes may recur in rejected epochs.
    pub async fn vm_receipt(&self, head: &Head, hash: &[u8]) -> Result<Option<Vec<u8>>> {
        let hash = std::str::from_utf8(hash).map_err(error)?;
        super::hex_hash::<32>(hash)?;
        if self.retained_head(head.cursor.sequence).await? != *head {
            return Err(error("VM receipt snapshot differs from canonical history"));
        }
        let indexed: i64 = sqlx::query_scalar(
            "SELECT sequence FROM node_vm_receipt_index WHERE id=0 AND version=1",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(error)?;
        if indexed < i64::try_from(head.cursor.sequence.0).map_err(error)? {
            return Err(error("VM receipt index is behind the published snapshot"));
        }
        let row = sqlx::query("SELECT raw,digest FROM node_vm_receipts WHERE hash=? AND sequence<=? ORDER BY sequence DESC LIMIT 1")
            .bind(hash).bind(i64::try_from(head.cursor.sequence.0).map_err(error)?)
            .fetch_optional(&self.pool).await.map_err(error)?;
        row.map(|row| {
            let raw: Vec<u8> = row.try_get("raw").map_err(error)?;
            let digest: Vec<u8> = row.try_get("digest").map_err(error)?;
            if Sha256::digest(&raw).as_slice() != digest {
                return Err(error("VM receipt archive checksum differs"));
            }
            Ok(raw)
        })
        .transpose()
    }
}
