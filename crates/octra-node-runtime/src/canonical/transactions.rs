//! Transaction lookup over the same committed prefix as a captured state tree.
//! This is a local archive index, not a substitute for finality authentication.
use super::{decode_head, error, transaction_commitment, CanonicalStore, Head, Reader, Result};
use octra_exex::{native_history::NativeTransaction, Sequence};
use sha2::{Digest, Sha256};
use sqlx::{sqlite::SqliteRow, Row, Sqlite, Transaction};
mod history;
pub(super) use history::retain_outcomes;
pub use history::{HistoryPage, HistoryQuery, HistoryReadError, RejectionPage, RejectionRecord};

async fn retained_head(tx: &mut Transaction<'_, Sqlite>, sequence: i64) -> Result<Head> {
    let row = sqlx::query("SELECT sequence,head,root FROM node_epochs WHERE sequence=?")
        .bind(sequence)
        .fetch_one(&mut **tx)
        .await
        .map_err(error)?;
    decode_head(&row)
}

/// The auxiliary hash/txid lookup is only a locator. Rebuild its containing
/// epoch's native commitment from the canonical outbox before using a record.
pub(super) fn epoch_records(
    row: &SqliteRow,
    parent: &Head,
    head: &Head,
) -> Result<Vec<NativeTransaction>> {
    if parent.cursor.sequence.0.checked_add(1) != Some(head.cursor.sequence.0)
        || parent.cursor.epoch.0.checked_add(1) != Some(head.cursor.epoch.0)
        || head.parent_commit.as_ref() != Some(&parent.irmin_commit)
        || row.try_get::<String, _>("event_sequence").map_err(error)?
            != format!("{:016x}", head.cursor.sequence.0)
        || row.try_get::<String, _>("event_epoch").map_err(error)?
            != format!("{:016x}", head.cursor.epoch.0)
        || row.try_get::<Vec<u8>, _>("event_parent").map_err(error)? != parent.cursor.state_root.0
        || row.try_get::<Vec<u8>, _>("event_root").map_err(error)? != head.cursor.state_root.0
    {
        return Err(error("transaction outbox epoch binding differs"));
    }
    let raw: Vec<u8> = row.try_get("events").map_err(error)?;
    let records: Vec<NativeTransaction> = serde_json::from_slice(&raw).map_err(error)?;
    let (index_hash, index_root, txid_hi) =
        transaction_commitment(parent, head.cursor.epoch.0, &records)?;
    if head.index_hash.as_ref() != Some(&index_hash)
        || head.index_root != index_root
        || head.txid_hi != txid_hi
    {
        return Err(error("transaction outbox commitment differs"));
    }
    Ok(records)
}

async fn schema(tx: &mut Transaction<'_, Sqlite>) -> Result<()> {
    sqlx::query("CREATE TABLE IF NOT EXISTS node_transactions(hash TEXT NOT NULL,txid INTEGER NOT NULL UNIQUE,sequence INTEGER NOT NULL REFERENCES node_epochs(sequence),record BLOB NOT NULL,digest BLOB NOT NULL,PRIMARY KEY(hash,txid))")
        .execute(&mut **tx).await.map_err(error)?;
    sqlx::query("CREATE TABLE IF NOT EXISTS node_transaction_index(id INTEGER PRIMARY KEY CHECK(id=0),version INTEGER NOT NULL,sequence INTEGER NOT NULL REFERENCES node_epochs(sequence))")
        .execute(&mut **tx).await.map_err(error)?;
    sqlx::query("INSERT OR IGNORE INTO node_transaction_index VALUES(0,1,0)")
        .execute(&mut **tx)
        .await
        .map_err(error)?;
    history::schema(tx).await?;
    Ok(())
}
pub(super) async fn retain(
    tx: &mut Transaction<'_, Sqlite>,
    sequence: Sequence,
    records: &[NativeTransaction],
) -> Result<()> {
    let sequence = i64::try_from(sequence.0).map_err(error)?;
    for record in records {
        if record.txid < 0 {
            return Err(error("negative archived transaction identifier"));
        }
        record.validate().map_err(error)?;
        let raw = serde_json::to_vec(record).map_err(error)?;
        let digest = Sha256::digest(&raw).to_vec();
        let prior =
            sqlx::query("SELECT hash,sequence,record,digest FROM node_transactions WHERE txid=?")
                .bind(record.txid)
                .fetch_optional(&mut **tx)
                .await
                .map_err(error)?;
        if let Some(prior) = prior {
            if prior.try_get::<String, _>("hash").map_err(error)? != record.hash
                || prior.try_get::<i64, _>("sequence").map_err(error)? != sequence
                || prior.try_get::<Vec<u8>, _>("record").map_err(error)? != raw
                || prior.try_get::<Vec<u8>, _>("digest").map_err(error)? != digest
            {
                return Err(error("transaction index differs from canonical archive"));
            }
        } else {
            sqlx::query("INSERT INTO node_transactions VALUES(?,?,?,?,?)")
                .bind(&record.hash)
                .bind(record.txid)
                .bind(sequence)
                .bind(raw)
                .bind(digest)
                .execute(&mut **tx)
                .await
                .map_err(error)?;
        }
    }
    history::retain_confirmed(tx, records).await?;
    Ok(())
}
pub(super) async fn advance(
    tx: &mut Transaction<'_, Sqlite>,
    base: Sequence,
    next: Sequence,
) -> Result<()> {
    let changed = sqlx::query(
        "UPDATE node_transaction_index SET sequence=? WHERE id=0 AND version=1 AND sequence=?",
    )
    .bind(i64::try_from(next.0).map_err(error)?)
    .bind(i64::try_from(base.0).map_err(error)?)
    .execute(&mut **tx)
    .await
    .map_err(error)?;
    if changed.rows_affected() != 1 {
        return Err(error("transaction index is behind canonical history"));
    }
    Ok(())
}
impl CanonicalStore {
    /// Old stores rebuild only from their retained canonical outbox. Snapshot
    /// anchors do not invent earlier transactions whose bytes were not imported.
    pub(super) async fn index_transactions(&self) -> Result<()> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(error)?;
        schema(&mut tx).await?;
        let mut after: i64 = sqlx::query_scalar(
            "SELECT sequence FROM node_transaction_index WHERE id=0 AND version=1",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(error)?;
        let head: i64 = sqlx::query_scalar("SELECT MAX(sequence) FROM node_epochs")
            .fetch_one(&mut *tx)
            .await
            .map_err(error)?;
        if after < 0 || after > head {
            return Err(error("invalid transaction index boundary"));
        }
        let mut parent = retained_head(&mut tx, after).await?;
        while after < head {
            let rows=sqlx::query("SELECT n.sequence,n.head,n.root,e.sequence AS event_sequence,e.epoch AS event_epoch,e.parent_root AS event_parent,e.root AS event_root,e.events FROM node_epochs n JOIN exex_committed_epoch e ON e.chain_id=? AND e.genesis=? AND e.sequence=printf('%016x',n.sequence) WHERE n.sequence>? AND n.sequence<=? ORDER BY n.sequence LIMIT 4")
                .bind(&self.chain.chain_id).bind(self.chain.namespace_key().as_slice()).bind(after).bind(head).fetch_all(&mut *tx).await.map_err(error)?;
            if rows.is_empty() {
                return Err(error("transaction index recovery history missing"));
            }
            for row in rows {
                let sequence: i64 = row.try_get("sequence").map_err(error)?;
                if sequence != after + 1 {
                    return Err(error("transaction index recovery history gap"));
                }
                let archived = decode_head(&row)?;
                let records = epoch_records(&row, &parent, &archived)?;
                retain(&mut tx, Sequence(sequence as u64), &records).await?;
                after = sequence;
                parent = archived;
            }
        }
        sqlx::query("UPDATE node_transaction_index SET sequence=? WHERE id=0")
            .bind(after)
            .execute(&mut *tx)
            .await
            .map_err(error)?;
        history::recover(self, &mut tx, head).await?;
        tx.commit().await.map_err(error)
    }
    pub async fn transaction(
        &self,
        head: &Head,
        hash: &[u8],
        max_bytes: usize,
    ) -> Result<Option<(Head, NativeTransaction)>> {
        self.reader().transaction(head, hash, max_bytes).await
    }
}
impl Reader {
    /// The captured head fixes the read prefix. The limit is a local read
    /// budget; it does not constrain canonical transaction acceptance. The
    /// index row is authenticated against its epoch's committed transaction
    /// list. Optional execution receipts remain auxiliary local output.
    pub async fn transaction(
        &self,
        head: &Head,
        hash: &[u8],
        max_bytes: usize,
    ) -> Result<Option<(Head, NativeTransaction)>> {
        let hash = std::str::from_utf8(hash).map_err(error)?;
        super::hex_hash::<32>(hash)?;
        let bound = max_bytes
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .filter(|_| max_bytes > 0)
            .ok_or_else(|| error("transaction read limit refused"))?;
        // One SQLite snapshot prevents an append from changing this captured
        // prefix or mixing lookup, outbox and epoch metadata from two views.
        let mut read = self.pool.begin().await.map_err(error)?;
        let prefix = i64::try_from(head.cursor.sequence.0).map_err(error)?;
        if retained_head(&mut read, prefix).await? != *head {
            return Err(error("transaction read head differs"));
        }
        let indexed: i64 = sqlx::query_scalar(
            "SELECT sequence FROM node_transaction_index WHERE id=0 AND version=1",
        )
        .fetch_one(&mut *read)
        .await
        .map_err(error)?;
        if indexed < prefix {
            return Err(error("transaction index is behind the published snapshot"));
        }
        // SQLite's substr length is a signed 32-bit argument in the bundled
        // engine. Clamp to the actual blob length before passing a larger local
        // read budget, so an unbounded projection cannot wrap it to a negative
        // length and report a false archive checksum mismatch.
        let row=sqlx::query("SELECT txid,sequence,substr(record,1,min(?,length(record))) AS record,digest FROM node_transactions WHERE hash=? AND sequence<=? ORDER BY txid DESC LIMIT 1")
            .bind(bound).bind(hash).bind(prefix).fetch_optional(&mut *read).await.map_err(error)?;
        let Some(row) = row else {
            read.commit().await.map_err(error)?;
            return Ok(None);
        };
        let raw: Vec<u8> = row.try_get("record").map_err(error)?;
        if raw.len() > max_bytes {
            return Err(error("transaction read exceeds limit"));
        }
        let digest: Vec<u8> = row.try_get("digest").map_err(error)?;
        if Sha256::digest(&raw).as_slice() != digest {
            return Err(error("transaction archive checksum differs"));
        }
        let record: NativeTransaction = serde_json::from_slice(&raw).map_err(error)?;
        record.validate().map_err(error)?;
        let sequence: i64 = row.try_get("sequence").map_err(error)?;
        let txid: i64 = row.try_get("txid").map_err(error)?;
        if sequence <= 0 || record.hash != hash || record.txid != txid {
            return Err(error("transaction archive identity differs"));
        }
        let archived = retained_head(&mut read, sequence).await?;
        let parent = retained_head(&mut read, sequence - 1).await?;
        if txid <= parent.txid_hi || txid > archived.txid_hi {
            return Err(error("transaction archive epoch differs"));
        }
        let outbox = sqlx::query("SELECT sequence AS event_sequence,epoch AS event_epoch,parent_root AS event_parent,root AS event_root,events FROM exex_committed_epoch WHERE chain_id=? AND genesis=? AND sequence=?")
            .bind(&self.chain().chain_id)
            .bind(self.chain().namespace_key().as_slice())
            .bind(format!("{:016x}", archived.cursor.sequence.0))
            .fetch_one(&mut *read).await.map_err(error)?;
        let records = epoch_records(&outbox, &parent, &archived)?;
        let position = txid
            .checked_sub(parent.txid_hi)
            .and_then(|offset| offset.checked_sub(1))
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or_else(|| error("transaction archive position differs"))?;
        if records.get(position) != Some(&record) {
            return Err(error("transaction index differs from committed outbox"));
        }
        read.commit().await.map_err(error)?;
        Ok(Some((archived, record)))
    }
}
