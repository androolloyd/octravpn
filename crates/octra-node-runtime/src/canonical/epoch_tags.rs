//! Native epoch branch lifetimes over SQLite's immutable commit archive.
//! Pruning a tag removes only its named binding; history and ExEx stay intact.
use super::{decode_head, error, hex_hash, CanonicalStore, Head, Reader, Result};
use octra_node_protocol::{native_integer::parse_int63, transaction::Nonce};
use sqlx::{Row, Sqlite, Transaction};

const DEFAULT_KEEP: i64 = 8192;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochTagStats {
    pub count: i64,
    pub min_epoch: i64,
    pub max_epoch: i64,
    pub keep_epochs: i64,
    // This backend has no Irmin pack collector or pack split branches.
    pub split_epoch: Option<i64>,
    pub gc_enabled: bool,
    pub gc_running: bool,
    pub gc_need: Option<i64>,
}

fn keep_of(raw: Option<&[u8]>) -> Result<i64> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_KEEP);
    };
    // OCaml String.trim, followed by its machine-integer parser.
    let space = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | 12);
    let start = raw.iter().position(|b| !space(b)).unwrap_or(raw.len());
    let end = raw.iter().rposition(|b| !space(b)).map_or(start, |i| i + 1);
    parse_int63(&raw[start..end])
        .filter(|keep| (4096..=65_536).contains(keep))
        .ok_or_else(|| error("OCTRA_GC_KEEP_EPOCHS must be in 4096..65536"))
}

pub(super) fn capture_keep() -> Result<i64> {
    keep_of(
        std::env::var_os("OCTRA_GC_KEEP_EPOCHS")
            .as_deref()
            .map(std::ffi::OsStr::as_encoded_bytes),
    )
}

fn initial_label(empty: bool, raw: Option<&[u8]>) -> Result<Option<i64>> {
    if !empty {
        return Ok(None);
    }
    raw.map(|raw| parse_int63(raw).ok_or_else(|| error("invalid initial epoch tag")))
        .transpose()
}

async fn schema(tx: &mut Transaction<'_, Sqlite>) -> Result<()> {
    sqlx::query("CREATE TABLE IF NOT EXISTS node_epoch_tags(epoch INTEGER PRIMARY KEY,sequence INTEGER NOT NULL REFERENCES node_epochs(sequence),commit_hash TEXT NOT NULL,root BLOB NOT NULL CHECK(length(root)=64))")
        .execute(&mut **tx).await.map_err(error)?;
    Ok(())
}

async fn insert(tx: &mut Transaction<'_, Sqlite>, epoch: i64, head: &Head) -> Result<()> {
    head.validate()?;
    sqlx::query("INSERT INTO node_epoch_tags(epoch,sequence,commit_hash,root) VALUES(?,?,?,?) ON CONFLICT(epoch) DO UPDATE SET sequence=excluded.sequence,commit_hash=excluded.commit_hash,root=excluded.root")
        .bind(epoch)
        .bind(head.cursor.sequence.0 as i64)
        .bind(&head.irmin_commit)
        .bind(hex_hash::<64>(&head.ledger_root)?.as_slice())
        .execute(&mut **tx)
        .await
        .map_err(error)?;
    Ok(())
}

fn cleanup_floor(applied: u64, keep: i64) -> Option<i64> {
    let current = Nonce::new(i64::try_from(applied).ok()?)
        .ok()?
        .successor()
        .get();
    (current > 0 && current % 100 == 0 && current > keep).then_some(current - keep)
}

pub(super) async fn record(tx: &mut Transaction<'_, Sqlite>, head: &Head, keep: i64) -> Result<()> {
    insert(tx, head.cursor.epoch.0 as i64, head).await?;
    if let Some(floor) = cleanup_floor(head.cursor.epoch.0, keep) {
        sqlx::query("DELETE FROM node_epoch_tags WHERE epoch<?")
            .bind(floor)
            .execute(&mut **tx)
            .await
            .map_err(error)?;
    }
    Ok(())
}

impl CanonicalStore {
    /// Startup migration mirrors the native initial checkpoint tag. It never
    /// invents tags for every historical record retained by an older backend.
    pub(super) async fn initialize_epoch_tags(&self) -> Result<()> {
        let (head, state) = self.snapshot().await?;
        let mut tx = self.pool.begin().await.map_err(error)?;
        sqlx::query("UPDATE node_identity SET id=id WHERE id=0")
            .execute(&mut *tx)
            .await
            .map_err(error)?;
        let row = sqlx::query(
            "SELECT sequence,head,root FROM node_epochs ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(error)?;
        if decode_head(&row)? != head {
            return Err(error("canonical HEAD moved during tag migration"));
        }
        schema(&mut tx).await?;
        let empty: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM node_epoch_tags)")
            .fetch_one(&mut *tx)
            .await
            .map_err(error)?;
        if let Some(epoch) = initial_label(empty, state.get(&[b"meta", b"last_epoch"]))? {
            insert(&mut tx, epoch, &head).await?;
        }
        tx.commit().await.map_err(error)
    }
}

impl Reader {
    /// Local named-commit metadata, independent of whether services are Serving.
    /// SQLite has no pack collector: its pack capability fields are false/null.
    pub async fn epoch_tag_stats(&self) -> Result<EpochTagStats> {
        let row = sqlx::query("SELECT count(*) AS count,COALESCE(min(epoch),0) AS min_epoch,COALESCE(max(epoch),0) AS max_epoch FROM node_epoch_tags")
            .fetch_one(&self.pool).await.map_err(error)?;
        Ok(EpochTagStats {
            count: row.try_get("count").map_err(error)?,
            min_epoch: row.try_get("min_epoch").map_err(error)?,
            max_epoch: row.try_get("max_epoch").map_err(error)?,
            keep_epochs: self.epoch_tag_keep,
            split_epoch: None,
            gc_enabled: false,
            gc_running: false,
            gc_need: None,
        })
    }

    /// Authenticate a named tag against the retained immutable commit and root.
    /// A pruned tag is absent even when its immutable history remains readable.
    /// Native startup can label the current commit using legacy last_epoch
    /// metadata. The label alone is not proof of that canonical chain epoch.
    pub async fn epoch_tag(&self, epoch: i64) -> Result<Option<Head>> {
        let row = sqlx::query("SELECT n.sequence,n.head,n.root,t.commit_hash AS tag_commit,t.root AS tag_root FROM node_epoch_tags t JOIN node_epochs n ON n.sequence=t.sequence WHERE t.epoch=?")
            .bind(epoch).fetch_optional(&self.pool).await.map_err(error)?;
        let Some(row) = row else { return Ok(None) };
        let head = decode_head(&row)?;
        if row.try_get::<String, _>("tag_commit").map_err(error)? != head.irmin_commit
            || row.try_get::<Vec<u8>, _>("tag_root").map_err(error)?
                != hex_hash::<64>(&head.ledger_root)?
        {
            return Err(error("epoch tag commitment differs"));
        }
        Ok(Some(head))
    }
}

#[cfg(test)]
mod tests;
