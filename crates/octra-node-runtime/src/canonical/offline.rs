//! Stopped-store diagnostics without schema creation, repair or index backfill.
//! This checks local durable commitments, not independent chain authority.
use super::{error, CanonicalStore, Head, HeadCache, Reader, Result};
use crate::state_batch::{Snapshot, StateBatch};
use octra_exex::{
    native_history::NativeTransaction, sqlite_source::SqliteEpochSource, ChainIdentity, Sequence,
};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row,
};
use std::{path::Path, sync::Arc, time::Duration};

/// Only immutable captured state is exposed. In particular this type cannot
/// prepare a canonical write. The caller holds the node writer lock throughout
/// opening and capturing the stopped database (including an existing WAL).
pub struct OfflineStore {
    store: CanonicalStore,
    head: Head,
    state: StateBatch,
}

impl OfflineStore {
    pub async fn open(path: &Path) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(path)
                    .read_only(true)
                    .create_if_missing(false)
                    .pragma("query_only", "ON")
                    .busy_timeout(Duration::from_secs(10)),
            )
            .await
            .map_err(error)?;
        let row = sqlx::query("SELECT chain,anchor FROM node_identity WHERE id=0")
            .fetch_one(&pool)
            .await
            .map_err(error)?;
        let chain: ChainIdentity =
            serde_json::from_slice(row.try_get("chain").map_err(error)?).map_err(error)?;
        let anchor: Head =
            serde_json::from_slice(row.try_get("anchor").map_err(error)?).map_err(error)?;
        chain.validate().map_err(error)?;
        if anchor.cursor.sequence != Sequence(0) {
            return Err(error("canonical anchor sequence differs"));
        }
        chain
            .bind_checkpoint(anchor.cursor.epoch.0, anchor.cursor.state_root)
            .map_err(error)?;
        anchor.validate()?;
        let source = Arc::new(
            SqliteEpochSource::<NativeTransaction>::open_existing(
                pool.clone(),
                chain.clone(),
                anchor.cursor,
            )
            .await
            .map_err(error)?,
        );
        let store = CanonicalStore {
            pool,
            chain,
            anchor: anchor.clone(),
            bootstrap: None,
            source,
            head_cache: Arc::new(HeadCache::new(anchor)),
            snapshots: Arc::default(),
            // No epoch-tag query/backfill is performed by this diagnostic.
            epoch_tag_keep: 0,
        };
        store.verify_history().await?;
        let (head, state) = store.snapshot().await?;
        Ok(Self { store, head, state })
    }
    pub fn chain(&self) -> &ChainIdentity {
        self.store.chain()
    }
    pub fn head(&self) -> &Head {
        &self.head
    }
    pub fn anchor(&self) -> &Head {
        self.store.anchor()
    }
    pub fn state(&self) -> &StateBatch {
        &self.state
    }
    /// Historical reads retain the same verified local chain namespace; they
    /// do not independently authenticate a stored consensus certificate.
    pub fn reader(&self) -> Reader {
        self.store.reader()
    }
    pub async fn retained_head(&self, sequence: Sequence) -> Result<Head> {
        self.store.retained_head(sequence).await
    }
    pub async fn certificate(&self, sequence: Sequence) -> Result<Vec<u8>> {
        self.store.certificate(sequence).await
    }
    pub async fn sequence_for_epoch(&self, epoch: u64) -> Result<Option<Sequence>> {
        self.store.sequence_for_epoch(epoch).await
    }
    pub async fn snapshot_at(&self, head: &Head) -> Result<Snapshot> {
        self.reader().snapshot_at(head).await
    }
    /// Raw persisted authority evidence. Callers must authenticate it against
    /// their configured trust before signing/exporting a checkpoint.
    pub async fn checkpoint_certificate(&self) -> Result<Option<Vec<u8>>> {
        self.bootstrap_blob(false).await
    }
    /// Raw pre-floor finality window; never an in-memory bootstrap cache or a
    /// replacement for checking its complete authenticated parent chain.
    pub async fn checkpoint_window(&self) -> Result<Option<Vec<u8>>> {
        self.bootstrap_blob(true).await
    }
    async fn bootstrap_blob(&self, window: bool) -> Result<Option<Vec<u8>>> {
        let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='node_bootstrap')")
            .fetch_one(&self.store.pool).await.map_err(error)?;
        if !present {
            return Ok(None);
        }
        let (sql, limit) = if window {
            (
                "SELECT substr(roots,1,?) FROM node_bootstrap WHERE id=0",
                octra_node_protocol::state_sync::roots::MAX_FILE,
            )
        } else {
            (
                "SELECT substr(certificate,1,?) FROM node_bootstrap WHERE id=0",
                octra_node_protocol::state_sync::manifest::MANIFEST_LIMIT,
            )
        };
        let raw: Option<Vec<u8>> = sqlx::query_scalar(sql)
            .bind(i64::try_from(limit + 1).map_err(error)?)
            .fetch_optional(&self.store.pool)
            .await
            .map_err(error)?;
        if raw.as_ref().is_some_and(|bytes| bytes.len() > limit) {
            return Err(error("persisted checkpoint evidence exceeds byte limit"));
        }
        Ok(raw)
    }
    pub async fn close(self) {
        self.store.close().await;
    }
}
