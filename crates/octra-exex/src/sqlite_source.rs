//! Durable epoch source for hosts whose canonical state uses the same SQLite
//! database. The host must append an epoch in its chain-state transaction and
//! commit that transaction before calling `ExExManager::notify_commit`.
//!
//! This is a storage adapter, not a consensus or finality implementation. A
//! separate database would leave a crash window between chain state and this
//! outbox, so callers must pass their canonical transaction to `append`.

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};

use crate::{
    ChainIdentity, CommittedEpoch, CommittedEpochSource, Cursor, EpochId, Error, Result, Sequence,
    StateRoot,
};

pub struct SqliteEpochSource<E> {
    pool: SqlitePool,
    chain: ChainIdentity,
    anchor: Cursor,
    event: PhantomData<E>,
}

impl<E> SqliteEpochSource<E> {
    /// `pool` must point to the host's canonical SQLite database. The anchor
    /// is immutable once installed and identifies the cursor just before the
    /// first retained epoch.
    pub async fn open(pool: SqlitePool, chain: ChainIdentity, anchor: Cursor) -> Result<Self> {
        if chain.chain_id.is_empty() {
            return Err(Error::InvalidChain);
        }
        sqlx::query("CREATE TABLE IF NOT EXISTS exex_epoch_anchor (chain_id TEXT NOT NULL, genesis BLOB NOT NULL CHECK(length(genesis)=32), sequence TEXT NOT NULL, epoch TEXT NOT NULL, root BLOB NOT NULL CHECK(length(root)=32), PRIMARY KEY(chain_id, genesis))")
            .execute(&pool).await.map_err(store)?;
        sqlx::query("CREATE TABLE IF NOT EXISTS exex_committed_epoch (chain_id TEXT NOT NULL, genesis BLOB NOT NULL CHECK(length(genesis)=32), sequence TEXT NOT NULL CHECK(length(sequence)=16), epoch TEXT NOT NULL CHECK(length(epoch)=16), parent_root BLOB NOT NULL CHECK(length(parent_root)=32), root BLOB NOT NULL CHECK(length(root)=32), events BLOB NOT NULL, PRIMARY KEY(chain_id, genesis, sequence))")
            .execute(&pool).await.map_err(store)?;
        sqlx::query("INSERT INTO exex_epoch_anchor(chain_id,genesis,sequence,epoch,root) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING")
            .bind(&chain.chain_id).bind(chain.genesis_root.0.as_slice())
            .bind(hex_u64(anchor.sequence.0)).bind(hex_u64(anchor.epoch.0))
            .bind(anchor.state_root.0.as_slice())
            .execute(&pool).await.map_err(store)?;
        Self::open_existing(pool, chain, anchor).await
    }

    /// Reopen a previously initialized source without recreating missing tables
    /// or anchor rows. Canonical hosts use this to fail closed on lost history.
    pub async fn open_existing(
        pool: SqlitePool,
        chain: ChainIdentity,
        anchor: Cursor,
    ) -> Result<Self> {
        if chain.chain_id.is_empty() {
            return Err(Error::InvalidChain);
        }
        let row = sqlx::query(
            "SELECT sequence,epoch,root FROM exex_epoch_anchor WHERE chain_id=? AND genesis=?",
        )
        .bind(&chain.chain_id)
        .bind(chain.genesis_root.0.as_slice())
        .fetch_one(&pool)
        .await
        .map_err(store)?;
        if cursor_from_row(&row)? != anchor {
            return Err(Error::Store(
                "persisted epoch anchor differs from requested anchor".into(),
            ));
        }
        Ok(Self {
            pool,
            chain,
            anchor,
            event: PhantomData,
        })
    }
}

impl<E: Serialize> SqliteEpochSource<E> {
    /// Called after a canonical epoch has been authenticated and applied, but
    /// before the same host transaction commits. Duplicate, skipped, or
    /// divergent epochs fail closed. The caller owns commit and rollback.
    pub async fn append(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        epoch: &CommittedEpoch<E>,
    ) -> Result<()> {
        if epoch.chain != self.chain {
            return Err(Error::InvalidEvent(epoch.cursor.sequence));
        }
        let row = sqlx::query("SELECT sequence,epoch,root FROM exex_committed_epoch WHERE chain_id=? AND genesis=? ORDER BY sequence DESC LIMIT 1")
            .bind(&self.chain.chain_id).bind(self.chain.genesis_root.0.as_slice())
            .fetch_optional(&mut **tx).await.map_err(store)?;
        let head = row
            .as_ref()
            .map(cursor_from_row)
            .transpose()?
            .unwrap_or(self.anchor);
        if head.sequence.0.checked_add(1) != Some(epoch.cursor.sequence.0)
            || epoch.cursor.epoch <= head.epoch
            || epoch.parent_root != head.state_root
        {
            return Err(Error::InvalidEvent(epoch.cursor.sequence));
        }
        let events = serde_json::to_vec(&epoch.events).map_err(store)?;
        sqlx::query("INSERT INTO exex_committed_epoch(chain_id,genesis,sequence,epoch,parent_root,root,events) VALUES(?,?,?,?,?,?,?)")
            .bind(&self.chain.chain_id).bind(self.chain.genesis_root.0.as_slice())
            .bind(hex_u64(epoch.cursor.sequence.0)).bind(hex_u64(epoch.cursor.epoch.0))
            .bind(epoch.parent_root.0.as_slice()).bind(epoch.cursor.state_root.0.as_slice())
            .bind(events)
            .execute(&mut **tx).await.map_err(store)?;
        Ok(())
    }
}

#[async_trait]
impl<E: DeserializeOwned + Send + Sync + 'static> CommittedEpochSource<E> for SqliteEpochSource<E> {
    fn chain(&self) -> ChainIdentity {
        self.chain.clone()
    }

    async fn anchor(&self) -> Result<Cursor> {
        Ok(self.anchor)
    }

    async fn head(&self) -> Result<Cursor> {
        let row = sqlx::query("SELECT sequence,epoch,root FROM exex_committed_epoch WHERE chain_id=? AND genesis=? ORDER BY sequence DESC LIMIT 1")
            .bind(&self.chain.chain_id).bind(self.chain.genesis_root.0.as_slice())
            .fetch_optional(&self.pool).await.map_err(store)?;
        row.as_ref()
            .map(cursor_from_row)
            .transpose()
            .map(|c| c.unwrap_or(self.anchor))
    }

    async fn load(&self, sequence: Sequence) -> Result<Option<Arc<CommittedEpoch<E>>>> {
        let row = sqlx::query("SELECT sequence,epoch,parent_root,root,events FROM exex_committed_epoch WHERE chain_id=? AND genesis=? AND sequence=?")
            .bind(&self.chain.chain_id).bind(self.chain.genesis_root.0.as_slice())
            .bind(hex_u64(sequence.0))
            .fetch_optional(&self.pool).await.map_err(store)?;
        row.map(|row| {
            let cursor = cursor_from_row(&row)?;
            let parent_root = root_from_row(&row, "parent_root")?;
            let events: Vec<u8> = row.try_get("events").map_err(store)?;
            let events = serde_json::from_slice(&events).map_err(store)?;
            Ok(Arc::new(CommittedEpoch {
                chain: self.chain.clone(),
                cursor,
                parent_root,
                events,
            }))
        })
        .transpose()
    }
}

fn store(error: impl std::fmt::Display) -> Error {
    Error::Store(error.to_string())
}

fn hex_u64(value: u64) -> String {
    format!("{value:016x}")
}

fn parse_hex(value: &str) -> Result<u64> {
    if value.len() != 16
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::Store("invalid persisted epoch cursor".into()));
    }
    u64::from_str_radix(value, 16).map_err(store)
}

fn root_from_row(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<StateRoot> {
    let bytes: Vec<u8> = row.try_get(column).map_err(store)?;
    let bytes = bytes
        .try_into()
        .map_err(|_| Error::Store("invalid persisted root".into()))?;
    Ok(StateRoot(bytes))
}

fn cursor_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Cursor> {
    let sequence: String = row.try_get("sequence").map_err(store)?;
    let epoch: String = row.try_get("epoch").map_err(store)?;
    Ok(Cursor {
        sequence: Sequence(parse_hex(&sequence)?),
        epoch: EpochId(parse_hex(&epoch)?),
        state_root: root_from_row(row, "root")?,
    })
}
