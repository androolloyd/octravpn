//! Persistent, chain-scoped compare-and-swap checkpoints for execution extensions.
//! This stores consumer progress. The host still owns canonical committed history.
use crate::{ChainIdentity, CheckpointStore, Cursor, EpochId, Error, Result, Sequence, StateRoot};
use async_trait::async_trait;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    Row, SqlitePool,
};
use std::{path::Path, time::Duration};

#[derive(Clone)]
pub struct SqliteCheckpoints {
    pool: SqlitePool,
}

impl SqliteCheckpoints {
    pub async fn open(path: &Path) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await
            .map_err(|e| Error::Store(e.to_string()))?;
        sqlx::query("CREATE TABLE IF NOT EXISTS exex_checkpoint (chain_id TEXT NOT NULL, genesis BLOB NOT NULL CHECK(length(genesis)=32), extension TEXT NOT NULL, sequence TEXT NOT NULL, epoch TEXT NOT NULL, root BLOB NOT NULL CHECK(length(root)=32), PRIMARY KEY(chain_id, genesis, extension))")
            .execute(&pool).await.map_err(|e| Error::Store(e.to_string()))?;
        Ok(Self { pool })
    }
    pub async fn close(self) {
        self.pool.close().await;
    }
}

#[async_trait]
impl CheckpointStore for SqliteCheckpoints {
    async fn load(&self, chain: &ChainIdentity, extension: &str) -> Result<Option<Cursor>> {
        let row = sqlx::query("SELECT sequence, epoch, root FROM exex_checkpoint WHERE chain_id=? AND genesis=? AND extension=?")
            .bind(&chain.chain_id).bind(chain.genesis_root.0.as_slice()).bind(extension)
            .fetch_optional(&self.pool).await.map_err(|e| Error::Store(e.to_string()))?;
        row.map(|r| {
            let sequence: String = r
                .try_get("sequence")
                .map_err(|e| Error::Store(e.to_string()))?;
            let epoch: String = r
                .try_get("epoch")
                .map_err(|e| Error::Store(e.to_string()))?;
            let root: Vec<u8> = r.try_get("root").map_err(|e| Error::Store(e.to_string()))?;
            let parse = |s: &str| -> Result<u64> {
                let n: u64 = s
                    .parse()
                    .map_err(|_| Error::Store("invalid persisted cursor".into()))?;
                if n.to_string() != s {
                    return Err(Error::Store("non-canonical persisted cursor".into()));
                }
                Ok(n)
            };
            Ok(Cursor {
                sequence: Sequence(parse(&sequence)?),
                epoch: EpochId(parse(&epoch)?),
                state_root: StateRoot(
                    root.try_into()
                        .map_err(|_| Error::Store("invalid persisted root".into()))?,
                ),
            })
        })
        .transpose()
    }
    async fn compare_and_save(
        &self,
        chain: &ChainIdentity,
        extension: &str,
        expected: Option<Cursor>,
        next: Cursor,
    ) -> Result<()> {
        let changed = if let Some(expected) = expected {
            sqlx::query("UPDATE exex_checkpoint SET sequence=?, epoch=?, root=? WHERE chain_id=? AND genesis=? AND extension=? AND sequence=? AND epoch=? AND root=?")
                .bind(next.sequence.0.to_string()).bind(next.epoch.0.to_string()).bind(next.state_root.0.as_slice())
                .bind(&chain.chain_id).bind(chain.genesis_root.0.as_slice()).bind(extension)
                .bind(expected.sequence.0.to_string()).bind(expected.epoch.0.to_string()).bind(expected.state_root.0.as_slice())
                .execute(&self.pool).await
        } else {
            sqlx::query("INSERT INTO exex_checkpoint(chain_id,genesis,extension,sequence,epoch,root) VALUES(?,?,?,?,?,?) ON CONFLICT DO NOTHING")
                .bind(&chain.chain_id).bind(chain.genesis_root.0.as_slice()).bind(extension)
                .bind(next.sequence.0.to_string()).bind(next.epoch.0.to_string()).bind(next.state_root.0.as_slice())
                .execute(&self.pool).await
        }.map_err(|e| Error::Store(e.to_string()))?;
        if changed.rows_affected() != 1 {
            return Err(Error::Store("checkpoint compare-and-swap conflict".into()));
        }
        Ok(())
    }
}
