//! Durable discovery index fed by authenticated, successful Circle effects.
//! It never authorizes a funded session or changes canonical chain state.
use std::{path::Path, time::Duration};

use octra_exex::{ChainIdentity, CommittedEpoch, Cursor, ExEx};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    Row, SqlitePool,
};

use crate::{valid_address, valid_circle_id, OperatorRecord, EVENT_TOPIC, MAX_RECORD_BYTES};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircleEvent {
    pub circle: String,
    pub code_hash: String,
    pub topic: String,
    pub data: Vec<u8>,
}

#[derive(Serialize)]
struct Binding<'a> {
    chain: &'a ChainIdentity,
    code_hash: &'a str,
    anchor: Cursor,
}

#[derive(Clone)]
pub struct RegistryProjection {
    pool: SqlitePool,
    domain: String,
    circle: String,
    code_hash: String,
    name: String,
    chain: ChainIdentity,
}

fn error(value: impl std::fmt::Display) -> String {
    value.to_string()
}

impl RegistryProjection {
    pub async fn open(
        path: &Path,
        chain: ChainIdentity,
        circle: String,
        code_hash: String,
        anchor: Cursor,
    ) -> Result<Self, String> {
        if chain.chain_id.is_empty()
            || !valid_circle_id(&circle)
            || code_hash.len() != 64
            || !code_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid registry binding".into());
        }
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
            .map_err(error)?;
        sqlx::query("CREATE TABLE IF NOT EXISTS vpn_registry_projection (domain TEXT NOT NULL,circle TEXT NOT NULL,binding TEXT NOT NULL,head TEXT NOT NULL,batch_hash BLOB NOT NULL,PRIMARY KEY(domain,circle))")
            .execute(&pool).await.map_err(error)?;
        sqlx::query("CREATE TABLE IF NOT EXISTS vpn_registry_offer (domain TEXT NOT NULL,circle TEXT NOT NULL,operator TEXT NOT NULL,record BLOB NOT NULL,PRIMARY KEY(domain,circle,operator))")
            .execute(&pool).await.map_err(error)?;
        let domain = serde_json::to_string(&chain).map_err(error)?;
        let binding = serde_json::to_string(&Binding {
            chain: &chain,
            code_hash: &code_hash,
            anchor,
        })
        .map_err(error)?;
        sqlx::query("INSERT INTO vpn_registry_projection(domain,circle,binding,head,batch_hash) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING")
            .bind(&domain).bind(&circle).bind(&binding).bind(serde_json::to_string(&anchor).map_err(error)?)
            .bind(Vec::<u8>::new())
            .execute(&pool).await.map_err(error)?;
        let saved: String =
            sqlx::query("SELECT binding FROM vpn_registry_projection WHERE domain=? AND circle=?")
                .bind(&domain)
                .bind(&circle)
                .fetch_one(&pool)
                .await
                .map_err(error)?
                .try_get("binding")
                .map_err(error)?;
        if saved != binding {
            return Err(
                "registry binding or replay anchor changed; explicit migration required".into(),
            );
        }
        let name = format!("vpn-registry/{circle}");
        Ok(Self {
            pool,
            domain,
            circle,
            code_hash,
            name,
            chain,
        })
    }

    pub async fn head(&self) -> Result<Cursor, String> {
        let head: String =
            sqlx::query("SELECT head FROM vpn_registry_projection WHERE domain=? AND circle=?")
                .bind(&self.domain)
                .bind(&self.circle)
                .fetch_one(&self.pool)
                .await
                .map_err(error)?
                .try_get("head")
                .map_err(error)?;
        serde_json::from_str(&head).map_err(error)
    }

    pub async fn operator(&self, operator: &str) -> Result<Option<OperatorRecord>, String> {
        if !valid_address(operator) {
            return Err("invalid operator address".into());
        }
        let row = sqlx::query(
            "SELECT record FROM vpn_registry_offer WHERE domain=? AND circle=? AND operator=?",
        )
        .bind(&self.domain)
        .bind(&self.circle)
        .bind(operator)
        .fetch_optional(&self.pool)
        .await
        .map_err(error)?;
        row.map(|row| {
            let data: Vec<u8> = row.try_get("record").map_err(error)?;
            serde_json::from_slice(&data).map_err(error)
        })
        .transpose()
    }

    async fn apply(&self, epoch: &CommittedEpoch<CircleEvent>) -> Result<(), String> {
        if epoch.chain != self.chain {
            return Err("registry event chain mismatch".into());
        }
        let mut tx = self.pool.begin().await.map_err(error)?;
        let row = sqlx::query(
            "SELECT head,batch_hash FROM vpn_registry_projection WHERE domain=? AND circle=?",
        )
        .bind(&self.domain)
        .bind(&self.circle)
        .fetch_one(&mut *tx)
        .await
        .map_err(error)?;
        let stored: String = row.try_get("head").map_err(error)?;
        let batch_hash = Sha256::digest(serde_json::to_vec(epoch).map_err(error)?).to_vec();
        let head: Cursor = serde_json::from_str(&stored).map_err(error)?;
        if epoch.cursor == head {
            let saved_hash: Vec<u8> = row.try_get("batch_hash").map_err(error)?;
            return if saved_hash == batch_hash {
                Ok(())
            } else {
                Err("registry replay payload differs".into())
            };
        } // Sink commit can precede ExEx checkpoint; only the identical batch is idempotent.
        if head.sequence.0.checked_add(1) != Some(epoch.cursor.sequence.0)
            || epoch.parent_root != head.state_root
            || epoch.cursor.epoch <= head.epoch
        {
            return Err("registry projection history mismatch; explicit resync required".into());
        }
        for event in &epoch.events {
            if event.circle != self.circle || event.topic != EVENT_TOPIC {
                continue;
            }
            if event.code_hash != self.code_hash || event.data.len() > MAX_RECORD_BYTES {
                return Err("registry code or event size mismatch".into());
            }
            let record: OperatorRecord = serde_json::from_slice(&event.data).map_err(error)?;
            if !valid_address(&record.operator) || record.updated_epoch != epoch.cursor.epoch.0 {
                return Err("invalid registry event identity or epoch".into());
            }
            record.offer.validate().map_err(error)?;
            let previous = sqlx::query(
                "SELECT record FROM vpn_registry_offer WHERE domain=? AND circle=? AND operator=?",
            )
            .bind(&self.domain)
            .bind(&self.circle)
            .bind(&record.operator)
            .fetch_optional(&mut *tx)
            .await
            .map_err(error)?;
            let revision = previous
                .map(|row| -> Result<u64, String> {
                    let data: Vec<u8> = row.try_get("record").map_err(error)?;
                    let previous: OperatorRecord = serde_json::from_slice(&data).map_err(error)?;
                    if previous.operator != record.operator {
                        return Err("stored registry identity mismatch".into());
                    }
                    Ok(previous.revision)
                })
                .transpose()?
                .unwrap_or(0);
            if revision.checked_add(1) != Some(record.revision) {
                return Err("registry event revision mismatch".into());
            }
            sqlx::query("INSERT INTO vpn_registry_offer(domain,circle,operator,record) VALUES(?,?,?,?) ON CONFLICT(domain,circle,operator) DO UPDATE SET record=excluded.record")
                .bind(&self.domain).bind(&self.circle).bind(&record.operator).bind(&event.data)
                .execute(&mut *tx).await.map_err(error)?;
        }
        let changed = sqlx::query("UPDATE vpn_registry_projection SET head=?,batch_hash=? WHERE domain=? AND circle=? AND head=?")
            .bind(serde_json::to_string(&epoch.cursor).map_err(error)?).bind(batch_hash).bind(&self.domain).bind(&self.circle).bind(stored)
            .execute(&mut *tx).await.map_err(error)?;
        if changed.rows_affected() != 1 {
            return Err("registry projection writer conflict".into());
        }
        tx.commit().await.map_err(error)
    }
}

impl ExEx<CircleEvent> for RegistryProjection {
    fn name(&self) -> &str {
        &self.name
    }
    async fn on_epoch(&mut self, epoch: &CommittedEpoch<CircleEvent>) -> Result<(), String> {
        self.apply(epoch).await
    }
}
