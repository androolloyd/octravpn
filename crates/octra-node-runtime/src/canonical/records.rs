// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Auxiliary Program records share the local database, without entering the
//! ledger tree, canonical history, certificates or the ExEx outbox.
use super::CanonicalStore;
use octra_node_protocol::{
    aml::rpc::verification::Verified,
    program_record::{self, Record},
    transaction::is_valid_address,
};
use sqlx::{Sqlite, SqlitePool, Transaction};
#[derive(Clone)]
pub struct ProgramRecords {
    pool: SqlitePool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordError {
    Conflict,
    Invalid(Vec<u8>),
    Unavailable(String),
}
impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict => f.write_str("program record differs"),
            Self::Invalid(reason) => write!(f, "{}", String::from_utf8_lossy(reason)),
            Self::Unavailable(reason) => f.write_str(reason),
        }
    }
}
impl std::error::Error for RecordError {}
type Result<T> = std::result::Result<T, RecordError>;
fn unavailable(error: impl std::fmt::Display) -> RecordError {
    RecordError::Unavailable(error.to_string())
}
fn invalid(reason: &[u8]) -> RecordError {
    RecordError::Invalid(reason.to_vec())
}
fn decode(raw: &[u8]) -> Result<Record> {
    Record::decode(raw).map_err(|error| match error {
        program_record::Error::Invalid(reason) => RecordError::Invalid(reason),
        program_record::Error::Unavailable(error) => unavailable(error),
    })
}
impl CanonicalStore {
    pub fn program_records(&self) -> ProgramRecords {
        ProgramRecords {
            pool: self.pool.clone(),
        }
    }
}
impl ProgramRecords {
    pub async fn get(&self, address: &[u8], code_hash: &[u8]) -> Result<Option<Record>> {
        let exists: i64 = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='node_program_records')")
            .fetch_one(&self.pool).await.map_err(unavailable)?;
        if exists == 0 {
            return Ok(None);
        }
        let mut raw: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT raw FROM node_program_records WHERE key=?")
                .bind(program_record::key(address, Some(code_hash)))
                .fetch_optional(&self.pool)
                .await
                .map_err(unavailable)?;
        if raw.is_none() {
            raw = sqlx::query_scalar("SELECT raw FROM node_program_records WHERE key=?")
                .bind(program_record::key(address, None))
                .fetch_optional(&self.pool)
                .await
                .map_err(unavailable)?;
        }
        match raw {
            None => Ok(None),
            Some(raw) => {
                let record = decode(&raw)?;
                Ok((record.code_hash == code_hash).then_some(record))
            }
        }
    }
    pub async fn save(&self, verified: &Verified) -> Result<Record> {
        let address = verified.address();
        let record = verified.record();
        if !is_valid_address(address) {
            return Err(invalid(b"program record address is invalid"));
        }
        if !program_record::valid_hash(&record.code_hash) {
            return Err(invalid(b"program record hash is invalid"));
        }
        if !verified.publishable() {
            return Err(unavailable(
                "only source-admitted Program records may be published",
            ));
        }
        sqlx::query("CREATE TABLE IF NOT EXISTS node_program_records(key BLOB PRIMARY KEY, raw BLOB NOT NULL) WITHOUT ROWID")
            .execute(&self.pool).await.map_err(unavailable)?;
        // Acquire the write lock before reading either native key. Concurrent
        // publication cannot turn a checked absence into an overwrite.
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(unavailable)?;
        let key = program_record::key(address, Some(&record.code_hash));
        let raw = read(&mut tx, &key).await?;
        let existing = match raw {
            Some(raw) => {
                let existing = decode(&raw)?;
                if existing.code_hash != record.code_hash {
                    return Err(invalid(b"program record hash differs"));
                }
                Some(existing)
            }
            None => match read(&mut tx, &program_record::key(address, None)).await? {
                None => None,
                Some(raw) => {
                    let existing = decode(&raw)?;
                    (existing.code_hash == record.code_hash).then_some(existing)
                }
            },
        };
        if let Some(existing) = existing {
            if existing != *record {
                return Err(RecordError::Conflict);
            }
            tx.commit().await.map_err(unavailable)?;
            return Ok(existing);
        }
        sqlx::query("INSERT INTO node_program_records(key,raw) VALUES(?,?)")
            .bind(&key)
            .bind(record.encode())
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        let saved = read(&mut tx, &key)
            .await?
            .ok_or_else(|| invalid(b"program record read missing"))?;
        let saved = decode(&saved)?;
        if saved != *record {
            return Err(invalid(b"program record read differs"));
        }
        tx.commit().await.map_err(unavailable)?;
        Ok(saved)
    }
}
async fn read(tx: &mut Transaction<'_, Sqlite>, key: &[u8]) -> Result<Option<Vec<u8>>> {
    sqlx::query_scalar("SELECT raw FROM node_program_records WHERE key=?")
        .bind(key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)
}
