//! Typed namespace metadata. Legacy Genesis rows remain readable in place;
//! checkpoint namespaces retain their explicit configured origin.
use crate::{ChainIdentity, Cursor, Error, Result};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
fn storage(error: impl std::fmt::Display) -> Error {
    Error::Store(error.to_string())
}
pub(crate) fn bind_cursor(chain: &ChainIdentity, cursor: Cursor) -> Result<()> {
    chain
        .bind_checkpoint(cursor.epoch.0, cursor.state_root)
        .map_err(storage)
}
pub(crate) async fn initialize(pool: &SqlitePool) -> Result<()> {
    sqlx::query("CREATE TABLE IF NOT EXISTS exex_origin(chain_id TEXT NOT NULL, namespace BLOB NOT NULL CHECK(length(namespace)=32), identity BLOB NOT NULL, PRIMARY KEY(chain_id,namespace))")
        .execute(pool).await.map_err(storage)?;
    Ok(())
}
pub(crate) async fn save(tx: &mut Transaction<'_, Sqlite>, chain: &ChainIdentity) -> Result<()> {
    chain.validate().map_err(storage)?;
    let raw = serde_json::to_vec(chain).map_err(storage)?;
    sqlx::query(
        "INSERT INTO exex_origin(chain_id,namespace,identity) VALUES(?,?,?) ON CONFLICT DO NOTHING",
    )
    .bind(&chain.chain_id)
    .bind(chain.namespace_key().as_slice())
    .bind(raw)
    .execute(&mut **tx)
    .await
    .map_err(storage)?;
    let row = sqlx::query("SELECT identity FROM exex_origin WHERE chain_id=? AND namespace=?")
        .bind(&chain.chain_id)
        .bind(chain.namespace_key().as_slice())
        .fetch_one(&mut **tx)
        .await
        .map_err(storage)?;
    matches(chain, row.try_get("identity").map_err(storage)?)
}
fn matches(chain: &ChainIdentity, raw: &[u8]) -> Result<()> {
    let actual: ChainIdentity = serde_json::from_slice(raw).map_err(storage)?;
    if &actual != chain {
        return Err(storage("persisted extension origin differs"));
    }
    Ok(())
}
pub(crate) async fn verify(pool: &SqlitePool, chain: &ChainIdentity) -> Result<()> {
    let table =
        sqlx::query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='exex_origin'")
            .fetch_optional(pool)
            .await
            .map_err(storage)?;
    let row = if table.is_some() {
        sqlx::query("SELECT identity FROM exex_origin WHERE chain_id=? AND namespace=?")
            .bind(&chain.chain_id)
            .bind(chain.namespace_key().as_slice())
            .fetch_optional(pool)
            .await
            .map_err(storage)?
    } else {
        None
    };
    match row {
        Some(row) => matches(chain, row.try_get("identity").map_err(storage)?),
        None if chain.genesis_root().is_some() => Ok(()),
        None => Err(storage("persisted checkpoint origin is missing")),
    }
}
