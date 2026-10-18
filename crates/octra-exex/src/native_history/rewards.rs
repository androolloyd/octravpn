//! Local native-header compatibility metadata. Separate from modern canonical
//! history and its mandatory finality/reward record. All writes share the outbox
//! transaction; no returned source authenticates a QC or a remote epoch.
use super::{hash, invalid, legacy, reward, NativeEpoch, NativeEpochSource, Result, RewardSource};
use crate::{ChainIdentity, CommittedEpochSource, Sequence};
use octra_node_protocol::{epoch_index, oce1::Writer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};

/// Implemented by a trusted host's historical policy/validator resolver. Values
/// must come independently of the exported header, not from reward recipients.
pub trait HistoricalRewardAuthority {
    fn for_epoch(&self, epoch: u64) -> Result<legacy::Authority>;
}
impl<F: Fn(u64) -> Result<legacy::Authority>> HistoricalRewardAuthority for F {
    fn for_epoch(&self, epoch: u64) -> Result<legacy::Authority> {
        self(epoch)
    }
}

#[derive(Clone, Debug)]
pub(super) struct Evidence {
    header_hash: [u8; 32],
    source: Vec<u8>,
}
fn wire(source: &RewardSource) -> Result<Vec<u8>> {
    let mut writer = Writer::new();
    reward::put(&mut writer, source).map_err(invalid)?;
    Ok(writer.into_bytes())
}
impl Evidence {
    pub(super) fn validate_header(&self, raw: &[u8]) -> Result<()> {
        if Sha256::digest(raw).as_slice() != self.header_hash {
            return Err(invalid("native epoch header hash differs"));
        }
        Ok(())
    }
}

fn bound_header(epoch: &NativeEpoch) -> Result<legacy::DecodedHeader> {
    let raw = epoch
        .epoch_header
        .as_ref()
        .ok_or_else(|| invalid("native epoch header missing"))?;
    // Native Epochlog bounds each record at 16 MiB, independently of the page.
    if raw.len() > 16 * 1024 * 1024 {
        return Err(invalid("native epoch header exceeds record limit"));
    }
    let header =
        legacy::DecodedHeader::parse(raw).ok_or_else(|| invalid("invalid native epoch header"))?;
    if u64::try_from(header.reward.epoch.get()).ok() != Some(epoch.boundary.epoch)
        || header.state_root != epoch.boundary.state_root.as_bytes()
        || header.previous_root != epoch.parent_root.as_bytes()
        || header.parent_commit != epoch.parent_commit.as_bytes()
        || header.start_txid != epoch.start_txid
        || usize::try_from(header.transaction_count.get()).ok() != Some(epoch.transactions.len())
    {
        return Err(invalid(
            "native epoch header differs from exported boundary",
        ));
    }
    Ok(header)
}

pub(super) fn derive(
    epoch: &NativeEpoch,
    authority: &impl HistoricalRewardAuthority,
) -> Result<Option<Evidence>> {
    let Some(raw) = &epoch.epoch_header else {
        return Ok(None);
    };
    let header = bound_header(epoch)?;
    let source = authority
        .for_epoch(epoch.boundary.epoch)?
        .source(&header.reward)
        .map_err(invalid)?;
    Ok(Some(Evidence {
        header_hash: Sha256::digest(raw).into(),
        source: wire(&source)?,
    }))
}

pub(super) async fn initialize(pool: &SqlitePool) -> Result<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.map_err(invalid)?;
    let tracked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='exex_native_export_version')")
        .fetch_one(&mut *tx).await.map_err(invalid)?;
    if !tracked {
        let rewards: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='exex_native_reward')")
            .fetch_one(&mut *tx).await.map_err(invalid)?;
        if rewards {
            return Err(invalid("native reward export version table missing"));
        }
    }
    sqlx::query("CREATE TABLE IF NOT EXISTS exex_native_export_version (chain_id TEXT NOT NULL, genesis BLOB NOT NULL, sequence TEXT NOT NULL, version INTEGER NOT NULL CHECK(version IN (1,2)), PRIMARY KEY(chain_id,genesis,sequence))").execute(&mut *tx).await.map_err(invalid)?;
    sqlx::query("CREATE TABLE IF NOT EXISTS exex_native_reward (chain_id TEXT NOT NULL, genesis BLOB NOT NULL, sequence TEXT NOT NULL, binding BLOB NOT NULL, header BLOB NOT NULL, header_hash BLOB NOT NULL CHECK(length(header_hash)=32), source BLOB NOT NULL, PRIMARY KEY(chain_id,genesis,sequence))").execute(&mut *tx).await.map_err(invalid)?;
    if !tracked {
        // Only the first schema installation can classify pre-feature native
        // outboxes as v1. Never heal a missing marker during an ordinary reopen.
        sqlx::query("INSERT INTO exex_native_export_version(chain_id,genesis,sequence,version) SELECT e.chain_id,e.genesis,e.sequence,1 FROM exex_committed_epoch e INNER JOIN exex_native_binding n ON n.chain_id=e.chain_id AND n.genesis=e.genesis")
            .execute(&mut *tx).await.map_err(invalid)?;
    }
    tx.commit().await.map_err(invalid)?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    previous: super::NativeBoundary,
    boundary: super::NativeBoundary,
    parent_root: String,
    parent_commit: String,
    start_txid: i64,
}

pub(super) async fn append(
    tx: &mut Transaction<'_, Sqlite>,
    chain: &ChainIdentity,
    sequence: Sequence,
    previous: &super::NativeBoundary,
    epoch: &NativeEpoch,
) -> Result<()> {
    let version = if epoch.rewards.is_some() { 2_i64 } else { 1 };
    let sequence = format!("{:016x}", sequence.0);
    sqlx::query(
        "INSERT INTO exex_native_export_version(chain_id,genesis,sequence,version) VALUES(?,?,?,?)",
    )
    .bind(&chain.chain_id)
    .bind(chain.namespace_key().as_slice())
    .bind(&sequence)
    .bind(version)
    .execute(&mut **tx)
    .await
    .map_err(invalid)?;
    if let Some(evidence) = &epoch.rewards {
        let binding = Binding {
            previous: previous.clone(),
            boundary: epoch.boundary.clone(),
            parent_root: epoch.parent_root.clone(),
            parent_commit: epoch.parent_commit.clone(),
            start_txid: epoch.start_txid,
        };
        sqlx::query("INSERT INTO exex_native_reward(chain_id,genesis,sequence,binding,header,header_hash,source) VALUES(?,?,?,?,?,?,?)").bind(&chain.chain_id).bind(chain.namespace_key().as_slice()).bind(sequence).bind(serde_json::to_vec(&binding).map_err(invalid)?).bind(epoch.epoch_header.as_ref().ok_or_else(|| invalid("native reward header missing"))?).bind(evidence.header_hash.as_slice()).bind(&evidence.source).execute(&mut **tx).await.map_err(invalid)?;
    }
    Ok(())
}

pub(super) async fn load(
    source: &NativeEpochSource,
    sequence: Sequence,
    authority: &impl HistoricalRewardAuthority,
) -> Result<Option<RewardSource>> {
    // One read transaction pins metadata and its outbox boundary together.
    let chain = source.source.chain();
    let mut tx = source.pool.begin().await.map_err(invalid)?;
    let key = format!("{:016x}", sequence.0);
    let version: Option<i64> = sqlx::query_scalar("SELECT version FROM exex_native_export_version WHERE chain_id=? AND genesis=? AND sequence=?").bind(&chain.chain_id).bind(chain.namespace_key().as_slice()).bind(&key).fetch_optional(&mut *tx).await.map_err(invalid)?;
    let metadata = sqlx::query("SELECT binding,header,header_hash,source FROM exex_native_reward WHERE chain_id=? AND genesis=? AND sequence=?").bind(&chain.chain_id).bind(chain.namespace_key().as_slice()).bind(&key).fetch_optional(&mut *tx).await.map_err(invalid)?;
    if version.is_none() {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM exex_committed_epoch WHERE chain_id=? AND genesis=? AND sequence=?)")
            .bind(&chain.chain_id).bind(chain.namespace_key().as_slice()).bind(&key)
            .fetch_one(&mut *tx).await.map_err(invalid)?;
        if exists || metadata.is_some() {
            return Err(invalid("native reward export version missing"));
        }
        return Ok(None);
    }
    if version == Some(1) {
        if metadata.is_some() {
            return Err(invalid("unexpected native reward metadata"));
        }
        return Ok(None);
    }
    if version != Some(2) {
        return Err(invalid("invalid native reward export version"));
    }
    let row = metadata.ok_or_else(|| invalid("native v2 reward metadata missing"))?;
    let raw: Vec<u8> = row.try_get("header").map_err(invalid)?;
    let digest: Vec<u8> = row.try_get("header_hash").map_err(invalid)?;
    if Sha256::digest(&raw).as_slice() != digest {
        return Err(invalid("native epoch header hash differs"));
    }
    let encoded: Vec<u8> = row.try_get("binding").map_err(invalid)?;
    let binding: Binding = serde_json::from_slice(&encoded).map_err(invalid)?;
    binding.previous.validate()?;
    if binding.previous.epoch.checked_add(1) != Some(binding.boundary.epoch)
        || binding.previous.state_root != binding.parent_root
        || binding.previous.irmin_commit != binding.parent_commit
        || binding.previous.txid_hi.checked_add(1) != Some(binding.start_txid)
    {
        return Err(invalid("native reward predecessor binding differs"));
    }
    let outbox = sqlx::query("SELECT epoch,parent_root,root,events FROM exex_committed_epoch WHERE chain_id=? AND genesis=? AND sequence=?").bind(&chain.chain_id).bind(chain.namespace_key().as_slice()).bind(&key).fetch_one(&mut *tx).await.map_err(invalid)?;
    let epoch_id: String = outbox.try_get("epoch").map_err(invalid)?;
    let parent: Vec<u8> = outbox.try_get("parent_root").map_err(invalid)?;
    let root: Vec<u8> = outbox.try_get("root").map_err(invalid)?;
    if epoch_id != format!("{:016x}", binding.boundary.epoch)
        || parent != hash(&binding.parent_root)?.0
        || root != binding.boundary.validate()?.0
    {
        return Err(invalid("native reward binding differs from outbox"));
    }
    let events: Vec<u8> = outbox.try_get("events").map_err(invalid)?;
    let epoch = NativeEpoch {
        boundary: binding.boundary,
        parent_root: binding.parent_root,
        parent_commit: binding.parent_commit,
        start_txid: binding.start_txid,
        transactions: serde_json::from_slice(&events).map_err(invalid)?,
        epoch_header: Some(raw),
        rewards: None,
    };
    let decoded = bound_header(&epoch)?;
    let count = i64::try_from(epoch.transactions.len()).map_err(invalid)?;
    if epoch
        .start_txid
        .checked_add(count)
        .and_then(|value| value.checked_sub(1))
        != Some(epoch.boundary.txid_hi)
    {
        return Err(invalid("native reward transaction range differs"));
    }
    for (index, event) in epoch.transactions.iter().enumerate() {
        if event.txid != epoch.start_txid + index as i64 {
            return Err(invalid("native reward transaction order differs"));
        }
        event.validate()?;
    }
    let items = epoch
        .transactions
        .iter()
        .map(|event| {
            Ok(epoch_index::Item {
                txid: event.txid,
                hash: hash(&event.hash)?.0.to_vec(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let (index_hash, index_root) = epoch_index::next_root(
        binding.previous.index_root.as_bytes(),
        epoch.boundary.epoch as i64,
        &items,
    )
    .map_err(invalid)?;
    if index_hash != hash(&epoch.boundary.index_hash)?.0
        || index_root != hash(&epoch.boundary.index_root)?.0
    {
        return Err(invalid("native reward transaction commitment differs"));
    }
    let resolved = authority
        .for_epoch(epoch.boundary.epoch)?
        .source(&decoded.reward)
        .map_err(invalid)?;
    let saved: Vec<u8> = row.try_get("source").map_err(invalid)?;
    if wire(&resolved)? != saved {
        return Err(invalid(
            "native reward source differs from historical authority",
        ));
    }
    Ok(Some(resolved))
}
