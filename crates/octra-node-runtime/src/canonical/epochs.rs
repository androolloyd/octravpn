//! Auxiliary native epoch observations retained in the canonical transaction.
//! Reads rebind metadata to the retained QC, index, outbox and reward source.
use super::{error, transactions, Head, PreparedCommit, Reader, Result};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use octra_exex::Sequence;
use octra_node_protocol::{
    consensus::{codec::Wire, qc, reward, reward_attribution, Finalize, ValidatorSet},
    epoch_journal::{self, Observation, Summary},
    epoch_page, oce1,
};
use sha2::{Digest, Sha256};
use sqlx::Row as _;

fn checksum(raw: &[u8], legacy: Option<&[u8]>) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"octra:local-epoch-journal:v1\0");
    hash.update((raw.len() as u64).to_be_bytes());
    hash.update(raw);
    hash.update([u8::from(legacy.is_some())]);
    if let Some(legacy) = legacy {
        hash.update(legacy);
    }
    hash.finalize().to_vec()
}

impl PreparedCommit {
    pub(crate) async fn retain_epoch_observation(
        &mut self,
        finalized: &Finalize,
        validators: &ValidatorSet,
        observation: &Observation,
    ) -> Result<()> {
        observation.validate().map_err(error)?;
        if finalized.epoch_id as u64 != self.head.cursor.epoch.0
            || finalized.header.proposed_state_root != self.head.cursor.state_root.0
            || finalized.header.ts.to_bits() != observation.finalized_at.to_bits()
        {
            return Err(error("epoch observation differs from finality"));
        }
        let raw = serde_json::to_vec(observation).map_err(error)?;
        if raw.len() > epoch_journal::MAX_RECORD {
            return Err(error("epoch observation exceeds record limit"));
        }
        sqlx::query("CREATE TABLE IF NOT EXISTS node_epoch_journal(sequence INTEGER PRIMARY KEY REFERENCES node_epochs(sequence),observation BLOB NOT NULL,digest BLOB NOT NULL,validators BLOB NOT NULL,certificate_hash BLOB NOT NULL,legacy_digest BLOB)")
            .execute(&mut *self.transaction).await.map_err(error)?;
        sqlx::query("INSERT INTO node_epoch_journal VALUES(?,?,?,?,?,NULL)")
            .bind(self.head.cursor.sequence.0 as i64)
            .bind(&raw)
            .bind(checksum(&raw, None))
            .bind(validators.encode().map_err(error)?)
            .bind(Sha256::digest(finalized.encode().map_err(error)?).to_vec())
            .execute(&mut *self.transaction)
            .await
            .map_err(error)?;
        Ok(())
    }
    /// The node's legacy Tree observer supplies its exact finalized digest.
    /// This is local journal metadata, never a new consensus commitment.
    pub async fn retain_epoch_legacy_digest(&mut self, digest: Option<&[u8]>) -> Result<()> {
        let Some(digest) = digest else {
            return Ok(());
        };
        if !epoch_page::hex(digest) || digest.len() != 64 {
            return Err(error("invalid legacy epoch digest"));
        }
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='node_epoch_journal')")
            .fetch_one(&mut *self.transaction).await.map_err(error)?;
        if !exists {
            return Ok(());
        }
        let row=sqlx::query("SELECT substr(observation,1,?) AS observation,digest,legacy_digest FROM node_epoch_journal WHERE sequence=?")
            .bind(epoch_journal::MAX_RECORD as i64+1).bind(self.head.cursor.sequence.0 as i64).fetch_optional(&mut *self.transaction).await.map_err(error)?;
        let Some(row) = row else {
            return Ok(());
        };
        let raw: Vec<u8> = row.try_get("observation").map_err(error)?;
        let prior: Option<Vec<u8>> = row.try_get("legacy_digest").map_err(error)?;
        if raw.len() > epoch_journal::MAX_RECORD
            || row.try_get::<Vec<u8>, _>("digest").map_err(error)?
                != checksum(&raw, prior.as_deref())
            || prior.as_ref().is_some_and(|prior| prior != digest)
        {
            return Err(error("conflicting legacy epoch material"));
        }
        sqlx::query("UPDATE node_epoch_journal SET legacy_digest=?,digest=? WHERE sequence=?")
            .bind(digest)
            .bind(checksum(&raw, Some(digest)))
            .bind(self.head.cursor.sequence.0 as i64)
            .execute(&mut *self.transaction)
            .await
            .map_err(error)?;
        Ok(())
    }
}
struct Entry {
    head: Head,
    parent: Head,
    finalized: Finalize,
    source: octra_node_protocol::consensus::RewardSource,
    observation: Observation,
    legacy: Option<Vec<u8>>,
}
impl Reader {
    async fn epoch_entry(&self, captured: &Head, epoch: i64) -> Result<Option<Entry>> {
        if self.head_at(captured.cursor.sequence).await? != *captured {
            return Err(error("epoch journal captured head differs"));
        }
        let Ok(epoch) = u64::try_from(epoch) else {
            return Ok(None);
        };
        if epoch <= self.anchor().epoch.0 || epoch > captured.cursor.epoch.0 {
            return Ok(None);
        }
        let Some(head) = self.head_for_epoch_opt(epoch).await? else {
            return Ok(None);
        };
        let parent = self
            .head_at(Sequence(
                head.cursor
                    .sequence
                    .0
                    .checked_sub(1)
                    .ok_or_else(|| error("epoch parent underflow"))?,
            ))
            .await?;
        let present:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='node_epoch_journal')")
            .fetch_one(&self.pool).await.map_err(error)?;
        if !present {
            return Ok(None);
        }
        let row=sqlx::query("SELECT substr(j.observation,1,?) AS observation,length(j.observation) AS observation_size,substr(j.digest,1,33) AS digest,substr(j.validators,1,1000001) AS validators,substr(j.certificate_hash,1,33) AS certificate_hash,substr(j.legacy_digest,1,65) AS legacy_digest,substr(n.certificate,1,33554433) AS certificate,substr(r.proposal,1,33) AS proposal,substr(r.source,1,4000001) AS source FROM node_epoch_journal j JOIN node_epochs n USING(sequence) LEFT JOIN node_epoch_rewards r USING(sequence) WHERE j.sequence=?")
            .bind(epoch_journal::MAX_RECORD as i64+1).bind(head.cursor.sequence.0 as i64).fetch_optional(&self.pool).await.map_err(error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let raw: Vec<u8> = row.try_get("observation").map_err(error)?;
        let legacy: Option<Vec<u8>> = row.try_get("legacy_digest").map_err(error)?;
        if raw.len() > epoch_journal::MAX_RECORD
            || row.try_get::<i64, _>("observation_size").map_err(error)? != raw.len() as i64
            || row.try_get::<Vec<u8>, _>("digest").map_err(error)?
                != checksum(&raw, legacy.as_deref())
        {
            return Err(error("epoch observation bytes differ"));
        }
        let observation: Observation = serde_json::from_slice(&raw).map_err(error)?;
        observation.validate().map_err(error)?;
        let certificate: Vec<u8> = row.try_get("certificate").map_err(error)?;
        let validators: Vec<u8> = row.try_get("validators").map_err(error)?;
        let source: Vec<u8> = row.try_get("source").map_err(error)?;
        if certificate.len() > 32 * 1024 * 1024
            || validators.len() > 1_000_000
            || source.len() > 4_000_000
            || row
                .try_get::<Vec<u8>, _>("certificate_hash")
                .map_err(error)?
                != Sha256::digest(&certificate).as_slice()
        {
            return Err(error("epoch journal authority bytes differ"));
        }
        let finalized = Finalize::decode(&certificate).map_err(error)?;
        let validators = ValidatorSet::decode(&validators).map_err(error)?;
        qc::validate_finalize(
            self.chain().chain_id.as_bytes(),
            &validators,
            &finalized,
            qc::FinalityMode::Persisted,
        )
        .map_err(error)?;
        let mut source_reader = oce1::Reader::new(&source);
        let reward = reward::get(&mut source_reader).map_err(error)?;
        source_reader.finish().map_err(error)?;
        reward_attribution::bind_finality(
            &validators,
            &finalized,
            &reward_attribution::of_source(&reward).map_err(error)?,
        )
        .map_err(error)?;
        if finalized.epoch_id as u64 != epoch
            || finalized.header.proposed_state_root != head.cursor.state_root.0
            || finalized.header.prev_state_root != parent.cursor.state_root.0
            || finalized.header.txid_hi != head.txid_hi
            || finalized.header.ts.to_bits() != observation.finalized_at.to_bits()
            || row.try_get::<Vec<u8>, _>("proposal").map_err(error)? != finalized.proposal_id
        {
            return Err(error("epoch journal finality binding differs"));
        }
        let outbox=sqlx::query("SELECT sequence AS event_sequence,epoch AS event_epoch,parent_root AS event_parent,root AS event_root,events FROM exex_committed_epoch WHERE chain_id=? AND genesis=? AND sequence=?")
            .bind(&self.chain().chain_id).bind(self.chain().namespace_key().as_slice()).bind(format!("{:016x}",head.cursor.sequence.0)).fetch_one(&self.pool).await.map_err(error)?;
        let records = transactions::epoch_records(&outbox, &parent, &head)?;
        let receipts: Vec<u8> = sqlx::query_scalar(
            "SELECT substr(receipts,1,33554433) FROM node_consensus_receipts WHERE sequence=?",
        )
        .bind(head.cursor.sequence.0 as i64)
        .fetch_one(&self.pool)
        .await
        .map_err(error)?;
        if receipts.len() > 32 * 1024 * 1024 {
            return Err(error("epoch receipt archive exceeds local read limit"));
        }
        let receipts: Vec<Vec<u8>> = serde_json::from_slice(&receipts).map_err(error)?;
        if octra_node_protocol::consensus::hash::receipt_root(&receipts)
            .map_err(error)?
            .as_slice()
            != finalized.header.receipt_root
        {
            return Err(error("epoch observation receipt root differs"));
        }
        check_fees(&records, &receipts, &observation)?;
        if legacy
            .as_ref()
            .is_some_and(|value| value.len() != 64 || !epoch_page::hex(value))
        {
            return Err(error("epoch legacy digest is invalid"));
        }
        Ok(Some(Entry {
            head,
            parent,
            finalized,
            source: reward,
            observation,
            legacy,
        }))
    }
    /// Native summary presence is distinct from retained state/QC presence.
    /// Checkpoint and historical observation gaps remain absent.
    pub async fn epoch_summary(&self, captured: &Head, epoch: i64) -> Result<Option<Vec<u8>>> {
        let Some(entry) = self.epoch_entry(captured, epoch).await? else {
            return Ok(None);
        };
        let Some(legacy) = entry.legacy.as_deref() else {
            return Ok(None);
        };
        Summary {
            epoch,
            state_root: hex::encode(entry.head.cursor.state_root.0).as_bytes(),
            parent_commit: legacy,
            tx_count: entry.head.txid_hi - entry.parent.txid_hi,
            finalized_by: &entry.source.reward_proposer_addr,
            observation: &entry.observation,
        }
        .encode()
        .map(Some)
        .map_err(error)
    }
    pub async fn epoch_legacy_digest(
        &self,
        captured: &Head,
        epoch: i64,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .epoch_entry(captured, epoch)
            .await?
            .and_then(|entry| entry.legacy))
    }
    pub async fn epoch_page_row(
        &self,
        captured: &Head,
        epoch: i64,
    ) -> Result<Option<(epoch_page::Row, usize)>> {
        let Some(entry) = self.epoch_entry(captured, epoch).await? else {
            return Ok(None);
        };
        let Some(legacy) = entry.legacy.as_deref() else {
            return Ok(None);
        };
        let row = epoch_page::Row {
            epoch,
            root: hex::encode(entry.head.cursor.state_root.0).into_bytes(),
            previous: hex::encode(entry.parent.cursor.state_root.0).into_bytes(),
            tx_start: entry
                .parent
                .txid_hi
                .checked_add(1)
                .ok_or_else(|| error("epoch transaction index exhausted"))?,
            tx_count: entry.head.txid_hi - entry.parent.txid_hi,
            time: entry.finalized.header.ts,
        };
        row.encode()
            .map_err(|fault| error(String::from_utf8_lossy(&fault.message)))?;
        let bytes = Summary {
            epoch,
            state_root: &row.root,
            parent_commit: legacy,
            tx_count: row.tx_count,
            finalized_by: &entry.source.reward_proposer_addr,
            observation: &entry.observation,
        }
        .header(
            &row.previous,
            row.tx_start,
            &entry.finalized.header.creator_addr,
            entry.finalized.commit_round,
            &entry.source,
        )
        .map_err(error)?
        .len();
        Ok(Some((row, bytes)))
    }
}

fn check_fees(
    records: &[octra_exex::native_history::NativeTransaction],
    receipts: &[Vec<u8>],
    observation: &Observation,
) -> Result<()> {
    use octra_node_protocol::{
        native_json::Document, transaction::Transaction, transaction_outcome,
    };
    let confirmed = records
        .iter()
        .map(|record| {
            Transaction::from_document(&Document::parse(&record.transaction).map_err(error)?)
                .map_err(error)
        })
        .collect::<Result<Vec<_>>>()?;
    let partition = transaction_outcome::decode(&confirmed, receipts, false).map_err(error)?;
    let mut lower = BigInt::zero();
    for tx in &confirmed {
        if tx.ou.is_negative() {
            return Err(error("confirmed epoch fee is negative"));
        }
        lower += &tx.ou;
    }
    let mut upper = lower.clone();
    for rejection in &partition.rejections {
        if rejection.charged {
            if rejection.tx.ou.is_negative() {
                return Err(error("charged epoch rejection fee is negative"));
            }
            lower += &rejection.tx.ou;
            upper += &rejection.tx.ou;
        } else if rejection.tx.ou.is_positive() {
            // Native legacy receipts do not mark every fee-preserving VM
            // refusal. Their exact charge requires execution replay; never
            // interpret an absent flag as a zero fee.
            upper += &rejection.tx.ou;
        }
    }
    let actual =
        octra_node_protocol::native_integer::parse_integer(observation.fees_total.as_bytes())
            .ok_or_else(|| error("invalid observed epoch fees"))?;
    if actual < lower || actual > upper {
        return Err(error(
            "observed epoch fees differ from authenticated outcome partition",
        ));
    }
    Ok(())
}
