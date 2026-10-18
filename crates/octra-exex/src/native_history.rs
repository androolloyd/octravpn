//! Recover an ExEx outbox from the native node's durable, retained history.
//!
//! Input comes from `scripts/node-port/native-history-export.ml`, which opens
//! the local Irmin/chaindata stores read-only and verifies their published HEAD.
//! This is a trusted local host boundary, **not** a peer certificate verifier.
//! Never accept these records from an RPC client or use receipts as funding
//! proofs. The native host remains responsible for consensus and execution.
//!
//! Each import atomically advances the copied history and its source binding.
//! A process may die between native HEAD publication and import: reopening and
//! exporting after `native_head()` recovers that gap. Notify the ExEx manager
//! only after `import()` returns. Missing/pruned history requires explicit resync.

use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    consensus::{reward, reward_attribution::legacy, RewardSource},
    epoch_index,
    native_json::Document,
    transaction::Transaction,
    transaction_archive::{Archive, Proof},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};

use crate::{
    sqlite_source::SqliteEpochSource, ChainIdentity, CommittedEpoch, CommittedEpochSource, Cursor,
    EpochId, Error, Result, Sequence, StateRoot,
};

const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_EPOCHS: usize = 64;
const MAX_TRANSACTIONS: usize = 100_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBoundary {
    pub epoch: u64,
    pub state_root: String,
    pub ledger_root: String,
    pub irmin_commit: String,
    pub index_hash: String,
    pub index_root: String,
    pub txid_hi: i64,
}

impl NativeBoundary {
    fn validate(&self) -> Result<StateRoot> {
        if self.epoch > i64::MAX as u64 >> 1
            || self.txid_hi < -1
            || self.ledger_root.is_empty()
            || self.irmin_commit.is_empty()
        {
            return Err(invalid("invalid native boundary"));
        }
        let root = hash(&self.state_root)?;
        hash(&self.index_hash)?;
        hash(&self.index_root)?;
        let folded =
            epoch_index::folded_state_root(self.ledger_root.as_bytes(), self.index_root.as_bytes())
                .map_err(invalid)?;
        if folded != root.0 {
            return Err(invalid("native ledger/index fold differs"));
        }
        Ok(root)
    }

    fn cursor(&self, sequence: Sequence) -> Result<Cursor> {
        Ok(Cursor {
            sequence,
            epoch: EpochId(self.epoch),
            state_root: self.validate()?,
        })
    }
}

/// Native identity and normalized transaction bytes, base64 in the export.
/// Exact identities include null optional fields; signed identities retain
/// only the native archive's proved fields. Consumers must decode the appropriate
/// execution receipt and only act on successful effects from their pinned app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTransaction {
    pub txid: i64,
    pub hash: String,
    pub proof: ArchiveProof,
    #[serde(with = "encoded_bytes")]
    pub identity: Vec<u8>,
    #[serde(with = "encoded_bytes")]
    pub transaction: Vec<u8>,
    #[serde(with = "optional_encoded_bytes")]
    pub receipt: Option<Vec<u8>>,
}

impl NativeTransaction {
    pub fn validate(&self) -> Result<()> {
        if Sha256::digest(&self.identity).as_slice() != hash(&self.hash)?.0 {
            return Err(invalid("native history transaction identity differs"));
        }
        let document = Document::parse(&self.transaction).map_err(invalid)?;
        let transaction = Transaction::from_document(&document).map_err(invalid)?;
        // The export uses the hash preimage for Exact records, while the archive
        // decoder expects Transaction.to_yojson with absent optionals omitted.
        let canonical = transaction.to_json_bytes().map_err(invalid)?;
        let archive = Archive::decode(self.hash.as_bytes(), &canonical).map_err(invalid)?;
        let (proof, identity, normalized) = match archive.proof() {
            Proof::Exact => {
                let identity = archive.transaction().identity_bytes().map_err(invalid)?;
                (ArchiveProof::Exact, identity.clone(), identity)
            }
            Proof::Signed | Proof::SignedOperation => (
                if archive.proof() == Proof::Signed {
                    ArchiveProof::Signed
                } else {
                    ArchiveProof::SignedOperation
                },
                archive.proof_bytes().to_vec(),
                archive.transaction().to_json_bytes().map_err(invalid)?,
            ),
        };
        if self.proof != proof || self.identity != identity || self.transaction != normalized {
            return Err(invalid(
                "native history normalized transaction differs from proved identity",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveProof {
    Exact,
    Signed,
    SignedOperation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeEpoch {
    boundary: NativeBoundary,
    parent_root: String,
    parent_commit: String,
    start_txid: i64,
    transactions: Vec<NativeTransaction>,
    #[serde(
        default,
        with = "optional_encoded_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    epoch_header: Option<Vec<u8>>,
    #[serde(skip)]
    rewards: Option<rewards::Evidence>,
}

mod rewards;
pub use rewards::HistoricalRewardAuthority;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeHistory {
    format: String,
    head_commit_id: String,
    head: NativeBoundary,
    anchor: NativeBoundary,
    epochs: Vec<NativeEpoch>,
}

impl NativeHistory {
    /// Parse a bounded export from the trusted local native host. Successful
    /// parsing alone does not authorize delivery; `import` checks all links.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let history = Self::decode(bytes)?;
        if history.format != "octra-exex-history-v1" {
            return Err(invalid(
                "native v2 history requires independent historical reward authority",
            ));
        }
        history.validate()?;
        Ok(history)
    }

    /// Read v2 native headers using independently selected historical policy.
    /// V1 remains importable, with reward metadata explicitly unavailable.
    /// This local compatibility boundary supplies no peer finality certificate.
    pub fn parse_with_rewards(
        bytes: &[u8],
        authority: &impl HistoricalRewardAuthority,
    ) -> Result<Self> {
        let mut history = Self::decode(bytes)?;
        history.validate_structure()?;
        for epoch in &mut history.epochs {
            epoch.rewards = rewards::derive(epoch, authority)?;
        }
        history.validate()?;
        Ok(history)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err(invalid("native history export exceeds byte limit"));
        }
        let history: Self = serde_json::from_slice(bytes).map_err(invalid)?;
        Ok(history)
    }

    pub fn anchor(&self) -> &NativeBoundary {
        &self.anchor
    }

    pub fn head(&self) -> &NativeBoundary {
        &self.head
    }

    fn validate(&self) -> Result<()> {
        self.validate_structure()?;
        for epoch in &self.epochs {
            match (&epoch.epoch_header, &epoch.rewards) {
                (None, None) if self.format == "octra-exex-history-v1" => (),
                (Some(header), Some(evidence)) if self.format == "octra-exex-history-v2" => {
                    evidence.validate_header(header)?;
                }
                _ => return Err(invalid("native reward evidence is missing or unexpected")),
            }
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<()> {
        if !matches!(
            self.format.as_str(),
            "octra-exex-history-v1" | "octra-exex-history-v2"
        ) || self.head_commit_id.is_empty()
            || self.epochs.len() > MAX_EPOCHS
            || self.head.epoch < self.anchor.epoch
        {
            return Err(invalid("invalid native history envelope"));
        }
        self.head.validate()?;
        self.anchor.validate()?;
        let mut previous = &self.anchor;
        let mut total = 0usize;
        for epoch in &self.epochs {
            if epoch.epoch_header.is_some() != (self.format == "octra-exex-history-v2") {
                return Err(invalid("native header version differs"));
            }
            let epoch_number = epoch.boundary.epoch;
            total = total
                .checked_add(epoch.transactions.len())
                .ok_or_else(|| invalid("native history count overflow"))?;
            if total > MAX_TRANSACTIONS
                || previous.epoch.checked_add(1) != Some(epoch_number)
                || epoch_number > self.head.epoch
                || epoch.parent_root != previous.state_root
                || epoch.parent_commit != previous.irmin_commit
                || previous.txid_hi.checked_add(1) != Some(epoch.start_txid)
            {
                return Err(invalid("native history predecessor or range differs"));
            }
            epoch.boundary.validate()?;
            let count = i64::try_from(epoch.transactions.len()).map_err(invalid)?;
            let last = epoch
                .start_txid
                .checked_add(count)
                .and_then(|next| next.checked_sub(1))
                .ok_or_else(|| invalid("native history transaction range exhausted"))?;
            if last != epoch.boundary.txid_hi {
                return Err(invalid("native history high-water differs"));
            }
            let mut items = Vec::with_capacity(epoch.transactions.len());
            for (index, transaction) in epoch.transactions.iter().enumerate() {
                if transaction.txid != epoch.start_txid + index as i64 {
                    return Err(invalid("native history transaction identity differs"));
                }
                transaction.validate()?;
                items.push(epoch_index::Item {
                    txid: transaction.txid,
                    hash: hash(&transaction.hash)?.0.to_vec(),
                });
            }
            let (index_hash, index_root) = epoch_index::next_root(
                previous.index_root.as_bytes(),
                epoch.boundary.epoch as i64,
                &items,
            )
            .map_err(invalid)?;
            if index_hash != hash(&epoch.boundary.index_hash)?.0
                || index_root != hash(&epoch.boundary.index_root)?.0
            {
                return Err(invalid("native transaction commitment differs"));
            }
            previous = &epoch.boundary;
        }
        // Empty output cannot conceal a missing successor. Partial pages are
        // allowed, but a page reaching HEAD must match every binding field.
        if (self.epochs.is_empty() && previous.epoch != self.head.epoch)
            || (previous.epoch == self.head.epoch && previous != &self.head)
        {
            return Err(invalid("native history does not match published HEAD"));
        }
        Ok(())
    }
}

pub struct NativeEpochSource {
    pool: SqlitePool,
    source: SqliteEpochSource<NativeTransaction>,
}

impl NativeEpochSource {
    /// Bind an empty/reopened outbox to an explicitly chosen retained native
    /// anchor. This never silently resets an existing source or its checkpoints.
    pub async fn open(
        pool: SqlitePool,
        chain: ChainIdentity,
        anchor: NativeBoundary,
    ) -> Result<Self> {
        let cursor = anchor.cursor(Sequence(0))?;
        let source = SqliteEpochSource::open(pool.clone(), chain.clone(), cursor).await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS exex_native_binding (chain_id TEXT NOT NULL, genesis BLOB NOT NULL, anchor TEXT NOT NULL, head TEXT NOT NULL, PRIMARY KEY(chain_id,genesis))")
            .execute(&pool).await.map_err(invalid)?;
        rewards::initialize(&pool).await?;
        let encoded = serde_json::to_string(&anchor).map_err(invalid)?;
        let mut tx = pool.begin().await.map_err(invalid)?;
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM exex_committed_epoch WHERE chain_id=? AND genesis=?",
        )
        .bind(&chain.chain_id)
        .bind(chain.namespace_key().as_slice())
        .fetch_one(&mut *tx)
        .await
        .map_err(invalid)?;
        let saved: Option<String> = sqlx::query_scalar(
            "SELECT anchor FROM exex_native_binding WHERE chain_id=? AND genesis=?",
        )
        .bind(&chain.chain_id)
        .bind(chain.namespace_key().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(invalid)?;
        match saved {
            Some(saved) if saved != encoded => return Err(invalid("native source anchor differs")),
            Some(_) => (),
            None if rows != 0 => return Err(invalid("cannot adopt an existing unbound outbox")),
            None => {
                sqlx::query(
                    "INSERT INTO exex_native_binding(chain_id,genesis,anchor,head) VALUES(?,?,?,?)",
                )
                .bind(&chain.chain_id)
                .bind(chain.namespace_key().as_slice())
                .bind(&encoded)
                .bind(&encoded)
                .execute(&mut *tx)
                .await
                .map_err(invalid)?;
            }
        }
        tx.commit().await.map_err(invalid)?;
        Ok(Self { pool, source })
    }

    pub async fn native_head(&self) -> Result<NativeBoundary> {
        let chain = self.source.chain();
        let binding = sqlx::query(
            "SELECT head,anchor FROM exex_native_binding WHERE chain_id=? AND genesis=?",
        )
        .bind(&chain.chain_id)
        .bind(chain.namespace_key().as_slice())
        .fetch_one(&self.pool)
        .await
        .map_err(invalid)?;
        let encoded: String = binding.try_get("head").map_err(invalid)?;
        let boundary: NativeBoundary = serde_json::from_str(&encoded).map_err(invalid)?;
        boundary.validate()?;
        Ok(boundary)
    }

    /// Persist a whole verified page or none of it. Stale pages fail closed;
    /// after an uncertain outcome, export again after `native_head()`.
    pub async fn import(&self, history: &NativeHistory) -> Result<Cursor> {
        history.validate()?;
        let chain = self.source.chain();
        let mut tx = self.pool.begin().await.map_err(invalid)?;
        let binding = sqlx::query(
            "SELECT head,anchor FROM exex_native_binding WHERE chain_id=? AND genesis=?",
        )
        .bind(&chain.chain_id)
        .bind(chain.namespace_key().as_slice())
        .fetch_one(&mut *tx)
        .await
        .map_err(invalid)?;
        let encoded: String = binding.try_get("head").map_err(invalid)?;
        let previous: NativeBoundary = serde_json::from_str(&encoded).map_err(invalid)?;
        let row = sqlx::query("SELECT sequence,epoch,root FROM exex_committed_epoch WHERE chain_id=? AND genesis=? ORDER BY sequence DESC LIMIT 1")
            .bind(&chain.chain_id).bind(chain.namespace_key().as_slice())
            .fetch_optional(&mut *tx).await.map_err(invalid)?;
        let mut sequence = Sequence(0);
        if let Some(row) = row {
            let saved: String = row.try_get("sequence").map_err(invalid)?;
            sequence = Sequence(u64::from_str_radix(&saved, 16).map_err(invalid)?);
            let epoch: String = row.try_get("epoch").map_err(invalid)?;
            let root: Vec<u8> = row.try_get("root").map_err(invalid)?;
            if epoch != format!("{:016x}", previous.epoch) || root != previous.validate()?.0 {
                return Err(invalid("native source and outbox disagree"));
            }
        } else {
            let original: String = binding.try_get("anchor").map_err(invalid)?;
            if original != encoded {
                return Err(invalid("native outbox is missing after source advanced"));
            }
        }
        if history.anchor != previous {
            return Err(invalid(
                "native history anchor differs; export after native_head",
            ));
        }
        let mut latest = &previous;
        for epoch in &history.epochs {
            sequence.0 = sequence.0.checked_add(1).ok_or(Error::SequenceExhausted)?;
            let event = CommittedEpoch {
                chain: chain.clone(),
                cursor: epoch.boundary.cursor(sequence)?,
                parent_root: hash(&epoch.parent_root)?,
                events: epoch.transactions.clone(),
            };
            self.source.append(&mut tx, &event).await?;
            rewards::append(&mut tx, &chain, sequence, latest, epoch).await?;
            latest = &epoch.boundary;
        }
        let result = latest.cursor(sequence)?;
        let updated = sqlx::query(
            "UPDATE exex_native_binding SET head=? WHERE chain_id=? AND genesis=? AND head=?",
        )
        .bind(serde_json::to_string(latest).map_err(invalid)?)
        .bind(&chain.chain_id)
        .bind(chain.namespace_key().as_slice())
        .bind(encoded)
        .execute(&mut *tx)
        .await
        .map_err(invalid)?;
        if updated.rows_affected() != 1 {
            return Err(invalid("native history writer conflict"));
        }
        tx.commit().await.map_err(invalid)?;
        Ok(result)
    }

    /// Legacy compatibility attribution, rechecked against the exact imported
    /// header and fresh independent authority. None means explicit v1 metadata
    /// unavailability; it is never a fallback for a modern canonical record.
    pub async fn reward_source(
        &self,
        sequence: Sequence,
        authority: &impl HistoricalRewardAuthority,
    ) -> Result<Option<RewardSource>> {
        rewards::load(self, sequence, authority).await
    }
}

#[async_trait]
impl CommittedEpochSource<NativeTransaction> for NativeEpochSource {
    fn chain(&self) -> ChainIdentity {
        self.source.chain()
    }
    async fn anchor(&self) -> Result<Cursor> {
        self.source.anchor().await
    }
    async fn head(&self) -> Result<Cursor> {
        self.source.head().await
    }
    async fn load(
        &self,
        sequence: Sequence,
    ) -> Result<Option<Arc<CommittedEpoch<NativeTransaction>>>> {
        self.source.load(sequence).await
    }
}

fn invalid(value: impl std::fmt::Display) -> Error {
    Error::Store(value.to_string())
}

fn hash(value: &str) -> Result<StateRoot> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("native hash is not canonical lowercase hex"));
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(invalid)?;
    Ok(StateRoot(bytes))
}

mod encoded_bytes {
    use super::{Deserialize, Engine, STANDARD};
    pub(super) fn serialize<S: serde::Serializer>(
        bytes: &[u8],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

mod optional_encoded_bytes {
    use super::{Deserialize, Engine, STANDARD};
    use serde::Serialize;
    #[allow(clippy::ref_option)] // Serde's `with` serializer receives a reference to the field.
    pub(super) fn serialize<S: serde::Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        bytes
            .as_ref()
            .map(|value| STANDARD.encode(value))
            .serialize(serializer)
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| STANDARD.decode(text).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod identity_tests {
    use super::{ArchiveProof, NativeTransaction};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use octra_node_protocol::transaction_archive::{Archive, Proof};
    use serde_json::{json, Value};

    #[test]
    fn native_legacy_fixtures_bind_all_proved_execution_fields_and_strip_unproved_fields() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../octra-node-protocol/tests/fixtures/transaction-archive.json"
        ))
        .unwrap();
        let mut count = 0;
        for case in fixture["cases"].as_array().unwrap() {
            if case["input"]["operation"] != "archive" {
                continue;
            }
            let expected = &case["output"]["result"];
            if expected["proof"] != "signed" && expected["proof"] != "operation" {
                continue;
            }
            let raw = STANDARD
                .decode(case["output"]["raw"].as_str().unwrap())
                .unwrap();
            let hash = case["output"]["hash"].as_str().unwrap();
            let archive = Archive::decode(hash.as_bytes(), &raw).unwrap();
            let event = NativeTransaction {
                txid: 0,
                hash: hash.into(),
                proof: if archive.proof() == Proof::Signed {
                    ArchiveProof::Signed
                } else {
                    ArchiveProof::SignedOperation
                },
                identity: archive.proof_bytes().to_vec(),
                transaction: archive.transaction().to_json_bytes().unwrap(),
                receipt: None,
            };
            event.validate().unwrap();
            let original: Value = serde_json::from_slice(&event.transaction).unwrap();
            for (field, value) in [
                ("from", json!("arbitrary sender")),
                ("to_", json!("arbitrary receiver")),
                ("amount", json!("999999999")),
                ("nonce", json!(12345)),
                ("ou", json!("99999")),
                ("timestamp", json!(42.5)),
                ("op_type", json!("circle_call")),
                ("public_key", json!("unproved key")),
                ("message", json!("unproved execution")),
                ("encrypted_data", json!("unproved ciphertext")),
                ("unknown", json!(true)),
            ] {
                let mut changed = event.clone();
                let mut tx = original.clone();
                tx[field] = value;
                let encoded = serde_json::to_vec(&tx).unwrap();
                changed.transaction = if field == "unknown" {
                    encoded
                } else {
                    let document =
                        octra_node_protocol::native_json::Document::parse(&encoded).unwrap();
                    octra_node_protocol::transaction::Transaction::from_document(&document)
                        .unwrap()
                        .to_json_bytes()
                        .unwrap()
                };
                assert!(
                    changed.validate().is_err(),
                    "legacy proof {hash} accepted changed {field}"
                );
            }
            let mut changed = event.clone();
            changed.proof = ArchiveProof::Exact;
            assert!(changed.validate().is_err());
            count += 1;
        }
        assert!(count >= 20);
    }
}
