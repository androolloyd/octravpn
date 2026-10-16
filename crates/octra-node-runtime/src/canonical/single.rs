//! Explicit private Single storage authority. Local signatures are host-journal
//! provenance, never QCs, and are never consumed by the BFT publisher.
use super::{
    error, hex_hash, transaction_commitment, AppliedEpoch, CanonicalStore, Head, PreparedCommit,
    Result,
};
use crate::state_batch::{Snapshot, StateBatch};
use ed25519_dalek::{Signer, SigningKey};
use octra_exex::{
    native_history::NativeTransaction, sqlite_source::SqliteEpochSource, ChainIdentity,
    CommittedEpochSource, Cursor, EpochId, Sequence, StateRoot,
};
use octra_node_protocol::{
    epoch_index, epoch_journal::Observation, irmin, network::verify_ed25519,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
const MAGIC: &[u8] = b"octra:private-single-epoch:v1\n";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    schema: String,
    pub chain: ChainIdentity,
    pub public_key: Vec<u8>,
    pub policy: [u8; 32],
}
pub struct Authority {
    identity: Identity,
    key: Arc<SigningKey>,
}
impl Authority {
    pub fn new(chain: ChainIdentity, key: SigningKey, policy: [u8; 32]) -> Result<Self> {
        chain.validate().map_err(error)?;
        if !chain.chain_id.starts_with("octra-single-local-") || chain.genesis_root().is_none() {
            return Err(error("Single requires an explicit private genesis origin"));
        }
        Ok(Self {
            identity: Identity {
                schema: "private-single-v1".into(),
                chain,
                public_key: key.verifying_key().to_bytes().to_vec(),
                policy,
            },
            key: Arc::new(key),
        })
    }
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    fn sign(&self, domain: &[u8], body: &[u8]) -> Result<Vec<u8>> {
        let mut h = Sha256::new();
        h.update(domain);
        h.update(serde_json::to_vec(&self.identity).map_err(error)?);
        h.update(body);
        Ok(self.key.sign(&h.finalize()).to_bytes().to_vec())
    }
    fn verify(&self, domain: &[u8], body: &[u8], signature: &[u8]) -> Result<()> {
        let mut h = Sha256::new();
        h.update(domain);
        h.update(serde_json::to_vec(&self.identity).map_err(error)?);
        h.update(body);
        if !verify_ed25519(&self.identity.public_key, &h.finalize(), signature) {
            return Err(error("Single local provenance signature differs"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub parent: Head,
    pub head: Head,
    pub legacy_parent: Vec<u8>,
    pub legacy_digest: Vec<u8>,
    pub observation: Observation,
    pub events_sha256: [u8; 32],
    pub processed: Vec<Vec<u8>>,
    pub deferred: Vec<Vec<u8>>,
    pub wall_time: f64,
    pub proposer: Vec<u8>,
    pub tree_state_root: Vec<u8>,
    pub outcomes: Vec<Vec<u8>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    body: Vec<u8>,
    signature: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Queue {
    cursor: Cursor,
    revision: i64,
    payload: Vec<u8>,
}
pub struct QueueSnapshot {
    pub cursor: Cursor,
    pub revision: i64,
    pub payload: Vec<u8>,
}
pub struct Store {
    canonical: Arc<CanonicalStore>,
    authority: Arc<Authority>,
}
pub struct Prepared {
    inner: PreparedCommit,
    pub record: Record,
}
pub struct Publication {
    pub epoch: u64,
    pub state: Snapshot,
    pub transactions: Vec<NativeTransaction>,
    pub legacy_parent: Vec<u8>,
    pub legacy_digest: Vec<u8>,
    pub observation: Observation,
    pub processed: Vec<Vec<u8>>,
    pub deferred: Vec<Vec<u8>>,
    pub wall_time: f64,
    pub date: i64,
    pub proposer: Vec<u8>,
    pub tree_state_root: Vec<u8>,
    pub outcomes: Vec<Vec<u8>>,
    pub vm_receipts: super::VmReceipts,
    pub queue: Vec<u8>,
    pub queue_revision: i64,
}
impl Store {
    pub async fn create(
        path: &Path,
        authority: Authority,
        state: Snapshot,
        date: i64,
        queue: Vec<u8>,
    ) -> Result<Self> {
        let canonical = Arc::new(
            CanonicalStore::create(path, authority.identity.chain.clone(), state, date).await?,
        );
        let authority = Arc::new(authority);
        let store = Self {
            canonical,
            authority,
        };
        let head = store.head().await?;
        let mut tx = store.canonical.pool.begin().await.map_err(error)?;
        sqlx::query("CREATE TABLE node_single_identity(id INTEGER PRIMARY KEY CHECK(id=0),identity BLOB NOT NULL)").execute(&mut *tx).await.map_err(error)?;
        sqlx::query("CREATE TABLE node_single_queue(id INTEGER PRIMARY KEY CHECK(id=0),revision INTEGER NOT NULL,body BLOB NOT NULL)").execute(&mut *tx).await.map_err(error)?;
        sqlx::query("INSERT INTO node_single_identity VALUES(0,?)")
            .bind(serde_json::to_vec(store.authority.identity()).map_err(error)?)
            .execute(&mut *tx)
            .await
            .map_err(error)?;
        let body = store.queue_wire(&Queue {
            cursor: head.cursor,
            revision: 0,
            payload: queue,
        })?;
        sqlx::query("INSERT INTO node_single_queue VALUES(0,0,?)")
            .bind(body)
            .execute(&mut *tx)
            .await
            .map_err(error)?;
        tx.commit().await.map_err(error)?;
        Ok(store)
    }
    pub async fn open(path: &Path, authority: Authority) -> Result<Self> {
        // Check the discriminator before CanonicalStore's auxiliary index migration.
        let pool = super::connect(path).await?;
        let saved: Vec<u8> =
            sqlx::query_scalar("SELECT identity FROM node_single_identity WHERE id=0")
                .fetch_one(&pool)
                .await
                .map_err(error)?;
        let saved: Identity = serde_json::from_slice(&saved).map_err(error)?;
        if saved != authority.identity {
            return Err(error("Single store origin or authority differs"));
        }
        pool.close().await;
        let canonical = Arc::new(CanonicalStore::open(path, &authority.identity.chain).await?);
        let store = Self {
            canonical,
            authority: Arc::new(authority),
        };
        store.audit().await?;
        store.queue().await?;
        Ok(store)
    }
    pub fn identity(&self) -> &Identity {
        self.authority.identity()
    }
    /// Read capabilities do not expose the local signing authority or writer.
    pub fn reader(&self) -> super::Reader {
        self.canonical.reader()
    }
    pub fn chain(&self) -> &ChainIdentity {
        self.canonical.chain()
    }
    pub fn cached_head(&self) -> Option<Head> {
        self.canonical.cached_head()
    }
    pub fn program_records(&self) -> super::ProgramRecords {
        self.canonical.program_records()
    }
    pub async fn vm_receipt(&self, head: &Head, hash: &[u8]) -> Result<Option<Vec<u8>>> {
        self.canonical.vm_receipt(head, hash).await
    }
    /// Canonical asset provenance comes only from the audited committed store.
    pub async fn assets(
        &self,
    ) -> std::result::Result<crate::circle_assets::CanonicalAssets, octra_browser::Error> {
        crate::circle_assets::CanonicalAssets::capture(&self.canonical).await
    }
    pub fn database_path(&self) -> PathBuf {
        self.canonical.database_path()
    }
    pub fn source(&self) -> Arc<SqliteEpochSource<NativeTransaction>> {
        self.canonical.source()
    }
    pub async fn head(&self) -> Result<Head> {
        self.canonical.head().await
    }
    pub async fn snapshot(&self) -> Result<(Head, StateBatch)> {
        self.canonical.snapshot().await
    }
    pub async fn root(&self, epoch: i64) -> Result<Option<Vec<u8>>> {
        let Ok(epoch) = u64::try_from(epoch) else {
            return Ok(None);
        };
        let head = self.head().await?;
        if epoch > head.cursor.epoch.0 {
            return Ok(None);
        }
        Ok(Some(
            self.canonical
                .retained_head(Sequence(epoch))
                .await?
                .cursor
                .state_root
                .0
                .to_vec(),
        ))
    }
    fn queue_wire(&self, queue: &Queue) -> Result<Vec<u8>> {
        let body = serde_json::to_vec(queue).map_err(error)?;
        let signature = self.authority.sign(b"single:queue:v1\0", &body)?;
        serde_json::to_vec(&Signed { body, signature }).map_err(error)
    }
    pub async fn queue(&self) -> Result<QueueSnapshot> {
        let row = sqlx::query("SELECT revision,body FROM node_single_queue WHERE id=0")
            .fetch_one(&self.canonical.pool)
            .await
            .map_err(error)?;
        let signed: Signed =
            serde_json::from_slice(row.try_get::<&[u8], _>("body").map_err(error)?)
                .map_err(error)?;
        self.authority
            .verify(b"single:queue:v1\0", &signed.body, &signed.signature)?;
        let queue: Queue = serde_json::from_slice(&signed.body).map_err(error)?;
        if queue.revision < 0
            || queue.revision != row.try_get::<i64, _>("revision").map_err(error)?
            || queue.cursor != self.head().await?.cursor
        {
            return Err(error("Single queue recovery cursor differs"));
        }
        Ok(QueueSnapshot {
            cursor: queue.cursor,
            revision: queue.revision,
            payload: queue.payload,
        })
    }
    pub async fn save_queue(&self, head: &Head, revision: i64, payload: Vec<u8>) -> Result<i64> {
        let next = revision
            .checked_add(1)
            .ok_or_else(|| error("Single queue revision exhausted"))?;
        let mut tx = self.canonical.pool.begin().await.map_err(error)?;
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
        if super::decode_head(&row)? != *head {
            return Err(error("Single queue canonical parent moved"));
        }
        let wire = self.queue_wire(&Queue {
            cursor: head.cursor,
            revision: next,
            payload,
        })?;
        if sqlx::query("UPDATE node_single_queue SET revision=?,body=? WHERE id=0 AND revision=?")
            .bind(next)
            .bind(wire)
            .bind(revision)
            .execute(&mut *tx)
            .await
            .map_err(error)?
            .rows_affected()
            != 1
        {
            return Err(error("Single queue revision moved"));
        }
        tx.commit().await.map_err(error)?;
        Ok(next)
    }
    pub async fn record(&self, sequence: Sequence) -> Result<Record> {
        if sequence.0 == 0 {
            return Err(error("Single genesis has no epoch record"));
        }
        let bytes = self.canonical.certificate(sequence).await?;
        let raw = bytes
            .strip_prefix(MAGIC)
            .ok_or_else(|| error("Single local provenance missing"))?;
        let signed: Signed = serde_json::from_slice(raw).map_err(error)?;
        self.authority
            .verify(MAGIC, &signed.body, &signed.signature)?;
        let record: Record = serde_json::from_slice(&signed.body).map_err(error)?;
        record.observation.validate().map_err(error)?;
        let head = self.canonical.retained_head(sequence).await?;
        let parent = self
            .canonical
            .retained_head(Sequence(sequence.0 - 1))
            .await?;
        let events = self
            .canonical
            .source
            .load(sequence)
            .await
            .map_err(error)?
            .ok_or_else(|| error("Single ExEx epoch missing"))?;
        if record.head != head
            || record.parent != parent
            || record.events_sha256
                != <[u8; 32]>::from(Sha256::digest(
                    serde_json::to_vec(&events.events).map_err(error)?,
                ))
            || !record.wall_time.is_finite()
            || record.wall_time < 0.
            || head.message != format!("epoch_{}", head.cursor.epoch.0).as_bytes()
        {
            return Err(error("Single local history binding differs"));
        }
        hex_hash::<32>(std::str::from_utf8(&record.legacy_digest).map_err(error)?)?;
        hex_hash::<64>(std::str::from_utf8(&record.tree_state_root).map_err(error)?)?;
        let epoch = octra_node_protocol::transaction::Nonce::new(
            i64::try_from(head.cursor.epoch.0).map_err(error)?,
        )
        .map_err(error)?;
        let confirmed = events
            .events
            .iter()
            .map(|event| {
                let doc = octra_node_protocol::native_json::Document::parse(&event.transaction)
                    .map_err(error)?;
                octra_node_protocol::transaction::Transaction::from_document(&doc).map_err(error)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut tree =
            octra_node_protocol::legacy_tree::Tree::create(epoch, record.legacy_parent.clone());
        let digest = tree
            .finalize_epoch(
                epoch,
                &record.proposer,
                record.tree_state_root.clone(),
                record.observation.finalized_at,
                &confirmed,
            )
            .map_err(error)?;
        if digest != record.legacy_digest
            || record.observation.finalized_at != 0.
            || record.tree_state_root != parent.ledger_root.as_bytes()
        {
            return Err(error("Single legacy tree differs"));
        }
        Ok(record)
    }
    pub async fn audit(&self) -> Result<()> {
        let end = self.head().await?;
        let mut legacy = b"GENESIS".to_vec();
        for seq in 1..=end.cursor.sequence.0 {
            let record = self.record(Sequence(seq)).await?;
            if record.legacy_parent != legacy {
                return Err(error("Single legacy history link differs"));
            }
            legacy = record.legacy_digest;
        }
        Ok(())
    }
    pub async fn prepare(&self, base: &Head, publication: Publication) -> Result<Prepared> {
        let Publication {
            epoch,
            state,
            transactions,
            legacy_parent,
            legacy_digest,
            observation,
            processed,
            deferred,
            wall_time,
            date,
            proposer,
            tree_state_root,
            outcomes,
            vm_receipts,
            queue,
            queue_revision,
        } = publication;
        observation.validate().map_err(error)?;
        if !wall_time.is_finite()
            || wall_time < 0.
            || observation.finalized_at != 0.
            || tree_state_root != base.ledger_root.as_bytes()
        {
            return Err(error("Single native timestamp or parent Tree root differs"));
        }
        let expected_legacy = if base.cursor.sequence.0 == 0 {
            b"GENESIS".to_vec()
        } else {
            self.record(base.cursor.sequence).await?.legacy_digest
        };
        if legacy_parent != expected_legacy {
            return Err(error("Single publication legacy parent differs"));
        }
        let confirmed = transactions
            .iter()
            .map(|tx| {
                let document = octra_node_protocol::native_json::Document::parse(&tx.transaction)
                    .map_err(error)?;
                octra_node_protocol::transaction::Transaction::from_document(&document)
                    .map_err(error)
            })
            .collect::<Result<Vec<_>>>()?;
        let native_epoch =
            octra_node_protocol::transaction::Nonce::new(i64::try_from(epoch).map_err(error)?)
                .map_err(error)?;
        let mut tree =
            octra_node_protocol::legacy_tree::Tree::create(native_epoch, legacy_parent.clone());
        if tree
            .finalize_epoch(
                native_epoch,
                &proposer,
                tree_state_root.clone(),
                0.,
                &confirmed,
            )
            .map_err(error)?
            != legacy_digest
        {
            return Err(error("Single publication legacy Tree differs"));
        }
        let state = state.with_persisted_counter().map_err(error)?;
        let (index_hash, index_root, txid_hi) = transaction_commitment(base, epoch, &transactions)?;
        let ledger = state.root().map_err(error)?;
        let ledger_root = hex::encode(ledger);
        let root = StateRoot(
            epoch_index::folded_state_root(ledger_root.as_bytes(), index_root.as_bytes())
                .map_err(error)?,
        );
        let message = format!("epoch_{epoch}").into_bytes();
        let head = Head {
            cursor: Cursor {
                sequence: Sequence(
                    base.cursor
                        .sequence
                        .0
                        .checked_add(1)
                        .ok_or_else(|| error("Single sequence exhausted"))?,
                ),
                epoch: EpochId(epoch),
                state_root: root,
            },
            ledger_root,
            irmin_commit: hex::encode(irmin::commit_hash(
                &ledger,
                &[hex_hash(&base.irmin_commit)?],
                date,
                b"octra",
                &message,
            )),
            parent_commit: Some(base.irmin_commit.clone()),
            index_root,
            index_hash: Some(index_hash),
            txid_hi,
            date,
            message: message.clone(),
        };
        let record = Record {
            parent: base.clone(),
            head: head.clone(),
            legacy_parent,
            legacy_digest,
            observation,
            events_sha256: Sha256::digest(serde_json::to_vec(&transactions).map_err(error)?).into(),
            processed,
            deferred,
            wall_time,
            proposer,
            tree_state_root,
            outcomes,
        };
        record.observation.validate().map_err(error)?;
        let body = serde_json::to_vec(&record).map_err(error)?;
        let signature = self.authority.sign(MAGIC, &body)?;
        let mut certificate = MAGIC.to_vec();
        certificate.extend(serde_json::to_vec(&Signed { body, signature }).map_err(error)?);
        let mut inner = self
            .canonical
            .prepare(
                base,
                AppliedEpoch {
                    epoch,
                    state,
                    expected_root: root,
                    transactions,
                    certificate,
                    date,
                    message,
                },
            )
            .await?;
        inner.retain_vm_receipts(&vm_receipts).await?;
        super::transactions::retain_outcomes(&mut inner.transaction, &inner.head, &record.outcomes)
            .await?;
        if inner.head != head {
            return Err(error("Single prepared head differs"));
        }
        let next = queue_revision
            .checked_add(1)
            .ok_or_else(|| error("Single queue revision exhausted"))?;
        let wire = self.queue_wire(&Queue {
            cursor: head.cursor,
            revision: next,
            payload: queue,
        })?;
        if sqlx::query("UPDATE node_single_queue SET revision=?,body=? WHERE id=0 AND revision=?")
            .bind(next)
            .bind(wire)
            .bind(queue_revision)
            .execute(&mut *inner.transaction)
            .await
            .map_err(error)?
            .rows_affected()
            != 1
        {
            return Err(error("Single queue revision moved"));
        }
        Ok(Prepared { inner, record })
    }
}
impl Prepared {
    pub async fn commit(self) -> Result<Head> {
        self.inner.commit().await
    }
}
impl CanonicalStore {
    pub(crate) async fn is_single(&self) -> Result<bool> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='node_single_identity')").fetch_one(&self.pool).await.map_err(error)
    }
}
