//! Durable publication for already authenticated and executed epochs.
//!
//! Irmin commitments remain native; SQLite is the local container for immutable
//! objects, canonical history and the ExEx outbox. A single FULL-synchronous WAL
//! transaction publishes all three. This layer does not authenticate consensus
//! certificates: `finality::Publisher` authenticates publication and recovery.
//! The raw `prepare` API is reserved for trusted local imports and storage tests.
use std::{path::Path, sync::Arc, time::Duration};

use octra_exex::{
    native_history::NativeTransaction, sqlite_source::SqliteEpochSource, ChainIdentity,
    CommittedEpoch, Cursor, EpochId, Sequence, StateRoot,
};
use octra_node_protocol::{epoch_index, irmin};
use serde::{Deserialize, Serialize};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    Row, Sqlite, SqlitePool, Transaction,
};

use crate::state_batch::{Snapshot, StateBatch, StoredObject};
mod epochs;
mod inodes;
mod reader;
mod records;
mod snapshots;
mod transactions;
pub use transactions::{
    HistoryPage, HistoryQuery, HistoryReadError, RejectionPage, RejectionRecord,
};
mod vm_receipts;
pub use reader::{Reader, RecordLengths, ReliefSource};
pub use records::{ProgramRecords, RecordError};
pub use vm_receipts::VmReceipts;
mod bootstrap;
#[cfg(test)]
mod relief_tests;
#[cfg(test)]
mod storage_tests;

#[derive(Debug, thiserror::Error)]
#[error("canonical store: {0}")]
pub struct Error(String);
type Result<T> = std::result::Result<T, Error>;
fn error(value: impl std::fmt::Display) -> Error {
    Error(value.to_string())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub cursor: Cursor,
    pub ledger_root: String,
    pub irmin_commit: String,
    pub parent_commit: Option<String>,
    pub index_root: String,
    pub index_hash: Option<String>,
    pub txid_hi: i64,
    pub date: i64,
    pub message: Vec<u8>,
}

fn hex_hash<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || value
            .bytes()
            .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
    {
        return Err(error("invalid canonical hash"));
    }
    hex::decode(value)
        .map_err(error)?
        .try_into()
        .map_err(|_| error("invalid hash size"))
}

impl Head {
    fn validate(&self) -> Result<()> {
        if self.cursor.epoch.0 > (1u64 << 62) - 1
            || self.cursor.sequence.0 > i64::MAX as u64
            || self.txid_hi < -1
        {
            return Err(error("invalid head counters"));
        }
        let node = hex_hash(&self.ledger_root)?;
        let parents = self
            .parent_commit
            .as_ref()
            .map(|h| hex_hash(h))
            .transpose()?
            .into_iter()
            .collect::<Vec<_>>();
        if irmin::commit_hash(&node, &parents, self.date, b"octra", &self.message)
            != hex_hash(&self.irmin_commit)?
        {
            return Err(error("commit preimage differs"));
        }
        hex_hash::<32>(&self.index_root)?;
        if let Some(hash) = &self.index_hash {
            hex_hash::<32>(hash)?;
        }
        if epoch_index::folded_state_root(self.ledger_root.as_bytes(), self.index_root.as_bytes())
            .map_err(error)?
            != self.cursor.state_root.0
        {
            return Err(error("state-root fold differs"));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct AppliedEpoch {
    pub epoch: u64,
    pub state: Snapshot,
    /// Root authenticated by the local consensus/catch-up verifier.
    pub expected_root: StateRoot,
    pub transactions: Vec<NativeTransaction>,
    /// Native encoded finality material, retained verbatim for history serving.
    pub certificate: Vec<u8>,
    pub date: i64,
    pub message: Vec<u8>,
}

pub struct CanonicalStore {
    pool: SqlitePool,
    chain: ChainIdentity,
    anchor: Head,
    bootstrap: Option<bootstrap::Bootstrap>,
    source: Arc<SqliteEpochSource<NativeTransaction>>,
    head_cache: Arc<HeadCache>,
    snapshots: Arc<snapshots::Cache>,
}

struct HeadCache(std::sync::RwLock<Head>);
impl HeadCache {
    fn new(head: Head) -> Self {
        Self(std::sync::RwLock::new(head))
    }
    fn remember(&self, head: &Head) -> Result<()> {
        let mut saved = self
            .0
            .write()
            .map_err(|_| error("canonical head cache poisoned"))?;
        if saved.cursor.sequence > head.cursor.sequence {
            return Ok(());
        }
        if saved.cursor.sequence == head.cursor.sequence && *saved != *head {
            return Err(error("canonical head cache commitment differs"));
        }
        *saved = head.clone();
        Ok(())
    }
    fn get(&self) -> Option<Head> {
        self.0.read().ok().map(|head| head.clone())
    }
}

/// Dropping this value rolls back state, history and outbox together. No ExEx
/// notification is valid until `commit` returns successfully.
pub struct PreparedCommit {
    transaction: Transaction<'static, Sqlite>,
    head: Head,
    head_cache: Arc<HeadCache>,
    snapshots: Arc<snapshots::Cache>,
    state: Snapshot,
}

impl PreparedCommit {
    pub(crate) async fn retain_relief(
        &mut self,
        mark: Option<&octra_node_protocol::consensus::relief::Mark>,
    ) -> Result<()> {
        let bytes = mark
            .map(octra_node_protocol::consensus::relief_log::encode)
            .transpose()
            .map_err(error)?;
        if bytes.as_ref().is_some_and(|b| {
            b.len() as u64 > octra_node_protocol::consensus::relief_log::MAX_WIRE_BYTES
        }) {
            return Err(error("relief archive exceeds native record limit"));
        }
        sqlx::query("CREATE TABLE IF NOT EXISTS node_epoch_relief(sequence INTEGER PRIMARY KEY REFERENCES node_epochs(sequence), mark BLOB)")
            .execute(&mut *self.transaction).await.map_err(error)?;
        sqlx::query("INSERT INTO node_epoch_relief VALUES(?,?)")
            .bind(self.head.cursor.sequence.0 as i64)
            .bind(bytes)
            .execute(&mut *self.transaction)
            .await
            .map_err(error)?;
        Ok(())
    }
    pub(crate) async fn retain_reward_source(
        &mut self,
        proposal: &[u8],
        source: &octra_node_protocol::consensus::RewardSource,
    ) -> Result<()> {
        let mut wire = octra_node_protocol::oce1::Writer::new();
        octra_node_protocol::consensus::reward::put(&mut wire, source).map_err(error)?;
        sqlx::query("CREATE TABLE IF NOT EXISTS node_epoch_rewards(sequence INTEGER PRIMARY KEY REFERENCES node_epochs(sequence), proposal BLOB NOT NULL UNIQUE, source BLOB NOT NULL)")
            .execute(&mut *self.transaction).await.map_err(error)?;
        sqlx::query("INSERT INTO node_epoch_rewards VALUES(?,?,?)")
            .bind(self.head.cursor.sequence.0 as i64)
            .bind(proposal)
            .bind(wire.into_bytes())
            .execute(&mut *self.transaction)
            .await
            .map_err(error)?;
        Ok(())
    }
    pub(crate) async fn retain_consensus_receipts(&mut self, receipts: &[Vec<u8>]) -> Result<()> {
        // Added transactionally for existing stores as well as new databases.
        sqlx::query("CREATE TABLE IF NOT EXISTS node_consensus_receipts(sequence INTEGER PRIMARY KEY REFERENCES node_epochs(sequence), receipts BLOB NOT NULL)")
            .execute(&mut *self.transaction).await.map_err(error)?;
        sqlx::query("INSERT INTO node_consensus_receipts VALUES(?,?)")
            .bind(self.head.cursor.sequence.0 as i64)
            .bind(serde_json::to_vec(receipts).map_err(error)?)
            .execute(&mut *self.transaction)
            .await
            .map_err(error)?;
        transactions::retain_outcomes(&mut self.transaction, &self.head, receipts).await?;
        Ok(())
    }

    pub fn candidate(&self) -> &Head {
        &self.head
    }
    pub async fn commit(self) -> Result<Head> {
        // The SQLite commit and publication-cache update have one owned
        // lifetime. An abandoned caller cannot leave a live process observing
        // its previous head after the transaction finishes committing.
        tokio::spawn(async move {
            self.transaction.commit().await.map_err(error)?;
            self.snapshots.remember(&self.head, self.state)?;
            self.head_cache.remember(&self.head)?;
            Ok(self.head)
        })
        .await
        .map_err(error)?
    }
}

async fn connect(path: &Path) -> Result<SqlitePool> {
    SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(false)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Full)
                .pragma("fullfsync", "ON")
                .pragma("checkpoint_fullfsync", "ON")
                .foreign_keys(true)
                .busy_timeout(Duration::from_secs(10)),
        )
        .await
        .map_err(error)
}

impl CanonicalStore {
    /// Local database path, used by the owning node to exclude a second service
    /// coordinator. Raw import/storage tools remain a trusted offline boundary.
    pub fn database_path(&self) -> std::path::PathBuf {
        self.pool.connect_options().get_filename().to_owned()
    }

    /// Initialize an explicitly supplied, authenticated genesis snapshot. The
    /// expected chain identity must match its native folded commitment.
    pub async fn create(
        path: &Path,
        chain: ChainIdentity,
        state: Snapshot,
        date: i64,
    ) -> Result<Self> {
        chain.validate().map_err(error)?;
        let ledger_root = hex::encode(state.root().map_err(error)?);
        let (index_hash, index_root) =
            epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
                .map_err(error)?;
        let index_root = hex::encode(index_root);
        let root = StateRoot(
            epoch_index::folded_state_root(ledger_root.as_bytes(), index_root.as_bytes())
                .map_err(error)?,
        );
        if chain.genesis_root() != Some(root) {
            return Err(error("genesis snapshot differs from chain identity"));
        }
        let cursor = Cursor {
            sequence: Sequence(0),
            epoch: EpochId(0),
            state_root: root,
        };
        let message = b"genesis".to_vec();
        let anchor = Head {
            cursor,
            irmin_commit: hex::encode(irmin::commit_hash(
                &hex_hash(&ledger_root)?,
                &[],
                date,
                b"octra",
                &message,
            )),
            ledger_root,
            index_root,
            index_hash: Some(hex::encode(index_hash)),
            parent_commit: None,
            txid_hi: -1,
            date,
            message,
        };
        Self::initialize(path, chain, state, anchor, None).await
    }

    async fn initialize(
        path: &Path,
        chain: ChainIdentity,
        state: Snapshot,
        anchor: Head,
        bootstrap: Option<bootstrap::Bootstrap>,
    ) -> Result<Self> {
        let state = state.with_persisted_counter().map_err(error)?;
        anchor.validate()?;
        let cursor = anchor.cursor;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(error)?;
        file.sync_all().map_err(error)?;
        // Closing another descriptor for the database after SQLite has locked it
        // can release this process's POSIX locks. Finish creation before connect.
        drop(file);
        // Persist the directory entry as well as subsequent SQLite contents.
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::File::open(parent)
                .and_then(|f| f.sync_all())
                .map_err(error)?;
        }
        let pool = connect(path).await?;
        let source = Arc::new(
            SqliteEpochSource::open(pool.clone(), chain.clone(), cursor)
                .await
                .map_err(error)?,
        );
        let mut tx = pool.begin().await.map_err(error)?;
        for statement in [
            "CREATE TABLE node_identity(id INTEGER PRIMARY KEY CHECK(id=0), chain BLOB NOT NULL, anchor BLOB NOT NULL)",
            "CREATE TABLE node_objects(hash BLOB PRIMARY KEY CHECK(length(hash)=64), contents INTEGER NOT NULL CHECK(contents IN (0,1)), data BLOB NOT NULL)",
            "CREATE TABLE node_edges(parent BLOB NOT NULL REFERENCES node_objects(hash), child BLOB NOT NULL REFERENCES node_objects(hash), PRIMARY KEY(parent,child))",
            "CREATE TABLE node_epochs(sequence INTEGER PRIMARY KEY, head BLOB NOT NULL, root BLOB NOT NULL REFERENCES node_objects(hash), certificate BLOB NOT NULL)",
        ] { sqlx::query(statement).execute(&mut *tx).await.map_err(error)?; }
        sqlx::query("INSERT INTO node_identity VALUES(0,?,?)")
            .bind(serde_json::to_vec(&chain).map_err(error)?)
            .bind(serde_json::to_vec(&anchor).map_err(error)?)
            .execute(&mut *tx)
            .await
            .map_err(error)?;
        write_snapshot(&mut tx, &state, None).await?;
        write_head(&mut tx, &anchor, &[]).await?;
        if let Some(evidence) = &bootstrap {
            sqlx::query("CREATE TABLE node_bootstrap(id INTEGER PRIMARY KEY CHECK(id=0), certificate BLOB NOT NULL, roots BLOB NOT NULL)")
                .execute(&mut *tx).await.map_err(error)?;
            sqlx::query("INSERT INTO node_bootstrap VALUES(0,?,?)")
                .bind(&evidence.raw)
                .bind(&evidence.window)
                .execute(&mut *tx)
                .await
                .map_err(error)?;
        }
        tx.commit().await.map_err(error)?;
        let head_cache = Arc::new(HeadCache::new(anchor.clone()));
        let snapshots = Arc::new(snapshots::Cache::default());
        snapshots.remember(&anchor, state)?;
        let store = Self {
            pool,
            chain,
            anchor,
            bootstrap,
            source,
            head_cache,
            snapshots,
        };
        store.index_vm_receipts().await?;
        store.index_transactions().await?;
        Ok(store)
    }

    /// Reopen without repairing missing history. Corruption or mismatched chain
    /// identity requires explicit recovery; no new anchor is silently installed.
    pub async fn open(path: &Path, expected_chain: &ChainIdentity) -> Result<Self> {
        let pool = connect(path).await?;
        let row = sqlx::query("SELECT chain,anchor FROM node_identity WHERE id=0")
            .fetch_one(&pool)
            .await
            .map_err(error)?;
        let chain: ChainIdentity =
            serde_json::from_slice(row.try_get::<&[u8], _>("chain").map_err(error)?)
                .map_err(error)?;
        let anchor: Head =
            serde_json::from_slice(row.try_get::<&[u8], _>("anchor").map_err(error)?)
                .map_err(error)?;
        if &chain != expected_chain
            || anchor.cursor.sequence != Sequence(0)
            || anchor.cursor.epoch != EpochId(0)
            || chain.genesis_root() != Some(anchor.cursor.state_root)
        {
            return Err(error("canonical chain identity differs"));
        }
        anchor.validate()?;
        let source = Arc::new(
            SqliteEpochSource::open_existing(pool.clone(), chain.clone(), anchor.cursor)
                .await
                .map_err(error)?,
        );
        let head_cache = Arc::new(HeadCache::new(anchor.clone()));
        let store = Self {
            pool,
            chain,
            anchor,
            bootstrap: None,
            source,
            head_cache,
            snapshots: Arc::default(),
        };
        store.verify_history().await?;
        store.snapshot().await?;
        store.index_vm_receipts().await?;
        store.index_transactions().await?;
        Ok(store)
    }

    pub fn anchor(&self) -> &Head {
        &self.anchor
    }

    /// Authenticated native finality bytes preceding the retained history floor.
    /// Callers must still verify the complete window against their export anchor.
    pub fn checkpoint_window(&self) -> Option<&[u8]> {
        self.bootstrap.as_ref().map(|value| value.window.as_slice())
    }

    /// Sequence numbers count retained commits; they are not chain epochs.
    pub async fn sequence_for_epoch(&self, epoch: u64) -> Result<Option<Sequence>> {
        let Some(offset) = epoch.checked_sub(self.anchor.cursor.epoch.0) else {
            return Ok(None);
        };
        if epoch > self.head().await?.cursor.epoch.0 {
            return Ok(None);
        }
        Ok(Some(Sequence(offset)))
    }

    pub fn source(&self) -> Arc<SqliteEpochSource<NativeTransaction>> {
        self.source.clone()
    }
    pub fn chain(&self) -> &ChainIdentity {
        &self.chain
    }

    /// Read-only access for historical rules and membership. The canonical
    /// writer remains exclusively owned by the node.
    pub fn reader(&self) -> Reader {
        Reader::new(
            self.pool.clone(),
            self.chain.clone(),
            self.anchor.cursor,
            self.snapshots.clone(),
        )
    }

    pub async fn head(&self) -> Result<Head> {
        let row = sqlx::query(
            "SELECT sequence,head,root FROM node_epochs ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(error)?;
        let head = decode_head(&row)?;
        self.head_cache.remember(&head)?;
        Ok(head)
    }
    /// Last locally published canonical head, independent of browser/VPN
    /// serving leases. Historical reads still authenticate their stored rows.
    pub fn cached_head(&self) -> Option<Head> {
        self.head_cache.get()
    }

    pub async fn snapshot(&self) -> Result<(Head, StateBatch)> {
        let head = self.head().await?;
        let snapshot = self.snapshots.load(&self.pool, &head).await?;
        Ok((head, StateBatch::from_snapshot(snapshot)))
    }

    pub async fn certificate(&self, sequence: Sequence) -> Result<Vec<u8>> {
        let number = i64::try_from(sequence.0).map_err(error)?;
        sqlx::query_scalar("SELECT certificate FROM node_epochs WHERE sequence=?")
            .bind(number)
            .fetch_one(&self.pool)
            .await
            .map_err(error)
    }

    pub async fn retained_head(&self, sequence: Sequence) -> Result<Head> {
        let number = i64::try_from(sequence.0).map_err(error)?;
        let row = sqlx::query("SELECT sequence,head,root FROM node_epochs WHERE sequence=?")
            .bind(number)
            .fetch_one(&self.pool)
            .await
            .map_err(error)?;
        decode_head(&row)
    }

    pub(crate) async fn consensus_receipts(&self, sequence: Sequence) -> Result<Vec<Vec<u8>>> {
        let number = i64::try_from(sequence.0).map_err(error)?;
        let bytes: Vec<u8> =
            sqlx::query_scalar("SELECT receipts FROM node_consensus_receipts WHERE sequence=?")
                .bind(number)
                .fetch_one(&self.pool)
                .await
                .map_err(error)?;
        serde_json::from_slice(&bytes).map_err(error)
    }

    pub(crate) async fn reward_source(
        &self,
        sequence: Sequence,
    ) -> Result<(Vec<u8>, octra_node_protocol::consensus::RewardSource)> {
        let row = sqlx::query("SELECT proposal,source FROM node_epoch_rewards WHERE sequence=?")
            .bind(i64::try_from(sequence.0).map_err(error)?)
            .fetch_one(&self.pool)
            .await
            .map_err(error)?;
        let bytes: Vec<u8> = row.try_get("source").map_err(error)?;
        let mut reader = octra_node_protocol::oce1::Reader::new(&bytes);
        let source = octra_node_protocol::consensus::reward::get(&mut reader).map_err(error)?;
        reader.finish().map_err(error)?;
        Ok((row.try_get("proposal").map_err(error)?, source))
    }

    pub(crate) async fn proposal_sequence(&self, proposal: &[u8; 32]) -> Result<Option<Sequence>> {
        if self.head().await?.cursor.sequence.0 == 0 {
            return Ok(None);
        }
        let value: Option<i64> =
            sqlx::query_scalar("SELECT sequence FROM node_epoch_rewards WHERE proposal=?")
                .bind(proposal.as_slice())
                .fetch_optional(&self.pool)
                .await
                .map_err(error)?;
        value
            .map(|n| u64::try_from(n).map(Sequence).map_err(error))
            .transpose()
    }

    /// Trusted local storage boundary. Normal node publication must go through
    /// `finality::Publisher`, which binds signatures and consensus receipts.
    pub async fn prepare(&self, base: &Head, mut applied: AppliedEpoch) -> Result<PreparedCommit> {
        base.validate()?;
        applied.state = applied.state.with_persisted_counter().map_err(error)?;
        let vm_receipts = vm_receipts::confirmed(&applied.transactions)?;
        if base.cursor.epoch.0.checked_add(1) != Some(applied.epoch)
            || applied.epoch > (1u64 << 62) - 1
        {
            return Err(error("nonconsecutive applied epoch"));
        }
        let sequence = base
            .cursor
            .sequence
            .0
            .checked_add(1)
            .filter(|n| i64::try_from(*n).is_ok())
            .ok_or_else(|| error("sequence exhausted"))?;
        let (index_hash, index_root, txid_hi) =
            transaction_commitment(base, applied.epoch, &applied.transactions)?;
        let node = applied.state.root().map_err(error)?;
        let ledger_root = hex::encode(node);
        let state_root = StateRoot(
            epoch_index::folded_state_root(ledger_root.as_bytes(), index_root.as_bytes())
                .map_err(error)?,
        );
        if state_root != applied.expected_root {
            return Err(error("executed state differs from authenticated root"));
        }
        let head = Head {
            cursor: Cursor {
                sequence: Sequence(sequence),
                epoch: EpochId(applied.epoch),
                state_root,
            },
            irmin_commit: hex::encode(irmin::commit_hash(
                &node,
                &[hex_hash(&base.irmin_commit)?],
                applied.date,
                b"octra",
                &applied.message,
            )),
            parent_commit: Some(base.irmin_commit.clone()),
            ledger_root,
            index_root,
            index_hash: Some(index_hash),
            txid_hi,
            date: applied.date,
            message: applied.message,
        };
        // Authenticate the persisted base before taking the writer connection.
        // It is the only reusable object prefix accepted by incremental writes.
        let persisted = self.reader().snapshot_at(base).await?;
        let mut tx = self.pool.begin().await.map_err(error)?;
        // Acquire the writer lock before reading HEAD. Competing processes may
        // prepare concurrently, but only one can publish against this base.
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
        if decode_head(&row)? != *base {
            return Err(error("canonical HEAD moved"));
        }
        write_snapshot(&mut tx, &applied.state, Some(&persisted)).await?;
        write_head(&mut tx, &head, &applied.certificate).await?;
        transactions::retain(&mut tx, head.cursor.sequence, &applied.transactions).await?;
        transactions::advance(&mut tx, base.cursor.sequence, head.cursor.sequence).await?;
        self.source
            .append(
                &mut tx,
                &CommittedEpoch {
                    chain: self.chain.clone(),
                    cursor: head.cursor,
                    parent_root: base.cursor.state_root,
                    events: applied.transactions,
                },
            )
            .await
            .map_err(error)?;
        let mut prepared = PreparedCommit {
            transaction: tx,
            head,
            head_cache: self.head_cache.clone(),
            snapshots: self.snapshots.clone(),
            state: applied.state,
        };
        prepared.retain_vm_receipts(&vm_receipts).await?;
        prepared.advance_vm_receipts(base.cursor.sequence).await?;
        Ok(prepared)
    }

    async fn verify_history(&self) -> Result<()> {
        // One read transaction fixes the recovery boundary while another host
        // may append. Bound memory by a page, not by retained chain length.
        let mut read = self.pool.begin().await.map_err(error)?;
        let mut previous: Option<Head> = None;
        let mut after = -1i64;
        loop {
            let rows = sqlx::query("SELECT n.sequence,n.head,n.root,e.sequence AS event_sequence,e.epoch AS event_epoch,e.parent_root AS event_parent,e.root AS event_root,e.events FROM node_epochs n LEFT JOIN exex_committed_epoch e ON e.chain_id=? AND e.genesis=? AND e.sequence=printf('%016x',n.sequence) WHERE n.sequence>? ORDER BY n.sequence LIMIT 16")
                .bind(&self.chain.chain_id).bind(self.chain.namespace_key().as_slice()).bind(after)
                .fetch_all(&mut *read).await.map_err(error)?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let head = decode_head(&row)?;
                if let Some(base) = &previous {
                    if head.cursor.sequence.0 != base.cursor.sequence.0 + 1
                        || head.cursor.epoch.0 != base.cursor.epoch.0 + 1
                        || head.parent_commit.as_ref() != Some(&base.irmin_commit)
                    {
                        return Err(error("canonical history gap"));
                    }
                    let events = row
                        .try_get::<Option<Vec<u8>>, _>("events")
                        .map_err(error)?
                        .ok_or_else(|| error("canonical outbox gap"))?;
                    let transactions: Vec<NativeTransaction> =
                        serde_json::from_slice(&events).map_err(error)?;
                    let (index_hash, index_root, txid_hi) =
                        transaction_commitment(base, head.cursor.epoch.0, &transactions)?;
                    if row.try_get::<String, _>("event_sequence").map_err(error)?
                        != format!("{:016x}", head.cursor.sequence.0)
                        || row.try_get::<String, _>("event_epoch").map_err(error)?
                            != format!("{:016x}", head.cursor.epoch.0)
                        || row.try_get::<Vec<u8>, _>("event_parent").map_err(error)?
                            != base.cursor.state_root.0
                        || row.try_get::<Vec<u8>, _>("event_root").map_err(error)?
                            != head.cursor.state_root.0
                        || head.index_hash.as_ref() != Some(&index_hash)
                        || head.index_root != index_root
                        || head.txid_hi != txid_hi
                    {
                        return Err(error("canonical history/outbox binding differs"));
                    }
                } else if head != self.anchor {
                    return Err(error("canonical anchor differs"));
                }
                after = head.cursor.sequence.0 as i64;
                previous = Some(head);
            }
        }
        let head = previous.ok_or_else(|| error("missing canonical history"))?;
        let event_head: Option<String> = sqlx::query_scalar("SELECT sequence FROM exex_committed_epoch WHERE chain_id=? AND genesis=? ORDER BY sequence DESC LIMIT 1")
            .bind(&self.chain.chain_id).bind(self.chain.namespace_key().as_slice()).fetch_optional(&mut *read).await.map_err(error)?;
        let expected = (head.cursor.sequence != self.anchor.cursor.sequence)
            .then(|| format!("{:016x}", head.cursor.sequence.0));
        if event_head != expected {
            return Err(error("outbox HEAD differs"));
        }
        read.commit().await.map_err(error)?;
        Ok(())
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}

fn transaction_commitment(
    base: &Head,
    epoch: u64,
    transactions: &[NativeTransaction],
) -> Result<(String, String, i64)> {
    let mut txid_hi = base.txid_hi;
    let mut items = Vec::with_capacity(transactions.len());
    for transaction in transactions {
        txid_hi = txid_hi
            .checked_add(1)
            .ok_or_else(|| error("transaction counter exhausted"))?;
        if transaction.txid != txid_hi {
            return Err(error("nonconsecutive transaction identifier"));
        }
        transaction.validate().map_err(error)?;
        items.push(epoch_index::Item {
            txid: txid_hi,
            hash: transaction.hash.as_bytes().to_vec(),
        });
    }
    let (hash, root) =
        epoch_index::next_root(base.index_root.as_bytes(), epoch as i64, &items).map_err(error)?;
    Ok((hex::encode(hash), hex::encode(root), txid_hi))
}

/// Compute the native ledger/index commitment without publishing state. This
/// is shared by proposal verification and authenticated canonical publication.
pub fn execution_root(
    base: &Head,
    epoch: u64,
    state: &Snapshot,
    transactions: &[NativeTransaction],
) -> Result<StateRoot> {
    let (_, index_root, _) = transaction_commitment(base, epoch, transactions)?;
    Ok(StateRoot(
        epoch_index::folded_state_root(
            hex::encode(state.root().map_err(error)?).as_bytes(),
            index_root.as_bytes(),
        )
        .map_err(error)?,
    ))
}

async fn write_snapshot(
    tx: &mut Transaction<'_, Sqlite>,
    snapshot: &Snapshot,
    base: Option<&Snapshot>,
) -> Result<()> {
    inodes::write(tx, snapshot, base).await
}

async fn write_head(
    tx: &mut Transaction<'_, Sqlite>,
    head: &Head,
    certificate: &[u8],
) -> Result<()> {
    head.validate()?;
    sqlx::query("INSERT INTO node_epochs(sequence,head,root,certificate) VALUES(?,?,?,?)")
        .bind(head.cursor.sequence.0 as i64)
        .bind(serde_json::to_vec(head).map_err(error)?)
        .bind(hex_hash::<64>(&head.ledger_root)?.as_slice())
        .bind(certificate)
        .execute(&mut **tx)
        .await
        .map_err(error)?;
    Ok(())
}

fn decode_head(row: &sqlx::sqlite::SqliteRow) -> Result<Head> {
    let head: Head =
        serde_json::from_slice(row.try_get::<&[u8], _>("head").map_err(error)?).map_err(error)?;
    head.validate()?;
    if row.try_get::<i64, _>("sequence").map_err(error)? != head.cursor.sequence.0 as i64
        || row.try_get::<Vec<u8>, _>("root").map_err(error)? != hex_hash::<64>(&head.ledger_root)?
    {
        return Err(error("canonical row binding differs"));
    }
    Ok(head)
}

pub mod single;
