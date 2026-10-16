//! Execution extensions consume immutable, durably committed epochs.
//!
//! The node supplies [`CommittedEpochSource`] from its canonical database and
//! [`CheckpointStore`] from persistent extension storage. The event outbox must
//! be written in the same transaction as the chain state, or reconstructed from
//! canonical history on recovery. Call [`ExExManager::notify_commit`] AFTER that
//! transaction is durable. Wakeups may coalesce; committed events never depend
//! on a volatile broadcast queue for delivery.
//!
//! Delivery is **at least once**. A crash after a sink write but before its
//! checkpoint causes replay. Extensions must apply events idempotently using
//! `(chain identity, sequence)`, or atomically persist sink changes with their
//! checkpoint. A successful callback alone does not establish exactly once.
//!
//! This library does not implement Octra consensus or authenticate incoming
//! certificates. Its source must expose authenticated, applied canonical epochs,
//! never proposals, simulation results or speculative VM side effects. It has
//! no mutable execution-state or validator-signing capability. Extensions that
//! submit transactions obtain an explicit submission capability from the host.

mod identity;
pub mod native_history;
pub mod sqlite;
pub mod sqlite_source;

use std::{collections::BTreeMap, future::Future, sync::Arc};

use async_trait::async_trait;
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use tokio::{sync::watch, task::JoinHandle};

pub use octra_node_protocol::chain_identity::{ChainIdentity, ChainOrigin, StateRoot};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EpochId(pub u64);

/// Sequence within the durable event outbox; distinct from the epoch number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Sequence(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    pub sequence: Sequence,
    pub epoch: EpochId,
    pub state_root: StateRoot,
}

/// One complete committed execution outcome. `E` is a typed protocol event.
/// Even epochs with no events are delivered for deadline-driven extensions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedEpoch<E> {
    pub chain: ChainIdentity,
    pub cursor: Cursor,
    pub parent_root: StateRoot,
    pub events: Vec<E>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("extension name must be nonempty and at most 128 bytes")]
    InvalidName,
    #[error("chain id must be nonempty")]
    InvalidChain,
    #[error("extension already registered: {0}")]
    DuplicateExtension(String),
    #[error("extension not registered: {0}")]
    UnknownExtension(String),
    #[error("event store: {0}")]
    Store(String),
    #[error("checkpoint for {0} does not match retained canonical history")]
    InvalidCheckpoint(String),
    #[error("missing retained event at sequence {0:?}; explicit resync is required")]
    Gap(Sequence),
    #[error("event at sequence {0:?} is not the next canonical epoch")]
    InvalidEvent(Sequence),
    #[error("event sequence exhausted")]
    SequenceExhausted,
    #[error("extension {name} failed: {reason}")]
    Extension { name: String, reason: String },
    #[error("extension task failed: {0}")]
    Task(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The node's durable, immutable canonical execution history/outbox.
///
/// `anchor` is the cursor preceding the first retained event. `load` returns
/// exactly the requested sequence. A source must retain all events needed by
/// required extensions; pruning must respect their durable checkpoints. Missing
/// history fails closed and requires explicit host-managed resynchronization.
/// Implementations must not block an async executor on database/file I/O.
#[async_trait]
pub trait CommittedEpochSource<E>: Send + Sync {
    fn chain(&self) -> ChainIdentity;
    async fn anchor(&self) -> Result<Cursor>;
    async fn head(&self) -> Result<Cursor>;
    async fn load(&self, sequence: Sequence) -> Result<Option<Arc<CommittedEpoch<E>>>>;
}

/// Persistent checkpoints, namespaced by BOTH chain identity and extension.
///
/// `compare_and_save` must durably compare the existing checkpoint with
/// `expected` and atomically replace it with `next`; an unexpected value is an
/// error. The comparison prevents competing processes from silently overwriting
/// progress. A new extension passes `None` for its first checkpoint. A source
/// adapter that uses memory alone cannot provide restart recovery.
#[async_trait]
pub trait CheckpointStore: Send + Sync {
    async fn load(&self, chain: &ChainIdentity, extension: &str) -> Result<Option<Cursor>>;
    async fn compare_and_save(
        &self,
        chain: &ChainIdentity,
        extension: &str,
        expected: Option<Cursor>,
        next: Cursor,
    ) -> Result<()>;
}

/// A trusted, in-process extension. This is task isolation, not a sandbox.
/// Returning an error stops this extension without advancing its checkpoint.
pub trait ExEx<E>: Send + 'static {
    fn name(&self) -> &str;
    fn on_epoch(
        &mut self,
        epoch: &CommittedEpoch<E>,
    ) -> impl Future<Output = std::result::Result<(), String>> + Send;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtensionStatus {
    Running { checkpoint: Cursor },
    Processing { checkpoint: Cursor, next: Cursor },
    Stopped { checkpoint: Cursor },
    Failed { checkpoint: Cursor, reason: String },
}

struct ExtensionTask {
    stop: watch::Sender<bool>,
    status: watch::Receiver<ExtensionStatus>,
    task: JoinHandle<Result<Cursor>>,
}

impl Drop for ExtensionTask {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Runs independently checkpointed extensions over one canonical event source.
/// No event payloads accumulate in the wakeup channel. A slow extension reads
/// backlog from the source and never backpressures `notify_commit`.
pub struct ExExManager<E> {
    source: Arc<dyn CommittedEpochSource<E>>,
    checkpoints: Arc<dyn CheckpointStore>,
    wake: watch::Sender<()>,
    extensions: BTreeMap<String, ExtensionTask>,
}

impl<E: Send + Sync + 'static> ExExManager<E> {
    pub fn new(
        source: Arc<dyn CommittedEpochSource<E>>,
        checkpoints: Arc<dyn CheckpointStore>,
    ) -> Result<Self> {
        if source.chain().chain_id.is_empty() {
            return Err(Error::InvalidChain);
        }
        let (wake, _) = watch::channel(());
        Ok(Self {
            source,
            checkpoints,
            wake,
            extensions: BTreeMap::new(),
        })
    }

    /// Signal a durable commit. This is a coalescing hint, not an event bus.
    /// Runtime adapters must persist canonical execution before calling this.
    pub fn notify_commit(&self) {
        self.wake.send_replace(());
    }

    pub fn extension_count(&self) -> usize {
        self.extensions.len()
    }

    pub fn status(&self, name: &str) -> Option<watch::Receiver<ExtensionStatus>> {
        self.extensions.get(name).map(|task| task.status.clone())
    }

    pub async fn register<X: ExEx<E>>(&mut self, extension: X) -> Result<()> {
        let name = extension.name().to_owned();
        if name.is_empty() || name.len() > 128 {
            return Err(Error::InvalidName);
        }
        if self.extensions.contains_key(&name) {
            return Err(Error::DuplicateExtension(name));
        }
        // Subscribe BEFORE inspecting history so an intervening commit cannot
        // become a missed wakeup between checking the head and waiting.
        let wake = self.wake.subscribe();
        let chain = self.source.chain();
        let persisted = self.checkpoints.load(&chain, &name).await?;
        let anchor = self.source.anchor().await?;
        let cursor = persisted.unwrap_or(anchor);
        validate_checkpoint(self.source.as_ref(), &chain, &name, anchor, cursor).await?;

        let (stop_tx, stop_rx) = watch::channel(false);
        let (status_tx, status_rx) =
            watch::channel(ExtensionStatus::Running { checkpoint: cursor });
        let worker = Worker {
            source: self.source.clone(),
            checkpoints: self.checkpoints.clone(),
            name: name.clone(),
            chain,
            cursor,
            persisted,
            wake,
            stop: stop_rx,
            status: status_tx,
        };
        let task = tokio::spawn(worker.run(extension));
        self.extensions.insert(
            name,
            ExtensionTask {
                stop: stop_tx,
                status: status_rx,
                task,
            },
        );
        Ok(())
    }

    /// Gracefully stop after the current callback and checkpoint. A failed or
    /// panicked task returns an error here, rather than being reported as stopped.
    /// Dropping/cancelling this operation aborts the removed worker.
    pub async fn stop(&mut self, name: &str) -> Result<Cursor> {
        let mut extension = self
            .extensions
            .remove(name)
            .ok_or_else(|| Error::UnknownExtension(name.to_owned()))?;
        extension.stop.send_replace(true);
        (&mut extension.task)
            .await
            .map_err(|error| Error::Task(error.to_string()))?
    }

    /// Stop every extension after its current callback and durable checkpoint.
    /// Signal all workers before joining; cancellation drops and aborts every
    /// remaining worker, including those not yet joined.
    pub async fn shutdown(&mut self) -> Result<()> {
        let mut tasks = std::mem::take(&mut self.extensions);
        for task in tasks.values() {
            task.stop.send_replace(true);
        }
        let mut failure = None;
        for task in tasks.values_mut() {
            let result = (&mut task.task)
                .await
                .map_err(|e| Error::Task(e.to_string()))
                .and_then(|r| r);
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

async fn validate_checkpoint<E: Send + Sync + 'static>(
    source: &dyn CommittedEpochSource<E>,
    chain: &ChainIdentity,
    name: &str,
    anchor: Cursor,
    cursor: Cursor,
) -> Result<()> {
    let head = source.head().await?;
    if cursor.sequence < anchor.sequence || cursor.sequence > head.sequence {
        return Err(Error::InvalidCheckpoint(name.to_owned()));
    }
    if cursor.sequence == anchor.sequence {
        if cursor != anchor {
            return Err(Error::InvalidCheckpoint(name.to_owned()));
        }
    } else {
        let event = source
            .load(cursor.sequence)
            .await?
            .ok_or_else(|| Error::InvalidCheckpoint(name.to_owned()))?;
        if &event.chain != chain || event.cursor != cursor {
            return Err(Error::InvalidCheckpoint(name.to_owned()));
        }
    }
    Ok(())
}

struct Worker<E> {
    source: Arc<dyn CommittedEpochSource<E>>,
    checkpoints: Arc<dyn CheckpointStore>,
    name: String,
    chain: ChainIdentity,
    cursor: Cursor,
    persisted: Option<Cursor>,
    wake: watch::Receiver<()>,
    stop: watch::Receiver<bool>,
    status: watch::Sender<ExtensionStatus>,
}

impl<E: Send + Sync + 'static> Worker<E> {
    async fn next(&mut self) -> Result<Option<Arc<CommittedEpoch<E>>>> {
        loop {
            if *self.stop.borrow() {
                return Ok(None);
            }
            let sequence = Sequence(
                self.cursor
                    .sequence
                    .0
                    .checked_add(1)
                    .ok_or(Error::SequenceExhausted)?,
            );
            if let Some(epoch) = self.source.load(sequence).await? {
                if epoch.chain != self.chain
                    || epoch.cursor.sequence != sequence
                    || epoch.parent_root != self.cursor.state_root
                    || epoch.cursor.epoch <= self.cursor.epoch
                {
                    return Err(Error::InvalidEvent(sequence));
                }
                return Ok(Some(epoch));
            }
            // load and head may straddle an append. Recheck load if head says
            // the event now exists; a genuine gap is never silently skipped.
            let head = self.source.head().await?;
            if head.sequence >= sequence {
                if self.source.load(sequence).await?.is_some() {
                    continue;
                }
                return Err(Error::Gap(sequence));
            }
            if head != self.cursor {
                return Err(Error::InvalidCheckpoint(self.name.clone()));
            }
            tokio::select! {
                result = self.wake.changed() => {
                    if result.is_err() { return Ok(None); }
                }
                _ = self.stop.changed() => return Ok(None),
            }
        }
    }

    async fn process<X: ExEx<E>>(&mut self, extension: &mut X) -> Result<Cursor> {
        while let Some(epoch) = self.next().await? {
            self.status.send_replace(ExtensionStatus::Processing {
                checkpoint: self.cursor,
                next: epoch.cursor,
            });
            extension
                .on_epoch(&epoch)
                .await
                .map_err(|reason| Error::Extension {
                    name: self.name.clone(),
                    reason,
                })?;
            self.checkpoints
                .compare_and_save(&self.chain, &self.name, self.persisted, epoch.cursor)
                .await?;
            self.cursor = epoch.cursor;
            self.persisted = Some(epoch.cursor);
            self.status.send_replace(ExtensionStatus::Running {
                checkpoint: self.cursor,
            });
        }
        Ok(self.cursor)
    }

    async fn run<X: ExEx<E>>(mut self, mut extension: X) -> Result<Cursor> {
        let result = std::panic::AssertUnwindSafe(self.process(&mut extension))
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(Error::Task(format!("extension {} panicked", self.name))));
        let status = match &result {
            Ok(cursor) => ExtensionStatus::Stopped {
                checkpoint: *cursor,
            },
            Err(error) => ExtensionStatus::Failed {
                checkpoint: self.cursor,
                reason: error.to_string(),
            },
        };
        self.status.send_replace(status);
        result
    }
}
