//! One canonical publication boundary for browsing, VPN admission and ExEx.
//!
//! The live validator driver publishes through `consensus::Canonical`. Proposal
//! execution and authenticated activation history remain explicit host inputs.
//! A host must exclusively own the canonical writer and explicitly resume
//! serving after catch-up. Restart starts suspended, even with valid history.
pub mod bootstrap;
mod compute;
pub mod consensus;
pub mod consensus_join;
pub mod devnet;
pub mod driver;
mod duty;
mod epoch_visibility;
pub mod executor;
pub mod gateway;
pub mod identity;
pub mod import;
mod launch;
mod legacy;
pub mod legacy_repair;
mod mesh;
pub mod native_tools;
pub mod network;
pub mod network_profile;
pub mod offline_cli;
pub mod peers;
pub mod proposal;
mod published;
mod recovery;
pub mod resource_attestation;
pub mod rpc;
mod services;
pub mod snapshot_export;
mod storage;
pub mod sync;
pub mod validator_cli;
pub mod vpn;

#[cfg(test)]
use octra_browser::Provenance;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use octra_browser::{
    application::{ApplicationHost, ReadRequest, ReviewedAction},
    http::Browser,
};
use octra_exex::{
    native_history::NativeTransaction, CheckpointStore, ExEx, ExExManager, ExtensionStatus,
};
use octra_node_runtime::{
    canonical::{CanonicalStore, Head, ReliefSource},
    circle::CircleRuntime,
    circle_application::CanonicalApplications,
    circle_assets::CanonicalAssets,
    finality::{EpochRules, ExecutedEpoch, Publisher, ValidatorHistory},
};
use octravpn_node::admission::Revocation;
use tokio::sync::{watch, Mutex as AsyncMutex};

pub use legacy::Status as LegacyStatus;
pub use octra_node_protocol::consensus::quarantine::RootEvidence;
pub use published::{Committed, RootQuarantineTicket, Status};
use published::{Handle as Published, Serving, Shared};
pub use services::Services;

/// Canonical finality authority with an optional local availability check.
/// Circle activation rules always come from authenticated canonical history.
pub trait Host: ValidatorHistory + 'static {
    fn check_views(&self, _head: &Head) -> Result<(), String> {
        Ok(())
    }
}

impl Host for octra_node_runtime::validator_history::Authority {}

struct Authority<A>(Arc<A>);
#[async_trait::async_trait]
impl<A: Host> ValidatorHistory for Authority<A> {
    async fn resolve(
        &self,
        parent: &Head,
        epoch: u64,
        relief: ReliefSource,
    ) -> Result<EpochRules, String> {
        self.0.resolve(parent, epoch, relief).await
    }
}

/// A successful publication stays successful if refreshing a local service
/// fails afterwards. Consumers can retry resume; they must not resubmit the
/// already committed epoch because of a browser/application configuration error.
pub struct Publication {
    pub head: Head,
    pub services: Status,
}

pub struct Node<A: Host> {
    store: Arc<CanonicalStore>,
    host: Arc<A>,
    publisher: Arc<Publisher<Authority<A>>>,
    runtime: CircleRuntime,
    view_graph: octra_node_protocol::rules::Graph,
    wallet: Arc<dyn ApplicationHost>,
    operations: Arc<AsyncMutex<()>>,
    syncing: AsyncMutex<()>,
    exex: AsyncMutex<ExExManager<NativeTransaction>>,
    shared: Arc<Shared>,
    legacy: Arc<Mutex<legacy::State>>,
    writer_lease: Arc<std::fs::File>,
}

/// A legacy observation belongs to one attempted publication. Losing its
/// caller before commit must not reuse the partially finalized Tree on retry.
struct CommitObservation {
    legacy: Arc<Mutex<legacy::State>>,
    armed: bool,
}
impl CommitObservation {
    fn committed(&mut self, head: &Head) {
        self.legacy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .committed(head);
        self.armed = false;
    }
}
impl Drop for CommitObservation {
    fn drop(&mut self) {
        if self.armed {
            self.legacy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .failed("legacy publication interrupted; restart before legacy observation".into());
        }
    }
}

impl<A: Host> Node<A> {
    /// Take exclusive ownership of the canonical writer. Audit retained finality
    /// before exposing even an ExEx source; service admission remains suspended.
    pub async fn open(
        store: CanonicalStore,
        host: A,
        runtime: CircleRuntime,
        wallet: Arc<dyn ApplicationHost>,
        checkpoints: Arc<dyn CheckpointStore>,
    ) -> Result<Self> {
        let writer = writer_lock(&store)?;
        let store = Arc::new(store);
        let host = Arc::new(host);
        let publisher = Arc::new(Publisher::open(store.clone(), Authority(host.clone())).await?);
        let exex = ExExManager::new(store.source(), checkpoints)?;
        let (legacy_head, legacy_state) = store.snapshot().await?;
        let genesis_parent = legacy_head.cursor.epoch.0 == 0
            && legacy_head.cursor.sequence.0 == 0
            && store.chain().genesis_root() == Some(legacy_head.cursor.state_root)
            && legacy_head.txid_hi == -1
            && legacy_head.parent_commit.is_none()
            && store.checkpoint_parent().is_none();
        let retained_legacy = store
            .reader()
            .epoch_legacy_digest(&legacy_head, legacy_head.cursor.epoch.0 as i64)
            .await?;
        let mut legacy = legacy::State::boot(
            legacy_head.clone(),
            &legacy_state.snapshot(),
            genesis_parent,
        )?;
        if let Some(digest) = retained_legacy {
            legacy.restore_parent(&legacy_head, &digest)?;
        }
        let view_graph = octra_node_protocol::rules::Graph::new(
            store.chain().chain_id.as_bytes().to_vec(),
            None,
        );
        Ok(Self {
            store,
            host,
            publisher,
            runtime,
            view_graph,
            wallet,
            operations: Arc::new(AsyncMutex::new(())),
            syncing: AsyncMutex::new(()),
            exex: AsyncMutex::new(exex),
            shared: Arc::new(Shared::new()),
            legacy: Arc::new(Mutex::new(legacy)),
            writer_lease: Arc::new(writer),
        })
    }

    /// Bind reads to the captured transaction-execution graph. Authentication
    /// occurs when each immutable view is built, after catch-up can supply its
    /// anchors. Changing configuration first revokes any prior service view.
    pub fn with_view_graph(mut self, graph: octra_node_protocol::rules::Graph) -> Result<Self> {
        anyhow::ensure!(
            graph.chain_id() == self.store.chain().chain_id.as_bytes(),
            "Circle graph chain differs"
        );
        self.shared.suspend("captured Circle profile changed");
        self.view_graph = graph;
        Ok(self)
    }

    pub(crate) fn published(&self) -> Published {
        Published::new(self.shared.clone())
    }

    pub fn status(&self) -> Status {
        self.shared.status()
    }
    pub async fn head(&self) -> Result<Head> {
        Ok(self.store.head().await?)
    }
    /// Wait for any already-dispatched owned commit, including a cancelled
    /// driver's SQLite/cache publication, before choosing a recovery parent.
    pub(crate) async fn quiesce(&self) -> Result<Head> {
        let _operation = self.operations.lock().await;
        self.head().await
    }
    /// Read-only, revalidated committed history for peer query services.
    pub fn history(&self) -> Arc<dyn octra_node_runtime::finality::history::History> {
        self.publisher.clone()
    }
    pub fn snapshot(&self) -> Result<Committed> {
        Ok(self.shared.current()?.committed.clone())
    }
    /// The actual live legacy Tree epoch/root count, independent of its optional
    /// unavailable parent digest and of the BFT root-history window.
    pub fn legacy_status(&self) -> Result<LegacyStatus> {
        let head = self
            .store
            .cached_head()
            .context("canonical head unavailable")?;
        self.legacy
            .lock()
            .map_err(|_| anyhow::anyhow!("legacy observation unavailable"))?
            .status(&head)
    }
    pub fn native_metrics(&self) -> Result<Vec<u8>> {
        self.legacy
            .lock()
            .map_err(|_| anyhow::anyhow!("native metrics observation unavailable"))?
            .metrics()
    }
    pub fn legacy_status_at(&self, head: &Head) -> Result<LegacyStatus> {
        self.legacy
            .lock()
            .map_err(|_| anyhow::anyhow!("legacy observation unavailable"))?
            .status(head)
    }
    /// Synchronous revocation also invalidates any in-flight resume operation.
    pub fn suspend(&self, reason: &str) {
        self.shared.suspend(reason);
    }

    /// Capture before collecting peer evidence. A newer conflict at the same
    /// head invalidates this ticket, independently of ordinary publication.
    pub fn root_quarantine_ticket(&self) -> RootQuarantineTicket {
        self.shared.root_quarantine_ticket()
    }

    pub fn root_quarantined(&self) -> bool {
        self.shared.root_quarantined()
    }

    /// Trusted recovery-controller input, after authenticated peer queries.
    /// Drain publication before checking the exact observed parent; stale
    /// samples cannot suspend a newly committed head.
    pub async fn quarantine_root_at(&self, observed: &Head, reason: &str) -> Result<bool> {
        let _operation = self.operations.lock().await;
        if self.head().await? != *observed {
            return Ok(false);
        }
        self.shared.quarantine_root(observed, reason);
        Ok(true)
    }

    /// The host must supply fresh matching root evidence. Clearing admission's
    /// conflict gate neither alters committed history nor resumes services.
    pub async fn clear_root_quarantine_at(
        &self,
        observed: &Head,
        ticket: &RootQuarantineTicket,
        evidence: RootEvidence,
        consensus_proved: bool,
    ) -> Result<bool> {
        let _operation = self.operations.lock().await;
        if self.head().await? != *observed {
            return Ok(false);
        }
        Ok(self
            .shared
            .clear_root_quarantine(ticket, evidence, consensus_proved))
    }

    /// Only a complete forward catch-up may use canonical publication as root
    /// recovery evidence. A zero-progress retry cannot clear a failed catch-up.
    pub(crate) async fn complete_catchup_at(
        &self,
        start: &Head,
        observed: &Head,
        ticket: &RootQuarantineTicket,
    ) -> Result<bool> {
        let _operation = self.operations.lock().await;
        if self.head().await? != *observed
            || observed.cursor.sequence <= start.cursor.sequence
            || start.cursor.sequence < self.store.anchor().cursor.sequence
            || self.store.retained_head(start.cursor.sequence).await? != *start
        {
            return Ok(false);
        }
        Ok(self.shared.complete_catchup(ticket))
    }

    /// Trusted local setup may inspect pinned application code before peer
    /// attestation. This grants no service, transaction or signing capability.
    pub(crate) async fn retained_view(&self) -> Result<Committed> {
        let head = self.store.head().await?;
        let assets = CanonicalAssets::capture(&self.store).await?;
        anyhow::ensure!(
            assets.identity().irmin_commit == head.irmin_commit
                && assets.identity().state_root == hex::encode(head.cursor.state_root.0),
            "canonical writer changed outside the node"
        );
        self.host.check_views(&head).map_err(anyhow::Error::msg)?;
        Ok(Committed { head, assets })
    }

    async fn serving(&self) -> Result<Serving> {
        let committed = self.retained_view().await?;
        let assets = committed.assets.clone();
        let rules = octra_node_runtime::circle_view::canonical_with_graph(
            &assets,
            &self.view_graph,
            self.publisher.as_ref(),
        )
        .await?;
        let revocation = Revocation::default();
        let application = CanonicalApplications::new(assets.clone(), self.runtime.clone(), rules)
            .with_wallet(Arc::new(Wallet {
                host: self.wallet.clone(),
                revocation: revocation.clone(),
            }));
        let router = Browser::new(Arc::new(assets.clone()), "")?
            .with_application(Arc::new(application))?
            .router();
        Ok(Serving {
            committed,
            router,
            revocation,
            observed_at: std::time::Instant::now(),
        })
    }

    /// Called by the host after catch-up. Reaudit durable history before enabling
    /// current reads and admission. Cancellation leaves services suspended.
    pub async fn resume(&self) -> Result<bool> {
        self.resume_observed(None).await
    }

    /// Resume only the exact head covered by the host's admission evidence.
    /// A concurrent canonical publication requires another authenticated query.
    pub async fn resume_at(&self, observed: &Head) -> Result<bool> {
        self.resume_observed(Some(observed)).await
    }

    async fn resume_observed(&self, observed: Option<&Head>) -> Result<bool> {
        let _sync = self.syncing.lock().await;
        let _operation = self.operations.lock().await;
        if self.root_quarantined() {
            return Ok(false);
        }
        if let Some(observed) = observed {
            if self.head().await? != *observed {
                return Ok(false);
            }
        }
        let (ticket, _) = self.shared.suspend("auditing canonical history");
        let result = async {
            self.publisher.audit().await?;
            self.serving().await
        }
        .await;
        let serving = match result {
            Ok(serving) => serving,
            Err(error) => {
                self.shared.fail(&ticket, error.to_string());
                return Err(error);
            }
        };
        self.exex.lock().await.notify_commit();
        Ok(self.shared.install(&ticket, serving))
    }

    /// The execution host supplies effects; the publisher checks their native
    /// commitments, outcome partition, receipt policy and quorum certificate.
    /// No VPN or browser change occurs for a refused certificate.
    pub async fn publish(
        &self,
        base: &Head,
        certificate: &[u8],
        executed: ExecutedEpoch,
    ) -> Result<Publication> {
        let operation = self.operations.clone().lock_owned().await;
        let observed_metrics = executed.metrics.clone();
        let material = executed
            .transactions
            .iter()
            .map(|record| record.transaction.clone())
            .collect::<Vec<_>>();
        let mut prepared = self.publisher.prepare(base, certificate, executed).await?;
        let visibility = self.shared.visibility().begin()?;
        let candidate = prepared.candidate().clone();
        let legacy_digest = {
            let mut legacy = self
                .legacy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                legacy.prepare(base, candidate.clone(), certificate, &material);
                legacy.observe_metrics(&observed_metrics);
            }));
            if observed.is_err() {
                legacy.failed("legacy observation failed".into());
            }
            legacy.pending_digest(&candidate)
        };
        let mut observation = CommitObservation {
            legacy: self.legacy.clone(),
            armed: true,
        };
        let (ticket, was_serving) = self.shared.suspend(published::PUBLICATION_REASON);
        if let Err(error) = prepared
            .retain_epoch_legacy_digest(legacy_digest.as_deref())
            .await
        {
            self.shared.fail(&ticket, error.to_string());
            return Err(error.into());
        }
        let writer = self.writer_lease.clone();
        let (completed, completion) = tokio::sync::oneshot::channel();
        if let Err(error) = std::thread::Builder::new()
            .name("octra-canonical-commit".into())
            .spawn(move || {
                // Tokio shutdown aborts ordinary owned async tasks. Retain the
                // serialization and file leases on a thread whose runtime can
                // finish SQLite COMMIT even when the calling runtime is gone.
                let outcome = (|| -> Result<_> {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    runtime.block_on(async move {
                        let _writer_lease = writer;
                        let head = prepared.commit().await?;
                        observation.committed(&head);
                        Ok::<_, anyhow::Error>((head, operation, visibility))
                    })
                })();
                let _ = completed.send(outcome);
            })
        {
            self.shared.fail(&ticket, error.to_string());
            return Err(error.into());
        }
        let outcome = completion
            .await
            .context("canonical commit worker stopped; resume before serving")
            .and_then(|completed| completed.context("canonical commit; resume before serving"));
        let (head, _operation, _visibility) = match outcome {
            Ok(completed) => completed,
            Err(error) => {
                self.shared.fail(&ticket, error.to_string());
                return Err(error);
            }
        };
        // The notification follows the durable state/history/outbox transaction.
        self.exex.lock().await.notify_commit();
        if was_serving {
            match self.serving().await {
                Ok(serving) => {
                    self.shared.install(&ticket, serving);
                }
                Err(error) => self.shared.fail(&ticket, error.to_string()),
            }
        }
        Ok(Publication {
            head,
            services: self.status(),
        })
    }

    pub async fn register<X: ExEx<NativeTransaction>>(&self, extension: X) -> Result<()> {
        Ok(self.exex.lock().await.register(extension).await?)
    }
    pub async fn extension_status(&self, name: &str) -> Option<watch::Receiver<ExtensionStatus>> {
        self.exex.lock().await.status(name)
    }
    pub async fn shutdown(&self) -> Result<()> {
        self.suspend("node stopped");
        let _operation = self.operations.lock().await;
        Ok(self.exex.lock().await.shutdown().await?)
    }
}

fn writer_lock(store: &CanonicalStore) -> Result<std::fs::File> {
    let mut path = std::fs::canonicalize(store.database_path())?.into_os_string();
    path.push(".node.lock");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        let file = options.open(path)?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .context("canonical node writer already in use")?;
        Ok(file)
    }
    #[cfg(not(unix))]
    anyhow::bail!("node writer locking requires a supported Unix host")
}

impl<A: Host> Drop for Node<A> {
    fn drop(&mut self) {
        self.shared.suspend("node dropped");
    }
}

// A request already dispatched to an old router may still be awaiting a wallet
// response when publication or catch-up revokes its snapshot. Do not disclose a
// late private response. The wallet host must additionally make admission atomic
// with current state; this guard cannot undo a submission that already happened.
struct Wallet {
    host: Arc<dyn ApplicationHost>,
    revocation: Revocation,
}
impl Wallet {
    fn current(&self) -> Result<(), octra_browser::Error> {
        if self.revocation.is_revoked() {
            Err(octra_browser::Error::SnapshotChanged)
        } else {
            Ok(())
        }
    }
}
#[async_trait::async_trait]
impl ApplicationHost for Wallet {
    async fn read(&self, request: ReadRequest) -> Result<serde_json::Value, octra_browser::Error> {
        self.current()?;
        let response = self.host.read(request).await?;
        self.current()?;
        Ok(response)
    }
    async fn submit(
        &self,
        action: ReviewedAction,
    ) -> Result<serde_json::Value, octra_browser::Error> {
        self.current()?;
        let response = self.host.submit(action).await?;
        if self.revocation.is_revoked() {
            return Err(octra_browser::Error::Unavailable(
                "submission outcome unknown after snapshot change; check transaction status".into(),
            ));
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octra_browser::application::{Context, ReadMethod};
    use tokio::sync::Notify;

    struct SlowWallet {
        entered: Arc<Notify>,
        finish: Arc<Notify>,
    }
    #[async_trait::async_trait]
    impl ApplicationHost for SlowWallet {
        async fn read(&self, _: ReadRequest) -> Result<serde_json::Value, octra_browser::Error> {
            self.entered.notify_one();
            self.finish.notified().await;
            Ok(serde_json::json!({"private": "wallet balance"}))
        }
        async fn submit(
            &self,
            _: ReviewedAction,
        ) -> Result<serde_json::Value, octra_browser::Error> {
            unreachable!()
        }
    }
    #[tokio::test]
    async fn snapshot_revocation_withholds_in_flight_private_wallet_reads() {
        let entered = Arc::new(Notify::new());
        let finish = Arc::new(Notify::new());
        let revocation = Revocation::default();
        let wallet = Wallet {
            host: Arc::new(SlowWallet {
                entered: entered.clone(),
                finish: finish.clone(),
            }),
            revocation: revocation.clone(),
        };
        let read = tokio::spawn(async move {
            wallet
                .read(ReadRequest {
                    context: Context {
                        circle_id: "fixture".into(),
                        provenance: Provenance::UnpinnedRpc,
                    },
                    method: ReadMethod::WalletBalance,
                    params: serde_json::json!({}),
                })
                .await
        });
        entered.notified().await;
        revocation.revoke();
        finish.notify_one();
        assert!(matches!(
            read.await.unwrap(),
            Err(octra_browser::Error::SnapshotChanged)
        ));
    }
}

pub mod single;
