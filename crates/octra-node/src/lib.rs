//! One canonical publication boundary for browsing, VPN admission and ExEx.
//!
//! The live validator driver publishes through `consensus::Canonical`. Proposal
//! execution and authenticated activation history remain explicit host inputs.
//! A host must exclusively own the canonical writer and explicitly resume
//! serving after catch-up. Restart starts suspended, even with valid history.
pub mod consensus;
pub mod devnet;
pub mod driver;
pub mod executor;
pub mod gateway;
pub mod import;
pub mod peers;
pub mod proposal;
pub mod rpc;
mod services;
mod storage;
pub mod sync;
pub mod vpn;

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::Router;
use octra_browser::{
    application::{ApplicationHost, ReadRequest, ReviewedAction},
    http::Browser,
    Provenance,
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
    state_batch::Snapshot,
};
use octravpn_node::admission::Revocation;
use tokio::sync::{watch, Mutex as AsyncMutex};

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

/// One immutable, published tree. Application adapters must validate their code
/// pin and all authorization/funding fields against this same tree.
#[derive(Clone)]
pub struct Committed {
    head: Head,
    assets: CanonicalAssets,
}
impl Committed {
    pub fn head(&self) -> &Head {
        &self.head
    }
    pub fn state(&self) -> &Snapshot {
        self.assets.snapshot()
    }
    pub fn provenance(&self) -> Provenance {
        use octra_browser::AssetResolver;
        self.assets.provenance()
    }
}

struct Serving {
    committed: Committed,
    router: Router,
    revocation: Revocation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Suspended(String),
    Serving(Box<Head>),
}

struct State {
    serving: Option<Arc<Serving>>,
    reason: String,
    // Identity, rather than a wrapping counter, prevents an old resume from
    // undoing a newer pause while it was awaiting disk or history validation.
    ticket: Arc<()>,
}
struct Shared(Mutex<State>);
impl Shared {
    fn new() -> Self {
        Self(Mutex::new(State {
            serving: None,
            reason: "awaiting catch-up".into(),
            ticket: Arc::new(()),
        }))
    }
    fn current(&self) -> Result<Arc<Serving>> {
        let state = self.0.lock().expect("service state lock");
        state
            .serving
            .clone()
            .ok_or_else(|| anyhow::anyhow!("{}", state.reason))
    }
    fn suspend(&self, reason: &str) -> (Arc<()>, bool) {
        let mut state = self.0.lock().expect("service state lock");
        let was_serving = state.serving.take();
        if let Some(previous) = &was_serving {
            // Packet checks see revocation before a new snapshot is exposed.
            previous.revocation.revoke();
        }
        state.reason = reason.into();
        state.ticket = Arc::new(());
        (state.ticket.clone(), was_serving.is_some())
    }
    fn install(&self, ticket: &Arc<()>, serving: Serving) -> bool {
        let mut state = self.0.lock().expect("service state lock");
        if !Arc::ptr_eq(ticket, &state.ticket) {
            return false;
        }
        state.serving = Some(Arc::new(serving));
        true
    }
    fn fail(&self, ticket: &Arc<()>, reason: String) {
        let mut state = self.0.lock().expect("service state lock");
        if Arc::ptr_eq(ticket, &state.ticket) {
            state.reason = reason;
        }
    }
    fn status(&self) -> Status {
        let state = self.0.lock().expect("service state lock");
        state.serving.as_ref().map_or_else(
            || Status::Suspended(state.reason.clone()),
            |s| Status::Serving(Box::new(s.committed.head.clone())),
        )
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
    wallet: Arc<dyn ApplicationHost>,
    operations: AsyncMutex<()>,
    syncing: AsyncMutex<()>,
    exex: AsyncMutex<ExExManager<NativeTransaction>>,
    shared: Arc<Shared>,
    _writer: std::fs::File,
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
        Ok(Self {
            store,
            host,
            publisher,
            runtime,
            wallet,
            operations: AsyncMutex::new(()),
            syncing: AsyncMutex::new(()),
            exex: AsyncMutex::new(exex),
            shared: Arc::new(Shared::new()),
            _writer: writer,
        })
    }

    pub fn status(&self) -> Status {
        self.shared.status()
    }
    pub async fn head(&self) -> Result<Head> {
        Ok(self.store.head().await?)
    }
    /// Read-only, revalidated committed history for peer query services.
    pub fn history(&self) -> Arc<dyn octra_node_runtime::finality::history::History> {
        self.publisher.clone()
    }
    pub fn snapshot(&self) -> Result<Committed> {
        Ok(self.shared.current()?.committed.clone())
    }
    /// Synchronous revocation also invalidates any in-flight resume operation.
    pub fn suspend(&self, reason: &str) {
        self.shared.suspend(reason);
    }

    async fn serving(&self) -> Result<Serving> {
        let head = self.store.head().await?;
        let assets = CanonicalAssets::capture(&self.store).await?;
        anyhow::ensure!(
            assets.identity().irmin_commit == head.irmin_commit
                && assets.identity().state_root == hex::encode(head.cursor.state_root.0),
            "canonical writer changed outside the node"
        );
        self.host.check_views(&head).map_err(anyhow::Error::msg)?;
        let rules =
            octra_node_runtime::circle_view::canonical(&assets, self.publisher.as_ref()).await?;
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
            committed: Committed { head, assets },
            router,
            revocation,
        })
    }

    /// Called by the host after catch-up. Reaudit durable history before enabling
    /// current reads and admission. Cancellation leaves services suspended.
    pub async fn resume(&self) -> Result<bool> {
        let _sync = self.syncing.lock().await;
        let _operation = self.operations.lock().await;
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
        let _operation = self.operations.lock().await;
        let prepared = self.publisher.prepare(base, certificate, executed).await?;
        let (ticket, was_serving) = self.shared.suspend("publishing canonical epoch");
        let head = prepared
            .commit()
            .await
            .context("canonical commit; resume before serving")?;
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
