//! One revocable, immutable service publication. Storage/finality hosts own
//! construction; services acquire no writer, signing or consensus authority.
use anyhow::Result;
use axum::Router;
use octra_browser::Provenance;
use octra_node_runtime::{canonical::Head, circle_assets::CanonicalAssets, state_batch::Snapshot};
use octravpn_node::admission::Revocation;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

/// One immutable, published tree. Application adapters must validate their code
/// pin and all authorization/funding fields against this same tree.
#[derive(Clone)]
pub struct Committed {
    pub(crate) head: Head,
    pub(crate) assets: CanonicalAssets,
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

pub(crate) struct Serving {
    pub(crate) committed: Committed,
    pub(crate) router: Router,
    pub(crate) revocation: Revocation,
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
pub(crate) struct Shared(Mutex<State>, pub(crate) watch::Sender<()>);
impl Shared {
    pub(crate) fn new() -> Self {
        Self(
            Mutex::new(State {
                serving: None,
                reason: "awaiting catch-up".into(),
                ticket: Arc::new(()),
            }),
            watch::channel(()).0,
        )
    }
    pub(crate) fn current(&self) -> Result<Arc<Serving>> {
        let state = self.0.lock().expect("service state lock");
        state
            .serving
            .clone()
            .ok_or_else(|| anyhow::anyhow!("{}", state.reason))
    }
    pub(crate) fn suspend(&self, reason: &str) -> (Arc<()>, bool) {
        let mut state = self.0.lock().expect("service state lock");
        let was_serving = state.serving.take();
        if let Some(previous) = &was_serving {
            // Packet checks see revocation before a new snapshot is exposed.
            previous.revocation.revoke();
        }
        state.reason = reason.into();
        state.ticket = Arc::new(());
        self.1.send_replace(());
        (state.ticket.clone(), was_serving.is_some())
    }
    pub(crate) fn install(&self, ticket: &Arc<()>, serving: Serving) -> bool {
        let mut state = self.0.lock().expect("service state lock");
        if !Arc::ptr_eq(ticket, &state.ticket) {
            return false;
        }
        state.serving = Some(Arc::new(serving));
        self.1.send_replace(());
        true
    }
    pub(crate) fn fail(&self, ticket: &Arc<()>, reason: String) {
        let mut state = self.0.lock().expect("service state lock");
        if Arc::ptr_eq(ticket, &state.ticket) {
            state.reason = reason;
        }
    }
    /// The lock remains held through the short queue transition. No await,
    /// proof work or disk I/O may occur inside the closure.
    pub(crate) fn with_current<T>(
        &self,
        parent: &Head,
        revocation: &Revocation,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let state = self
            .0
            .try_lock()
            .map_err(|_| anyhow::anyhow!("canonical view busy"))?;
        anyhow::ensure!(
            !revocation.is_revoked()
                && state
                    .serving
                    .as_ref()
                    .is_some_and(|s| s.committed.head() == parent),
            "proposal snapshot was revoked"
        );
        action()
    }

    pub(crate) fn status(&self) -> Status {
        let state = self.0.lock().expect("service state lock");
        state.serving.as_ref().map_or_else(
            || Status::Suspended(state.reason.clone()),
            |s| Status::Serving(Box::new(s.committed.head.clone())),
        )
    }
}

/// Shared service lifecycle without an execution/finality host parameter.
#[derive(Clone)]
pub(crate) struct Handle {
    pub(crate) shared: Arc<Shared>,
}
impl Handle {
    pub(crate) fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }
}
