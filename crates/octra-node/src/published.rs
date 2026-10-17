//! One revocable, immutable service publication. Storage/finality hosts own
//! construction; services acquire no writer, signing or consensus authority.
use anyhow::Result;
use axum::Router;
use octra_browser::Provenance;
use octra_node_runtime::{
    canonical::Head,
    circle_assets::{CanonicalAssets, RetainedAssets},
    state_batch::Snapshot,
};
use octravpn_node::admission::Revocation;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::watch;

const PUBLICATION_READ_GRACE: Duration = Duration::from_secs(15);
pub(crate) const PUBLICATION_REASON: &str = "publishing canonical epoch";

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
    pub(crate) observed_at: Instant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Suspended(String),
    Serving(Box<Head>),
}

struct State {
    serving: Option<Arc<Serving>>,
    publishing_assets: Option<(RetainedAssets, Instant)>,
    reason: String,
    // Identity, rather than a wrapping counter, prevents an old resume from
    // undoing a newer pause while it was awaiting disk or history validation.
    ticket: Arc<()>,
    // Resuming the same retained head must not renew paid admission forever.
    head_observed: Option<(Head, Instant)>,
}
pub(crate) struct Shared(Mutex<State>, pub(crate) watch::Sender<()>);
impl Shared {
    pub(crate) fn new() -> Self {
        Self(
            Mutex::new(State {
                serving: None,
                publishing_assets: None,
                reason: "awaiting catch-up".into(),
                ticket: Arc::new(()),
                head_observed: None,
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
    /// Public assets belong to an immutable committed root. Keep that root
    /// readable briefly while its successor is published; never reuse it for
    /// catch-up, failures, wallets, execution, or VPN admission.
    pub(crate) fn gateway_view(&self) -> Result<(RetainedAssets, Arc<()>)> {
        let state = self.0.lock().expect("service state lock");
        let assets = if let Some(serving) = &state.serving {
            serving.committed.assets.retained()
        } else if state.reason == PUBLICATION_REASON {
            let (assets, captured) = state
                .publishing_assets
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("{}", state.reason))?;
            anyhow::ensure!(
                captured.elapsed() <= PUBLICATION_READ_GRACE,
                "publication read grace elapsed"
            );
            assets.clone()
        } else {
            anyhow::bail!("{}", state.reason);
        };
        Ok((assets, state.ticket.clone()))
    }
    pub(crate) fn gateway_view_still_valid(&self, ticket: &Arc<()>) -> bool {
        let state = self.0.lock().expect("service state lock");
        Arc::ptr_eq(ticket, &state.ticket)
            && (state.serving.is_some()
                || (state.reason == PUBLICATION_REASON
                    && state
                        .publishing_assets
                        .as_ref()
                        .is_some_and(|(_, captured)| captured.elapsed() <= PUBLICATION_READ_GRACE)))
    }
    pub(crate) fn suspend(&self, reason: &str) -> (Arc<()>, bool) {
        let mut state = self.0.lock().expect("service state lock");
        let was_serving = state.serving.take();
        state.publishing_assets = if reason == PUBLICATION_REASON {
            was_serving
                .as_ref()
                .map(|previous| (previous.committed.assets.retained(), Instant::now()))
        } else {
            None
        };
        if let Some(previous) = &was_serving {
            // Packet checks see revocation before a new snapshot is exposed.
            previous.revocation.revoke();
        }
        state.reason = reason.into();
        state.ticket = Arc::new(());
        self.1.send_replace(());
        (state.ticket.clone(), was_serving.is_some())
    }
    pub(crate) fn install(&self, ticket: &Arc<()>, mut serving: Serving) -> bool {
        let mut state = self.0.lock().expect("service state lock");
        if !Arc::ptr_eq(ticket, &state.ticket) {
            return false;
        }
        let head = serving.committed.head();
        serving.observed_at = match &state.head_observed {
            Some((previous, observed)) if previous == head => *observed,
            _ => {
                let now = Instant::now();
                state.head_observed = Some((head.clone(), now));
                now
            }
        };
        state.serving = Some(Arc::new(serving));
        state.publishing_assets = None;
        self.1.send_replace(());
        true
    }
    pub(crate) fn fail(&self, ticket: &Arc<()>, reason: String) {
        let mut state = self.0.lock().expect("service state lock");
        if Arc::ptr_eq(ticket, &state.ticket) {
            state.reason = reason;
            state.publishing_assets = None;
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
