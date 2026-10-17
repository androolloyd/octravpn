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

/// Captured before an authenticated root query. A later conflict invalidates
/// the token even when the canonical head itself has not changed.
#[derive(Clone)]
pub struct RootQuarantineTicket(Arc<()>);

struct State {
    serving: Option<Arc<Serving>>,
    publishing_assets: Option<(RetainedAssets, Instant)>,
    reason: String,
    // Identity, rather than a wrapping counter, prevents an old resume from
    // undoing a newer pause while it was awaiting disk or history validation.
    ticket: Arc<()>,
    // Resuming the same retained head must not renew paid admission forever.
    head_observed: Option<(Head, Instant)>,
    // The originating head is diagnostic metadata, not a restriction on which
    // later authenticated canonical head may establish recovery.
    root_conflict: Option<(Head, String)>,
    root_ticket: Arc<()>,
}
impl State {
    fn reason(&self) -> &str {
        self.root_conflict
            .as_ref()
            .map_or(&self.reason, |(_, reason)| reason)
    }
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
                root_conflict: None,
                root_ticket: Arc::new(()),
            }),
            watch::channel(()).0,
        )
    }
    pub(crate) fn current(&self) -> Result<Arc<Serving>> {
        let state = self.0.lock().expect("service state lock");
        anyhow::ensure!(state.root_conflict.is_none(), "{}", state.reason());
        state
            .serving
            .clone()
            .ok_or_else(|| anyhow::anyhow!("{}", state.reason()))
    }
    /// Public assets belong to an immutable committed root. Keep that root
    /// readable briefly while its successor is published; never reuse it for
    /// catch-up, failures, wallets, execution, or VPN admission.
    pub(crate) fn gateway_view(&self) -> Result<(RetainedAssets, Arc<()>)> {
        let state = self.0.lock().expect("service state lock");
        anyhow::ensure!(state.root_conflict.is_none(), "{}", state.reason());
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
        state.root_conflict.is_none()
            && Arc::ptr_eq(ticket, &state.ticket)
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
        state.publishing_assets = if reason == PUBLICATION_REASON && state.root_conflict.is_none() {
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
    /// The owning node checks the expected canonical head under its operation
    /// lease. No ordinary publication or suspension may remove this gate.
    pub(crate) fn quarantine_root(&self, head: &Head, reason: &str) {
        let mut state = self.0.lock().expect("service state lock");
        if let Some(previous) = state.serving.take() {
            previous.revocation.revoke();
        }
        state.publishing_assets = None;
        state.root_conflict = Some((head.clone(), reason.into()));
        state.root_ticket = Arc::new(());
        state.ticket = Arc::new(());
        self.1.send_replace(());
    }
    pub(crate) fn root_quarantine_ticket(&self) -> RootQuarantineTicket {
        RootQuarantineTicket(
            self.0
                .lock()
                .expect("service state lock")
                .root_ticket
                .clone(),
        )
    }
    pub(crate) fn root_quarantined(&self) -> bool {
        self.0
            .lock()
            .expect("service state lock")
            .root_conflict
            .is_some()
    }
    /// Only the host's fresh authenticated matching sample may clear this
    /// token. Recovery still requires a new resume ticket and canonical audit.
    pub(crate) fn clear_root_quarantine(&self, ticket: &RootQuarantineTicket) -> bool {
        let mut state = self.0.lock().expect("service state lock");
        if state.root_conflict.is_none() || !Arc::ptr_eq(&ticket.0, &state.root_ticket) {
            return false;
        }
        state.root_conflict = None;
        state.root_ticket = Arc::new(());
        state.publishing_assets = None;
        state.reason = "root quarantine cleared; awaiting fresh publication".into();
        state.ticket = Arc::new(());
        self.1.send_replace(());
        true
    }
    pub(crate) fn install(&self, ticket: &Arc<()>, mut serving: Serving) -> bool {
        let mut state = self.0.lock().expect("service state lock");
        if state.root_conflict.is_some() || !Arc::ptr_eq(ticket, &state.ticket) {
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
            state.root_conflict.is_none()
                && !revocation.is_revoked()
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
        if state.root_conflict.is_some() {
            return Status::Suspended(state.reason().into());
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use octra_exex::{ChainIdentity, StateRoot};
    use octra_node_protocol::epoch_index;
    use octra_node_runtime::{canonical::CanonicalStore, state_batch::StateBatch};

    struct Fixture {
        _directory: tempfile::TempDir,
        _store: CanonicalStore,
        head: Head,
        assets: CanonicalAssets,
        shared: Shared,
    }
    impl Fixture {
        async fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let mut state = StateBatch::default();
            state.begin().unwrap();
            state.set(&[b"meta", b"last_epoch"], b"0".to_vec()).unwrap();
            state.acknowledge_commit().unwrap();
            let (_, index) =
                epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
                    .unwrap();
            let root = epoch_index::folded_state_root(
                hex::encode(state.root().unwrap()).as_bytes(),
                hex::encode(index).as_bytes(),
            )
            .unwrap();
            let store = CanonicalStore::create(
                &directory.path().join("canonical.db"),
                ChainIdentity::genesis("root-quarantine-fixture", StateRoot(root)),
                state.snapshot(),
                0,
            )
            .await
            .unwrap();
            let head = store.head().await.unwrap();
            let assets = CanonicalAssets::capture(&store).await.unwrap();
            Self {
                _directory: directory,
                _store: store,
                head,
                assets,
                shared: Shared::new(),
            }
        }
        fn serving(&self) -> Serving {
            Serving {
                committed: Committed {
                    head: self.head.clone(),
                    assets: self.assets.clone(),
                },
                router: Router::new(),
                revocation: Revocation::default(),
                observed_at: Instant::now(),
            }
        }
        fn install(&self) -> Arc<Serving> {
            let (ticket, _) = self.shared.suspend("fixture ready");
            assert!(self.shared.install(&ticket, self.serving()));
            self.shared.current().unwrap()
        }
    }

    #[tokio::test]
    async fn root_conflict_revokes_current_gateway_and_inflight_resume_tickets() {
        let fixture = Fixture::new().await;
        let previous = fixture.install();
        let (_, gateway_ticket) = fixture.shared.gateway_view().unwrap();
        let old_resume = fixture.shared.0.lock().unwrap().ticket.clone();
        fixture
            .shared
            .quarantine_root(&fixture.head, "authenticated root conflict");
        assert!(previous.revocation.is_revoked());
        assert!(fixture.shared.current().is_err());
        assert!(fixture.shared.gateway_view().is_err());
        assert!(!fixture.shared.gateway_view_still_valid(&gateway_ticket));
        assert!(fixture
            .shared
            .with_current(&fixture.head, &Revocation::default(), || Ok(()))
            .is_err());
        assert!(!fixture.shared.install(&old_resume, fixture.serving()));
        assert_eq!(
            fixture.shared.status(),
            Status::Suspended("authenticated root conflict".into())
        );
        let state = fixture.shared.0.lock().unwrap();
        assert_eq!(state.root_conflict.as_ref().unwrap().0, fixture.head);
    }

    #[tokio::test]
    async fn ordinary_publication_failure_and_resume_cannot_clear_root_conflict() {
        let fixture = Fixture::new().await;
        fixture.install();
        let (publishing, _) = fixture.shared.suspend(PUBLICATION_REASON);
        assert!(
            fixture.shared.gateway_view().is_ok(),
            "ordinary publication retains read grace"
        );
        fixture
            .shared
            .quarantine_root(&fixture.head, "root conflict");
        assert!(
            fixture.shared.gateway_view().is_err(),
            "quarantine removes retained asset grace"
        );
        assert!(!fixture.shared.install(&publishing, fixture.serving()));
        let recovery = fixture.shared.root_quarantine_ticket();
        for reason in [
            PUBLICATION_REASON,
            "auditing canonical history",
            "catching up",
        ] {
            let (ticket, _) = fixture.shared.suspend(reason);
            fixture.shared.fail(&ticket, "ordinary view failure".into());
            assert!(!fixture.shared.install(&ticket, fixture.serving()));
            assert_eq!(
                fixture.shared.status(),
                Status::Suspended("root conflict".into())
            );
            assert!(Arc::ptr_eq(
                &recovery.0,
                &fixture.shared.root_quarantine_ticket().0
            ));
        }
    }

    #[tokio::test]
    async fn fresh_root_clear_requires_a_new_resume_without_renewing_same_head_age() {
        let fixture = Fixture::new().await;
        let previous = fixture.install();
        let preconflict_query = fixture.shared.root_quarantine_ticket();
        fixture
            .shared
            .quarantine_root(&fixture.head, "first conflict");
        assert!(!fixture.shared.clear_root_quarantine(&preconflict_query));
        let stale_query = fixture.shared.root_quarantine_ticket();
        fixture
            .shared
            .quarantine_root(&fixture.head, "new same-head conflict");
        assert!(!fixture.shared.clear_root_quarantine(&stale_query));
        let current_query = fixture.shared.root_quarantine_ticket();
        let (before_clear, _) = fixture.shared.suspend("auditing canonical history");
        assert!(fixture.shared.clear_root_quarantine(&current_query));
        assert!(fixture.shared.current().is_err());
        assert!(fixture.shared.gateway_view().is_err());
        assert!(!fixture.shared.install(&before_clear, fixture.serving()));
        assert!(!fixture.shared.clear_root_quarantine(&current_query));
        let current = fixture.install();
        assert!(!current.revocation.is_revoked());
        assert_eq!(current.observed_at, previous.observed_at);
        assert!(previous.revocation.is_revoked());
    }
}
