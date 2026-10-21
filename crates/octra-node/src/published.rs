//! One revocable, immutable service publication. Storage/finality hosts own
//! construction; services acquire no writer, signing or consensus authority.
use anyhow::Result;
use axum::Router;
use octra_browser::Provenance;
use octra_node_protocol::consensus::quarantine::{self, RootEvidence};
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

/// No current service view. Callers may wait without accepting an old view;
/// errors from staged work and root quarantine remain separate failures.
pub(crate) use octravpn_core::payments::Unavailable;

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

/// Exact service publication for application adapters. Validate funding against
/// committed(), then guard the final nonblocking handoff with with_current().
/// This lease grants no execution, signing or consensus authority.
#[derive(Clone)]
pub struct SnapshotLease {
    shared: Arc<Shared>,
    serving: Arc<Serving>,
}
impl SnapshotLease {
    pub(crate) fn capture(shared: Arc<Shared>) -> Result<Self> {
        let serving = shared.current()?;
        Ok(Self { shared, serving })
    }
    /// A revoked/busy publication retries admission; errors from current staged
    /// work remain fatal. The action must be nonblocking and perform no proof IO.
    pub(crate) fn admit<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<Option<T>> {
        match self
            .shared
            .with_current(self.committed().head(), &self.serving.revocation, || {
                Ok(action())
            }) {
            Ok(result) => result.map(Some),
            Err(_) => Ok(None),
        }
    }
    pub fn committed(&self) -> &Committed {
        &self.serving.committed
    }
    pub fn age(&self) -> Duration {
        self.serving.observed_at.elapsed()
    }
    /// Advisory fast check. Every handoff still needs with_current(). The caller
    /// must supply its application freshness policy; same-head resume cannot
    /// renew the original canonical observation time.
    pub fn is_live(&self, max_age: Duration) -> bool {
        !self.serving.revocation.is_revoked() && self.age() < max_age
    }
    /// Holds the publication guard through one nonblocking operation. No await,
    /// proof work or disk I/O may occur inside the closure.
    pub fn with_current<T>(
        &self,
        max_age: Duration,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.shared
            .with_current(self.committed().head(), &self.serving.revocation, || {
                if self.age() >= max_age {
                    return Err(Unavailable::new("service snapshot lease expired").into());
                }
                action()
            })
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
pub(crate) struct Shared(
    Mutex<State>,
    pub(crate) watch::Sender<()>,
    crate::epoch_visibility::Visibility,
);
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
            crate::epoch_visibility::Visibility::default(),
        )
    }
    pub(crate) fn visibility(&self) -> crate::epoch_visibility::Visibility {
        self.2.clone()
    }
    pub(crate) fn current(&self) -> Result<Arc<Serving>> {
        let state = self.0.lock().expect("service state lock");
        anyhow::ensure!(state.root_conflict.is_none(), "{}", state.reason());
        state
            .serving
            .clone()
            .ok_or_else(|| Unavailable::new(state.reason()).into())
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
        if state.root_conflict.as_ref().is_none_or(|(_, existing)| {
            quarantine::replace_reason(existing.as_bytes(), reason.as_bytes())
        }) {
            state.root_conflict = Some((head.clone(), reason.into()));
        }
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
    /// Guard historical proof verification without publishing a serving view.
    /// This supplies no freshness, admission, transaction or signing authority.
    #[cfg(any(test, feature = "private-payments-experimental"))]
    pub(crate) fn with_root_ticket<T>(
        &self,
        ticket: &RootQuarantineTicket,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let state = self.0.lock().expect("service state lock");
        anyhow::ensure!(
            state.root_conflict.is_none() && Arc::ptr_eq(&ticket.0, &state.root_ticket),
            "retained proof invalidated by root quarantine"
        );
        action()
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
    pub(crate) fn clear_root_quarantine(
        &self,
        ticket: &RootQuarantineTicket,
        evidence: RootEvidence,
        consensus_proved: bool,
    ) -> bool {
        self.clear_quarantine(ticket, false, |reason| {
            quarantine::root_recovery_evidence(
                reason.as_bytes(),
                evidence.as_bytes(),
                consensus_proved,
            )
            .is_some_and(|evidence| quarantine::clear_allowed(reason.as_bytes(), evidence))
        })
    }
    pub(crate) fn complete_catchup(&self, ticket: &RootQuarantineTicket) -> bool {
        self.clear_quarantine(ticket, true, |reason| {
            quarantine::clear_allowed(
                reason.as_bytes(),
                b"catchup_complete:root_verified:canonical_forward",
            )
        })
    }
    fn clear_quarantine(
        &self,
        ticket: &RootQuarantineTicket,
        allow_inactive: bool,
        allowed: impl FnOnce(&str) -> bool,
    ) -> bool {
        let mut state = self.0.lock().expect("service state lock");
        if !Arc::ptr_eq(&ticket.0, &state.root_ticket) {
            return false;
        }
        let Some((_, reason)) = &state.root_conflict else {
            return allow_inactive;
        };
        if !allowed(reason) {
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
        let state = self.0.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => {
                anyhow::Error::new(Unavailable::new("canonical view busy"))
            }
            std::sync::TryLockError::Poisoned(_) => anyhow::anyhow!("canonical view lock poisoned"),
        })?;
        anyhow::ensure!(state.root_conflict.is_none(), "{}", state.reason());
        if revocation.is_revoked()
            || !state
                .serving
                .as_ref()
                .is_some_and(|s| s.committed.head() == parent)
        {
            return Err(Unavailable::new("proposal snapshot was revoked").into());
        }
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

    fn leased_publication(fixture: &Fixture) -> Arc<Shared> {
        let shared = Arc::new(Shared::new());
        let (ticket, _) = shared.suspend("lease fixture ready");
        assert!(shared.install(&ticket, fixture.serving()));
        shared
    }

    #[tokio::test]
    async fn unavailable_views_do_not_reclassify_work_errors_or_root_quarantine() {
        let fixture = Fixture::new().await;
        let shared = leased_publication(&fixture);
        let lease = SnapshotLease::capture(shared.clone()).unwrap();
        let work = lease
            .with_current(Duration::from_secs(120), || -> Result<()> {
                anyhow::bail!("corrupt staged financial record")
            })
            .unwrap_err();
        assert!(!work.is::<Unavailable>());
        let (ticket, _) = shared.suspend("auditing canonical history");
        assert!(SnapshotLease::capture(shared.clone())
            .err()
            .unwrap()
            .is::<Unavailable>());
        assert!(lease
            .with_current(Duration::from_secs(120), || Ok(()))
            .unwrap_err()
            .is::<Unavailable>());
        assert!(shared.install(&ticket, fixture.serving()));
        assert!(SnapshotLease::capture(shared.clone()).is_ok());
        shared.quarantine_root(&fixture.head, "authenticated root conflict");
        assert!(!SnapshotLease::capture(shared)
            .err()
            .unwrap()
            .is::<Unavailable>());
        assert!(!lease
            .with_current(Duration::from_secs(120), || Ok(()))
            .unwrap_err()
            .is::<Unavailable>());
    }

    #[tokio::test]
    async fn retained_proof_ticket_does_not_publish_and_never_survives_quarantine() {
        let fixture = Fixture::new().await;
        let ticket = fixture.shared.root_quarantine_ticket();
        fixture.shared.with_root_ticket(&ticket, || Ok(())).unwrap();
        assert!(fixture.shared.current().is_err());
        fixture
            .shared
            .quarantine_root(&fixture.head, "catchup_apply_failed:invalid");
        assert!(fixture.shared.with_root_ticket(&ticket, || Ok(())).is_err());
        let blocked = fixture.shared.root_quarantine_ticket();
        assert!(fixture
            .shared
            .with_root_ticket(&blocked, || Ok(()))
            .is_err());
        assert!(fixture.shared.complete_catchup(&blocked));
        assert!(fixture.shared.with_root_ticket(&ticket, || Ok(())).is_err());
        assert!(fixture
            .shared
            .with_root_ticket(&blocked, || Ok(()))
            .is_err());
        fixture
            .shared
            .with_root_ticket(&fixture.shared.root_quarantine_ticket(), || Ok(()))
            .unwrap();
        assert!(fixture.shared.current().is_err());
    }

    #[tokio::test]
    async fn service_lease_refuses_before_publication_and_enforces_freshness() {
        assert!(SnapshotLease::capture(Arc::new(Shared::new())).is_err());
        let fixture = Fixture::new().await;
        let shared = leased_publication(&fixture);
        let lease = SnapshotLease::capture(shared).unwrap();
        assert_eq!(lease.committed().head(), &fixture.head);
        assert!(lease.is_live(Duration::from_secs(60)));
        assert!(!lease.is_live(Duration::ZERO));
        let mut called = false;
        assert!(lease
            .with_current(Duration::ZERO, || {
                called = true;
                Ok(())
            })
            .unwrap_err()
            .is::<Unavailable>());
        assert!(!called);
        assert_eq!(
            lease
                .with_current(Duration::from_secs(60), || Ok(7))
                .unwrap(),
            7
        );
    }

    #[tokio::test]
    async fn service_lease_cannot_resurrect_after_same_head_resume_or_renew_freshness() {
        let fixture = Fixture::new().await;
        let shared = leased_publication(&fixture);
        let lease = SnapshotLease::capture(shared.clone()).unwrap();
        let (ticket, _) = shared.suspend("fixture suspension");
        assert!(!lease.is_live(Duration::from_secs(60)));
        assert!(shared.install(&ticket, fixture.serving()));
        let fresh = SnapshotLease::capture(shared).unwrap();
        assert_eq!(fresh.committed().head(), lease.committed().head());
        assert_eq!(fresh.serving.observed_at, lease.serving.observed_at);
        assert!(fresh.is_live(Duration::from_secs(60)));
        let mut called = false;
        assert!(lease
            .with_current(Duration::from_secs(60), || {
                called = true;
                Ok(())
            })
            .is_err());
        assert!(!called);
    }

    #[tokio::test]
    async fn service_lease_retries_stale_generation_but_preserves_current_faults() {
        let fixture = Fixture::new().await;
        let shared = leased_publication(&fixture);
        let lease = SnapshotLease::capture(shared.clone()).unwrap();
        let staged: Result<()> = Err(anyhow::anyhow!("staged generation failed"));
        let (ticket, _) = shared.suspend("quarantine during async generation build");
        let mut called = false;
        assert!(lease
            .admit(|| {
                called = true;
                staged
            })
            .unwrap()
            .is_none());
        assert!(!called);
        assert!(shared.install(&ticket, fixture.serving()));
        let fresh = SnapshotLease::capture(shared).unwrap();
        assert_eq!(fresh.admit(|| Ok(7)).unwrap(), Some(7));
        let fault = fresh
            .admit(|| Err::<(), _>(anyhow::anyhow!("current journal corruption")))
            .unwrap_err();
        assert_eq!(fault.to_string(), "current journal corruption");
    }

    #[tokio::test]
    async fn service_lease_has_no_gateway_publication_grace_or_quarantine_bypass() {
        let fixture = Fixture::new().await;
        let shared = leased_publication(&fixture);
        let lease = SnapshotLease::capture(shared.clone()).unwrap();
        let (ticket, _) = shared.suspend(PUBLICATION_REASON);
        assert!(shared.gateway_view().is_ok());
        assert!(SnapshotLease::capture(shared.clone()).is_err());
        assert!(!lease.is_live(Duration::from_secs(60)));
        assert!(shared.install(&ticket, fixture.serving()));
        let lease = SnapshotLease::capture(shared.clone()).unwrap();
        shared.quarantine_root(&fixture.head, "authenticated root conflict");
        assert!(SnapshotLease::capture(shared).is_err());
        let mut called = false;
        assert!(lease
            .with_current(Duration::from_secs(60), || {
                called = true;
                Ok(())
            })
            .is_err());
        assert!(!called);
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
            .quarantine_root(&fixture.head, "peer_root_mismatch_at_head first conflict");
        assert!(!fixture.shared.clear_root_quarantine(
            &preconflict_query,
            RootEvidence::InSync,
            false
        ));
        let stale_query = fixture.shared.root_quarantine_ticket();
        fixture.shared.quarantine_root(
            &fixture.head,
            "peer_root_mismatch_at_head new same-head conflict",
        );
        assert!(!fixture
            .shared
            .clear_root_quarantine(&stale_query, RootEvidence::InSync, false));
        let current_query = fixture.shared.root_quarantine_ticket();
        let (before_clear, _) = fixture.shared.suspend("auditing canonical history");
        assert!(fixture
            .shared
            .clear_root_quarantine(&current_query, RootEvidence::InSync, false));
        assert!(fixture.shared.current().is_err());
        assert!(fixture.shared.gateway_view().is_err());
        assert!(!fixture.shared.install(&before_clear, fixture.serving()));
        assert!(!fixture
            .shared
            .clear_root_quarantine(&current_query, RootEvidence::InSync, false));
        let current = fixture.install();
        assert!(!current.revocation.is_revoked());
        assert_eq!(current.observed_at, previous.observed_at);
        assert!(previous.revocation.is_revoked());
    }

    #[tokio::test]
    async fn first_cause_survives_soft_observations_and_hard_causes_never_root_clear() {
        let fixture = Fixture::new().await;
        fixture.shared.quarantine_root(&fixture.head, "lag_7");
        let first = fixture.shared.root_quarantine_ticket();
        fixture
            .shared
            .quarantine_root(&fixture.head, "catchup_failed:unavailable");
        assert_eq!(fixture.shared.status(), Status::Suspended("lag_7".into()));
        assert!(!fixture
            .shared
            .clear_root_quarantine(&first, RootEvidence::InSync, true));

        let mut hard_head = fixture.head.clone();
        hard_head.cursor.epoch.0 += 1;
        fixture
            .shared
            .quarantine_root(&hard_head, "local_state_root_mismatch_at_head_1");
        let hard = fixture.shared.root_quarantine_ticket();
        fixture
            .shared
            .quarantine_root(&fixture.head, "peer_root_mismatch_at_head new sample");
        assert!(!fixture
            .shared
            .clear_root_quarantine(&hard, RootEvidence::InSync, true));
        let current = fixture.shared.root_quarantine_ticket();
        for evidence in [
            RootEvidence::InSync,
            RootEvidence::AheadCurrentRootQuorum,
            RootEvidence::SoftLagCurrentRoot,
        ] {
            assert!(!fixture
                .shared
                .clear_root_quarantine(&current, evidence, true));
        }
        assert!(!fixture.shared.complete_catchup(&current));
        let state = fixture.shared.0.lock().unwrap();
        assert_eq!(state.root_conflict.as_ref().unwrap().0, hard_head);
        assert_eq!(state.reason(), "local_state_root_mismatch_at_head_1");
    }

    #[tokio::test]
    async fn failed_catchup_requires_in_sync_consensus_or_verified_forward_recovery() {
        let fixture = Fixture::new().await;
        fixture
            .shared
            .quarantine_root(&fixture.head, "catchup_failed:unavailable");
        let ticket = fixture.shared.root_quarantine_ticket();
        assert!(!fixture
            .shared
            .clear_root_quarantine(&ticket, RootEvidence::InSync, false));
        for evidence in [
            RootEvidence::AheadWaitCurrentHead,
            RootEvidence::AheadCurrentRootQuorum,
            RootEvidence::SoftLagCurrentRoot,
        ] {
            assert!(!fixture
                .shared
                .clear_root_quarantine(&ticket, evidence, true));
        }
        assert!(fixture
            .shared
            .clear_root_quarantine(&ticket, RootEvidence::InSync, true));
        fixture
            .shared
            .quarantine_root(&fixture.head, "catchup_apply_failed:invalid");
        let ticket = fixture.shared.root_quarantine_ticket();
        assert!(fixture.shared.complete_catchup(&ticket));
        assert!(!fixture.shared.complete_catchup(&ticket));
    }
}
