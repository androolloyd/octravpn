//! Local publication lifecycle. A captured state can resume only while no
//! canonical write has begun since its lease was captured.
use crate::{
    published::{Serving, Shared},
    single::PublicationHook,
};
use anyhow::{ensure, Result};
use octra_node_runtime::canonical::Head;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;
struct State {
    generation: Arc<()>,
    inflight: usize,
    head: Option<Head>,
    stopped: bool,
}
pub(super) struct Bridge {
    shared: Arc<Shared>,
    state: Mutex<State>,
    changed: watch::Sender<()>,
}
pub(super) struct Lease {
    generation: Arc<()>,
    ticket: Arc<()>,
    pub(super) head: Head,
}
impl Bridge {
    pub(super) fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            state: Mutex::new(State {
                generation: Arc::new(()),
                inflight: 0,
                head: None,
                stopped: false,
            }),
            changed: watch::channel(()).0,
        }
    }
    /// Called after installing the quiesced core hook. An actual commit/revoke
    /// racing the initial read takes precedence over this startup observation.
    pub(super) fn initialize(&self, head: Head) {
        let mut state = self.state.lock().expect("local publication state");
        if !state.stopped && state.inflight == 0 && state.head.is_none() {
            state.head = Some(head);
            self.changed.send_replace(());
        }
    }
    pub(super) fn completed_head(&self) -> Option<Head> {
        let state = self.state.lock().expect("local publication state");
        if state.stopped || state.inflight != 0 {
            None
        } else {
            state.head.clone()
        }
    }
    pub(super) fn subscribe(&self) -> watch::Receiver<()> {
        self.changed.subscribe()
    }
    pub(super) fn capture(&self) -> Result<Lease> {
        let state = self.state.lock().expect("local publication state");
        ensure!(
            !state.stopped && state.inflight == 0,
            "local publication is suspended"
        );
        let head = state
            .head
            .clone()
            .ok_or_else(|| anyhow::anyhow!("local publication is not initialized"))?;
        let (ticket, _) = self.shared.suspend("authenticating local canonical view");
        Ok(Lease {
            generation: state.generation.clone(),
            ticket,
            head,
        })
    }
    fn current<T>(&self, lease: &Lease, action: impl FnOnce() -> T) -> Option<T> {
        let state = self.state.lock().expect("local publication state");
        if state.stopped
            || state.inflight != 0
            || !Arc::ptr_eq(&state.generation, &lease.generation)
            || state.head.as_ref() != Some(&lease.head)
        {
            return None;
        }
        // This same lock serializes precommit revoke with the final install.
        // The closure is private, short and performs no I/O/await/core calls.
        Some(action())
    }
    pub(super) fn install(&self, lease: &Lease, serving: Serving) -> bool {
        self.current(lease, || self.shared.install(&lease.ticket, serving))
            .unwrap_or(false)
    }
    pub(super) fn close(&self) {
        let mut state = self.state.lock().expect("local publication state");
        state.stopped = true;
        state.generation = Arc::new(());
        self.shared.suspend("local services stopped");
        self.changed.send_replace(());
    }
}
impl PublicationHook for Bridge {
    fn revoke(&self) {
        let mut state = self.state.lock().expect("local publication state");
        if state.stopped {
            return;
        }
        state.generation = Arc::new(());
        match state.inflight.checked_add(1) {
            Some(inflight) => state.inflight = inflight,
            None => state.stopped = true,
        }
        self.shared.suspend("local canonical publication");
        self.changed.send_replace(());
    }
    fn committed(&self, head: &Head) {
        let mut state = self.state.lock().expect("local publication state");
        if state.stopped {
            return;
        }
        if state.inflight == 0 {
            state.stopped = true;
            self.shared
                .suspend("local publication callback is inconsistent");
            self.changed.send_replace(());
            return;
        }
        state.inflight -= 1;
        match &state.head {
            Some(previous)
                if previous.cursor.sequence == head.cursor.sequence && previous != head =>
            {
                state.stopped = true;
                self.shared.suspend("local publication head differs");
            }
            Some(previous) if previous.cursor.sequence.0 > head.cursor.sequence.0 => {}
            _ => state.head = Some(head.clone()),
        }
        // Post-release callbacks may arrive out of order. All paired writes
        // must finish; only their highest actual head can become available.
        self.changed.send_replace(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octra_exex::{Cursor, EpochId, Sequence, StateRoot};
    fn head(sequence: u64) -> Head {
        Head {
            cursor: Cursor {
                sequence: Sequence(sequence),
                epoch: EpochId(sequence),
                state_root: StateRoot([u8::try_from(sequence).unwrap(); 32]),
            },
            ledger_root: "00".repeat(32),
            irmin_commit: "11".repeat(64),
            parent_commit: None,
            index_root: "22".repeat(32),
            index_hash: None,
            txid_hi: -1,
            date: 0,
            message: vec![],
        }
    }
    #[test]
    fn revoke_between_capture_and_install_invalidates_that_generation() {
        let bridge = Bridge::new(Arc::new(Shared::new()));
        bridge.initialize(head(0));
        let old = bridge.capture().unwrap();
        assert_eq!(bridge.current(&old, || 42), Some(42));
        bridge.revoke();
        assert!(bridge.current(&old, || 42).is_none());
        assert!(bridge.capture().is_err());
        bridge.committed(&head(1));
        assert!(bridge.current(&old, || 42).is_none());
        assert_eq!(bridge.capture().unwrap().head, head(1));
    }
    #[test]
    fn overlapping_postrelease_callbacks_keep_highest_completed_head() {
        let bridge = Bridge::new(Arc::new(Shared::new()));
        bridge.initialize(head(0));
        bridge.revoke();
        bridge.revoke();
        bridge.committed(&head(2));
        assert!(bridge.completed_head().is_none());
        assert!(bridge.capture().is_err());
        bridge.committed(&head(1));
        assert_eq!(bridge.completed_head(), Some(head(2)));
        assert_eq!(bridge.capture().unwrap().head, head(2));
        bridge.initialize(head(0));
        assert_eq!(bridge.completed_head(), Some(head(2)));
    }
    #[test]
    fn failed_commit_or_terminal_close_cannot_resume_via_later_callback() {
        let bridge = Bridge::new(Arc::new(Shared::new()));
        bridge.initialize(head(0));
        bridge.revoke(); // An interrupted write never sends committed.
        bridge.revoke();
        bridge.committed(&head(1));
        assert!(bridge.capture().is_err());
        bridge.close();
        bridge.committed(&head(2));
        bridge.initialize(head(2));
        assert!(bridge.capture().is_err());
        assert!(bridge.completed_head().is_none());
    }
    #[test]
    fn conflicting_same_sequence_and_unmatched_callbacks_suspend_permanently() {
        for conflict in [false, true] {
            let bridge = Bridge::new(Arc::new(Shared::new()));
            bridge.initialize(head(1));
            if conflict {
                bridge.revoke();
                let mut bad = head(1);
                bad.txid_hi = 1;
                bridge.committed(&bad);
            } else {
                bridge.committed(&head(2));
            }
            assert!(bridge.capture().is_err());
            assert!(bridge.completed_head().is_none());
        }
    }
}
