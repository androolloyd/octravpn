//! Periodic sweeper: evicts sessions idle past TTL. Not an HTTP
//! handler; spawned once at boot by `Hub` via
//! `tokio::spawn(crate::control::run_sweeper(state.clone()))`.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::control::state::{ControlState, CONTROL_SWEEP_PERIOD};

/// Periodic sweeper: evicts sessions idle past TTL.
pub(crate) async fn run_sweeper(state: Arc<ControlState>) {
    loop {
        tokio::time::sleep(CONTROL_SWEEP_PERIOD).await;
        let n = state.sessions.sweep();
        if n > 0 {
            // Each evicted entry is a "session close" from the
            // control plane's perspective: the client stopped fetching
            // /session/:id and the BoundedMap aged its row out. Bump
            // by N so the Prometheus counter rate matches the eviction
            // log line.
            state
                .metrics
                .session_closes_total
                .fetch_add(n as u64, Ordering::Relaxed);
            tracing::debug!(evicted = n, "control plane sweep");
        }
    }
}
