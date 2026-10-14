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
        refresh_admissions(&state).await;
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

/// Refresh at most 16 chain probes concurrently. RPC timeouts never extend leases.
/// An old RPC result cannot resurrect a replaced/revoked binding.
pub(crate) async fn refresh_admissions(state: &Arc<ControlState>) {
    use futures_util::{stream, StreamExt};
    let entries = state.allowlist.snapshot();
    stream::iter(entries)
        .map(|(key, binding)| async move {
            let permit = if let Some(authority) = &state.native_authority {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    authority.authorize(&binding.request, &state.receipt_context),
                )
                .await
                {
                    Ok(Ok(Some(permit)))
                        if permit.matches(&binding.request, &state.receipt_context) =>
                    {
                        Some(permit.with_service_stop(state.native_stop.clone()))
                    }
                    _ => None,
                }
            } else {
                None
            };
            let live = if !state.sessions.contains_key(&binding.request.session_id) {
                false
            } else if state.native_authority.is_some() {
                permit.is_some()
            } else if let Some(verifier) = &state.session_verifier {
                matches!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        verifier.session_opened(&binding.request)
                    )
                    .await,
                    Ok(Ok(crate::control::state::SessionAdmission::Accepted))
                )
            } else {
                // Tests without chain wiring require reannounce; never refresh from traffic.
                false
            };
            let _guard = state.admission_lock.lock();
            state.allowlist.modify(&key, |current| {
                if current.admitted_at == binding.admitted_at {
                    current.permit = permit;
                    if !state.sessions.contains_key(&current.request.session_id) {
                        state.router.remove(&current.request.session_id);
                    }
                    current.expires_at = std::time::Instant::now()
                        + if live {
                            crate::tunnel::ADMISSION_LEASE
                        } else {
                            std::time::Duration::ZERO
                        };
                }
            });
        })
        .buffer_unordered(16)
        .collect::<Vec<_>>()
        .await;
}
