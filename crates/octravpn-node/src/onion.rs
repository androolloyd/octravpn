//! Per-session onion-route bookkeeping for the node.
//!
//! When a client opens a session it sends an onion-wrapped first packet
//! addressed to this node. We peel one layer (`octravpn_core::onion::peel_layer`)
//! and stash:
//!   - the role of this hop in the route (Forward to next hop / Egress)
//!   - byte counters per direction so we can sign receipts
//!
//! Subsequent tunnel packets reuse the cached route.

use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use octravpn_core::{onion::HopAction, session::SessionId};
use parking_lot::RwLock;

#[derive(Default)]
pub(crate) struct OnionRouter {
    sessions: RwLock<HashMap<SessionId, SessionRoute>>,
    /// Cumulative bytes seen across all sessions (survives session eviction).
    /// Exposed via /metrics as `octravpn_bytes_served_total`.
    bytes_total_in: AtomicU64,
    bytes_total_out: AtomicU64,
}

pub(crate) struct SessionRoute {
    pub action: HopAction,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    /// Perf-Data-Plane #3 onion-peel-required flag.
    ///
    /// `true` (default): every inbound layer for this session is
    /// peeled via `octravpn_core::onion::peel_layer` (or the
    /// pinned-key fast path from Perf-Data-Plane #9). This is the
    /// safe path; a relay hop MUST peel to know where to forward.
    ///
    /// `false`: the session is verified Direct
    /// (`ConnState::is_direct() == true`) and there's no relay between
    /// us and the peer. We can skip the AEAD+ECDH onion cost. The
    /// `Server::dispatch_inner` path enforces this with a debug-only
    /// `is_direct || onion_peel_required` assertion before the skip
    /// fires; a regression that mis-sets this on a relay session
    /// would panic in debug builds rather than silently leak.
    pub onion_peel_required: AtomicBool,
}

impl Clone for SessionRoute {
    fn clone(&self) -> Self {
        Self {
            action: self.action.clone(),
            bytes_in: AtomicU64::new(self.bytes_in.load(Ordering::Relaxed)),
            bytes_out: AtomicU64::new(self.bytes_out.load(Ordering::Relaxed)),
            onion_peel_required: AtomicBool::new(self.onion_peel_required.load(Ordering::Relaxed)),
        }
    }
}

impl OnionRouter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Install a route for a session. Idempotent: subsequent calls with
    /// the same `session_id` are a no-op (preserving accumulated byte
    /// counters), so the per-packet hot path may call it unconditionally.
    pub(crate) fn install(&self, session: SessionId, action: HopAction) {
        self.sessions
            .write()
            .entry(session)
            .or_insert_with(|| SessionRoute {
                action,
                bytes_in: AtomicU64::new(0),
                bytes_out: AtomicU64::new(0),
                onion_peel_required: AtomicBool::new(true),
            });
    }

    /// Mark a session as direct (onion-peel can be skipped). Called by
    /// the mesh manager when `ConnState::is_direct() == true` at
    /// session-open. Idempotent + race-free: a relay-state session
    /// that races to `set_onion_peel_required(true)` always wins on
    /// the conservative path because the datapath checks the flag
    /// every packet.
    ///
    /// `peel_required = true` is the safe default. `peel_required = false`
    /// is the optimization. The data plane's debug-only assertion
    /// guards against the mis-set case.
    #[allow(dead_code)]
    pub(crate) fn set_onion_peel_required(&self, session: &SessionId, peel_required: bool) {
        if let Some(route) = self.sessions.read().get(session) {
            route
                .onion_peel_required
                .store(peel_required, Ordering::Relaxed);
        }
    }

    /// Read the current peel-required policy for `session`. Returns
    /// `None` if the session isn't installed yet (in which case the
    /// caller MUST treat it as `true` — the conservative path).
    pub(crate) fn onion_peel_required(&self, session: &SessionId) -> Option<bool> {
        self.sessions
            .read()
            .get(session)
            .map(|r| r.onion_peel_required.load(Ordering::Relaxed))
    }

    pub(crate) fn record_bytes(&self, session: &SessionId, dir: Direction, n: u64) {
        if let Some(route) = self.sessions.read().get(session) {
            match dir {
                Direction::In => {
                    route.bytes_in.fetch_add(n, Ordering::Relaxed);
                    self.bytes_total_in.fetch_add(n, Ordering::Relaxed);
                }
                Direction::Out => {
                    route.bytes_out.fetch_add(n, Ordering::Relaxed);
                    self.bytes_total_out.fetch_add(n, Ordering::Relaxed);
                }
            }
        }
    }

    pub(crate) fn bytes(&self, session: &SessionId) -> Option<(u64, u64)> {
        self.sessions.read().get(session).map(|r| {
            (
                r.bytes_in.load(Ordering::Relaxed),
                r.bytes_out.load(Ordering::Relaxed),
            )
        })
    }

    /// Cumulative bytes (in + out) across all sessions ever served.
    pub(crate) fn total_bytes(&self) -> u64 {
        self.bytes_total_in.load(Ordering::Relaxed) + self.bytes_total_out.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    In,
    Out,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_and_count() {
        let r = OnionRouter::new();
        let id = SessionId::new([1u8; 32]);
        r.install(id.clone(), HopAction::Egress);
        r.record_bytes(&id, Direction::In, 100);
        r.record_bytes(&id, Direction::Out, 50);
        let (i, o) = r.bytes(&id).unwrap();
        assert_eq!(i, 100);
        assert_eq!(o, 50);
    }

    /// Perf-Data-Plane #3: peel-required defaults to true on install —
    /// the conservative path. A regression that flips the default
    /// would silently turn off onion routing for every fresh session.
    #[test]
    fn fresh_install_requires_peel() {
        let r = OnionRouter::new();
        let id = SessionId::new([2u8; 32]);
        r.install(id.clone(), HopAction::Egress);
        assert_eq!(r.onion_peel_required(&id), Some(true));
    }

    /// The setter flips to false (the optimization) and back; unknown
    /// sessions return None (caller MUST default-to-true).
    #[test]
    fn set_and_read_peel_required() {
        let r = OnionRouter::new();
        let id = SessionId::new([3u8; 32]);
        let unknown = SessionId::new([99u8; 32]);
        r.install(id.clone(), HopAction::Egress);

        r.set_onion_peel_required(&id, false);
        assert_eq!(r.onion_peel_required(&id), Some(false));
        r.set_onion_peel_required(&id, true);
        assert_eq!(r.onion_peel_required(&id), Some(true));
        // Unknown session: caller is expected to treat None as true.
        assert_eq!(r.onion_peel_required(&unknown), None);
    }
}
