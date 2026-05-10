//! Per-session onion-route bookkeeping for the node.
//!
//! When a client opens a session it sends an onion-wrapped first packet
//! addressed to this node. We peel one layer (`octravpn_core::onion::peel_layer`)
//! and stash:
//!   - the role of this hop in the route (Forward to next hop / Egress)
//!   - byte counters per direction so we can sign receipts
//!
//! Subsequent tunnel packets reuse the cached route.

use std::{collections::HashMap, sync::atomic::{AtomicU64, Ordering}};

use octravpn_core::{onion::HopAction, session::SessionId};
use parking_lot::RwLock;

#[derive(Default)]
pub struct OnionRouter {
    sessions: RwLock<HashMap<SessionId, SessionRoute>>,
}

pub struct SessionRoute {
    pub action: HopAction,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}

impl Clone for SessionRoute {
    fn clone(&self) -> Self {
        Self {
            action: self.action.clone(),
            bytes_in: AtomicU64::new(self.bytes_in.load(Ordering::Relaxed)),
            bytes_out: AtomicU64::new(self.bytes_out.load(Ordering::Relaxed)),
        }
    }
}

impl OnionRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn install(&self, session: SessionId, action: HopAction) {
        self.sessions.write().insert(
            session,
            SessionRoute {
                action,
                bytes_in: AtomicU64::new(0),
                bytes_out: AtomicU64::new(0),
            },
        );
    }

    pub fn record_bytes(&self, session: &SessionId, dir: Direction, n: u64) {
        if let Some(route) = self.sessions.read().get(session) {
            match dir {
                Direction::In => route.bytes_in.fetch_add(n, Ordering::Relaxed),
                Direction::Out => route.bytes_out.fetch_add(n, Ordering::Relaxed),
            };
        }
    }

    pub fn bytes(&self, session: &SessionId) -> Option<(u64, u64)> {
        self.sessions.read().get(session).map(|r| {
            (
                r.bytes_in.load(Ordering::Relaxed),
                r.bytes_out.load(Ordering::Relaxed),
            )
        })
    }

    pub fn action(&self, session: &SessionId) -> Option<HopAction> {
        self.sessions.read().get(session).map(|r| r.action.clone())
    }

    pub fn close(&self, session: &SessionId) {
        self.sessions.write().remove(session);
    }
}

#[derive(Clone, Copy)]
pub enum Direction {
    In,
    Out,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_and_count() {
        let r = OnionRouter::new();
        let id = SessionId([1u8; 32]);
        r.install(id.clone(), HopAction::Egress);
        r.record_bytes(&id, Direction::In, 100);
        r.record_bytes(&id, Direction::Out, 50);
        let (i, o) = r.bytes(&id).unwrap();
        assert_eq!(i, 100);
        assert_eq!(o, 50);
        assert!(matches!(r.action(&id).unwrap(), HopAction::Egress));
        r.close(&id);
        assert!(r.bytes(&id).is_none());
    }
}
