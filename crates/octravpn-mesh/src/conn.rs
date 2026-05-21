//! Per-peer connection state machine.
//!
//! The mesh manager wraps every reachable peer in a `Connection` whose
//! state moves through:
//!
//! ```text
//!    Init ──probe──▶ Probing ──direct success──▶ Direct
//!                       │
//!                       └──direct fail──▶ Relay
//!                                          │
//!                                          └──upgrade tick──▶ Direct
//! ```
//!
//! State transitions are explicit: the manager calls
//! `try_promote_to_direct()` periodically while a connection sits in
//! `Relay`; if the peer is now directly reachable (STUN candidate
//! responds within a short timeout), the connection upgrades.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::RwLock;

use crate::peer::{Peer, PeerCandidate, PeerRegistry};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnState {
    Init,
    Probing,
    Direct,
    Relay,
}

impl ConnState {
    /// Is this connection routing data plane traffic directly to the
    /// peer (no onion-relay hop in between)? Perf-Data-Plane #3 uses
    /// this to decide whether the data plane needs to wrap/peel the
    /// onion layer: a Direct session traverses no relay, so the onion
    /// has no recipient and we can short-circuit the AEAD+ECDH cost.
    ///
    /// Privacy invariant: a `false` return MUST mean we will *still*
    /// peel the onion. `Relay`-state connections rely on the onion
    /// for unlinkability. The `octravpn-node` data plane enforces this
    /// with a debug-only assertion before short-circuiting.
    pub fn is_direct(self) -> bool {
        matches!(self, Self::Direct)
    }
}

#[derive(Clone, Debug)]
pub struct Connection {
    pub peer_addr: String, // Octra address of the remote peer
    pub state: ConnState,
    pub direct_via: Option<SocketAddr>,
    pub relay_validator: Option<String>,
    pub last_probe: Instant,
    /// How many consecutive direct-probe failures we've seen since the
    /// last success. Used to back off the upgrade tick.
    pub direct_failures: u32,
}

impl Connection {
    pub fn new(peer_addr: impl Into<String>) -> Self {
        Self {
            peer_addr: peer_addr.into(),
            state: ConnState::Init,
            direct_via: None,
            relay_validator: None,
            last_probe: Instant::now(),
            direct_failures: 0,
        }
    }
}

pub struct ConnectionManager {
    /// `(tailnet_id, peer_addr)` → connection state.
    inner: RwLock<HashMap<(String, String), Connection>>,
    peers: Arc<PeerRegistry>,
    /// How often a `Relay` connection re-attempts an upgrade.
    upgrade_period: Duration,
}

impl ConnectionManager {
    pub fn new(peers: Arc<PeerRegistry>) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            peers,
            upgrade_period: Duration::from_secs(60),
        }
    }

    pub fn with_upgrade_period(mut self, p: Duration) -> Self {
        self.upgrade_period = p;
        self
    }

    /// Get the current snapshot of state for a peer in a tailnet.
    pub fn state(&self, tailnet_id: &str, peer_addr: &str) -> Option<Connection> {
        self.inner
            .read()
            .get(&(tailnet_id.into(), peer_addr.into()))
            .cloned()
    }

    /// Run one decision cycle for `(tailnet, peer)`. Inspects the peer
    /// registry to choose the best candidate; promotes / demotes the
    /// connection accordingly. Returns the resulting state.
    pub fn step(&self, tailnet_id: &str, peer_addr: &str) -> ConnState {
        let key = (tailnet_id.to_string(), peer_addr.to_string());
        let mut conns = self.inner.write();
        let conn = conns
            .entry(key)
            .or_insert_with(|| Connection::new(peer_addr));

        let Some(peer) = self.peers.get(tailnet_id, peer_addr) else {
            // Peer dropped out of the registry — tear down.
            conn.state = ConnState::Init;
            conn.direct_via = None;
            conn.relay_validator = None;
            return conn.state;
        };

        let now = Instant::now();
        match conn.state {
            ConnState::Init => {
                conn.state = ConnState::Probing;
                Self::pick_direct(&peer, conn);
                conn.last_probe = now;
            }
            ConnState::Probing => {
                if conn.direct_via.is_none() {
                    if Self::pick_direct(&peer, conn) {
                        conn.state = ConnState::Direct;
                    } else {
                        Self::pick_relay(&peer, conn);
                        if conn.relay_validator.is_some() {
                            conn.state = ConnState::Relay;
                        }
                    }
                } else {
                    conn.state = ConnState::Direct;
                }
            }
            ConnState::Direct => {
                // If the underlying candidate goes away, demote.
                if !peer.snapshot.candidates.iter().any(|c| {
                    matches!(c, PeerCandidate::Lan(a) | PeerCandidate::Stun(a)
                        if Some(*a) == conn.direct_via)
                }) {
                    conn.direct_via = None;
                    conn.state = ConnState::Probing;
                }
            }
            ConnState::Relay => {
                if now.duration_since(conn.last_probe) >= self.upgrade_period {
                    conn.last_probe = now;
                    if Self::pick_direct(&peer, conn) {
                        conn.state = ConnState::Direct;
                        conn.direct_failures = 0;
                    } else {
                        conn.direct_failures = conn.direct_failures.saturating_add(1);
                    }
                }
            }
        }
        conn.state
    }

    /// Run [`Self::step`] for every peer currently in the registry for
    /// `tailnet_id`. Returns the resulting state per peer for telemetry.
    pub fn step_all(&self, tailnet_id: &str, self_addr: &str) -> Vec<(String, ConnState)> {
        let peers = self.peers.peers_in(tailnet_id, self_addr);
        peers
            .into_iter()
            .map(|p| {
                let addr = p.snapshot.addr;
                let st = self.step(tailnet_id, &addr);
                (addr, st)
            })
            .collect()
    }

    pub fn forget(&self, tailnet_id: &str, peer_addr: &str) {
        self.inner
            .write()
            .remove(&(tailnet_id.into(), peer_addr.into()));
    }

    /// Demote every connection in `tailnet_id` back to `Probing` and
    /// clear the cached `direct_via` endpoint. The next `step` call
    /// re-discovers the best candidate against the (presumably
    /// refreshed) peer registry. Used by the data plane when the local
    /// network interface changes (wifi → cellular and similar).
    /// Returns the number of connections demoted.
    pub fn reprobe_all(&self, tailnet_id: &str) -> usize {
        let mut n = 0;
        let mut conns = self.inner.write();
        for ((tid, _addr), conn) in conns.iter_mut() {
            if tid == tailnet_id {
                conn.state = ConnState::Probing;
                conn.direct_via = None;
                conn.last_probe = std::time::Instant::now();
                conn.direct_failures = 0;
                n += 1;
            }
        }
        n
    }

    fn pick_direct(peer: &Peer, conn: &mut Connection) -> bool {
        // Prefer LAN candidates over STUN; both beat Relay.
        for cand in &peer.snapshot.candidates {
            if let PeerCandidate::Lan(addr) = cand {
                conn.direct_via = Some(*addr);
                return true;
            }
        }
        for cand in &peer.snapshot.candidates {
            if let PeerCandidate::Stun(addr) = cand {
                conn.direct_via = Some(*addr);
                return true;
            }
        }
        conn.direct_via = None;
        false
    }

    fn pick_relay(peer: &Peer, conn: &mut Connection) -> bool {
        for cand in &peer.snapshot.candidates {
            if let PeerCandidate::Relay { validator_addr } = cand {
                conn.relay_validator = Some(validator_addr.clone());
                return true;
            }
        }
        conn.relay_validator = None;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerSnapshot;

    fn snap(tid: &str, addr: &str, cands: Vec<PeerCandidate>) -> PeerSnapshot {
        PeerSnapshot {
            tailnet_id: tid.into(),
            addr: addr.into(),
            wg_pubkey: [0u8; 32],
            candidates: cands,
            hostname: None,
            last_refresh: Instant::now(),
        }
    }

    #[test]
    fn init_to_direct_when_lan_candidate_present() {
        let reg = Arc::new(PeerRegistry::new());
        reg.publish_unverified(snap(
            "t",
            "octB",
            vec![PeerCandidate::Lan("10.0.0.1:51820".parse().unwrap())],
        ));
        let cm = ConnectionManager::new(reg);
        assert_eq!(cm.step("t", "octB"), ConnState::Probing);
        assert_eq!(cm.step("t", "octB"), ConnState::Direct);
    }

    #[test]
    fn falls_back_to_relay_when_only_relay_candidate() {
        let reg = Arc::new(PeerRegistry::new());
        reg.publish_unverified(snap(
            "t",
            "octB",
            vec![PeerCandidate::Relay {
                validator_addr: "octV".into(),
            }],
        ));
        let cm = ConnectionManager::new(reg);
        cm.step("t", "octB");
        let s = cm.step("t", "octB");
        assert_eq!(s, ConnState::Relay);
        let st = cm.state("t", "octB").unwrap();
        assert_eq!(st.relay_validator.as_deref(), Some("octV"));
    }

    #[test]
    fn upgrades_relay_to_direct_when_lan_appears() {
        let reg = Arc::new(PeerRegistry::new());
        reg.publish_unverified(snap(
            "t",
            "octB",
            vec![PeerCandidate::Relay {
                validator_addr: "octV".into(),
            }],
        ));
        let cm = ConnectionManager::new(reg.clone()).with_upgrade_period(Duration::ZERO);
        cm.step("t", "octB"); // Init → Probing
        let s = cm.step("t", "octB"); // → Relay
        assert_eq!(s, ConnState::Relay);
        // Peer publishes a LAN candidate.
        reg.publish_unverified(snap(
            "t",
            "octB",
            vec![
                PeerCandidate::Relay {
                    validator_addr: "octV".into(),
                },
                PeerCandidate::Lan("10.0.0.2:51820".parse().unwrap()),
            ],
        ));
        // upgrade_period=0 lets the next step attempt promotion.
        let s = cm.step("t", "octB");
        assert_eq!(s, ConnState::Direct);
    }

    /// Perf-Data-Plane #3: ConnState::is_direct() reports true only
    /// for the Direct variant. This is the privacy invariant the data
    /// plane's onion-skip path keys off — a regression here would
    /// flip the conservative default and silently leak plaintext on
    /// relay flows.
    #[test]
    fn is_direct_only_for_direct_state() {
        assert!(!ConnState::Init.is_direct());
        assert!(!ConnState::Probing.is_direct());
        assert!(ConnState::Direct.is_direct());
        assert!(!ConnState::Relay.is_direct());
    }

    #[test]
    fn demotes_direct_when_candidate_disappears() {
        let reg = Arc::new(PeerRegistry::new());
        reg.publish_unverified(snap(
            "t",
            "octB",
            vec![PeerCandidate::Lan("10.0.0.1:1".parse().unwrap())],
        ));
        let cm = ConnectionManager::new(reg.clone());
        cm.step("t", "octB"); // Probing
        cm.step("t", "octB"); // Direct
                              // Peer republishes with no usable candidates.
        reg.publish_unverified(snap("t", "octB", vec![]));
        let s = cm.step("t", "octB");
        assert_eq!(s, ConnState::Probing);
    }
}
