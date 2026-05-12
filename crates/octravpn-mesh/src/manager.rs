//! Mesh manager — the orchestrator that ties stun + peers + conn FSM +
//! magic DNS + subnets into one async coordinator.
//!
//! The manager doesn't own sockets or tunnels directly. Instead it
//! emits [`MeshAction`] events the host daemon consumes (open WG
//! tunnel, close WG tunnel, route subnet, etc.). This keeps the mesh
//! crate test-only-deps + lets the same logic run in `octravpn-node`
//! and `octravpn-client` without duplicating WG plumbing.

use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::Arc,
};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::{
    conn::{ConnState, ConnectionManager},
    ip_alloc::TailnetIpAllocator,
    magic_dns::MagicDns,
    peer::{PeerCandidate, PeerRegistry, PeerSnapshot},
    subnet::{SubnetAdvertisement, SubnetRouter},
};

/// Per-tick instruction for the data plane.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MeshAction {
    /// Open (or update) a peer-to-peer WireGuard tunnel directly to
    /// the given endpoint. `allowed_ips` covers the peer's tailnet IP
    /// + any subnets they advertise.
    OpenDirect {
        tailnet_id: String,
        peer_addr: String,
        peer_wg_pubkey: [u8; 32],
        endpoint: SocketAddr,
        allowed_ips: Vec<crate::subnet::Cidr>,
    },
    /// Route traffic to this peer through the named Octra validator.
    OpenRelay {
        tailnet_id: String,
        peer_addr: String,
        peer_wg_pubkey: [u8; 32],
        relay_validator: String,
        allowed_ips: Vec<crate::subnet::Cidr>,
    },
    /// Tear down whatever connection currently exists.
    Close {
        tailnet_id: String,
        peer_addr: String,
    },
}

pub struct MeshManager {
    /// This node's Octra address (used to scope publish/peer-list calls).
    self_addr: String,
    /// This node's WireGuard public key.
    self_wg_pubkey: [u8; 32],
    /// This node's currently-known candidate set (set externally via
    /// `set_self_candidates`).
    self_candidates: Mutex<Vec<PeerCandidate>>,
    peers: Arc<PeerRegistry>,
    conns: Arc<ConnectionManager>,
    dns: Arc<MagicDns>,
    subnets: Arc<SubnetRouter>,
    /// Per-tailnet set of `peer_addr`s with a currently-open data-plane
    /// connection. Tracked so closing tracks correctly across ticks.
    opened: Mutex<HashSet<(String, String)>>,
}

impl MeshManager {
    pub fn new(self_addr: impl Into<String>, self_wg_pubkey: [u8; 32]) -> Self {
        let peers = Arc::new(PeerRegistry::new());
        let conns = Arc::new(ConnectionManager::new(peers.clone()));
        Self {
            self_addr: self_addr.into(),
            self_wg_pubkey,
            self_candidates: Mutex::new(Vec::new()),
            peers,
            conns,
            dns: Arc::new(MagicDns::new()),
            subnets: Arc::new(SubnetRouter::new()),
            opened: Mutex::new(HashSet::new()),
        }
    }

    pub fn peers(&self) -> Arc<PeerRegistry> {
        self.peers.clone()
    }

    pub fn dns(&self) -> Arc<MagicDns> {
        self.dns.clone()
    }

    pub fn subnets(&self) -> Arc<SubnetRouter> {
        self.subnets.clone()
    }

    pub fn conns(&self) -> Arc<ConnectionManager> {
        self.conns.clone()
    }

    pub fn self_addr(&self) -> &str {
        &self.self_addr
    }

    pub fn set_self_candidates(&self, cands: Vec<PeerCandidate>) {
        *self.self_candidates.lock() = cands;
    }

    /// Build a `PeerSnapshot` describing ourselves in `tailnet_id`.
    /// Used both for local registry seed (so loop-back tests work) and
    /// for publishing to remote peers via the control plane.
    pub fn self_snapshot(&self, tailnet_id: &str, hostname: Option<String>) -> PeerSnapshot {
        PeerSnapshot {
            tailnet_id: tailnet_id.into(),
            addr: self.self_addr.clone(),
            wg_pubkey: self.self_wg_pubkey,
            candidates: self.self_candidates.lock().clone(),
            hostname,
            last_refresh: std::time::Instant::now(),
        }
    }

    /// Register our own hostname inside the DNS resolver and allocate
    /// our tailnet IP.
    pub fn register_self_dns(&self, tailnet_id: &str, hostname: &str) {
        let ip = TailnetIpAllocator::new(tailnet_id).allocate(&self.self_addr);
        self.dns.register(tailnet_id, hostname, ip);
    }

    /// Run one decision cycle for `tailnet_id`. Returns the list of
    /// actions the caller should apply to the data plane (open/close
    /// tunnels, etc.).
    pub fn tick(&self, tailnet_id: &str) -> Vec<MeshAction> {
        let mut actions = Vec::new();
        let mut alive: HashSet<(String, String)> = HashSet::new();
        let snapshots = self.peers.peers_in(tailnet_id, &self.self_addr);
        for peer in snapshots {
            let state = self.conns.step(tailnet_id, &peer.snapshot.addr);
            let key = (tailnet_id.to_string(), peer.snapshot.addr.clone());
            alive.insert(key.clone());
            let Some(conn) = self.conns.state(tailnet_id, &peer.snapshot.addr) else {
                continue;
            };
            let allowed_ips = self.allowed_ips_for_peer(tailnet_id, &peer.snapshot.addr);
            match state {
                ConnState::Direct => {
                    if let Some(ep) = conn.direct_via {
                        actions.push(MeshAction::OpenDirect {
                            tailnet_id: tailnet_id.into(),
                            peer_addr: peer.snapshot.addr.clone(),
                            peer_wg_pubkey: peer.snapshot.wg_pubkey,
                            endpoint: ep,
                            allowed_ips,
                        });
                    }
                }
                ConnState::Relay => {
                    if let Some(v) = conn.relay_validator.clone() {
                        actions.push(MeshAction::OpenRelay {
                            tailnet_id: tailnet_id.into(),
                            peer_addr: peer.snapshot.addr.clone(),
                            peer_wg_pubkey: peer.snapshot.wg_pubkey,
                            relay_validator: v,
                            allowed_ips,
                        });
                    }
                }
                ConnState::Init | ConnState::Probing => {
                    // Not yet ready. Don't emit anything.
                }
            }
        }
        // Anything we had open but is no longer alive → close.
        let mut opened = self.opened.lock();
        for old in opened.iter() {
            if old.0 == tailnet_id && !alive.contains(old) {
                actions.push(MeshAction::Close {
                    tailnet_id: old.0.clone(),
                    peer_addr: old.1.clone(),
                });
            }
        }
        // Replace the opened set for this tailnet with the now-alive
        // entries; preserve entries from other tailnets.
        opened.retain(|k| k.0 != tailnet_id);
        opened.extend(alive);
        actions
    }

    /// Network-migration hook. Call when the local interface set
    /// changes (wifi → cellular, dock plug, etc.). Clears cached
    /// candidates and demotes every per-peer connection in
    /// `tailnet_id` back to `Probing` so the next `tick` re-discovers.
    /// Returns the number of connections demoted.
    pub fn on_network_change(&self, tailnet_id: &str) -> usize {
        self.self_candidates.lock().clear();
        self.conns.reprobe_all(tailnet_id)
    }

    /// Advertise a subnet from this node into a tailnet.
    pub fn advertise_subnet(&self, tailnet_id: &str, cidr: crate::subnet::Cidr) {
        self.subnets.advertise(SubnetAdvertisement {
            tailnet_id: tailnet_id.into(),
            advertiser_addr: self.self_addr.clone(),
            cidr,
        });
    }

    /// Compute the AllowedIPs entries for a peer's WireGuard tunnel:
    /// the peer's /32 tailnet IP plus every subnet they currently
    /// advertise.
    fn allowed_ips_for_peer(&self, tailnet_id: &str, peer_addr: &str) -> Vec<crate::subnet::Cidr> {
        let mut out = Vec::new();
        let ip = TailnetIpAllocator::new(tailnet_id).allocate(peer_addr);
        out.push(crate::subnet::Cidr {
            network: ip,
            prefix_len: 32,
        });
        for ad in self.subnets.list(tailnet_id) {
            if ad.advertiser_addr == peer_addr {
                out.push(ad.cidr);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerCandidate;
    use std::time::Instant;

    fn snap(tid: &str, addr: &str, cands: Vec<PeerCandidate>) -> PeerSnapshot {
        PeerSnapshot {
            tailnet_id: tid.into(),
            addr: addr.into(),
            wg_pubkey: [9u8; 32],
            candidates: cands,
            hostname: Some(format!("h-{addr}")),
            last_refresh: Instant::now(),
        }
    }

    #[test]
    fn tick_emits_open_direct_when_lan_candidate() {
        let mgr = MeshManager::new("octSELF", [1u8; 32]);
        mgr.peers().publish_unverified(snap(
            "t",
            "octB",
            vec![PeerCandidate::Lan("10.0.0.1:51820".parse().unwrap())],
        ));
        mgr.tick("t"); // Probing
        let acts = mgr.tick("t"); // Direct
        assert_eq!(acts.len(), 1);
        match &acts[0] {
            MeshAction::OpenDirect { peer_addr, .. } => assert_eq!(peer_addr, "octB"),
            other => panic!("expected OpenDirect, got {other:?}"),
        }
    }

    #[test]
    fn tick_emits_open_relay_when_only_relay() {
        let mgr = MeshManager::new("octSELF", [1u8; 32]);
        mgr.peers().publish_unverified(snap(
            "t",
            "octB",
            vec![PeerCandidate::Relay {
                validator_addr: "octV".into(),
            }],
        ));
        mgr.tick("t");
        let acts = mgr.tick("t");
        assert!(acts.iter().any(|a| matches!(a, MeshAction::OpenRelay { .. })));
    }

    #[test]
    fn tick_emits_close_when_peer_disappears() {
        let mgr = MeshManager::new("octSELF", [1u8; 32]);
        mgr.peers().publish_unverified(snap(
            "t",
            "octB",
            vec![PeerCandidate::Lan("10.0.0.1:1".parse().unwrap())],
        ));
        mgr.tick("t");
        mgr.tick("t"); // Direct (open recorded)
        mgr.peers().remove("t", "octB");
        let acts = mgr.tick("t");
        assert!(acts
            .iter()
            .any(|a| matches!(a, MeshAction::Close { peer_addr, .. } if peer_addr == "octB")));
    }

    #[test]
    fn self_snapshot_carries_candidates() {
        let mgr = MeshManager::new("octSELF", [7u8; 32]);
        mgr.set_self_candidates(vec![PeerCandidate::Lan("10.0.0.99:51820".parse().unwrap())]);
        let s = mgr.self_snapshot("tnet", Some("me".into()));
        assert_eq!(s.addr, "octSELF");
        assert_eq!(s.wg_pubkey, [7u8; 32]);
        assert_eq!(s.candidates.len(), 1);
        assert_eq!(s.hostname.as_deref(), Some("me"));
    }

    #[test]
    fn on_network_change_demotes_connections() {
        let mgr = MeshManager::new("octSELF", [1u8; 32]);
        mgr.set_self_candidates(vec![PeerCandidate::Lan(
            "10.0.0.99:51820".parse().unwrap(),
        )]);
        mgr.peers().publish_unverified(snap(
            "t",
            "octB",
            vec![PeerCandidate::Lan("10.0.0.1:51820".parse().unwrap())],
        ));
        mgr.tick("t");
        mgr.tick("t"); // direct
        let s_before = mgr.conns().state("t", "octB").unwrap();
        assert_eq!(s_before.state, ConnState::Direct);

        // Simulate wifi → cellular: candidates clear, every peer goes
        // back to Probing.
        let n = mgr.on_network_change("t");
        assert!(n >= 1, "should have demoted at least one connection");
        let s_after = mgr.conns().state("t", "octB").unwrap();
        assert_eq!(s_after.state, ConnState::Probing);
        assert!(s_after.direct_via.is_none());
        // The self-candidates are cleared; caller is expected to
        // refresh STUN and re-publish.
        let snap = mgr.self_snapshot("t", None);
        assert!(snap.candidates.is_empty());
    }

    #[test]
    fn open_direct_includes_advertised_subnets_in_allowed_ips() {
        use crate::subnet::Cidr;
        let mgr = MeshManager::new("octSELF", [1u8; 32]);
        let lan_cidr = Cidr::parse("192.168.7.0/24").unwrap();
        // Peer octB advertises a subnet and exposes a LAN candidate.
        mgr.subnets().advertise(SubnetAdvertisement {
            tailnet_id: "t".into(),
            advertiser_addr: "octB".into(),
            cidr: lan_cidr,
        });
        mgr.peers().publish_unverified(snap(
            "t",
            "octB",
            vec![PeerCandidate::Lan("10.0.0.5:51820".parse().unwrap())],
        ));
        mgr.tick("t");
        let acts = mgr.tick("t");
        assert_eq!(acts.len(), 1);
        match &acts[0] {
            MeshAction::OpenDirect { allowed_ips, .. } => {
                assert!(allowed_ips.contains(&lan_cidr));
                // Plus the peer's /32 tailnet IP.
                assert!(allowed_ips.iter().any(|c| c.prefix_len == 32));
            }
            other => panic!("expected OpenDirect, got {other:?}"),
        }
    }
}
