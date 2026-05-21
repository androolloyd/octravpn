//! Userspace boringtun [`WgBackend`] impl (Perf-10).
//!
//! Maintains a `pubkey → PeerEntry` registry in memory. Counters are
//! incremented out-of-band by the data-plane `Server` once Perf-DP
//! wires the peer pubkey through `handle_packet`; for now they reflect
//! only what `add_peer`/`update_endpoint`/`remove_peer` have observed
//! plus what the caller has explicitly bumped via [`record_rx`] /
//! [`record_tx`]. This is enough for the FSM tests and lets the
//! kernel-backend tests share a trait-level harness.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::SystemTime;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use super::{InterfaceStats, IpNet, PeerStats, PresharedKey, PublicKey, WgBackend};

#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // allowed_ips / endpoint / keepalive_secs read once Perf-DP plumbs route lookup
struct PeerEntry {
    /// Optional preshared key. Stored so a future `Tunn::new` rebuild
    /// (e.g. after an endpoint change) reuses the same psk.
    _preshared_key: Option<PresharedKey>,
    allowed_ips: Vec<IpNet>,
    endpoint: Option<SocketAddr>,
    keepalive_secs: Option<u16>,
    rx_bytes: u64,
    tx_bytes: u64,
    last_handshake_at: Option<SystemTime>,
}

pub(crate) struct BoringtunBackend {
    peers: Mutex<HashMap<[u8; 32], PeerEntry>>,
}

impl BoringtunBackend {
    pub(crate) fn new() -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
        }
    }

    /// Bump rx counter for a peer. The data-plane decap loop calls this
    /// once Perf-DP plumbs the pubkey through; until then this is only
    /// exercised by tests. Unknown peers silently no-op (the trait
    /// promises `peer_stats` is the only key-existence check).
    #[allow(dead_code)]
    pub(crate) fn record_rx(&self, public_key: &PublicKey, n: u64) {
        if let Some(e) = self.peers.lock().get_mut(&public_key.0) {
            e.rx_bytes = e.rx_bytes.saturating_add(n);
        }
    }

    /// Bump tx counter for a peer. Unknown peers silently no-op (see
    /// [`Self::record_rx`]).
    #[allow(dead_code)]
    pub(crate) fn record_tx(&self, public_key: &PublicKey, n: u64) {
        if let Some(e) = self.peers.lock().get_mut(&public_key.0) {
            e.tx_bytes = e.tx_bytes.saturating_add(n);
        }
    }

    /// Mark a successful handshake. The boringtun `Server` doesn't
    /// distinguish handshake-complete from any other `WriteToNetwork`
    /// variant (see the TODO in `tunnel/mod.rs::handle_tunn_result`),
    /// so the data plane bumps this conservatively on every peer
    /// admission. Unknown peers silently no-op.
    #[allow(dead_code)]
    pub(crate) fn record_handshake(&self, public_key: &PublicKey) {
        if let Some(e) = self.peers.lock().get_mut(&public_key.0) {
            e.last_handshake_at = Some(SystemTime::now());
        }
    }
}

#[async_trait]
impl WgBackend for BoringtunBackend {
    async fn add_peer(
        &self,
        public_key: PublicKey,
        preshared_key: Option<PresharedKey>,
        allowed_ips: Vec<IpNet>,
        endpoint: Option<SocketAddr>,
        keepalive_secs: Option<u16>,
    ) -> Result<()> {
        let mut peers = self.peers.lock();
        // Idempotent: replace existing entry. We preserve counters
        // (rx/tx) so a re-add for, say, an allowed-ips change doesn't
        // zero out the bandwidth ledger.
        let existing = peers.remove(&public_key.0).unwrap_or_default();
        peers.insert(
            public_key.0,
            PeerEntry {
                _preshared_key: preshared_key,
                allowed_ips,
                endpoint,
                keepalive_secs,
                rx_bytes: existing.rx_bytes,
                tx_bytes: existing.tx_bytes,
                last_handshake_at: existing.last_handshake_at,
            },
        );
        Ok(())
    }

    async fn remove_peer(&self, public_key: &PublicKey) -> Result<()> {
        // No-op (returns Ok) if the peer was never added — matches the
        // kernel `wg set <iface> peer <pk> remove` semantics (the
        // kernel also silently succeeds for unknown peers).
        self.peers.lock().remove(&public_key.0);
        Ok(())
    }

    async fn update_endpoint(&self, public_key: &PublicKey, endpoint: SocketAddr) -> Result<()> {
        let mut peers = self.peers.lock();
        let Some(e) = peers.get_mut(&public_key.0) else {
            anyhow::bail!("update_endpoint: peer not found");
        };
        e.endpoint = Some(endpoint);
        Ok(())
    }

    async fn peer_stats(&self, public_key: &PublicKey) -> Result<PeerStats> {
        let peers = self.peers.lock();
        let Some(e) = peers.get(&public_key.0) else {
            anyhow::bail!("peer_stats: peer not found");
        };
        Ok(PeerStats {
            rx_bytes: e.rx_bytes,
            tx_bytes: e.tx_bytes,
            last_handshake_at: e.last_handshake_at,
        })
    }

    async fn interface_stats(&self) -> Result<InterfaceStats> {
        let peers = self.peers.lock();
        let mut rx = 0u64;
        let mut tx = 0u64;
        for e in peers.values() {
            rx = rx.saturating_add(e.rx_bytes);
            tx = tx.saturating_add(e.tx_bytes);
        }
        Ok(InterfaceStats {
            rx_bytes: rx,
            tx_bytes: tx,
            peer_count: peers.len(),
        })
    }

    fn name(&self) -> &'static str {
        "boringtun"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> PublicKey {
        PublicKey([b; 32])
    }

    fn cidr(s: &str) -> IpNet {
        let mut parts = s.split('/');
        let addr = parts.next().unwrap().parse().unwrap();
        let prefix = parts.next().unwrap().parse().unwrap();
        IpNet { addr, prefix }
    }

    #[tokio::test]
    async fn add_peer_then_remove_round_trips() {
        let be = BoringtunBackend::new();
        be.add_peer(pk(1), None, vec![cidr("10.0.0.1/32")], None, None)
            .await
            .unwrap();
        assert_eq!(be.interface_stats().await.unwrap().peer_count, 1);
        be.remove_peer(&pk(1)).await.unwrap();
        assert_eq!(be.interface_stats().await.unwrap().peer_count, 0);
    }

    #[tokio::test]
    async fn remove_unknown_peer_is_ok() {
        let be = BoringtunBackend::new();
        // Mirrors the kernel `wg set peer <pk> remove` no-op behaviour.
        be.remove_peer(&pk(7)).await.unwrap();
    }

    #[tokio::test]
    async fn update_endpoint_requires_existing_peer() {
        let be = BoringtunBackend::new();
        let ep: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let err = be
            .update_endpoint(&pk(2), ep)
            .await
            .expect_err("must reject unknown peer");
        assert!(err.to_string().contains("peer not found"));
    }

    #[tokio::test]
    async fn add_peer_is_idempotent_and_preserves_counters() {
        let be = BoringtunBackend::new();
        be.add_peer(pk(3), None, vec![], None, None).await.unwrap();
        be.record_rx(&pk(3), 100);
        be.record_tx(&pk(3), 50);

        // Re-add with new allowed-ips: counters should survive.
        be.add_peer(pk(3), None, vec![cidr("10.0.0.3/32")], None, Some(25))
            .await
            .unwrap();
        let s = be.peer_stats(&pk(3)).await.unwrap();
        assert_eq!(s.rx_bytes, 100);
        assert_eq!(s.tx_bytes, 50);
    }

    #[tokio::test]
    async fn interface_stats_sums_per_peer_counters() {
        let be = BoringtunBackend::new();
        be.add_peer(pk(4), None, vec![], None, None).await.unwrap();
        be.add_peer(pk(5), None, vec![], None, None).await.unwrap();
        be.record_rx(&pk(4), 10);
        be.record_rx(&pk(5), 7);
        be.record_tx(&pk(4), 3);
        let s = be.interface_stats().await.unwrap();
        assert_eq!(s.rx_bytes, 17);
        assert_eq!(s.tx_bytes, 3);
        assert_eq!(s.peer_count, 2);
    }

    #[tokio::test]
    async fn record_handshake_advances_timestamp() {
        let be = BoringtunBackend::new();
        be.add_peer(pk(6), None, vec![], None, None).await.unwrap();
        assert!(be
            .peer_stats(&pk(6))
            .await
            .unwrap()
            .last_handshake_at
            .is_none());
        be.record_handshake(&pk(6));
        assert!(be
            .peer_stats(&pk(6))
            .await
            .unwrap()
            .last_handshake_at
            .is_some());
    }
}
