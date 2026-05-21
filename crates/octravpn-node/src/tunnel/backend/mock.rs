//! `MockBackend` — an in-memory [`WgBackend`] for trait-level FSM tests.
//!
//! Identical semantics to [`super::boringtun::BoringtunBackend`] but
//! reported as `name() == "mock"` so the trait-level tests can pin
//! exactly which impl they're exercising.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::SystemTime;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use super::{InterfaceStats, IpNet, PeerStats, PresharedKey, PublicKey, WgBackend};

#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // FSM-test fields (allowed_ips / keepalive) — not asserted on but persisted
struct Entry {
    allowed_ips: Vec<IpNet>,
    endpoint: Option<SocketAddr>,
    keepalive_secs: Option<u16>,
    rx: u64,
    tx: u64,
    last_handshake_at: Option<SystemTime>,
    _psk: Option<PresharedKey>,
}

#[derive(Default)]
#[allow(dead_code)] // Used in `#[cfg(test)]` blocks across the backend tree
pub(crate) struct MockBackend {
    peers: Mutex<HashMap<[u8; 32], Entry>>,
}

impl MockBackend {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl WgBackend for MockBackend {
    async fn add_peer(
        &self,
        public_key: PublicKey,
        preshared_key: Option<PresharedKey>,
        allowed_ips: Vec<IpNet>,
        endpoint: Option<SocketAddr>,
        keepalive_secs: Option<u16>,
    ) -> Result<()> {
        let mut peers = self.peers.lock();
        let prev = peers.remove(&public_key.0).unwrap_or_default();
        peers.insert(
            public_key.0,
            Entry {
                allowed_ips,
                endpoint,
                keepalive_secs,
                rx: prev.rx,
                tx: prev.tx,
                last_handshake_at: prev.last_handshake_at,
                _psk: preshared_key,
            },
        );
        Ok(())
    }
    async fn remove_peer(&self, public_key: &PublicKey) -> Result<()> {
        self.peers.lock().remove(&public_key.0);
        Ok(())
    }
    async fn update_endpoint(&self, public_key: &PublicKey, endpoint: SocketAddr) -> Result<()> {
        let mut peers = self.peers.lock();
        let Some(e) = peers.get_mut(&public_key.0) else {
            anyhow::bail!("update_endpoint: peer not found")
        };
        e.endpoint = Some(endpoint);
        Ok(())
    }
    async fn peer_stats(&self, public_key: &PublicKey) -> Result<PeerStats> {
        let peers = self.peers.lock();
        let Some(e) = peers.get(&public_key.0) else {
            anyhow::bail!("peer_stats: peer not found")
        };
        Ok(PeerStats {
            rx_bytes: e.rx,
            tx_bytes: e.tx,
            last_handshake_at: e.last_handshake_at,
        })
    }
    async fn interface_stats(&self) -> Result<InterfaceStats> {
        let peers = self.peers.lock();
        let (mut rx, mut tx) = (0u64, 0u64);
        for e in peers.values() {
            rx += e.rx;
            tx += e.tx;
        }
        Ok(InterfaceStats {
            rx_bytes: rx,
            tx_bytes: tx,
            peer_count: peers.len(),
        })
    }
    fn name(&self) -> &'static str {
        "mock"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> PublicKey {
        PublicKey([b; 32])
    }

    /// Full FSM walk: add → update_endpoint → stats → remove. Covers
    /// the trait-level contract via the `dyn WgBackend` indirection so
    /// any impl that satisfies it (Mock today; Boringtun + Kernel
    /// soon) is exercised the same way.
    #[tokio::test]
    async fn fsm_add_update_endpoint_remove() {
        let be: Box<dyn WgBackend> = Box::new(MockBackend::new());
        be.add_peer(pk(1), None, vec![], None, None).await.unwrap();
        let s = be.interface_stats().await.unwrap();
        assert_eq!(s.peer_count, 1);
        let ep: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        be.update_endpoint(&pk(1), ep).await.unwrap();
        be.peer_stats(&pk(1)).await.unwrap();
        be.remove_peer(&pk(1)).await.unwrap();
        let s = be.interface_stats().await.unwrap();
        assert_eq!(s.peer_count, 0);
    }

    #[tokio::test]
    async fn fsm_update_endpoint_unknown_errors() {
        let be: Box<dyn WgBackend> = Box::new(MockBackend::new());
        let ep: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        let err = be.update_endpoint(&pk(2), ep).await.unwrap_err();
        assert!(err.to_string().contains("peer not found"));
    }

    #[tokio::test]
    async fn fsm_remove_unknown_is_idempotent_ok() {
        let be: Box<dyn WgBackend> = Box::new(MockBackend::new());
        // Matches the kernel `wg set peer X remove` contract.
        be.remove_peer(&pk(3)).await.unwrap();
        be.remove_peer(&pk(3)).await.unwrap();
    }
}
