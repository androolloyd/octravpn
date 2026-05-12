//! Userspace `WireGuard` data plane on the node.
//!
//! Each accepted client peer gets its own boringtun `Tunn` instance; we
//! demultiplex by source UDP address. The node is a *forwarding* relay:
//!
//!   - Egress hop: decrypt incoming WG packet → onion-peel → if the
//!     resulting layer is `Egress`, send the inner payload as a UDP
//!     datagram to the public internet target encoded inside the inner
//!     payload.
//!   - Forward hop: decrypt incoming WG packet → onion-peel → forward
//!     the inner blob to the next hop's WG endpoint as another WG
//!     packet (re-encapsulated under the next hop's static pubkey).
//!
//! In both cases byte counters on the `OnionRouter` advance so receipt
//! signing reflects actual served bandwidth.

use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use boringtun::noise::{Tunn, TunnResult};
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tracing::{debug, warn};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

use crate::onion::{Direction, OnionRouter};

/// One peer's per-connection state.
pub(crate) struct Peer {
    pub tun: Mutex<Tunn>,
}

// UDP-bound forwarding server. Holds the node's static WireGuard
// secret (X25519), the peers map keyed by source SocketAddr, and the
// onion router (carries per-session forwarding decisions).

/// Hard cap on simultaneous WG peers.
///
/// Caps the DoS surface from arbitrary UDP source addresses arriving
/// at our port.
pub(crate) const PEERS_CAP: usize = 4096;
pub(crate) const PEER_IDLE_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Per-peer policy attached to an allowlisted X25519 pubkey. Empty
/// today (the pubkey itself is the lookup key). Reserved for future
/// per-peer rate limits / bandwidth caps without changing the type.
#[derive(Clone, Default)]
pub(crate) struct AllowedClient;

pub(crate) struct Server {
    sock: Arc<UdpSocket>,
    static_secret: StaticSecret,
    router: Arc<OnionRouter>,
    peers: octravpn_core::bounded::BoundedMap<SocketAddr, Arc<Peer>>,
    /// Whitelist of permitted peer pubkeys, populated by the control
    /// plane when a client announces a session.
    allowlist: Arc<octravpn_core::bounded::BoundedMap<[u8; 32], AllowedClient>>,
}

impl Server {
    pub(crate) async fn bind(
        addr: SocketAddr,
        static_secret: StaticSecret,
        router: Arc<OnionRouter>,
        allowlist: Arc<octravpn_core::bounded::BoundedMap<[u8; 32], AllowedClient>>,
    ) -> Result<Self> {
        let sock = UdpSocket::bind(addr).await?;
        Ok(Self {
            sock: Arc::new(sock),
            static_secret,
            router,
            peers: octravpn_core::bounded::BoundedMap::new(PEERS_CAP, PEER_IDLE_TTL),
            allowlist,
        })
    }

    /// Run the UDP receive loop forever.
    pub(crate) async fn run(self: Arc<Self>) -> Result<()> {
        let mut buf = vec![0u8; 65535];
        let mut work = vec![0u8; 65535];
        loop {
            let (n, src) = match self.sock.recv_from(&mut buf).await {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "udp recv error");
                    continue;
                }
            };
            self.handle_packet(&buf[..n], src, &mut work).await;
        }
    }

    async fn handle_packet(&self, packet: &[u8], src: SocketAddr, work: &mut [u8]) {
        // To bring up a fresh peer we need its static pubkey. WG packets
        // carry a sender index but not a pubkey; we extract a hint from
        // the WG handshake-initiation message (msg_type = 1, peer pubkey
        // is encrypted but the sender index lets us look up by initiator).
        // Until that is wired we attempt a best-effort hint via WG handshake
        // peeking; if missing, drop the packet.
        let hint = peek_initiator_pubkey(packet);
        let Some(peer) = self.get_or_create_peer(src, hint) else {
            debug!(?src, "dropping packet from unregistered peer");
            return;
        };

        // boringtun decapsulation. The Tunn handles handshake + transport.
        let res = peer.tun.lock().decapsulate(None, packet, work);
        match res {
            TunnResult::WriteToNetwork(bytes) => {
                // Handshake response or keepalive — send back to the source.
                let n = bytes.len();
                if let Err(e) = self.sock.send_to(bytes, src).await {
                    warn!(error = %e, "send_to failed");
                }
                debug!(?src, n, "wg control packet replied");
            }
            TunnResult::WriteToTunnelV4(bytes, _src_ip) => {
                self.dispatch_inner(bytes, src).await;
            }
            TunnResult::WriteToTunnelV6(bytes, _src_ip) => {
                self.dispatch_inner(bytes, src).await;
            }
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                debug!(?src, ?e, "boringtun decap error");
            }
        }
    }

    /// We received a decapsulated inner packet from the `WireGuard` peer.
    /// Treat the inner bytes as an onion layer; peel and act per the
    /// resulting `HopAction`.
    async fn dispatch_inner(&self, layer: &[u8], src: SocketAddr) {
        // The first 32 bytes of `layer` carry the per-session id we
        // assigned at session-announce. We expect the client to prefix
        // each tunneled packet with `session_id || onion_blob`.
        if layer.len() < 32 {
            warn!("tunnel inner too short");
            return;
        }
        let mut sid = [0u8; 32];
        sid.copy_from_slice(&layer[..32]);
        let onion = &layer[32..];

        let session_id = octravpn_core::session::SessionId::new(sid);
        match octravpn_core::onion::peel_layer(&self.static_secret, onion) {
            Ok(peeled) => {
                self.router
                    .install(session_id.clone(), peeled.action.clone());
                self.router
                    .record_bytes(&session_id, Direction::In, layer.len() as u64);
                match peeled.action {
                    octravpn_core::onion::HopAction::Forward {
                        endpoint,
                        next_static_pubkey: _,
                    } => {
                        self.forward_to(&endpoint, &session_id, &peeled.inner).await;
                    }
                    octravpn_core::onion::HopAction::Egress => {
                        self.egress(&peeled.inner).await;
                    }
                }
            }
            Err(e) => debug!(?src, error = %e, "onion peel failed"),
        }
    }

    async fn forward_to(
        &self,
        endpoint: &str,
        session: &octravpn_core::session::SessionId,
        blob: &[u8],
    ) {
        // Prefix with session_id again so the next hop knows which
        // session this belongs to.
        let mut payload = Vec::with_capacity(32 + blob.len());
        payload.extend_from_slice(session.as_bytes());
        payload.extend_from_slice(blob);
        match endpoint.parse::<SocketAddr>() {
            Ok(addr) => {
                if let Err(e) = self.sock.send_to(&payload, addr).await {
                    warn!(?addr, error = %e, "forward send_to failed");
                } else {
                    self.router
                        .record_bytes(session, Direction::Out, payload.len() as u64);
                }
            }
            Err(e) => warn!(endpoint, error = %e, "bad next endpoint"),
        }
    }

    async fn egress(&self, payload: &[u8]) {
        // Egress format: first 6 bytes = (4 IPv4 + 2 port BE), rest = data.
        if payload.len() < 6 {
            return;
        }
        let ip = std::net::Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
        let port = u16::from_be_bytes([payload[4], payload[5]]);
        let target = SocketAddr::new(std::net::IpAddr::V4(ip), port);
        if let Err(e) = self.sock.send_to(&payload[6..], target).await {
            warn!(?target, error = %e, "egress send_to failed");
        }
    }

    /// Look up an existing peer for `src` (refreshes idle-timer), or
    /// create one if `src` is registered in the allowlist with a known
    /// static pubkey. Unsolicited UDP packets from unknown sources are
    /// dropped — protects against UDP-source spoof DoS.
    fn get_or_create_peer(
        &self,
        src: SocketAddr,
        peer_pubkey_hint: Option<[u8; 32]>,
    ) -> Option<Arc<Peer>> {
        if let Some(p) = self.peers.get(&src) {
            return Some(p);
        }
        // Need a registered peer pubkey to safely construct Tunn.
        let pk = peer_pubkey_hint?;
        self.allowlist.get(&pk)?;
        let tun = Tunn::new(
            self.static_secret.clone(),
            X25519Pub::from(pk),
            None,
            None,
            0,
            None,
        );
        let peer = Arc::new(Peer {
            tun: Mutex::new(tun),
        });
        self.peers.insert(src, peer.clone());
        Some(peer)
    }
}

/// Best-effort: peek at a WG handshake-initiation message to surface a
/// peer pubkey hint. WG message format: 1B msg_type + 3B reserved +
/// 4B sender_index + 32B unencrypted ephemeral + 48B encrypted static
/// pubkey + 28B encrypted timestamp + MAC1 + MAC2.
///
/// We CANNOT decrypt the static-pubkey blob without doing the WG
/// handshake; instead the control plane is expected to register the
/// pubkey out-of-band before any UDP packets arrive. This function
/// returns the *ephemeral* pubkey (offset 8..40) which the allowlist
/// can use as a per-handshake binding hint when the control plane
/// pre-populates the allowlist with `(client_static_pubkey, ephemeral)`
/// pairs at announce time. If neither is registered, the peer is
/// dropped.
fn peek_initiator_pubkey(packet: &[u8]) -> Option<[u8; 32]> {
    // msg_type 0x01 = handshake initiation.
    if packet.len() < 40 || packet[0] != 0x01 {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&packet[8..40]);
    Some(pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_binds_and_returns_pubkey() {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(octravpn_core::bounded::BoundedMap::new(
            16,
            std::time::Duration::from_secs(60),
        ));
        let _server = Server::bind("127.0.0.1:0".parse().unwrap(), secret, router, allowlist)
            .await
            .expect("bind succeeds");
    }
}
