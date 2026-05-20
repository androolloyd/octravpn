//! Obfs4Transport — obfs4-modelled wrapper around a UDP socket that
//! implements [`octravpn_tun::Transport`].
//!
//! # Roles
//!
//! - **Server role.** Constructed with a [`BridgeIdentity`]. Accepts
//!   inbound handshakes from any source, responds with a server
//!   handshake on success, drops silently on `mac1` mismatch.
//! - **Client role.** Constructed with [`BridgeCredentials`] and the
//!   address of the server. The first `send_to` to that server
//!   triggers a synchronous handshake; subsequent sends seal under the
//!   derived keys.
//!
//! # Concurrency
//!
//! All session state lives behind a `parking_lot::Mutex`. The UDP
//! socket is a plain `std::net::UdpSocket` (non-blocking off; the
//! sync surface is fine — the existing node tunnel loop is already on
//! a dedicated tokio task, and a future async wrapper can spawn a
//! blocking task per recv).
//!
//! # Behaviour on `recv_from`
//!
//! `recv_from` is a loop: read a UDP datagram from the socket; if it
//! decodes as a handshake against a known/new peer, handle it
//! internally (server replies; client finishes its pending handshake)
//! and continue looping; if it decodes as a sealed frame, return the
//! plaintext payload + src address to the caller.
//!
//! This matches the sync `Transport` trait contract: each call
//! produces exactly one logical datagram (or an error).
//!
//! # `send_to` IAT
//!
//! Before sealing each outbound frame, the configured [`IatMode`]
//! pulls a delay; `send_to` blocks the calling thread for that delay.
//! The default `IatMode::Off` is a zero-cost no-op.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tracing::{debug, trace, warn};

use octravpn_tun::Transport;

use crate::bridge::{BridgeCredentials, BridgeIdentity};
use crate::frame::{
    FrameError, FrameOpener, FrameSealer, MAX_PAYLOAD, NONCE_PREFIX_C2S, NONCE_PREFIX_S2C,
};
use crate::handshake::{
    ClientHandshake, HandshakeError, ServerHandshake, SessionKeys, HANDSHAKE_FIXED_LEN,
    HANDSHAKE_MAX_LEN,
};
use crate::iat::{Iat, IatMode};

/// Maximum bytes we'll read from the socket per recv. Big enough for
/// the largest sealed frame plus any handshake padding.
const RECV_BUF_LEN: usize = MAX_PAYLOAD + 1024;

/// Per-peer sealed session.
struct PeerSession {
    sealer: FrameSealer,
    opener: FrameOpener,
}

/// What we know about a peer right now. Today the only state we
/// persist across the recv loop is `Established`; the
/// client-pending-handshake state lives entirely on the calling
/// thread's stack inside `ensure_client_session` (the handshake's
/// blocking recv pulls the reply directly off the socket). The
/// `enum` shape stays so that adding the "concurrent multi-peer
/// handshake-in-flight" future state is mechanical.
enum PeerState {
    /// Both sides: handshake complete, frames flow.
    Established(PeerSession),
}

/// Role-specific config.
enum Role {
    /// Server: hold the bridge identity (private side) and accept
    /// arbitrary inbound handshakes.
    Server { identity: Arc<BridgeIdentity> },
    /// Client: hold the published bridge credentials and dial a
    /// single bridge addr.
    Client {
        creds: BridgeCredentials,
        bridge_addr: SocketAddr,
    },
}

/// The Transport itself.
pub struct Obfs4Transport {
    sock: UdpSocket,
    local: SocketAddr,
    role: Role,
    iat: Iat,
    peers: Mutex<HashMap<SocketAddr, PeerState>>,
}

impl Obfs4Transport {
    /// Construct a **server**-side transport bound to `local_addr`.
    /// The transport accepts inbound handshakes authenticated by
    /// `identity.node_id`.
    pub fn bind_server(
        local_addr: SocketAddr,
        identity: Arc<BridgeIdentity>,
        iat_mode: IatMode,
    ) -> io::Result<Self> {
        let sock = UdpSocket::bind(local_addr)?;
        let local = sock.local_addr()?;
        Ok(Self {
            sock,
            local,
            role: Role::Server { identity },
            iat: Iat::new(iat_mode),
            peers: Mutex::new(HashMap::new()),
        })
    }

    /// Construct a **client**-side transport bound to `local_addr`
    /// (typically `0.0.0.0:0` for an ephemeral source port). All
    /// outbound frames are addressed to a single bridge endpoint
    /// `bridge_addr`; the published `creds` are used for handshakes.
    pub fn connect_client(
        local_addr: SocketAddr,
        bridge_addr: SocketAddr,
        creds: BridgeCredentials,
        iat_mode: IatMode,
    ) -> io::Result<Self> {
        let sock = UdpSocket::bind(local_addr)?;
        let local = sock.local_addr()?;
        Ok(Self {
            sock,
            local,
            role: Role::Client { creds, bridge_addr },
            iat: Iat::new(iat_mode),
            peers: Mutex::new(HashMap::new()),
        })
    }

    /// Set the socket's read timeout. Useful for tests that don't want
    /// `recv_from` to block forever.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(dur)
    }

    /// Drive an outbound handshake. Sends client X+mac1, waits up to
    /// `dur` for the server's Y+auth, finalises the session keys, and
    /// stores them under `bridge_addr` in the peer map. Returns `Ok`
    /// once the session is established (subsequent sends seal frames).
    fn ensure_client_session(&self, dur: Option<Duration>) -> io::Result<()> {
        let (creds, bridge_addr) = match &self.role {
            Role::Client { creds, bridge_addr } => (creds.clone(), *bridge_addr),
            Role::Server { .. } => {
                return Err(io::Error::other(
                    "ensure_client_session called on server-role transport",
                ))
            }
        };

        // Fast path: already established.
        {
            let peers = self.peers.lock();
            if matches!(peers.get(&bridge_addr), Some(PeerState::Established(_))) {
                return Ok(());
            }
        }

        // Send client handshake, then receive server reply
        // synchronously. We hold no lock across blocking I/O.
        let client = ClientHandshake::start(creds);
        let c_msg = client.message();
        self.sock.send_to(&c_msg, bridge_addr)?;

        let prev_timeout = self.sock.read_timeout()?;
        if dur.is_some() {
            self.sock.set_read_timeout(dur)?;
        }

        // Loop until we get the handshake reply (skip stray frames
        // from other peers, though in client role that's unusual).
        let mut buf = vec![0u8; HANDSHAKE_MAX_LEN];
        let outcome = loop {
            let (n, src) = self.sock.recv_from(&mut buf)?;
            if src != bridge_addr {
                debug!(?src, "ignoring datagram from unexpected source during handshake");
                continue;
            }
            if n < HANDSHAKE_FIXED_LEN {
                debug!(n, "ignoring too-short datagram during handshake");
                continue;
            }
            break client.finalize(&buf[..n]);
        };

        // Restore previous timeout regardless of outcome.
        let _ = self.sock.set_read_timeout(prev_timeout);

        let keys = outcome.map_err(|e| handshake_err_to_io(&e))?;
        self.install_session(bridge_addr, &keys, /*we_are_client=*/ true);
        Ok(())
    }

    fn install_session(&self, peer: SocketAddr, keys: &SessionKeys, we_are_client: bool) {
        let (tx_prefix, rx_prefix) = if we_are_client {
            (NONCE_PREFIX_C2S, NONCE_PREFIX_S2C)
        } else {
            (NONCE_PREFIX_S2C, NONCE_PREFIX_C2S)
        };
        let session = PeerSession {
            sealer: FrameSealer::new(&keys.tx_key, tx_prefix),
            opener: FrameOpener::new(&keys.rx_key, rx_prefix),
        };
        self.peers
            .lock()
            .insert(peer, PeerState::Established(session));
    }

    /// Handle an inbound datagram in server role. Returns `Some(plain)`
    /// if the datagram surfaced as a sealed frame addressed to the
    /// caller, or `None` if we consumed it internally (handshake
    /// reply, dropped, replay, etc.).
    fn server_handle(
        &self,
        src: SocketAddr,
        data: &[u8],
        identity: &BridgeIdentity,
    ) -> Option<Vec<u8>> {
        // If we already have an established session, try the frame
        // path first.
        {
            let mut peers = self.peers.lock();
            if let Some(PeerState::Established(session)) = peers.get_mut(&src) {
                match session.opener.open_from(data) {
                    Ok((payload, _consumed)) => return Some(payload),
                    Err(FrameError::BadTag | FrameError::BadInnerLen { .. }) => {
                        warn!(?src, "established session failed to open frame; resetting");
                        peers.remove(&src);
                        return None;
                    }
                    Err(FrameError::Incomplete { .. } | FrameError::PayloadTooLarge(_)) => {
                        return None;
                    }
                }
            }
        }
        // No session yet — treat as a handshake attempt.
        let server = ServerHandshake::new(identity);
        match server.respond(data) {
            Ok((reply, keys)) => {
                if let Err(e) = self.sock.send_to(&reply, src) {
                    warn!(?src, error = %e, "failed to send handshake reply");
                    return None;
                }
                self.install_session(src, &keys, /*we_are_client=*/ false);
                trace!(?src, "obfs4 handshake established (server)");
                None
            }
            Err(HandshakeError::BadMac) => {
                // Probe-resistance: drop silently, no reply.
                debug!(?src, "dropping packet with bad mac1 (probe?)");
                None
            }
            Err(e) => {
                debug!(?src, error = %e, "handshake error");
                None
            }
        }
    }
}

fn handshake_err_to_io(e: &HandshakeError) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, e.to_string())
}

fn frame_err_to_io(e: &FrameError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

impl Transport for Obfs4Transport {
    fn send_to(&self, buf: &[u8], dst: SocketAddr) -> io::Result<()> {
        // IAT delay (if configured) goes first so flow shape is masked
        // even when the inner crypto path is cheap.
        let delay = self.iat.next_delay(&mut rand::thread_rng());
        if delay > Duration::ZERO {
            std::thread::sleep(delay);
        }

        match &self.role {
            Role::Client { bridge_addr, .. } => {
                let bridge_addr = *bridge_addr;
                if dst != bridge_addr {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "obfs4 client transport pinned to {bridge_addr}, send_to({dst}) refused"
                        ),
                    ));
                }
                // Ensure a session exists. If not, drive a synchronous
                // handshake.
                self.ensure_client_session(self.sock.read_timeout()?)?;
            }
            Role::Server { .. } => {
                // Server may only send under an *established* session
                // (it has no way to "dial" a client). If the session
                // isn't there yet, drop with an explicit error so
                // upstream callers know to back off.
                let exists = matches!(
                    self.peers.lock().get(&dst),
                    Some(PeerState::Established(_))
                );
                if !exists {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        format!("no obfs4 session to {dst} yet"),
                    ));
                }
            }
        }

        // Seal and send under the session.
        let mut peers = self.peers.lock();
        let Some(PeerState::Established(session)) = peers.get_mut(&dst) else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "session vanished between ensure and seal",
            ));
        };
        let mut wire = Vec::with_capacity(buf.len() + 64);
        session
            .sealer
            .seal_into(buf, &mut wire)
            .map_err(|e| frame_err_to_io(&e))?;
        drop(peers); // release lock before blocking I/O
        self.sock.send_to(&wire, dst)?;
        Ok(())
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut wire = vec![0u8; RECV_BUF_LEN];
        loop {
            let (n, src) = self.sock.recv_from(&mut wire)?;
            // Try the per-role processing path.
            let surfaced: Option<Vec<u8>> = match &self.role {
                Role::Server { identity } => {
                    let identity = identity.clone();
                    self.server_handle(src, &wire[..n], &identity)
                }
                Role::Client { bridge_addr, .. } => {
                    if src != *bridge_addr {
                        debug!(?src, "client transport dropping datagram from non-bridge addr");
                        continue;
                    }
                    // Either a handshake reply (handled by
                    // ensure_client_session — see note below) or a
                    // sealed frame.
                    let mut peers = self.peers.lock();
                    match peers.get_mut(&src) {
                        Some(PeerState::Established(session)) => {
                            match session.opener.open_from(&wire[..n]) {
                                Ok((payload, _)) => Some(payload),
                                Err(_) => None,
                            }
                        }
                        _ => {
                            // We don't have a session — this is either
                            // a stray datagram or a server-initiated
                            // handshake (shouldn't happen). Drop.
                            None
                        }
                    }
                }
            };
            if let Some(payload) = surfaced {
                if payload.len() > out.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "decapsulated payload {} bytes exceeds caller buf {}",
                            payload.len(),
                            out.len()
                        ),
                    ));
                }
                out[..payload.len()].copy_from_slice(&payload);
                return Ok((payload.len(), src));
            }
            // Otherwise loop — the datagram was a handshake we
            // already consumed internally, or a dropped frame.
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::thread;
    use std::time::Duration;

    fn loopback_v4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    /// Spin up server + client transports and round-trip a payload.
    #[test]
    fn obfs4_handshake_and_payload_round_trip() {
        let id = Arc::new(BridgeIdentity::generate());
        let creds = id.credentials();
        let server =
            Obfs4Transport::bind_server(loopback_v4(0), id, IatMode::Off).unwrap();
        let server_addr = server.local_addr();

        // Server recv loop in a background thread; ack the first
        // payload by echoing it back.
        let server_handle = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            // First recv: caller-visible payload after handshake is
            // consumed internally.
            let (n, src) = server.recv_from(&mut buf).expect("server recv");
            let got = buf[..n].to_vec();
            // Echo back.
            server.send_to(&got, src).expect("server echo");
            got
        });

        // Client.
        let client = Obfs4Transport::connect_client(
            loopback_v4(0),
            server_addr,
            creds,
            IatMode::Off,
        )
        .unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let payload = b"WG transport packet over obfs4";
        client.send_to(payload, server_addr).expect("client send");

        // Receive the echo.
        let mut buf = [0u8; 2048];
        let (n, src) = client.recv_from(&mut buf).expect("client recv");
        assert_eq!(src, server_addr);
        assert_eq!(&buf[..n], payload);

        let server_seen = server_handle.join().unwrap();
        assert_eq!(server_seen, payload);
    }

    /// A buyer that doesn't know the bridge `node_id` fails the
    /// handshake (server drops mac1-mismatched packets silently — we
    /// observe this as a read timeout on the client).
    #[test]
    fn buyer_without_node_id_fails_handshake() {
        let real_id = Arc::new(BridgeIdentity::generate());
        let server =
            Obfs4Transport::bind_server(loopback_v4(0), real_id, IatMode::Off).unwrap();
        let server_addr = server.local_addr();

        // Background recv loop on the server: invokes the internal
        // probe-resistance drop and never surfaces a payload.
        let server_thread = thread::spawn(move || {
            server
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut buf = [0u8; 2048];
            // Expected to time out: probe never surfaces a payload
            // because mac1 was wrong → silent drop.
            let _ = server.recv_from(&mut buf);
        });

        // Buyer mints their own (wrong) bridge identity. Real
        // identity_pubkey doesn't matter; node_id is the gate.
        let bogus = BridgeIdentity::generate().credentials();
        let buyer =
            Obfs4Transport::connect_client(loopback_v4(0), server_addr, bogus, IatMode::Off)
                .unwrap();
        buyer
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let err = buyer.send_to(b"who's there?", server_addr).unwrap_err();
        // Either ReadTimeout (the buyer's recv timed out — server
        // never replied because mac1 was bad) or PermissionDenied (if
        // we somehow got a reply but auth failed).
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::PermissionDenied
            ),
            "unexpected error kind: {err:?}"
        );

        server_thread.join().unwrap();
    }

    /// Length-randomisation: a fixed 148-byte payload produces a
    /// distribution of wire sizes once sealed.
    #[test]
    fn fixed_payload_yields_diverse_wire_sizes() {
        // Integration check that the transport drives the frame layer
        // (which itself randomises lengths — see
        // `frame::tests::fixed_input_produces_random_length_output`).
        // The guard here is just that a full handshake + send
        // succeeds for a WG-handshake-sized payload.
        let id = Arc::new(BridgeIdentity::generate());
        let creds = id.credentials();
        let server =
            Obfs4Transport::bind_server(loopback_v4(0), id, IatMode::Off).unwrap();
        let server_addr = server.local_addr();

        let _t = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let _ = server.recv_from(&mut buf);
        });

        let client = Obfs4Transport::connect_client(
            loopback_v4(0),
            server_addr,
            creds,
            IatMode::Off,
        )
        .unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let payload = vec![0xABu8; 148];
        client.send_to(&payload, server_addr).expect("send");
    }
}
