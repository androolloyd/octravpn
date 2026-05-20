//! Pluggable UDP-shaped transport for OctraVPN's WireGuard data plane.
//!
//! `Transport` is the abstraction the WG forwarding path uses to put a
//! datagram on the wire and pull a datagram off the wire. Today the
//! data plane (see `crates/octravpn-node/src/tunnel.rs`) talks to
//! `tokio::net::UdpSocket` directly; this trait lets the same data
//! plane drive an obfuscation wrapper (obfs4, meek, etc.) without
//! boringtun, the receipt layer, or the onion router observing the
//! difference.
//!
//! Contract (deliberately minimal and *sync* in surface so both an
//! async impl over a tokio socket and a blocking-fallback shim can
//! satisfy it):
//!
//!   - `send_to(buf, dst)`     — put one logical WG datagram on the wire
//!   - `recv_from(buf)`        — read one logical WG datagram + its src
//!   - `local_addr()`          — bound public-facing address
//!
//! The wire encoding is implementation-defined: `DirectUdp` is a
//! pass-through; `Obfs4Transport` (in `octravpn-obfs4`) wraps the
//! datagram in obfs4-style frames. Boringtun sees only "an opaque
//! packet arrived" either way.
//!
//! Threading: the trait requires `Send + Sync` so a single instance
//! can be shared (via `Arc`) across the recv loop and any number of
//! send tasks. Implementations must guarantee that overlapping
//! `send_to` calls do not corrupt each other's frames.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

/// Pluggable UDP-shaped transport. See module docs.
pub trait Transport: Send + Sync {
    /// Put one logical datagram on the wire, addressed to `dst`. May
    /// internally fragment the datagram into multiple smaller wire
    /// frames; the receiver's `recv_from` MUST surface the datagram
    /// whole (matching UDP semantics from the boringtun side).
    fn send_to(&self, buf: &[u8], dst: SocketAddr) -> io::Result<()>;

    /// Block (or busy-loop on the runtime) until a logical datagram
    /// arrives, copy at most `buf.len()` bytes into `buf`, and return
    /// `(n, src)` where `src` is the peer that sent the datagram.
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    /// The local bind address this transport is reachable on (the
    /// public-facing UDP port for a node).
    fn local_addr(&self) -> SocketAddr;
}

/// Pass-through UDP transport. Each `send_to` becomes one
/// `UdpSocket::send_to`; each `recv_from` becomes one
/// `UdpSocket::recv_from`. This is the default for nodes that don't
/// opt into an obfuscating transport.
///
/// Wraps a `std::net::UdpSocket` rather than a tokio socket because
/// the `Transport` trait is sync. For the node's tokio-driven recv
/// loop (`crates/octravpn-node/src/tunnel.rs`) we keep using the
/// tokio socket directly; this impl exists so out-of-band tooling
/// (and the obfs4 frame tests below) can speak the same trait.
pub struct DirectUdp {
    sock: std::net::UdpSocket,
    local: SocketAddr,
}

impl DirectUdp {
    /// Bind a fresh socket on `addr`.
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let sock = std::net::UdpSocket::bind(addr)?;
        let local = sock.local_addr()?;
        Ok(Self { sock, local })
    }

    /// Wrap an already-bound socket.
    pub fn from_socket(sock: std::net::UdpSocket) -> io::Result<Self> {
        let local = sock.local_addr()?;
        Ok(Self { sock, local })
    }

    /// Convenience helper for tests that want to share the same
    /// transport between two threads. Returns an `Arc<dyn Transport>`
    /// so the wrapping crate doesn't need to re-spell the trait.
    pub fn shared(self) -> Arc<dyn Transport> {
        Arc::new(self)
    }
}

impl Transport for DirectUdp {
    fn send_to(&self, buf: &[u8], dst: SocketAddr) -> io::Result<()> {
        let mut sent = 0;
        while sent < buf.len() {
            let n = self.sock.send_to(&buf[sent..], dst)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "DirectUdp::send_to wrote 0 bytes",
                ));
            }
            sent += n;
        }
        Ok(())
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.sock.recv_from(buf)
    }

    fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn direct_udp_round_trip() {
        let a = DirectUdp::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        let b = DirectUdp::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        let b_addr = b.local_addr();

        a.send_to(b"hello obfs4 plug point", b_addr).unwrap();
        let mut buf = [0u8; 128];
        let (n, src) = b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello obfs4 plug point");
        assert_eq!(src.ip(), a.local_addr().ip());
    }

    #[test]
    fn local_addr_is_bound() {
        let s = DirectUdp::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        assert!(s.local_addr().port() > 0);
    }
}
