//! Minimal STUN client (RFC 5389) for public-address discovery.
//!
//! We need exactly two operations:
//!   1. Send a `Binding Request` to a STUN server.
//!   2. Parse the `XOR-MAPPED-ADDRESS` from the response.
//!
//! No long-term credentials, no TURN. The full STUN crate stack
//! (`stun-rs`, `webrtc-rs`) is overkill for this single message
//! exchange and adds ~50 transitive deps. RFC 5389 is short enough to
//! implement in ~100 lines of carefully-laid-out Rust.
//!
//! References:
//!   - RFC 5389 §6 Message Structure
//!   - RFC 5389 §15.2 XOR-MAPPED-ADDRESS

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use tokio::net::UdpSocket;

/// Magic cookie (RFC 5389 §6).
const MAGIC_COOKIE: u32 = 0x2112_A442;
/// Binding Request message type.
const BINDING_REQUEST: u16 = 0x0001;
/// Binding Response (success) message type.
const BINDING_RESPONSE: u16 = 0x0101;
/// XOR-MAPPED-ADDRESS attribute type.
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Header length.
const HDR_LEN: usize = 20;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum StunError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("server returned non-success class: {0:04x}")]
    NonSuccess(u16),
    #[error("transaction id mismatch")]
    TxidMismatch,
    #[error("magic cookie mismatch")]
    MagicMismatch,
    #[error("response truncated")]
    Truncated,
    #[error("missing XOR-MAPPED-ADDRESS attribute")]
    MissingAttribute,
    #[error("unsupported address family: {0:02x}")]
    UnsupportedFamily(u8),
    #[error("timed out waiting for STUN response")]
    Timeout,
}

/// Send a Binding Request to `server` from a freshly-bound UDP socket
/// and return our public `SocketAddr` as seen by the server.
///
/// The socket binds to `0.0.0.0:0` (or `[::]:0` if `server` is v6).
pub async fn stun_binding_request(server: SocketAddr) -> Result<SocketAddr, StunError> {
    let bind_addr: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().expect("v6 wildcard")
    } else {
        "0.0.0.0:0".parse().expect("v4 wildcard")
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    stun_binding_via(&sock, server, Duration::from_secs(3)).await
}

/// Same as [`stun_binding_request`] but reuses an existing socket so
/// the discovered public endpoint matches the one the caller will
/// actually use for data.
pub async fn stun_binding_via(
    sock: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr, StunError> {
    let mut tx_id = [0u8; 12];
    OsRng.fill_bytes(&mut tx_id);

    // Header: type(2) length(2) cookie(4) tx_id(12).
    let mut req = [0u8; HDR_LEN];
    req[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    req[2..4].copy_from_slice(&0u16.to_be_bytes()); // no attributes
    req[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    req[8..20].copy_from_slice(&tx_id);

    sock.send_to(&req, server).await?;

    let mut buf = [0u8; 1500];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| StunError::Timeout)??;

    parse_xor_mapped(&buf[..n], &tx_id)
}

/// Parse a STUN Binding Response, returning the XOR-MAPPED-ADDRESS.
fn parse_xor_mapped(buf: &[u8], expected_tx_id: &[u8; 12]) -> Result<SocketAddr, StunError> {
    if buf.len() < HDR_LEN {
        return Err(StunError::Truncated);
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_RESPONSE {
        return Err(StunError::NonSuccess(msg_type));
    }
    let attr_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::MagicMismatch);
    }
    if &buf[8..20] != expected_tx_id {
        return Err(StunError::TxidMismatch);
    }
    let body = buf
        .get(HDR_LEN..HDR_LEN + attr_len)
        .ok_or(StunError::Truncated)?;

    let mut cursor = 0;
    while cursor + 4 <= body.len() {
        let attr_type = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
        let alen = u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]) as usize;
        cursor += 4;
        let value = body
            .get(cursor..cursor + alen)
            .ok_or(StunError::Truncated)?;
        cursor += alen;
        // Attributes are padded to 4-byte boundaries.
        cursor = (cursor + 3) & !3;

        if attr_type == XOR_MAPPED_ADDRESS {
            return decode_xor_mapped(value, expected_tx_id);
        }
    }
    Err(StunError::MissingAttribute)
}

fn decode_xor_mapped(value: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::Truncated);
    }
    let family = value[1];
    let xport = u16::from_be_bytes([value[2], value[3]]);
    let cookie_hi = ((MAGIC_COOKIE >> 16) & 0xFFFF) as u16;
    let port = xport ^ cookie_hi;

    match family {
        0x01 => {
            // IPv4: 4 bytes of XOR-addr.
            if value.len() < 8 {
                return Err(StunError::Truncated);
            }
            let xa = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let addr = xa ^ MAGIC_COOKIE;
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(addr.to_be_bytes())),
                port,
            ))
        }
        0x02 => {
            // IPv6: 16 bytes XORed with magic cookie + transaction id.
            if value.len() < 20 {
                return Err(StunError::Truncated);
            }
            let mut xor_pad = [0u8; 16];
            xor_pad[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            xor_pad[4..].copy_from_slice(tx_id);
            let mut addr_bytes = [0u8; 16];
            for i in 0..16 {
                addr_bytes[i] = value[4 + i] ^ xor_pad[i];
            }
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(addr_bytes)),
                port,
            ))
        }
        other => Err(StunError::UnsupportedFamily(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use tokio::net::UdpSocket;

    /// Build a synthetic STUN Binding Response containing the given
    /// mapped address. Useful for testing the parser without a server.
    fn build_response(tx_id: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        // Header.
        out.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        // Attribute body length: type(2) + length(2) + value(8 or 20).
        let attr_value_len = if mapped.is_ipv4() { 8 } else { 20 };
        let attr_len = 4 + attr_value_len;
        out.extend_from_slice(&(attr_len as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(tx_id);
        // Attribute header.
        out.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        out.extend_from_slice(&(attr_value_len as u16).to_be_bytes());
        // XOR-MAPPED-ADDRESS value.
        let xport = mapped.port() ^ ((MAGIC_COOKIE >> 16) as u16);
        out.push(0);
        match mapped.ip() {
            IpAddr::V4(a) => {
                out.push(0x01);
                out.extend_from_slice(&xport.to_be_bytes());
                let xa = u32::from_be_bytes(a.octets()) ^ MAGIC_COOKIE;
                out.extend_from_slice(&xa.to_be_bytes());
            }
            IpAddr::V6(a) => {
                out.push(0x02);
                out.extend_from_slice(&xport.to_be_bytes());
                let mut xor_pad = [0u8; 16];
                xor_pad[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                xor_pad[4..].copy_from_slice(tx_id);
                let mut xa = [0u8; 16];
                for i in 0..16 {
                    xa[i] = a.octets()[i] ^ xor_pad[i];
                }
                out.extend_from_slice(&xa);
            }
        }
        out
    }

    #[test]
    fn parse_v4_xor_mapped_address_round_trip() {
        let tx_id = [1u8; 12];
        let want = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 51820);
        let buf = build_response(&tx_id, want);
        let got = parse_xor_mapped(&buf, &tx_id).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn parse_v6_xor_mapped_address_round_trip() {
        let tx_id = [42u8; 12];
        let want = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            12345,
        );
        let buf = build_response(&tx_id, want);
        let got = parse_xor_mapped(&buf, &tx_id).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn parser_rejects_wrong_txid() {
        let tx_id = [1u8; 12];
        let mut buf = build_response(&tx_id, "10.0.0.1:1".parse().unwrap());
        buf[8] ^= 0xff;
        assert!(matches!(
            parse_xor_mapped(&buf, &tx_id),
            Err(StunError::TxidMismatch)
        ));
    }

    #[test]
    fn parser_rejects_wrong_cookie() {
        let tx_id = [1u8; 12];
        let mut buf = build_response(&tx_id, "10.0.0.1:1".parse().unwrap());
        buf[4] ^= 0xff;
        assert!(matches!(
            parse_xor_mapped(&buf, &tx_id),
            Err(StunError::MagicMismatch)
        ));
    }

    /// End-to-end round-trip against a tiny in-process STUN responder.
    #[tokio::test]
    async fn round_trip_against_local_responder() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            // Parse request to fish out the tx_id; reply with mapped=from.
            let mut tx_id = [0u8; 12];
            tx_id.copy_from_slice(&buf[8..20]);
            let resp = build_response(&tx_id, from);
            server.send_to(&resp, from).await.unwrap();
            let _ = n;
        });
        let mine = stun_binding_request(server_addr).await.unwrap();
        // The server reported us back as "from"; we just check the addr is
        // a loopback (the kernel picks the port for us).
        assert!(mine.ip().is_loopback(), "got: {mine}");
        server_task.await.unwrap();
    }
}
