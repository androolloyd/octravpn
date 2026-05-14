//! Magic DNS — in-process DNS resolver mapping
//! `<peer>.<tailnet>.octra` → the peer's allocated tailnet IP.
//!
//! Loosely models Tailscale's MagicDNS. The resolver listens on the
//! tailnet's router IP (port 53 by default but configurable). Each
//! tailnet client sets that address as its DNS server while connected.
//!
//! We implement only what's needed for an internal name service:
//!   - A queries for our `<peer>.<tailnet>.octra` zone → answer
//!     with the allocated IP.
//!   - Everything else → REFUSED (the client falls back to the system
//!     resolver for non-tailnet names).

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use parking_lot::RwLock;
use tokio::net::UdpSocket;

use crate::ip_alloc::TailnetIpAllocator;

/// DNS classes / opcodes (RFC 1035) we actually use.
const QCLASS_IN: u16 = 1;
const QTYPE_A: u16 = 1;
#[allow(dead_code)]
const QTYPE_AAAA: u16 = 28;

const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;
const RCODE_SERVFAIL: u8 = 2;

/// Magic-DNS zone suffix.
const ZONE: &str = "octra";

/// How long to wait for the upstream resolver before SERVFAILing.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Default)]
pub struct MagicDns {
    /// (tailnet_id → hostname → ip) registrations.
    inner: Arc<RwLock<HashMap<String, HashMap<String, Ipv4Addr>>>>,
    /// Optional upstream DNS server used for out-of-zone queries by
    /// `respond_async`. When `None`, out-of-zone returns REFUSED.
    upstream: Option<SocketAddr>,
}

impl MagicDns {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure an upstream DNS resolver (e.g. `1.1.1.1:53`). When set,
    /// `respond_async` forwards out-of-zone queries to this server.
    pub fn with_upstream(mut self, upstream: SocketAddr) -> Self {
        self.upstream = Some(upstream);
        self
    }

    /// Register a peer's `hostname` in `tailnet_id` mapped to its allocated IP.
    pub fn register(
        &self,
        tailnet_id: impl Into<String>,
        hostname: impl Into<String>,
        ip: Ipv4Addr,
    ) {
        let mut m = self.inner.write();
        m.entry(tailnet_id.into())
            .or_default()
            .insert(hostname.into(), ip);
    }

    /// Register every member of a tailnet by their human-readable
    /// hostname, computing IPs via the deterministic allocator.
    pub fn register_tailnet_members(
        &self,
        tailnet_id: &str,
        members: impl IntoIterator<Item = (String, String)>,
    ) {
        let alloc = TailnetIpAllocator::new(tailnet_id);
        for (hostname, addr) in members {
            let ip = alloc.allocate(&addr);
            self.register(tailnet_id, hostname, ip);
        }
    }

    pub fn resolve(&self, tailnet_id: &str, hostname: &str) -> Option<Ipv4Addr> {
        self.inner
            .read()
            .get(tailnet_id)
            .and_then(|m| m.get(hostname).copied())
    }

    /// Spawn the UDP DNS server on `bind`. Returns immediately.
    pub async fn spawn(&self, bind: SocketAddr) -> std::io::Result<tokio::task::JoinHandle<()>> {
        let sock = Arc::new(UdpSocket::bind(bind).await?);
        let s = self.clone();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        // Copy the request so we can move it into a task,
                        // freeing the recv buffer for the next packet.
                        let req = buf[..n].to_vec();
                        let s2 = s.clone();
                        let sock2 = sock.clone();
                        tokio::spawn(async move {
                            if let Some(reply) = s2.respond_async(&req).await {
                                let _ = sock2.send_to(&reply, from).await;
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(?e, "magic-dns recv_from");
                    }
                }
            }
        });
        Ok(handle)
    }

    /// Handle a single DNS request packet, returning a response packet
    /// or `None` if the request was unparseable.
    pub fn respond(&self, req: &[u8]) -> Option<Vec<u8>> {
        let (id, flags, qname, qtype, qclass) = parse_query(req)?;
        if qclass != QCLASS_IN {
            return Some(build_response(
                id,
                flags,
                &qname,
                qtype,
                qclass,
                RCODE_REFUSED,
                None,
            ));
        }
        // Names look like "<hostname>.<tailnet>.octra" — split off the
        // zone suffix and pass the rest to the registry.
        let parts: Vec<&str> = qname.split('.').collect();
        if parts.len() < 3 || parts.last() != Some(&ZONE) {
            return Some(build_response(
                id,
                flags,
                &qname,
                qtype,
                qclass,
                RCODE_REFUSED,
                None,
            ));
        }
        let hostname = parts[0];
        let tailnet_id = parts[1..parts.len() - 1].join(".");
        let ip = self.resolve(&tailnet_id, hostname);
        let rcode = if ip.is_some() && qtype == QTYPE_A {
            RCODE_NOERROR
        } else if qtype == QTYPE_A {
            RCODE_NXDOMAIN
        } else {
            // AAAA always says nothing for now (we're IPv4-only inside
            // the tailnet); reply NOERROR with empty answer section
            // rather than NXDOMAIN so clients fall through to A.
            RCODE_NOERROR
        };
        Some(build_response(
            id,
            flags,
            &qname,
            qtype,
            qclass,
            rcode,
            if qtype == QTYPE_A { ip } else { None },
        ))
    }

    /// Like `respond`, but for out-of-zone queries forwards to the
    /// configured upstream resolver (if any) instead of returning
    /// REFUSED. In-zone behavior is identical to `respond`.
    pub async fn respond_async(&self, req: &[u8]) -> Option<Vec<u8>> {
        let (id, _flags, qname, _qtype, qclass) = parse_query(req)?;
        // Decide whether this query is for our zone. We mirror the
        // shape used in `respond`.
        let parts: Vec<&str> = qname.split('.').collect();
        let in_zone = qclass == QCLASS_IN && parts.len() >= 3 && parts.last() == Some(&ZONE);
        if in_zone {
            return self.respond(req);
        }
        // Out of zone: forward to upstream if configured, else REFUSED
        // (preserves sync behavior for callers without an upstream).
        match self.upstream {
            Some(upstream) => Some(forward_upstream(req, upstream, id).await),
            None => self.respond(req),
        }
    }
}

/// Forward `req` to `upstream` and return its reply verbatim. On
/// timeout or any I/O error, synthesize a SERVFAIL response that
/// preserves the original transaction ID and question section.
async fn forward_upstream(req: &[u8], upstream: SocketAddr, id: u16) -> Vec<u8> {
    match tokio::time::timeout(UPSTREAM_TIMEOUT, forward_once(req, upstream)).await {
        Ok(Ok(reply)) => reply,
        Ok(Err(e)) => {
            tracing::warn!(?e, ?upstream, "magic-dns upstream error");
            servfail(req, id)
        }
        Err(_) => {
            tracing::warn!(?upstream, "magic-dns upstream timeout");
            servfail(req, id)
        }
    }
}

async fn forward_once(req: &[u8], upstream: SocketAddr) -> std::io::Result<Vec<u8>> {
    // Ephemeral local socket. Bind v4 when upstream is v4 and v6
    // otherwise so connect() works regardless of stack.
    let bind: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(upstream).await?;
    sock.send(req).await?;
    let mut buf = vec![0u8; 1500];
    let n = sock.recv(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

/// Build a minimal SERVFAIL response: copy the request's QID/question,
/// set QR=1 and RCODE=SERVFAIL, zero answers/authorities/additionals.
fn servfail(req: &[u8], id: u16) -> Vec<u8> {
    // Re-parse to recover qname/qtype/qclass for echoing back. If the
    // request is unparseable, return a bare 12-byte SERVFAIL header.
    if let Some((_, flags, qname, qtype, qclass)) = parse_query(req) {
        build_response(id, flags, &qname, qtype, qclass, RCODE_SERVFAIL, None)
    } else {
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&id.to_be_bytes());
        let resp_flags: u16 = 0x8000 | u16::from(RCODE_SERVFAIL);
        out.extend_from_slice(&resp_flags.to_be_bytes());
        out.extend_from_slice(&[0; 8]);
        out
    }
}

/// Parse `(id, flags, qname, qtype, qclass)` from a DNS query.
fn parse_query(buf: &[u8]) -> Option<(u16, u16, String, u16, u16)> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut i = 12usize;
    let mut name = String::new();
    loop {
        let len = *buf.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            // Compression in the question is unusual; we don't follow
            // pointers here.
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        let label = buf.get(i..i + len)?;
        i += len;
        name.push_str(std::str::from_utf8(label).ok()?);
    }
    if buf.len() < i + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
    let qclass = u16::from_be_bytes([buf[i + 2], buf[i + 3]]);
    Some((id, flags, name.to_lowercase(), qtype, qclass))
}

fn build_response(
    id: u16,
    flags: u16,
    qname: &str,
    qtype: u16,
    qclass: u16,
    rcode: u8,
    answer: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    // Header: id(2) + flags(2) + counts(8).
    out.extend_from_slice(&id.to_be_bytes());
    // QR=1, OPCODE=0, AA=1, TC=0, RD=copy, RA=0, Z=0, RCODE.
    let qr_aa = 0x8400u16;
    let rd_bit = flags & 0x0100;
    let resp_flags = qr_aa | rd_bit | u16::from(rcode);
    out.extend_from_slice(&resp_flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    let ancount = u16::from(answer.is_some());
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                // Question section: name + qtype + qclass.
    encode_name(&mut out, qname);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());
    // Answer.
    if let Some(ip) = answer {
        encode_name(&mut out, qname);
        out.extend_from_slice(&QTYPE_A.to_be_bytes());
        out.extend_from_slice(&QCLASS_IN.to_be_bytes());
        out.extend_from_slice(&30u32.to_be_bytes()); // TTL 30s
        out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        out.extend_from_slice(&ip.octets());
    }
    out
}

fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ancount/nscount/arcount
        encode_name(&mut out, qname);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&QCLASS_IN.to_be_bytes());
        out
    }

    #[test]
    fn a_query_for_registered_name_returns_answer() {
        let dns = MagicDns::new();
        dns.register("tid1", "alice", Ipv4Addr::new(100, 64, 1, 7));
        let q = build_query(0x1234, "alice.tid1.octra", QTYPE_A);
        let r = dns.respond(&q).unwrap();
        // header[3] high nibble is RA/Z, low nibble is RCODE.
        assert_eq!(r[3] & 0x0F, RCODE_NOERROR);
        // Answer count == 1.
        let ancount = u16::from_be_bytes([r[6], r[7]]);
        assert_eq!(ancount, 1);
        // The last 4 bytes of the response are the IPv4 RDATA.
        let last = &r[r.len() - 4..];
        assert_eq!(last, &[100, 64, 1, 7]);
    }

    #[test]
    fn a_query_for_unknown_name_returns_nxdomain() {
        let dns = MagicDns::new();
        let q = build_query(0x4321, "ghost.tid1.octra", QTYPE_A);
        let r = dns.respond(&q).unwrap();
        assert_eq!(r[3] & 0x0F, RCODE_NXDOMAIN);
    }

    #[test]
    fn out_of_zone_query_is_refused() {
        let dns = MagicDns::new();
        let q = build_query(0x5555, "example.com", QTYPE_A);
        let r = dns.respond(&q).unwrap();
        assert_eq!(r[3] & 0x0F, RCODE_REFUSED);
    }

    #[test]
    fn aaaa_query_returns_noerror_with_no_answer() {
        let dns = MagicDns::new();
        dns.register("tid1", "alice", Ipv4Addr::new(100, 64, 1, 7));
        let q = build_query(0x9999, "alice.tid1.octra", QTYPE_AAAA);
        let r = dns.respond(&q).unwrap();
        assert_eq!(r[3] & 0x0F, RCODE_NOERROR);
        let ancount = u16::from_be_bytes([r[6], r[7]]);
        assert_eq!(ancount, 0);
    }

    #[test]
    fn register_tailnet_members_uses_allocator() {
        let dns = MagicDns::new();
        dns.register_tailnet_members(
            "tid",
            [
                ("alice".into(), "octA".into()),
                ("bob".into(), "octB".into()),
            ],
        );
        assert!(dns.resolve("tid", "alice").is_some());
        assert!(dns.resolve("tid", "bob").is_some());
        assert_ne!(dns.resolve("tid", "alice"), dns.resolve("tid", "bob"));
    }

    /// Spawn a tiny loopback UDP "upstream" that, on each received
    /// query, replies with `reply_bytes` (with the request's QID
    /// patched in so the response matches the wire-level rule). Returns
    /// the bound address.
    async fn spawn_fake_upstream(reply_bytes: Vec<u8>) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let req_id = u16::from_be_bytes([buf[0], buf[1]]);
                let mut reply = reply_bytes.clone();
                if reply.len() >= 2 {
                    reply[0..2].copy_from_slice(&req_id.to_be_bytes());
                }
                let _ = sock.send_to(&reply, from).await;
                // Re-arm `n` so clippy doesn't bark; not really needed.
                let _ = n;
            }
        });
        addr
    }

    /// Spawn a black-hole UDP socket that receives but never replies.
    async fn spawn_blackhole() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            // Keep the socket alive; consume packets silently.
            let mut buf = [0u8; 1500];
            loop {
                if sock.recv_from(&mut buf).await.is_err() {
                    break;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn respond_async_passes_through_in_zone_a_query() {
        // Configure an upstream that would scream if hit, then ensure
        // the in-zone query is answered locally without touching it.
        let upstream = spawn_fake_upstream(vec![0xFF; 20]).await;
        let dns = MagicDns::new().with_upstream(upstream);
        dns.register("tid1", "alice", Ipv4Addr::new(100, 64, 1, 7));
        let q = build_query(0x1234, "alice.tid1.octra", QTYPE_A);
        let r = dns.respond_async(&q).await.unwrap();
        assert_eq!(r[3] & 0x0F, RCODE_NOERROR);
        let ancount = u16::from_be_bytes([r[6], r[7]]);
        assert_eq!(ancount, 1);
        let last = &r[r.len() - 4..];
        assert_eq!(last, &[100, 64, 1, 7]);
    }

    #[tokio::test]
    async fn respond_async_forwards_to_upstream_when_configured() {
        // Canned reply: a complete-ish DNS response with a distinctive
        // RDATA so we can verify it round-tripped verbatim. Use the
        // build_response helper to produce a well-formed packet.
        let canned = build_response(
            0x0000, // ID will be patched by the fake upstream
            0x0100, // RD bit set
            "example.com",
            QTYPE_A,
            QCLASS_IN,
            RCODE_NOERROR,
            Some(Ipv4Addr::new(93, 184, 216, 34)),
        );
        let upstream = spawn_fake_upstream(canned).await;
        let dns = MagicDns::new().with_upstream(upstream);
        let q = build_query(0xABCD, "example.com", QTYPE_A);
        let r = dns.respond_async(&q).await.unwrap();
        // The reply should carry the canned RDATA verbatim, with our
        // request's QID patched in.
        let rid = u16::from_be_bytes([r[0], r[1]]);
        assert_eq!(rid, 0xABCD);
        assert_eq!(r[3] & 0x0F, RCODE_NOERROR);
        let ancount = u16::from_be_bytes([r[6], r[7]]);
        assert_eq!(ancount, 1);
        let last = &r[r.len() - 4..];
        assert_eq!(last, &[93, 184, 216, 34]);
    }

    #[tokio::test]
    async fn respond_async_returns_servfail_on_upstream_timeout() {
        // Override the 2s production timeout: we don't want the test to
        // wait that long. The forward path uses UPSTREAM_TIMEOUT, so we
        // use tokio's time pause / advance to fast-forward, or just
        // accept that this test takes ~2s. Use tokio::test's start
        // paused so we can advance time deterministically.
        let upstream = spawn_blackhole().await;
        let dns = MagicDns::new().with_upstream(upstream);
        let q = build_query(0xDEAD, "slow.example.com", QTYPE_A);
        let start = std::time::Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(5), dns.respond_async(&q))
            .await
            .expect("respond_async hung past upstream timeout")
            .expect("respond_async returned None");
        let elapsed = start.elapsed();
        // SERVFAIL with our QID echoed.
        let rid = u16::from_be_bytes([r[0], r[1]]);
        assert_eq!(rid, 0xDEAD);
        assert_eq!(r[3] & 0x0F, RCODE_SERVFAIL);
        // Should have given up within a small margin around the 2s
        // upstream timeout — definitely much less than 5s.
        assert!(
            elapsed < Duration::from_secs(4),
            "elapsed {elapsed:?} should be near UPSTREAM_TIMEOUT (2s)"
        );
    }
}
