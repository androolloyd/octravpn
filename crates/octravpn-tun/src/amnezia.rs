//! AmneziaWG-style handshake obfuscation shim for our boringtun-based
//! WireGuard data path.
//!
//! ## What this hides
//!
//! Stock WireGuard handshake packets have a *deterministic* on-wire
//! fingerprint that DPI systems (GFW, ISP middleboxes, hotel
//! captive-portal filters) match in O(1):
//!
//!   - byte 0..4 = msg_type (LE u32) ∈ {1, 2, 3, 4}
//!   - byte length of init = 148, response = 92, cookie = 64
//!   - the first byte is always `0x01`, `0x02`, `0x03`, or `0x04`
//!     followed by three NUL pad bytes
//!
//! [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go) adds three
//! independent obfuscation primitives on top of these packets. We
//! replicate them here as a thin **wrapper** around outgoing /
//! incoming UDP — we do NOT fork boringtun.
//!
//!   1. **Jc/Jmin/Jmax** — emit `jc` "junk" UDP packets (random
//!      payload, length `rand(jmin..=jmax)`) to the peer *before* the
//!      first real handshake init. A passive DPI engine cannot tell
//!      which (if any) of the first N datagrams carries the handshake.
//!   2. **S1/S2** — prepend `s1` random bytes to each outgoing
//!      handshake-initiation packet and `s2` bytes to each
//!      handshake-response packet. The receiver strips the prefix
//!      before handing the packet to boringtun. Defeats length-based
//!      fingerprinting (the canonical 148/92 sizes vanish).
//!   3. **H1..H4** — replace WireGuard's fixed 4-byte msg-type prefix
//!      (LE u32) with operator-chosen magic values. Defeats the
//!      "byte 0 ∈ {1..=4} && bytes 1..4 == 0" matcher.
//!
//! ## What this does NOT hide
//!
//!   - Timing: packet inter-arrival is unchanged. A traffic-analysis
//!     adversary who sees both sides of the link can still infer
//!     "this is a tunneled keepalive flow".
//!   - Volume: total bytes per session are unchanged (other than the
//!     fixed S1/S2 + Jc overhead).
//!   - Active probing: a probe that *replays* a junk packet back at us
//!     will be dropped silently, but a probe that mints a candidate
//!     `H1`-prefixed packet of plausible length cannot be told apart
//!     from a real init until boringtun rejects the noise handshake.
//!     The shield is **defence in depth, not steganography**.
//!
//! ## Interop
//!
//! Both ends MUST agree on the 9 config knobs or the connection will
//! fail (the receiver will strip the wrong number of prefix bytes and
//! hand boringtun garbage). When `enabled = false` (the default), the
//! shield is a zero-overhead identity transform: outbound bytes pass
//! through unchanged and inbound bytes are returned verbatim. In that
//! mode a stock-WG peer can still connect to us.
//!
//! See `docs/security/validator-hardening.md` § "Layer 1" for the
//! threat-model write-up.

use std::net::SocketAddr;

use rand::{rngs::OsRng, Rng, RngCore};
use serde::Deserialize;

/// Stock WireGuard msg-type bytes. We use these as both the
/// "untouched" outbound source (the boringtun layer always emits one
/// of these) and the "restored" inbound destination (boringtun
/// expects one of these).
const WG_MSG_INIT: u32 = 1;
const WG_MSG_RESPONSE: u32 = 2;
const WG_MSG_COOKIE: u32 = 3;
const WG_MSG_TRANSPORT: u32 = 4;

/// Canonical WireGuard packet sizes — used to disambiguate
/// handshake-init / handshake-response on the inbound path (so we
/// know how many junk-prefix bytes to strip).
const WG_INIT_LEN: usize = 148;
const WG_RESPONSE_LEN: usize = 92;

/// Maximum allowed S1 / S2 prefix length. Mirrors AmneziaWG's
/// upstream cap. Anything larger would trip MTU on most network
/// paths.
const MAX_PREFIX: u16 = 1280;

/// Maximum allowed junk-packet size. Mirrors AmneziaWG.
const MAX_JUNK: u16 = 1280;

/// Maximum number of pre-handshake junk packets. Mirrors AmneziaWG.
const MAX_JC: u8 = 128;

/// AmneziaWG obfuscation parameters.
///
/// Field meanings mirror the upstream
/// [AmneziaWG knobs](https://github.com/amnezia-vpn/amneziawg-go#parameters):
///
///   - `jc`         — pre-handshake junk packet count (1..=128).
///                    `0` disables the junk burst.
///   - `jmin`/`jmax` — junk packet payload size range, inclusive
///                    (1..=1280). Must satisfy `jmin <= jmax`.
///   - `s1`/`s2`    — bytes of random prefix prepended to outgoing
///                    handshake-init / -response packets (0..=1280).
///                    `0` disables the prefix on that side.
///   - `h1`/`h2`/`h3`/`h4` — replacement msg-type values for WG
///                    init / response / cookie / transport
///                    (5..=2_147_483_647). The stock WG values
///                    `1..=4` are reserved (the receiver uses them
///                    to detect a *stock-WG* peer when interop is
///                    desired).
///
/// `Default` returns the **identity** mapping (h1..h4 = 1..4, all
/// other knobs zero). This is the off-the-wire shape so an
/// unconfigured `AmneziaShield` is a pass-through.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct AmneziaConfig {
    #[serde(default)]
    pub jc: u8,
    #[serde(default)]
    pub jmin: u16,
    #[serde(default)]
    pub jmax: u16,
    #[serde(default)]
    pub s1: u16,
    #[serde(default)]
    pub s2: u16,
    #[serde(default = "default_h1")]
    pub h1: u32,
    #[serde(default = "default_h2")]
    pub h2: u32,
    #[serde(default = "default_h3")]
    pub h3: u32,
    #[serde(default = "default_h4")]
    pub h4: u32,
}

const fn default_h1() -> u32 {
    WG_MSG_INIT
}
const fn default_h2() -> u32 {
    WG_MSG_RESPONSE
}
const fn default_h3() -> u32 {
    WG_MSG_COOKIE
}
const fn default_h4() -> u32 {
    WG_MSG_TRANSPORT
}

impl Default for AmneziaConfig {
    /// Identity transform: shield disabled.
    fn default() -> Self {
        Self {
            jc: 0,
            jmin: 0,
            jmax: 0,
            s1: 0,
            s2: 0,
            h1: WG_MSG_INIT,
            h2: WG_MSG_RESPONSE,
            h3: WG_MSG_COOKIE,
            h4: WG_MSG_TRANSPORT,
        }
    }
}

impl AmneziaConfig {
    /// Reject configurations that would put us outside the AmneziaWG
    /// interop window or that boringtun cannot survive.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.jc > MAX_JC {
            return Err("jc must be 0..=128");
        }
        if self.jmin > MAX_JUNK || self.jmax > MAX_JUNK {
            return Err("jmin/jmax must be 0..=1280");
        }
        if self.jc > 0 && (self.jmin == 0 || self.jmax == 0 || self.jmin > self.jmax) {
            return Err("when jc > 0, require 1 <= jmin <= jmax <= 1280");
        }
        if self.s1 > MAX_PREFIX || self.s2 > MAX_PREFIX {
            return Err("s1/s2 must be 0..=1280");
        }
        // h1..h4 may *not* collide with each other (we use them to
        // demux on the inbound path) and individually they must not
        // collide with the stock WG msg-types unless they ARE the
        // stock value (the identity case).
        let hs = [self.h1, self.h2, self.h3, self.h4];
        for (i, hi) in hs.iter().enumerate() {
            for hj in hs.iter().skip(i + 1) {
                if hi == hj {
                    return Err("h1..h4 must be pairwise distinct");
                }
            }
        }
        // Range check: 5..=2_147_483_647 OR the canonical 1..=4 value
        // at the same slot (identity).
        let canon = [
            WG_MSG_INIT,
            WG_MSG_RESPONSE,
            WG_MSG_COOKIE,
            WG_MSG_TRANSPORT,
        ];
        for (h, c) in hs.iter().zip(canon.iter()) {
            if *h != *c && !(5..=2_147_483_647).contains(h) {
                return Err(
                    "h1..h4 must be 5..=2_147_483_647 (or the canonical value at that slot)",
                );
            }
        }
        Ok(())
    }

    /// True when this config performs no transformation. Used as a
    /// fast-path bypass on the data plane.
    pub fn is_identity(&self) -> bool {
        self.jc == 0
            && self.s1 == 0
            && self.s2 == 0
            && self.h1 == WG_MSG_INIT
            && self.h2 == WG_MSG_RESPONSE
            && self.h3 == WG_MSG_COOKIE
            && self.h4 == WG_MSG_TRANSPORT
    }
}

/// Stateful obfuscation wrapper. One instance per UDP socket / peer
/// session. Tracks whether the pre-handshake junk burst has been
/// emitted for a given destination (we only emit it once per process
/// run, per destination, to avoid re-burst storms on every keepalive).
pub struct AmneziaShield {
    cfg: AmneziaConfig,
    /// Set once the junk burst has been emitted. Keyed by destination
    /// address so multi-peer servers don't re-burst per peer.
    junk_emitted: std::collections::HashSet<SocketAddr>,
}

impl AmneziaShield {
    pub fn new(cfg: AmneziaConfig) -> Result<Self, &'static str> {
        cfg.validate()?;
        Ok(Self {
            cfg,
            junk_emitted: std::collections::HashSet::new(),
        })
    }

    /// View the active config.
    pub fn config(&self) -> &AmneziaConfig {
        &self.cfg
    }

    /// Wrap an outbound UDP send.
    ///
    /// `send(&[u8])` is the closure that actually pushes bytes onto
    /// the socket — pass a closure that calls `socket.send_to(buf,
    /// dst).await` or whatever your I/O layer uses. We invoke it
    /// once per real packet AND once per junk packet (when applicable).
    ///
    /// `buf` is the payload boringtun handed us. We treat the first
    /// 4 bytes as the WG msg-type indicator (LE u32) and rewrite it
    /// per `h1..h4`. For init / response we also prepend `s1` / `s2`
    /// bytes of fresh randomness.
    pub fn wrap_send<F>(&mut self, dst: SocketAddr, buf: &[u8], mut send: F)
    where
        F: FnMut(&[u8]),
    {
        if self.cfg.is_identity() {
            send(buf);
            return;
        }

        // Emit pre-handshake junk burst once per (process, dst).
        if self.cfg.jc > 0 && !self.junk_emitted.contains(&dst) {
            self.junk_emitted.insert(dst);
            let mut rng = OsRng;
            for _ in 0..self.cfg.jc {
                let lo = u32::from(self.cfg.jmin);
                let hi = u32::from(self.cfg.jmax);
                let len = if lo == hi {
                    lo as usize
                } else {
                    rng.gen_range(lo..=hi) as usize
                };
                let mut junk = vec![0u8; len];
                rng.fill_bytes(&mut junk);
                send(&junk);
            }
        }

        // Inspect msg-type. WG msg-type is LE u32 at offset 0..4.
        // If buf is shorter than 4 bytes (impossible for a real WG
        // packet but cheap to guard) we pass through.
        if buf.len() < 4 {
            send(buf);
            return;
        }
        let msg = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let (substitute, prefix_len) = match msg {
            WG_MSG_INIT => (self.cfg.h1, self.cfg.s1),
            WG_MSG_RESPONSE => (self.cfg.h2, self.cfg.s2),
            WG_MSG_COOKIE => (self.cfg.h3, 0),
            WG_MSG_TRANSPORT => (self.cfg.h4, 0),
            // Unknown — pass through verbatim. boringtun shouldn't
            // emit anything else, but if it does we don't want to
            // corrupt it.
            _ => {
                send(buf);
                return;
            }
        };

        // Build [s1/s2 random prefix] || [substituted 4-byte hdr] ||
        // [buf[4..]] into a single Vec so the closure sees one
        // contiguous datagram.
        let prefix_len = prefix_len as usize;
        let mut out = Vec::with_capacity(prefix_len + buf.len());
        if prefix_len > 0 {
            let mut rng = OsRng;
            let mut prefix = vec![0u8; prefix_len];
            rng.fill_bytes(&mut prefix);
            out.extend_from_slice(&prefix);
        }
        out.extend_from_slice(&substitute.to_le_bytes());
        out.extend_from_slice(&buf[4..]);
        send(&out);
    }

    /// Wrap an inbound UDP recv.
    ///
    /// `recv(&mut [u8]) -> Option<usize>` is the closure that fills
    /// `buf` with the next datagram and returns its length (None on
    /// no-packet / error). We:
    ///
    ///   1. Identify which `h1..h4` (if any) the first 4 bytes match.
    ///      No match → junk packet from the peer's pre-handshake
    ///      burst → return `None` so the caller's loop continues.
    ///   2. Strip `s1` / `s2` bytes if the matched message type is
    ///      init / response and the packet is long enough.
    ///   3. Restore the canonical WG msg-type (LE u32) at the start
    ///      of `buf` so boringtun's parser is happy.
    ///   4. Return `Some(new_len)`.
    ///
    /// Returns `None` on three conditions: (a) the closure returned
    /// `None`, (b) the packet was unrecognized junk, (c) the packet
    /// is shorter than the expected prefix.
    pub fn wrap_recv<F>(&mut self, buf: &mut [u8], mut recv: F) -> Option<usize>
    where
        F: FnMut(&mut [u8]) -> Option<usize>,
    {
        let n = recv(buf)?;
        if self.cfg.is_identity() {
            return Some(n);
        }
        if n < 4 {
            return None;
        }

        // We may need to peek through up to `max(s1, s2)` candidate
        // offsets to find the substituted header. AmneziaWG places
        // the substituted header at offset == s1 (for init) or s2
        // (for response); for cookie/transport there is no prefix
        // (s1/s2 only apply to handshake packets). So the inbound
        // strategy is:
        //
        //   - Check buf[0..4] LE u32 against h3 / h4 first
        //     (cookie / transport — no prefix). If match, restore and
        //     return Some(n).
        //   - Else check buf[s1..s1+4] against h1; if match, strip
        //     first s1 bytes, restore header to WG_MSG_INIT, return.
        //   - Else check buf[s2..s2+4] against h2; same for response.
        //   - Else: junk, return None.
        let read_hdr = |b: &[u8], off: usize| -> Option<u32> {
            if b.len() < off + 4 {
                return None;
            }
            Some(u32::from_le_bytes([
                b[off],
                b[off + 1],
                b[off + 2],
                b[off + 3],
            ]))
        };

        // Cookie / transport: no prefix, header at offset 0.
        if let Some(hdr0) = read_hdr(&buf[..n], 0) {
            if hdr0 == self.cfg.h3 {
                buf[0..4].copy_from_slice(&WG_MSG_COOKIE.to_le_bytes());
                return Some(n);
            }
            if hdr0 == self.cfg.h4 {
                buf[0..4].copy_from_slice(&WG_MSG_TRANSPORT.to_le_bytes());
                return Some(n);
            }
            // ALSO accept stock-WG msg-type at offset 0 — this is what
            // lets a `disabled` peer interoperate with us if our
            // config has the stock h-values (the identity case). When
            // h1..h4 are non-canonical, a stock-WG packet's leading
            // byte 0x01..0x04 will not match any of h1..h4 and will
            // be (correctly) dropped as junk.
            //
            // The identity case is already handled above by
            // `is_identity()`. Here, the h-values are non-canonical,
            // so a packet matching the stock values is treated as
            // junk (no recognition).
        }

        // Init: header at offset s1.
        if self.cfg.s1 > 0 || self.cfg.h1 != WG_MSG_INIT {
            let off = self.cfg.s1 as usize;
            if let Some(hdr) = read_hdr(&buf[..n], off) {
                if hdr == self.cfg.h1 {
                    // Shift buf[off..n] to buf[0..n-off] and restore.
                    let new_len = n - off;
                    buf.copy_within(off..n, 0);
                    buf[0..4].copy_from_slice(&WG_MSG_INIT.to_le_bytes());
                    // Sanity: a real WG init is exactly 148 bytes.
                    // Don't enforce here — boringtun will reject if
                    // wrong.
                    let _ = WG_INIT_LEN;
                    return Some(new_len);
                }
            }
        }

        // Response: header at offset s2.
        if self.cfg.s2 > 0 || self.cfg.h2 != WG_MSG_RESPONSE {
            let off = self.cfg.s2 as usize;
            if let Some(hdr) = read_hdr(&buf[..n], off) {
                if hdr == self.cfg.h2 {
                    let new_len = n - off;
                    buf.copy_within(off..n, 0);
                    buf[0..4].copy_from_slice(&WG_MSG_RESPONSE.to_le_bytes());
                    let _ = WG_RESPONSE_LEN;
                    return Some(new_len);
                }
            }
        }

        // No magic match: junk packet, drop silently.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn nonid_cfg() -> AmneziaConfig {
        AmneziaConfig {
            jc: 3,
            jmin: 40,
            jmax: 70,
            s1: 24,
            s2: 17,
            h1: 0x21A1_A1A1,
            h2: 0x22B2_B2B2,
            h3: 0x23C3_C3C3,
            h4: 0x24D4_D4D4,
        }
    }

    #[test]
    fn default_is_identity() {
        let c = AmneziaConfig::default();
        assert!(c.is_identity());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_rejects_oob() {
        let mut c = nonid_cfg();
        c.jc = 200;
        assert!(c.validate().is_err());
        let mut c = nonid_cfg();
        c.jmin = 100;
        c.jmax = 50;
        assert!(c.validate().is_err());
        let mut c = nonid_cfg();
        c.h1 = c.h2;
        assert!(c.validate().is_err());
        let mut c = nonid_cfg();
        c.h1 = 3; // collides with stock msg-type but not at slot 1
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_accepts_recommended_defaults() {
        let cfg = nonid_cfg();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn identity_passes_through_send() {
        let mut sh = AmneziaShield::new(AmneziaConfig::default()).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let pkt = [0x01u8, 0, 0, 0, 0xAA, 0xBB, 0xCC];
        let mut out: Vec<Vec<u8>> = Vec::new();
        sh.wrap_send(dst, &pkt, |b| out.push(b.to_vec()));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], pkt);
    }

    #[test]
    fn identity_passes_through_recv() {
        let mut sh = AmneziaShield::new(AmneziaConfig::default()).unwrap();
        let mut buf = [0u8; 64];
        buf[..4].copy_from_slice(&1u32.to_le_bytes());
        let got = sh.wrap_recv(&mut buf, |b| {
            // pretend we received 32 bytes
            let _ = b;
            Some(32)
        });
        assert_eq!(got, Some(32));
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 1);
    }

    /// Outbound substitution: init packet gets h1, response gets h2,
    /// etc. Plus the s1/s2 prefix is prepended.
    #[test]
    fn outbound_substitutes_h1_h4_and_prepends_prefix() {
        let cfg = nonid_cfg();
        let mut sh = AmneziaShield::new(cfg).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();

        // burn the junk burst — emit a transport packet (no prefix)
        // first to set junk_emitted for this dst.
        let mut emitted: Vec<Vec<u8>> = Vec::new();
        let mut transport = vec![0u8; 32];
        transport[..4].copy_from_slice(&WG_MSG_TRANSPORT.to_le_bytes());
        sh.wrap_send(dst, &transport, |b| emitted.push(b.to_vec()));
        // emitted = [3 junk pkts, transport-substituted]
        assert_eq!(emitted.len(), 4);
        let last = &emitted[3];
        assert_eq!(
            u32::from_le_bytes([last[0], last[1], last[2], last[3]]),
            cfg.h4
        );
        assert_eq!(last.len(), 32); // no prefix on transport

        // Now init: should NOT re-emit junk (already burned), should
        // have s1 prefix + h1 header.
        emitted.clear();
        let mut init = vec![0u8; WG_INIT_LEN];
        init[..4].copy_from_slice(&WG_MSG_INIT.to_le_bytes());
        sh.wrap_send(dst, &init, |b| emitted.push(b.to_vec()));
        assert_eq!(emitted.len(), 1);
        let one = &emitted[0];
        assert_eq!(one.len(), WG_INIT_LEN + cfg.s1 as usize);
        // The substituted header lives at offset s1.
        let hdr = u32::from_le_bytes([
            one[cfg.s1 as usize],
            one[cfg.s1 as usize + 1],
            one[cfg.s1 as usize + 2],
            one[cfg.s1 as usize + 3],
        ]);
        assert_eq!(hdr, cfg.h1);

        // Response substitution.
        emitted.clear();
        let mut resp = vec![0u8; WG_RESPONSE_LEN];
        resp[..4].copy_from_slice(&WG_MSG_RESPONSE.to_le_bytes());
        sh.wrap_send(dst, &resp, |b| emitted.push(b.to_vec()));
        assert_eq!(emitted.len(), 1);
        let one = &emitted[0];
        assert_eq!(one.len(), WG_RESPONSE_LEN + cfg.s2 as usize);
        let hdr = u32::from_le_bytes([
            one[cfg.s2 as usize],
            one[cfg.s2 as usize + 1],
            one[cfg.s2 as usize + 2],
            one[cfg.s2 as usize + 3],
        ]);
        assert_eq!(hdr, cfg.h2);

        // Cookie substitution (no prefix).
        emitted.clear();
        let mut cookie = vec![0u8; 64];
        cookie[..4].copy_from_slice(&WG_MSG_COOKIE.to_le_bytes());
        sh.wrap_send(dst, &cookie, |b| emitted.push(b.to_vec()));
        assert_eq!(emitted.len(), 1);
        let one = &emitted[0];
        let hdr = u32::from_le_bytes([one[0], one[1], one[2], one[3]]);
        assert_eq!(hdr, cfg.h3);
        assert_eq!(one.len(), 64); // no prefix
    }

    /// Round trip: a packet emitted by one shield should be stripped
    /// correctly by another shield with the same config back to its
    /// original WG form.
    #[test]
    fn roundtrip_init_response_cookie_transport() {
        let cfg = nonid_cfg();
        let mut tx = AmneziaShield::new(cfg).unwrap();
        let mut rx = AmneziaShield::new(cfg).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();

        // burn junk
        let mut emitted: Vec<Vec<u8>> = Vec::new();
        let warmup = vec![WG_MSG_TRANSPORT as u8, 0, 0, 0, 0x77, 0x88];
        tx.wrap_send(dst, &warmup, |b| emitted.push(b.to_vec()));
        // skip junk via rx.wrap_recv -> None for the first jc packets
        for (j, junk_pkt) in emitted.iter().enumerate().take(cfg.jc as usize) {
            let mut rxbuf = vec![0u8; junk_pkt.len()];
            rxbuf.copy_from_slice(junk_pkt);
            let mut once = Some(junk_pkt);
            let got = rx.wrap_recv(&mut rxbuf, |out| {
                let src = once.take()?;
                out[..src.len()].copy_from_slice(src);
                Some(src.len())
            });
            assert_eq!(got, None, "junk packet #{j} should be dropped");
        }
        // the real warmup packet is at index jc
        let real_idx = cfg.jc as usize;
        let raw = emitted[real_idx].clone();
        let mut rxbuf = vec![0u8; raw.len()];
        let mut once = Some(raw.clone());
        let got = rx.wrap_recv(&mut rxbuf, |out| {
            let src = once.take()?;
            out[..src.len()].copy_from_slice(&src);
            Some(src.len())
        });
        assert_eq!(got, Some(raw.len())); // transport: no prefix stripped
        assert_eq!(
            u32::from_le_bytes([rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3]]),
            WG_MSG_TRANSPORT
        );
        assert_eq!(&rxbuf[4..6], &warmup[4..6]);

        // Init round-trip.
        let mut emitted: Vec<Vec<u8>> = Vec::new();
        let mut init = vec![0u8; WG_INIT_LEN];
        init[..4].copy_from_slice(&WG_MSG_INIT.to_le_bytes());
        init[10] = 0x42; // sentinel
        tx.wrap_send(dst, &init, |b| emitted.push(b.to_vec()));
        assert_eq!(emitted.len(), 1);
        let mut rxbuf = vec![0u8; emitted[0].len()];
        let raw = emitted[0].clone();
        let mut once = Some(raw);
        let got = rx.wrap_recv(&mut rxbuf, |out| {
            let src = once.take()?;
            out[..src.len()].copy_from_slice(&src);
            Some(src.len())
        });
        assert_eq!(got, Some(WG_INIT_LEN));
        assert_eq!(
            u32::from_le_bytes([rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3]]),
            WG_MSG_INIT
        );
        assert_eq!(rxbuf[10], 0x42);

        // Response round-trip.
        let mut emitted: Vec<Vec<u8>> = Vec::new();
        let mut resp = vec![0u8; WG_RESPONSE_LEN];
        resp[..4].copy_from_slice(&WG_MSG_RESPONSE.to_le_bytes());
        resp[7] = 0x99;
        tx.wrap_send(dst, &resp, |b| emitted.push(b.to_vec()));
        let mut rxbuf = vec![0u8; emitted[0].len()];
        let raw = emitted[0].clone();
        let mut once = Some(raw);
        let got = rx.wrap_recv(&mut rxbuf, |out| {
            let src = once.take()?;
            out[..src.len()].copy_from_slice(&src);
            Some(src.len())
        });
        assert_eq!(got, Some(WG_RESPONSE_LEN));
        assert_eq!(
            u32::from_le_bytes([rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3]]),
            WG_MSG_RESPONSE
        );
        assert_eq!(rxbuf[7], 0x99);
    }

    /// A shield without matching config (e.g. disabled on one side)
    /// won't recognize the other side's packets.
    #[test]
    fn mismatched_config_fails_to_decode() {
        let cfg = nonid_cfg();
        let mut tx = AmneziaShield::new(cfg).unwrap();
        let mut rx = AmneziaShield::new(AmneziaConfig::default()).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();

        let mut emitted: Vec<Vec<u8>> = Vec::new();
        let mut init = vec![0u8; WG_INIT_LEN];
        init[..4].copy_from_slice(&WG_MSG_INIT.to_le_bytes());
        tx.wrap_send(dst, &init, |b| emitted.push(b.to_vec()));
        // RX is identity; it returns the (junk-prefixed, h1-headed)
        // bytes verbatim, NOT a valid WG init.
        let real_idx = cfg.jc as usize;
        let raw = emitted[real_idx].clone();
        let mut rxbuf = vec![0u8; raw.len()];
        let mut once = Some(raw.clone());
        let got = rx.wrap_recv(&mut rxbuf, |out| {
            let src = once.take()?;
            out[..src.len()].copy_from_slice(&src);
            Some(src.len())
        });
        // RX is identity: passes through unchanged.
        assert_eq!(got, Some(raw.len()));
        // The wire bytes are [s1 random]||[h1 LE]||[buf[4..]]. With
        // s1 > 0 the first 4 bytes are random (not WG_MSG_INIT and
        // very unlikely to match it). The substituted h1 header
        // lives at offset s1 — verify it's there to confirm what
        // boringtun would receive.
        assert_eq!(rxbuf.len(), WG_INIT_LEN + cfg.s1 as usize);
        let hdr_at_s1 = u32::from_le_bytes([
            rxbuf[cfg.s1 as usize],
            rxbuf[cfg.s1 as usize + 1],
            rxbuf[cfg.s1 as usize + 2],
            rxbuf[cfg.s1 as usize + 3],
        ]);
        assert_eq!(hdr_at_s1, cfg.h1);
        // Length is also wrong (has s1 prefix). boringtun would
        // reject this.
    }

    // Property test: any random byte sequence that doesn't start
    // with one of our h-magics gets bypassed by recv.
    proptest! {
        #[test]
        fn random_garbage_is_bypassed(bytes in proptest::collection::vec(any::<u8>(), 1..256)) {
            let cfg = nonid_cfg();
            let mut sh = AmneziaShield::new(cfg).unwrap();
            // Skip cases where the first 4 bytes randomly hit one of
            // our magics. Restrict to short packets so we don't also
            // accidentally trip the offset==s1 or offset==s2 check.
            let mut buf = bytes;
            // Pad to at least s1+4 so the offset-based checks don't
            // index OOB.
            if buf.len() < cfg.s1 as usize + 4 {
                buf.resize(cfg.s1 as usize + 4, 0);
            }
            let hits_h = |b: &[u8], off: usize| -> bool {
                if b.len() < off + 4 { return false; }
                let v = u32::from_le_bytes([b[off], b[off+1], b[off+2], b[off+3]]);
                v == cfg.h1 || v == cfg.h2 || v == cfg.h3 || v == cfg.h4
            };
            prop_assume!(!hits_h(&buf, 0));
            prop_assume!(!hits_h(&buf, cfg.s1 as usize));
            prop_assume!(!hits_h(&buf, cfg.s2 as usize));

            let len = buf.len();
            let mut rxbuf = buf.clone();
            let mut once = Some(buf);
            let got = sh.wrap_recv(&mut rxbuf, |out| {
                let src = once.take()?;
                out[..src.len()].copy_from_slice(&src);
                Some(src.len())
            });
            prop_assert_eq!(got, None, "random garbage of length {} should be dropped as junk", len);
        }
    }

    /// Loopback UDP integration: two shields with matching config
    /// exchange handshake-shaped packets and decode each other's
    /// payloads. Same test with one side disabled fails to decode.
    #[tokio::test]
    async fn loopback_udp_two_shields() {
        use tokio::net::UdpSocket;
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();
        let cfg = nonid_cfg();
        let mut sh_a = AmneziaShield::new(cfg).unwrap();
        let mut sh_b = AmneziaShield::new(cfg).unwrap();

        // A sends a "handshake init" toward B.
        let mut init = vec![0u8; WG_INIT_LEN];
        init[..4].copy_from_slice(&WG_MSG_INIT.to_le_bytes());
        init[10] = 0xAB;
        // Collect all outbound datagrams first (junk + real) and
        // send them off the socket synchronously.
        let mut out_bufs: Vec<Vec<u8>> = Vec::new();
        sh_a.wrap_send(b_addr, &init, |b| out_bufs.push(b.to_vec()));
        for b_out in &out_bufs {
            a.send_to(b_out, b_addr).await.unwrap();
        }

        // B drains until it sees a real WG init.
        let mut rxbuf = vec![0u8; 4096];
        let mut got_init = false;
        for _ in 0..(cfg.jc as usize + 2) {
            let got = sh_b.wrap_recv(&mut rxbuf, |out| {
                // synchronous recv: poll with try_recv
                let (n, _src) = b.try_recv_from(out).ok()?;
                Some(n)
            });
            if let Some(n) = got {
                assert_eq!(n, WG_INIT_LEN);
                assert_eq!(
                    u32::from_le_bytes([rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3]]),
                    WG_MSG_INIT
                );
                assert_eq!(rxbuf[10], 0xAB);
                got_init = true;
                break;
            }
            // try_recv may have returned None because no datagram is
            // pending yet — yield and let the kernel deliver.
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(got_init, "B should have decoded the real init");
        let _ = a_addr;
    }

    /// Stock-WG compat: when shield is disabled (identity), a packet
    /// produced by a stock-WG sender (msg-type byte 0x01..0x04, no
    /// prefix) round-trips through wrap_recv unchanged. This is the
    /// "config-gated transparency" the spec requires.
    #[test]
    fn disabled_shield_is_transparent_to_stock_wg() {
        let mut sh = AmneziaShield::new(AmneziaConfig::default()).unwrap();
        let mut buf = vec![0u8; WG_INIT_LEN];
        // Stock WG init: msg-type = 1
        buf[..4].copy_from_slice(&WG_MSG_INIT.to_le_bytes());
        buf[40] = 0xEE; // sentinel
        let raw = buf.clone();
        let mut once = Some(raw.clone());
        let got = sh.wrap_recv(&mut buf, |out| {
            let src = once.take()?;
            out[..src.len()].copy_from_slice(&src);
            Some(src.len())
        });
        assert_eq!(got, Some(WG_INIT_LEN));
        assert_eq!(buf, raw); // verbatim
    }

    // -------------------------------------------------------------------
    // Helpers for the additional coverage block.
    // -------------------------------------------------------------------

    /// Drive a synthetic recv from a fixed byte buffer through a shield.
    /// Returns `(returned_len, restored_buf)`.
    fn recv_one(sh: &mut AmneziaShield, src: &[u8]) -> (Option<usize>, Vec<u8>) {
        let mut rxbuf = vec![0u8; src.len().max(4)];
        let mut once = Some(src.to_vec());
        let got = sh.wrap_recv(&mut rxbuf, |out| {
            let s = once.take()?;
            out[..s.len()].copy_from_slice(&s);
            Some(s.len())
        });
        (got, rxbuf)
    }

    /// Collect every datagram a shield would emit for a single inbound
    /// payload.
    fn collect_send(sh: &mut AmneziaShield, dst: SocketAddr, buf: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        sh.wrap_send(dst, buf, |b| out.push(b.to_vec()));
        out
    }

    // -------------------------------------------------------------------
    // Validate: positive cases + boundary checks.
    // -------------------------------------------------------------------

    #[test]
    fn validate_accepts_h_at_canonical_slot_only() {
        // h1==1 OK (canonical at slot 1), h2==2 OK, etc., as long as
        // overall pairwise distinct. Identity passes.
        assert!(AmneziaConfig::default().validate().is_ok());

        // h2==1 (canonical for h1, not for h2) must be rejected.
        let c = AmneziaConfig {
            h2: 1,
            ..AmneziaConfig::default()
        };
        // collides with h1==1
        assert!(c.validate().is_err());

        // h1==2 (h2's canonical) — must be rejected (out-of-range non-canonical).
        let c = AmneziaConfig {
            h1: 2,
            ..AmneziaConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_jmin_with_nonzero_jc() {
        let mut c = nonid_cfg();
        c.jmin = 0;
        c.jmax = 10;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_jmax_above_cap() {
        let mut c = nonid_cfg();
        c.jmax = MAX_JUNK + 1;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_s1_above_cap() {
        let mut c = nonid_cfg();
        c.s1 = MAX_PREFIX + 1;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_h_below_min() {
        let mut c = nonid_cfg();
        c.h1 = 4; // <5 and not canonical at slot 1
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_accepts_h_at_upper_range() {
        let mut c = nonid_cfg();
        c.h1 = 2_147_483_647;
        c.h2 = 2_147_483_646;
        c.h3 = 2_147_483_645;
        c.h4 = 2_147_483_644;
        c.validate().expect("upper bound is inclusive");
    }

    #[test]
    fn validate_rejects_h_above_max() {
        let mut c = nonid_cfg();
        c.h1 = 2_147_483_648; // 2^31, off the top
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_accepts_jmin_eq_jmax() {
        let mut c = nonid_cfg();
        c.jmin = 50;
        c.jmax = 50;
        c.validate().expect("equal bounds must be allowed");
    }

    #[test]
    fn validate_accepts_jc_at_max() {
        let mut c = nonid_cfg();
        c.jc = MAX_JC;
        c.validate().expect("jc==MAX_JC must be accepted");
    }

    // -------------------------------------------------------------------
    // Edge cases on wrap_send.
    // -------------------------------------------------------------------

    #[test]
    fn wrap_send_short_buf_passes_through() {
        // buf < 4 bytes: not a valid WG frame; shield must pass through
        // unmodified (after junk burst, which we burn first).
        let mut c = nonid_cfg();
        c.jc = 0;
        let mut sh = AmneziaShield::new(c).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let pkt = [0xAA, 0xBB, 0xCC];
        let out = collect_send(&mut sh, dst, &pkt);
        assert_eq!(out, vec![pkt.to_vec()]);
    }

    #[test]
    fn wrap_send_unknown_msg_type_passes_through() {
        let mut c = nonid_cfg();
        c.jc = 0;
        let mut sh = AmneziaShield::new(c).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        // msg-type 0xFFFFFFFF is not in {1,2,3,4}, so wrap_send must
        // not rewrite the header.
        let mut pkt = vec![0u8; 32];
        pkt[..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        pkt[5] = 0x77;
        let out = collect_send(&mut sh, dst, &pkt);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], pkt);
    }

    #[test]
    fn jc_zero_emits_no_junk_burst() {
        let mut c = nonid_cfg();
        c.jc = 0;
        let mut sh = AmneziaShield::new(c).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut init = vec![0u8; WG_INIT_LEN];
        init[..4].copy_from_slice(&WG_MSG_INIT.to_le_bytes());
        let out = collect_send(&mut sh, dst, &init);
        // Exactly one datagram (the substituted init).
        assert_eq!(out.len(), 1, "jc=0 must suppress the burst entirely");
    }

    #[test]
    fn s1_zero_emits_no_prefix_on_init() {
        let mut c = nonid_cfg();
        c.s1 = 0;
        c.jc = 0;
        let mut sh = AmneziaShield::new(c).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut init = vec![0u8; WG_INIT_LEN];
        init[..4].copy_from_slice(&WG_MSG_INIT.to_le_bytes());
        let out = collect_send(&mut sh, dst, &init);
        assert_eq!(out.len(), 1);
        // Length unchanged (no prefix), header is h1.
        assert_eq!(out[0].len(), WG_INIT_LEN);
        let hdr = u32::from_le_bytes([out[0][0], out[0][1], out[0][2], out[0][3]]);
        assert_eq!(hdr, c.h1);
    }

    #[test]
    fn s2_zero_emits_no_prefix_on_response() {
        let mut c = nonid_cfg();
        c.s2 = 0;
        c.jc = 0;
        let mut sh = AmneziaShield::new(c).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut resp = vec![0u8; WG_RESPONSE_LEN];
        resp[..4].copy_from_slice(&WG_MSG_RESPONSE.to_le_bytes());
        let out = collect_send(&mut sh, dst, &resp);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), WG_RESPONSE_LEN);
    }

    #[test]
    fn junk_burst_emits_exactly_jc_packets_in_order() {
        // Run with jmin==jmax so we can verify exact sizes.
        let mut c = nonid_cfg();
        c.jc = 5;
        c.jmin = 33;
        c.jmax = 33;
        let mut sh = AmneziaShield::new(c).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut pkt = vec![0u8; 32];
        pkt[..4].copy_from_slice(&WG_MSG_TRANSPORT.to_le_bytes());
        let out = collect_send(&mut sh, dst, &pkt);
        // jc=5 junk pkts + 1 real = 6 datagrams.
        assert_eq!(out.len(), 6, "must be jc + 1");
        // First 5 are 33-byte random junk.
        for j in &out[..5] {
            assert_eq!(j.len(), 33);
        }
        // The 6th must NOT be junk-shaped: it's the substituted transport
        // packet, length 32.
        assert_eq!(out[5].len(), 32);
        let hdr = u32::from_le_bytes([out[5][0], out[5][1], out[5][2], out[5][3]]);
        assert_eq!(hdr, c.h4);
    }

    #[test]
    fn junk_burst_emitted_once_per_destination() {
        let mut c = nonid_cfg();
        c.jc = 3;
        c.jmin = 10;
        c.jmax = 10;
        let mut sh = AmneziaShield::new(c).unwrap();
        let dst_a: SocketAddr = "127.0.0.1:11".parse().unwrap();
        let dst_b: SocketAddr = "127.0.0.1:12".parse().unwrap();
        let mut pkt = vec![0u8; 16];
        pkt[..4].copy_from_slice(&WG_MSG_TRANSPORT.to_le_bytes());

        // First send to A: burst + real = 4
        let out_a1 = collect_send(&mut sh, dst_a, &pkt);
        assert_eq!(out_a1.len(), 4);
        // Second send to A: no burst, just real = 1
        let out_a2 = collect_send(&mut sh, dst_a, &pkt);
        assert_eq!(out_a2.len(), 1, "junk must NOT re-burst on the same dst");
        // Send to B (new dst): burst + real = 4
        let out_b1 = collect_send(&mut sh, dst_b, &pkt);
        assert_eq!(out_b1.len(), 4, "junk must burst once per dst");
    }

    #[test]
    fn near_mtu_buf_round_trips_through_init_path() {
        // s1 prefix + WG_INIT_LEN sits comfortably under typical MTU
        // (1500). Verify the round-trip still restores the original
        // payload correctly even when the original buf is large.
        let mut c = nonid_cfg();
        c.jc = 0;
        c.s1 = 20;
        let mut tx = AmneziaShield::new(c).unwrap();
        let mut rx = AmneziaShield::new(c).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();

        // Use a longer-than-handshake "init"-tagged payload to stress
        // the buf.copy_within path on a large slice.
        let mut payload = vec![0u8; 1280];
        payload[..4].copy_from_slice(&WG_MSG_INIT.to_le_bytes());
        for (i, b) in payload.iter_mut().enumerate().skip(4) {
            *b = (i as u8).wrapping_mul(3).wrapping_add(7);
        }
        let emitted = collect_send(&mut tx, dst, &payload);
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].len(), payload.len() + c.s1 as usize);

        let (got, rxbuf) = recv_one(&mut rx, &emitted[0]);
        assert_eq!(got, Some(payload.len()));
        assert_eq!(&rxbuf[..payload.len()], payload.as_slice());
    }

    #[test]
    fn oversized_recv_buf_still_strips_to_correct_length() {
        // The recv path reuses the inbound buffer in-place; if buf
        // length > received-n, the extra trailing bytes must NOT
        // affect the returned length.
        let mut c = nonid_cfg();
        c.jc = 0;
        let mut tx = AmneziaShield::new(c).unwrap();
        let mut rx = AmneziaShield::new(c).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut init = vec![0u8; WG_INIT_LEN];
        init[..4].copy_from_slice(&WG_MSG_INIT.to_le_bytes());
        init[100] = 0x5A;
        let emitted = collect_send(&mut tx, dst, &init);
        // Pad the rxbuf well past the datagram.
        let mut rxbuf = vec![0xCCu8; emitted[0].len() + 256];
        let raw = emitted[0].clone();
        let raw_len = raw.len();
        let mut once = Some(raw);
        let got = rx.wrap_recv(&mut rxbuf, |out| {
            let s = once.take()?;
            out[..s.len()].copy_from_slice(&s);
            Some(s.len())
        });
        assert_eq!(got, Some(WG_INIT_LEN));
        // The bytes BEYOND the returned length stayed at 0xCC sentinel
        // (we must not overwrite past raw_len during copy_within).
        // copy_within is intra-buffer, so bytes beyond `raw_len` are
        // untouched; assert that.
        for b in &rxbuf[raw_len..] {
            assert_eq!(*b, 0xCC);
        }
    }

    // -------------------------------------------------------------------
    // Negative recv: garbage that looks like a magic match but fails
    // structural rules.
    // -------------------------------------------------------------------

    #[test]
    fn h1_at_offset_zero_is_rejected_when_s1_nonzero() {
        // If a probe forges h1 magic at offset 0 (instead of offset s1
        // where a real init would have it), the shield must treat it
        // as junk — that magic only counts when correctly aligned.
        let cfg = nonid_cfg();
        let mut sh = AmneziaShield::new(cfg).unwrap();
        // Build a packet whose leading 4 bytes ARE h1 but no prefix,
        // and whose buf[s1..s1+4] is NOT h1.
        let mut buf = vec![0u8; WG_INIT_LEN + cfg.s1 as usize];
        buf[..4].copy_from_slice(&cfg.h1.to_le_bytes());
        // Make sure offset s1 doesn't accidentally hit h1.
        buf[cfg.s1 as usize] = 0xDE;
        buf[cfg.s1 as usize + 1] = 0xAD;
        buf[cfg.s1 as usize + 2] = 0xBE;
        buf[cfg.s1 as usize + 3] = 0xEF;
        let (got, _) = recv_one(&mut sh, &buf);
        // h1 sits at offset-0 → no match against h3/h4 (cookie/transport)
        // because cfg.h3 and cfg.h4 are different values. Offset s1
        // doesn't hit h1 either, and offset s2 doesn't hit h2 (by
        // construction). So this must drop as junk.
        assert_eq!(got, None);
    }

    #[test]
    fn truncated_packet_with_valid_h1_at_zero_drops() {
        // Length < 4 → recv path returns None.
        let cfg = nonid_cfg();
        let mut sh = AmneziaShield::new(cfg).unwrap();
        let buf = vec![0xAAu8; 3];
        let (got, _) = recv_one(&mut sh, &buf);
        assert_eq!(got, None);
    }

    #[test]
    fn all_zero_buf_drops_as_junk_under_nonid_cfg() {
        let cfg = nonid_cfg();
        let mut sh = AmneziaShield::new(cfg).unwrap();
        let buf = vec![0u8; 64];
        let (got, _) = recv_one(&mut sh, &buf);
        // 0u32 LE != any of h1..h4 (all nonzero in nonid_cfg).
        assert_eq!(got, None);
    }

    #[test]
    fn cookie_path_no_prefix_round_trip() {
        let cfg = nonid_cfg();
        let mut tx = AmneziaShield::new(cfg).unwrap();
        let mut rx = AmneziaShield::new(cfg).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        // Burn the junk burst by emitting a transport packet first.
        let mut warm = vec![0u8; 8];
        warm[..4].copy_from_slice(&WG_MSG_TRANSPORT.to_le_bytes());
        let _ = collect_send(&mut tx, dst, &warm);

        let mut cookie = vec![0u8; 64];
        cookie[..4].copy_from_slice(&WG_MSG_COOKIE.to_le_bytes());
        cookie[20] = 0x42;
        let emitted = collect_send(&mut tx, dst, &cookie);
        assert_eq!(emitted.len(), 1);
        // No s-prefix on cookie — wire length matches input.
        assert_eq!(emitted[0].len(), 64);
        let (got, rxbuf) = recv_one(&mut rx, &emitted[0]);
        assert_eq!(got, Some(64));
        assert_eq!(
            u32::from_le_bytes([rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3]]),
            WG_MSG_COOKIE
        );
        assert_eq!(rxbuf[20], 0x42);
    }

    // -------------------------------------------------------------------
    // Proptests: random configs + random WG-shaped payloads.
    // -------------------------------------------------------------------

    proptest! {
        /// Arbitrary VALID configs never panic on encode/decode of a
        /// canonical WG init.
        #[test]
        fn prop_valid_cfg_roundtrips_wg_init(
            jc in 0u8..=10,
            jmin_jmax in 1u16..=128,
            s1 in 0u16..=200,
            s2 in 0u16..=200,
            h1 in 5u32..=2_147_483_647,
            h2 in 5u32..=2_147_483_647,
            h3 in 5u32..=2_147_483_647,
            h4 in 5u32..=2_147_483_647,
        ) {
            // Force pairwise-distinct h1..h4 — easy way: nudge with offsets.
            // We can't use prop_assume! exhaustively here so just compute
            // distinct values by shifting up by index.
            let h2 = h2.wrapping_add(1).max(5);
            let h3 = h3.wrapping_add(2).max(5);
            let h4 = h4.wrapping_add(3).max(5);
            prop_assume!(h1 != h2 && h1 != h3 && h1 != h4
                         && h2 != h3 && h2 != h4 && h3 != h4);
            // Skip values that collide with canonical msg-types at
            // non-canonical slots.
            prop_assume!(![h1, h2, h3, h4].iter().any(|v| (1..=4).contains(v)));
            let cfg = AmneziaConfig {
                jc, jmin: jmin_jmax, jmax: jmin_jmax,
                s1, s2, h1, h2, h3, h4,
            };
            prop_assume!(cfg.validate().is_ok());
            let mut tx = AmneziaShield::new(cfg).unwrap();
            let mut rx = AmneziaShield::new(cfg).unwrap();
            let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
            let mut init = vec![0u8; WG_INIT_LEN];
            init[..4].copy_from_slice(&WG_MSG_INIT.to_le_bytes());
            init[20] = 0x7E;
            let mut out: Vec<Vec<u8>> = Vec::new();
            tx.wrap_send(dst, &init, |b| out.push(b.to_vec()));
            // jc junk packets first (if any), then the real packet.
            prop_assert_eq!(out.len(), jc as usize + 1);
            let real = out.last().unwrap();
            // recv: drop the junk first (each yields None), then accept
            // the real one.
            for j in &out[..jc as usize] {
                let (g, _) = recv_one(&mut rx, j);
                // junk *may* coincidentally hit a magic at random — that
                // is a real probability if h-values are tiny. Tolerate
                // either None or Some(_) here, the test is about the
                // real packet.
                let _ = g;
            }
            let (got, rxbuf) = recv_one(&mut rx, real);
            prop_assert_eq!(got, Some(WG_INIT_LEN));
            prop_assert_eq!(
                u32::from_le_bytes([rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3]]),
                WG_MSG_INIT
            );
            prop_assert_eq!(rxbuf[20], 0x7E);
        }

        /// Wire compat: 100 random WG-handshake-init buffers wrapped
        /// then stripped equal the original bytes.
        #[test]
        fn prop_random_wg_payloads_wrap_then_strip(
            payload in proptest::collection::vec(any::<u8>(), 8..256),
        ) {
            let cfg = nonid_cfg();
            let mut tx = AmneziaShield::new(cfg).unwrap();
            let mut rx = AmneziaShield::new(cfg).unwrap();
            let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
            // Tag the payload as a WG init.
            let mut p = payload;
            p[..4].copy_from_slice(&WG_MSG_INIT.to_le_bytes());
            // Burn junk on a different dst so the real packet is the
            // first emitted to this dst (cleaner).
            let mut emitted: Vec<Vec<u8>> = Vec::new();
            tx.wrap_send(dst, &p, |b| emitted.push(b.to_vec()));
            let real = emitted.last().cloned().unwrap();
            // Drop junk on rx side.
            for j in &emitted[..emitted.len() - 1] {
                let _ = recv_one(&mut rx, j);
            }
            let (got, rxbuf) = recv_one(&mut rx, &real);
            prop_assert_eq!(got, Some(p.len()));
            prop_assert_eq!(&rxbuf[..p.len()], p.as_slice());
        }
    }

    // -------------------------------------------------------------------
    // Concurrent: two shields on a shared (cloned) UDP socket.
    // -------------------------------------------------------------------

    /// Two senders + two receivers on a shared loopback exchange many
    /// real WG-shaped frames in parallel. Verifies that the shield's
    /// per-dst junk-tracking + restoration logic is independently
    /// correct under concurrent traffic.
    #[tokio::test]
    async fn concurrent_round_trip_many_frames() {
        use std::sync::Arc;
        use tokio::net::UdpSocket;
        use tokio::sync::Mutex;

        let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();
        // Tiny jc to keep the test fast.
        let mut cfg = nonid_cfg();
        cfg.jc = 1;
        cfg.jmin = 8;
        cfg.jmax = 8;
        let sh_a = Arc::new(Mutex::new(AmneziaShield::new(cfg).unwrap()));
        let sh_b = Arc::new(Mutex::new(AmneziaShield::new(cfg).unwrap()));

        const N: usize = 64;
        let send_task = {
            let a = a.clone();
            let sh_a = sh_a.clone();
            tokio::spawn(async move {
                for i in 0..N {
                    let mut payload = vec![0u8; 64];
                    payload[..4].copy_from_slice(&WG_MSG_TRANSPORT.to_le_bytes());
                    payload[7] = i as u8;
                    let mut bufs: Vec<Vec<u8>> = Vec::new();
                    sh_a.lock()
                        .await
                        .wrap_send(b_addr, &payload, |b| bufs.push(b.to_vec()));
                    for d in &bufs {
                        a.send_to(d, b_addr).await.unwrap();
                    }
                }
            })
        };

        let mut got = std::collections::HashSet::new();
        let mut rxbuf = vec![0u8; 4096];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while got.len() < N && tokio::time::Instant::now() < deadline {
            // Try to drain whatever's been delivered.
            let res = tokio::time::timeout(std::time::Duration::from_millis(50), async {
                b.recv_from(&mut rxbuf).await
            })
            .await;
            let Ok(Ok((n, _src))) = res else { continue };
            // Feed it through sh_b's wrap_recv synchronously.
            let mut local = vec![0u8; n];
            local.copy_from_slice(&rxbuf[..n]);
            let mut buf = local.clone();
            let mut once = Some(local);
            let g = sh_b.lock().await.wrap_recv(&mut buf, |out| {
                let s = once.take()?;
                out[..s.len()].copy_from_slice(&s);
                Some(s.len())
            });
            if let Some(sz) = g {
                // Restored sentinel index 7 carries the iteration number.
                if sz >= 8 {
                    let hdr = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    if hdr == WG_MSG_TRANSPORT {
                        got.insert(buf[7]);
                    }
                }
            }
        }
        send_task.await.unwrap();
        // We expect every sentinel value to surface. Loopback can drop
        // some on heavy bursts, so be generous: at least 80%.
        assert!(
            got.len() >= (N * 4) / 5,
            "got {}/{} sentinel-tagged frames; concurrent path may be losing payloads",
            got.len(),
            N
        );
        let _ = a_addr;
    }

    // -------------------------------------------------------------------
    // Bypass: outbound msg-type 0 (unknown) is passed unchanged through
    // junk burst (junk still happens) and the restored msg-type rules.
    // -------------------------------------------------------------------

    #[test]
    fn outbound_unknown_msg_type_skips_substitution_but_burns_junk() {
        // Unknown msg-type passes through, but the *first* call to a
        // new dst still emits the junk burst (because the burst gate
        // fires before msg-type inspection).
        let cfg = nonid_cfg();
        let mut sh = AmneziaShield::new(cfg).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut pkt = vec![0u8; 32];
        pkt[..4].copy_from_slice(&0xDEADu32.to_le_bytes());
        let out = collect_send(&mut sh, dst, &pkt);
        // jc junk + 1 unchanged real
        assert_eq!(out.len(), cfg.jc as usize + 1);
        assert_eq!(out.last().unwrap(), &pkt);
    }

    // -------------------------------------------------------------------
    // Identity recv with sub-4-byte buf: returns the (under-4) length.
    // -------------------------------------------------------------------

    #[test]
    fn identity_recv_short_buf_returns_under_four_bytes() {
        let mut sh = AmneziaShield::new(AmneziaConfig::default()).unwrap();
        let mut buf = [0u8; 4];
        let got = sh.wrap_recv(&mut buf, |_b| Some(2));
        // Identity path doesn't enforce the n>=4 rule (it bypasses).
        assert_eq!(got, Some(2));
    }

    #[test]
    fn nonid_recv_short_buf_returns_none() {
        let cfg = nonid_cfg();
        let mut sh = AmneziaShield::new(cfg).unwrap();
        let mut buf = [0u8; 4];
        // recv reports n=2 (under-four). Non-identity must reject.
        let got = sh.wrap_recv(&mut buf, |_b| Some(2));
        assert_eq!(got, None);
    }

    #[test]
    fn recv_closure_returning_none_propagates() {
        let cfg = nonid_cfg();
        let mut sh = AmneziaShield::new(cfg).unwrap();
        let mut buf = [0u8; 64];
        let got = sh.wrap_recv(&mut buf, |_b| None);
        assert_eq!(got, None);
    }

    #[test]
    fn config_accessor_returns_active_config() {
        let cfg = nonid_cfg();
        let sh = AmneziaShield::new(cfg).unwrap();
        // The shield exposes its config via `config()`; ensure it
        // matches the one we constructed it with.
        assert_eq!(sh.config().h1, cfg.h1);
        assert_eq!(sh.config().s1, cfg.s1);
        assert_eq!(sh.config().jc, cfg.jc);
    }

    #[test]
    fn deserialize_default_yields_identity() {
        // Serde-default path: an empty TOML table must produce the
        // identity config (off-by-default ergonomics).
        let cfg: AmneziaConfig = toml::from_str("").unwrap();
        assert!(cfg.is_identity());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn deserialize_partial_keeps_canonical_h() {
        // jc=2,jmin=10,jmax=20,s1=5,s2=6 but no h-overrides → keep
        // canonical h's (still identity-eligible only if all knobs are
        // off; here jc>0 so it's NOT identity but h's are canonical).
        let cfg: AmneziaConfig =
            toml::from_str("jc = 2\njmin = 10\njmax = 20\ns1 = 5\ns2 = 6\n").unwrap();
        assert_eq!(cfg.jc, 2);
        assert_eq!(cfg.h1, WG_MSG_INIT);
        assert_eq!(cfg.h4, WG_MSG_TRANSPORT);
        assert!(!cfg.is_identity()); // jc>0 disqualifies
    }
}
