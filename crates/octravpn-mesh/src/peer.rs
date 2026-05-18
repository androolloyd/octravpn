//! Tailnet peer registry + candidate exchange.
//!
//! Each tailnet member publishes its current connectivity candidates
//! (WG public key, local LAN addresses, STUN-discovered public address)
//! into a per-tailnet registry. Other members read the registry to
//! decide whether to attempt a direct WireGuard connection or fall
//! back to a paid validator relay.
//!
//! The registry is in-memory + serializable; production deployments
//! gossip it via the validator control plane (cheap, low-rate, signed
//! by the publishing member's account key).
//!
//! Each entry is authenticated by an Ed25519 signature over a canonical
//! byte representation of the snapshot. The signing key is the
//! publishing member's wallet public key — this prevents a malicious
//! peer from spoofing another member's reachability candidates and
//! steering traffic toward an attacker-controlled endpoint.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use octravpn_core::{
    sig::{verify as sig_verify, PublicKey, Signature},
    util::now_unix_secs,
};

use crate::MeshError;

/// Snapshots older than this are rejected at verify-time. Bounds replay
/// of stale candidate sets gossiped on the control plane.
pub const PEER_SNAPSHOT_MAX_AGE_SECS: u64 = 120;

/// Domain-separation tag for the v2 canonical peer-snapshot
/// encoding. Every variable-length field is length-prefixed; the
/// signature commits to this tag + frame, not the raw concatenation.
///
/// Bump this constant on any incompatible change to the encoding.
pub const PEER_SNAPSHOT_DOMAIN: &str = "octravpn-peer-snapshot-v2";

/// First byte of every v2 canonical message. Old (unframed) v1
/// snapshots cannot reach this prefix because their first bytes are
/// the UTF-8 of the `tailnet_id`. Receivers MAY use this byte to
/// reject v1 with a clear "old peer snapshot format" error before
/// signature verification ever runs.
pub const PEER_SNAPSHOT_FRAME_MAGIC: u8 = 0x02;

/// A reachability candidate for a peer.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum PeerCandidate {
    /// Reachable on a private LAN address (e.g. RFC1918).
    Lan(SocketAddr),
    /// Reachable on a public address discovered via STUN.
    Stun(SocketAddr),
    /// Reachable only via a relay endpoint operated by `validator_addr`.
    Relay { validator_addr: String },
}

impl PeerCandidate {
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Lan(a) | Self::Stun(a) => Some(*a),
            Self::Relay { .. } => None,
        }
    }
}

/// A snapshot of one peer's state at some moment in time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerSnapshot {
    pub tailnet_id: String,
    pub addr: String,        // Octra address (e.g. "oct...")
    pub wg_pubkey: [u8; 32], // WireGuard static public key
    pub candidates: Vec<PeerCandidate>,
    /// Optional hostname that magic DNS will resolve to this peer's
    /// allocated tailnet IP.
    pub hostname: Option<String>,
    /// Last time the publishing peer refreshed its entry. The registry
    /// evicts entries older than `Peer::TTL`.
    #[serde(skip, default = "Instant::now")]
    pub last_refresh: Instant,
}

/// An Ed25519-signed peer snapshot. Wraps an inner [`PeerSnapshot`] with
/// a wall-clock timestamp and a 64-byte signature over the canonical
/// message bytes.
///
/// ## Canonical v2 framing
///
/// The canonical message is built as:
///
/// ```text
/// PEER_SNAPSHOT_FRAME_MAGIC (0x02)
///   || PEER_SNAPSHOT_DOMAIN (utf-8)
///   || 0x00 (domain terminator)
///   || u32be(len(tailnet_id)) || tailnet_id
///   || u32be(len(addr))       || addr
///   || u32be(32)              || wg_pubkey (32 bytes)
///   || u32be(len(candidates)) || candidates
///   || u32be(len(hostname))   || hostname
///   || u32be(8)               || ts_unix_be (8 bytes)
/// ```
///
/// Every variable-length field is length-prefixed. Fixed-size
/// fields are length-prefixed too: defense-in-depth costs nothing
/// here and lets a future format do tagged decoding.
///
/// `candidates` is the [`canonical_candidates`] byte encoding,
/// itself length-prefixed.
///
/// **Old (v1) format**: previous releases concatenated
/// `tailnet_id || addr || wg_pubkey || candidates || hostname || ts_unix_be`
/// without length prefixes. That permitted ambiguity such as
/// `("aa", "bb")` and `("a", "abb")` collapsing to the same bytes.
/// The v2 encoding is incompatible by construction (different
/// leading byte); receivers that need to detect a v1 producer can
/// inspect the first byte and reject with
/// [`MeshError::OldPeerSnapshotFormat`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPeerSnapshot {
    pub snapshot: PeerSnapshot,
    pub ts_unix: u64,
    #[serde(with = "serde_sig_bytes")]
    pub sig: [u8; 64],
}

mod serde_sig_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{serde_as, Bytes};

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    struct Wrap(#[serde_as(as = "Bytes")] [u8; 64]);

    pub(super) fn serialize<S: Serializer>(b: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        Wrap(*b).serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        Wrap::deserialize(d).map(|w| w.0)
    }
}

/// Build the canonical byte encoding of a candidate list. Format per
/// candidate is a 1-byte discriminator followed by:
///
/// - `Lan` (0x00) / `Stun` (0x01): 16 bytes of the IP in v4-mapped-into-v6
///   form (length-prefixed `u32be(16)`), then `u32be(2) || port_be`.
/// - `Relay` (0x02): `u32be(len(validator_addr)) || validator_addr`.
///
/// Every variable field carries its own length. The list itself
/// gets a length prefix when embedded in the outer
/// [`canonical_message`].
fn canonical_candidates(cands: &[PeerCandidate]) -> Vec<u8> {
    let mut out = Vec::with_capacity(cands.len() * 28);
    for c in cands {
        match c {
            PeerCandidate::Lan(sa) => {
                out.push(0u8);
                push_socket_addr(&mut out, sa);
            }
            PeerCandidate::Stun(sa) => {
                out.push(1u8);
                push_socket_addr(&mut out, sa);
            }
            PeerCandidate::Relay { validator_addr } => {
                out.push(2u8);
                push_lp(&mut out, validator_addr.as_bytes());
            }
        }
    }
    out
}

fn push_socket_addr(out: &mut Vec<u8>, sa: &SocketAddr) {
    let ip6 = match sa.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    // Length-prefix the 16-byte IP and 2-byte port — fixed sizes,
    // but the framing is uniform.
    push_lp(out, &ip6.octets());
    push_lp(out, &sa.port().to_be_bytes());
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("part length fits in u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Build the v2 canonical message signed by [`SignedPeerSnapshot`].
/// See the type-level docstring for the byte-by-byte layout.
fn canonical_message(snap: &PeerSnapshot, ts_unix: u64) -> Vec<u8> {
    let cands = canonical_candidates(&snap.candidates);
    let host = snap.hostname.as_deref().unwrap_or("");
    let domain = PEER_SNAPSHOT_DOMAIN.as_bytes();
    // 1 magic + domain + 0x00 + 6 × (4-byte len) + each part.
    let mut out = Vec::with_capacity(
        1 + domain.len()
            + 1
            + snap.tailnet_id.len()
            + snap.addr.len()
            + 32
            + cands.len()
            + host.len()
            + 8
            + 24,
    );
    out.push(PEER_SNAPSHOT_FRAME_MAGIC);
    out.extend_from_slice(domain);
    out.push(0x00);
    push_lp(&mut out, snap.tailnet_id.as_bytes());
    push_lp(&mut out, snap.addr.as_bytes());
    push_lp(&mut out, &snap.wg_pubkey);
    push_lp(&mut out, &cands);
    push_lp(&mut out, host.as_bytes());
    push_lp(&mut out, &ts_unix.to_be_bytes());
    out
}

impl SignedPeerSnapshot {
    /// Sign `snapshot` with `kp`. Stamps the current Unix time so
    /// receivers can reject stale gossip even if the signature is
    /// otherwise valid.
    pub fn sign(snapshot: PeerSnapshot, kp: &octravpn_core::sig::KeyPair) -> Self {
        let ts_unix = now_unix_secs();
        let msg = canonical_message(&snapshot, ts_unix);
        let Signature(sig) = kp.sign(&msg);
        Self {
            snapshot,
            ts_unix,
            sig,
        }
    }

    /// Verify both the Ed25519 signature and that the snapshot was
    /// produced within `max_age_secs` of now. Returns the specific
    /// [`MeshError`] variant the registry should surface.
    pub fn verify(&self, expected_pubkey: &PublicKey, max_age_secs: u64) -> Result<(), MeshError> {
        let now = now_unix_secs();
        // saturating_sub so clock skew (slightly future ts) doesn't
        // wrap around and accidentally pass the freshness check.
        let age = now.saturating_sub(self.ts_unix);
        if age > max_age_secs {
            return Err(MeshError::SnapshotExpired { age_secs: age });
        }
        let msg = canonical_message(&self.snapshot, self.ts_unix);
        let sig = Signature(self.sig);
        sig_verify(expected_pubkey, &msg, &sig).map_err(|_| MeshError::SignatureMismatch)
    }

    pub fn into_snapshot(self) -> PeerSnapshot {
        self.snapshot
    }
}

#[derive(Clone, Debug)]
pub struct Peer {
    pub snapshot: PeerSnapshot,
}

impl Peer {
    /// Stale-after window; idle peers fall out of the registry.
    pub const TTL: Duration = Duration::from_secs(300);

    pub fn is_fresh(&self, now: Instant) -> bool {
        now.duration_since(self.snapshot.last_refresh) < Self::TTL
    }
}

#[derive(Default)]
pub struct PeerRegistry {
    inner: RwLock<HashMap<(String, String), Peer>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Authenticated publish. Verifies the snapshot against
    /// `publisher_pubkey` and rejects stale entries before insertion.
    /// `publisher_pubkey` must be the wallet public key the publisher
    /// uses to sign its gossip — the caller is responsible for binding
    /// the Octra address in `snapshot.addr` to that pubkey out-of-band
    /// (e.g. by looking it up in the on-chain account map).
    pub fn publish(
        &self,
        signed: SignedPeerSnapshot,
        publisher_pubkey: &PublicKey,
    ) -> Result<(), MeshError> {
        signed.verify(publisher_pubkey, PEER_SNAPSHOT_MAX_AGE_SECS)?;
        let snap = signed.into_snapshot();
        let key = (snap.tailnet_id.clone(), snap.addr.clone());
        self.inner.write().insert(key, Peer { snapshot: snap });
        Ok(())
    }

    /// Test-only escape hatch: insert a snapshot without verifying any
    /// signature. Keeps the long-standing test fixtures in this crate
    /// from having to thread a keypair through every assertion.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn publish_unverified(&self, snap: PeerSnapshot) {
        let key = (snap.tailnet_id.clone(), snap.addr.clone());
        self.inner.write().insert(key, Peer { snapshot: snap });
    }

    /// Return the freshest peers for `tailnet_id` excluding `self_addr`.
    /// Evicts stale entries as a side-effect.
    pub fn peers_in(&self, tailnet_id: &str, self_addr: &str) -> Vec<Peer> {
        let now = Instant::now();
        let mut w = self.inner.write();
        w.retain(|_, p| p.is_fresh(now));
        w.iter()
            .filter(|((tid, addr), _)| tid == tailnet_id && addr != self_addr)
            .map(|(_, p)| p.clone())
            .collect()
    }

    pub fn get(&self, tailnet_id: &str, addr: &str) -> Option<Peer> {
        self.inner
            .read()
            .get(&(tailnet_id.into(), addr.into()))
            .cloned()
    }

    pub fn remove(&self, tailnet_id: &str, addr: &str) {
        self.inner.write().remove(&(tailnet_id.into(), addr.into()));
    }

    /// Bounded count for observability.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octravpn_core::sig::KeyPair;

    fn fake_snapshot(tid: &str, addr: &str, host: &str) -> PeerSnapshot {
        PeerSnapshot {
            tailnet_id: tid.into(),
            addr: addr.into(),
            wg_pubkey: [0u8; 32],
            candidates: vec![PeerCandidate::Lan("10.0.0.1:51820".parse().unwrap())],
            hostname: Some(host.into()),
            last_refresh: Instant::now(),
        }
    }

    #[test]
    fn publish_and_lookup_filters_self() {
        let r = PeerRegistry::new();
        r.publish_unverified(fake_snapshot("t1", "octA", "alice"));
        r.publish_unverified(fake_snapshot("t1", "octB", "bob"));
        r.publish_unverified(fake_snapshot("t2", "octA", "alice2"));

        let peers = r.peers_in("t1", "octA");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].snapshot.addr, "octB");
    }

    #[test]
    fn stale_entries_get_evicted_on_lookup() {
        let r = PeerRegistry::new();
        let mut snap = fake_snapshot("t1", "octStale", "host");
        snap.last_refresh = Instant::now()
            .checked_sub(Peer::TTL)
            .unwrap()
            .checked_sub(Duration::from_secs(1))
            .unwrap();
        r.publish_unverified(snap);
        let peers = r.peers_in("t1", "self");
        assert!(peers.is_empty(), "expected stale peer to be evicted");
    }

    #[test]
    fn candidate_socket_addr_for_lan_and_stun() {
        let lan = PeerCandidate::Lan("10.0.0.1:1".parse().unwrap());
        let stun = PeerCandidate::Stun("203.0.113.1:2".parse().unwrap());
        let relay = PeerCandidate::Relay {
            validator_addr: "octV".into(),
        };
        assert!(lan.socket_addr().is_some());
        assert!(stun.socket_addr().is_some());
        assert!(relay.socket_addr().is_none());
    }

    #[test]
    fn signs_and_verifies_round_trip() {
        let kp = KeyPair::generate();
        let snap = PeerSnapshot {
            tailnet_id: "t1".into(),
            addr: "octA".into(),
            wg_pubkey: [3u8; 32],
            candidates: vec![
                PeerCandidate::Lan("10.0.0.1:51820".parse().unwrap()),
                PeerCandidate::Stun("203.0.113.4:7777".parse().unwrap()),
                PeerCandidate::Relay {
                    validator_addr: "octValidator".into(),
                },
            ],
            hostname: Some("alice".into()),
            last_refresh: Instant::now(),
        };
        let signed = SignedPeerSnapshot::sign(snap, &kp);
        // Direct verify.
        signed
            .verify(&kp.public, PEER_SNAPSHOT_MAX_AGE_SECS)
            .expect("verify should pass for unmodified signed snapshot");
        // Goes into the registry.
        let r = PeerRegistry::new();
        r.publish(signed, &kp.public)
            .expect("publish should accept");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn rejects_tampered_candidates() {
        let kp = KeyPair::generate();
        let snap = PeerSnapshot {
            tailnet_id: "t1".into(),
            addr: "octA".into(),
            wg_pubkey: [0u8; 32],
            candidates: vec![PeerCandidate::Lan("10.0.0.1:51820".parse().unwrap())],
            hostname: None,
            last_refresh: Instant::now(),
        };
        let mut signed = SignedPeerSnapshot::sign(snap, &kp);
        // Flip a byte in the candidate list — change the port.
        signed.snapshot.candidates = vec![PeerCandidate::Lan("10.0.0.1:51821".parse().unwrap())];
        match signed.verify(&kp.public, PEER_SNAPSHOT_MAX_AGE_SECS) {
            Err(MeshError::SignatureMismatch) => {}
            other => panic!("expected SignatureMismatch, got {other:?}"),
        }
        // The registry surface also rejects it.
        let r = PeerRegistry::new();
        match r.publish(signed, &kp.public) {
            Err(MeshError::SignatureMismatch) => {}
            other => panic!("expected publish to reject, got {other:?}"),
        }
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn canonical_framing_prevents_field_boundary_ambiguity() {
        // Two snapshots that would have been bit-identical under the
        // old unframed encoding (concat of tailnet_id || addr || ...):
        //   left: tailnet_id = "aa", addr = "bb", hostname = ""
        //   right: tailnet_id = "a",  addr = "abb", hostname = ""
        // and similarly the swap on hostname:
        //   left: addr = "x", hostname = "yz"
        //   right: addr = "xy", hostname = "z"
        let mk = |tid: &str, addr: &str, host: Option<&str>| PeerSnapshot {
            tailnet_id: tid.into(),
            addr: addr.into(),
            wg_pubkey: [0u8; 32],
            candidates: vec![],
            hostname: host.map(str::to_owned),
            last_refresh: Instant::now(),
        };
        let tid_left = canonical_message(&mk("aa", "bb", None), 0);
        let tid_right = canonical_message(&mk("a", "abb", None), 0);
        assert_ne!(
            tid_left, tid_right,
            "tailnet_id/addr boundary must be unambiguous"
        );

        let host_left = canonical_message(&mk("t", "x", Some("yz")), 0);
        let host_right = canonical_message(&mk("t", "xy", Some("z")), 0);
        assert_ne!(
            host_left, host_right,
            "addr/hostname boundary must be unambiguous"
        );

        // And one more: candidates list vs an "empty list immediately
        // followed by data that looks like a candidate".
        let cands = vec![PeerCandidate::Relay {
            validator_addr: "octV".into(),
        }];
        let with_cands = canonical_message(
            &PeerSnapshot {
                tailnet_id: "t".into(),
                addr: "a".into(),
                wg_pubkey: [0u8; 32],
                candidates: cands,
                hostname: Some("x".into()),
                last_refresh: Instant::now(),
            },
            0,
        );
        let without_cands = canonical_message(
            &PeerSnapshot {
                tailnet_id: "t".into(),
                addr: "a".into(),
                wg_pubkey: [0u8; 32],
                candidates: vec![],
                hostname: Some("x".into()),
                last_refresh: Instant::now(),
            },
            0,
        );
        assert_ne!(
            with_cands, without_cands,
            "candidates list length must be unambiguous"
        );
    }

    #[test]
    fn canonical_frame_begins_with_magic_and_domain() {
        let snap = fake_snapshot("t1", "octA", "alice");
        let msg = canonical_message(&snap, 1234);
        assert_eq!(msg[0], PEER_SNAPSHOT_FRAME_MAGIC);
        let dom = PEER_SNAPSHOT_DOMAIN.as_bytes();
        let dom_end = 1 + dom.len();
        assert_eq!(&msg[1..dom_end], dom);
        assert_eq!(msg[dom_end], 0x00);
    }

    #[test]
    fn rejects_expired_snapshots() {
        let kp = KeyPair::generate();
        let snap = fake_snapshot("t1", "octA", "alice");
        let mut signed = SignedPeerSnapshot::sign(snap, &kp);
        // Backdate by well over the max age. We need to re-sign with the
        // backdated timestamp so that the signature still verifies — the
        // freshness check must reject before the signature check ever
        // accepts.
        let max = PEER_SNAPSHOT_MAX_AGE_SECS;
        signed.ts_unix = now_unix_secs().saturating_sub(max + 60);
        let msg = canonical_message(&signed.snapshot, signed.ts_unix);
        signed.sig = kp.sign(&msg).0;
        match signed.verify(&kp.public, max) {
            Err(MeshError::SnapshotExpired { age_secs }) => {
                assert!(age_secs > max, "age {age_secs} should exceed max {max}");
            }
            other => panic!("expected SnapshotExpired, got {other:?}"),
        }
    }
}
