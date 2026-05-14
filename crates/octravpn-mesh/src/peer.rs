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
/// The canonical message format is:
///   tailnet_id || addr || wg_pubkey || candidates || hostname_or_empty || ts_unix_be
/// where `candidates` is the length-prefixed concatenation defined in
/// [`canonical_candidates`] and each string field is concatenated as
/// UTF-8 bytes (no separators — the surrounding fields are
/// fixed-length or length-prefixed, so there is no ambiguity for the
/// fields that are not).
///
/// Note: `tailnet_id`/`addr`/`hostname` are not themselves
/// length-prefixed because the production gossip envelope already binds
/// each field separately. Within the mesh crate every snapshot is
/// produced and consumed in lock-step, so a simple concatenation is
/// sufficient and matches the existing serde representation.
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
///   form, then 2 bytes of port in big-endian.
/// - `Relay` (0x02): 4 bytes of `validator_addr` length in big-endian,
///   then the UTF-8 bytes.
fn canonical_candidates(cands: &[PeerCandidate]) -> Vec<u8> {
    // Per-candidate cost is at most 19 bytes for Lan/Stun, plus the
    // variable Relay strings. Preallocate generously to avoid reallocs.
    let mut out = Vec::with_capacity(cands.len() * 20);
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
                let bytes = validator_addr.as_bytes();
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(bytes);
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
    out.extend_from_slice(&ip6.octets()); // 16 bytes
    out.extend_from_slice(&sa.port().to_be_bytes()); // 2 bytes
}

fn canonical_message(snap: &PeerSnapshot, ts_unix: u64) -> Vec<u8> {
    let cands = canonical_candidates(&snap.candidates);
    let host = snap.hostname.as_deref().unwrap_or("");
    let mut out = Vec::with_capacity(
        snap.tailnet_id.len() + snap.addr.len() + 32 + cands.len() + host.len() + 8,
    );
    out.extend_from_slice(snap.tailnet_id.as_bytes());
    out.extend_from_slice(snap.addr.as_bytes());
    out.extend_from_slice(&snap.wg_pubkey);
    out.extend_from_slice(&cands);
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&ts_unix.to_be_bytes());
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
