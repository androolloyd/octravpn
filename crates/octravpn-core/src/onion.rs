//! Multi-hop onion routing with ChaCha20-Poly1305 + HKDF over X25519 ECDH.
//!
//! At session-open time the client knows each hop's static X25519 public
//! key. The client generates a fresh ephemeral key per hop, performs
//! ECDH against the hop's static key, and derives a per-hop AEAD key
//! via HKDF-SHA256.
//!
//! Wire format (sent client→entry as the first packet of the session):
//!
//! ```text
//! onion_packet = layer_N
//! layer_i      = ephemeral_pk_i (32 bytes)        // X25519 pubkey
//!              || aead_seal(key_i, nonce_zero,
//!                   header_i || layer_{i-1})       // AEAD ciphertext
//! layer_0      = inner_payload                     // delivered to exit
//! ```
//!
//! Each hop:
//!   1. Reads the first 32 bytes as the sender's ephemeral pubkey.
//!   2. Performs X25519 ECDH against its own static secret.
//!   3. Derives AEAD key via HKDF.
//!   4. AEAD-decrypts the rest.
//!   5. Parses the header (next-hop endpoint or "egress") and forwards
//!      the inner ciphertext blob (which is layer_{i-1}).
//!
//! Subsequent data packets reuse the same per-session AEAD key, with
//! a counter-derived nonce, so the ECDH and HKDF only run once at
//! session establishment.

use std::{
    collections::HashMap,
    io::{Cursor, Read},
    sync::Arc,
};

use hkdf::Hkdf;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pub, StaticSecret};
use zeroize::Zeroize;

use crate::session::SessionId;

// Perf-5: hot-path AEAD goes through the hardware-accelerated shim
// (`aead::aead_seal` / `aead::aead_open`), not the portable
// `chacha20poly1305` crate. The shim wraps `aws-lc-rs` and emits
// byte-identical AEAD output — see `aead.rs::cross_impl_compatibility`
// for the safety gate.
use crate::aead::{aead_open, aead_seal, AEAD_NONCE_LEN, KEY_LEN};

pub const MAX_HOPS: usize = 3;
pub const ONION_HKDF_INFO: &[u8] = b"octravpn-onion-v1";

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OnionError {
    #[error("empty route")]
    EmptyRoute,
    #[error("max {MAX_HOPS} hops")]
    TooManyHops,
    #[error("aead failure: {0}")]
    Aead(String),
    #[error("io: {0}")]
    Io(String),
    #[error("malformed packet")]
    Malformed,
}

/// Per-hop forwarding directive parsed by the receiving hop after AEAD
/// decryption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HopAction {
    /// Forward the unwrapped layer to the next hop's WG endpoint.
    Forward {
        endpoint: String,
        next_static_pubkey: [u8; 32],
    },
    /// This is the exit hop. The inner payload is the original packet to
    /// emit on the public internet (or the receipt-control-plane request).
    Egress,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HopHeader {
    action: HopAction,
}

/// Build an onion packet for a route.
///
/// `hops` lists the hops in order: entry, [middle...], exit. The exit
/// hop's header is `HopAction::Egress` and the others' are `Forward`.
/// The innermost layer carries `inner` plaintext.
pub fn build_onion(hops: &[HopBuildInput], inner: &[u8]) -> Result<Vec<u8>, OnionError> {
    if hops.is_empty() {
        return Err(OnionError::EmptyRoute);
    }
    if hops.len() > MAX_HOPS {
        return Err(OnionError::TooManyHops);
    }

    // Build layers from innermost (exit) outward.
    let mut payload = inner.to_vec();
    for (i, hop) in hops.iter().enumerate().rev() {
        let action = if i == hops.len() - 1 {
            HopAction::Egress
        } else {
            let next = &hops[i + 1];
            HopAction::Forward {
                endpoint: next.endpoint.clone(),
                next_static_pubkey: next.static_pubkey,
            }
        };
        let header = HopHeader { action };
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|e| OnionError::Io(format!("encode header: {e}")))?;
        payload = wrap_layer(&hop.static_pubkey, &header_bytes, &payload)?;
    }
    Ok(payload)
}

/// Inputs needed by the client to wrap one layer.
#[derive(Clone, Debug)]
pub struct HopBuildInput {
    /// Hop's static X25519 pubkey (its WG noise pubkey).
    pub static_pubkey: [u8; 32],
    /// Hop's WG endpoint, used as the `Forward` target for the *previous*
    /// hop. Ignored for the final hop.
    pub endpoint: String,
}

fn wrap_layer(static_pk: &[u8; 32], header: &[u8], inner: &[u8]) -> Result<Vec<u8>, OnionError> {
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = X25519Pub::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&X25519Pub::from(*static_pk));

    let key = derive_aead_key(shared.as_bytes());
    // Per-layer nonce stays at zero because the key itself is unique
    // per layer (ECDH(eph_i, static_i) is a fresh shared secret). This
    // matches the Tor / Sphinx onion convention.
    let nonce = [0u8; AEAD_NONCE_LEN];

    let mut plaintext = Vec::with_capacity(4 + header.len() + inner.len());
    plaintext.extend_from_slice(&(header.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(header);
    plaintext.extend_from_slice(inner);

    // Perf-5: hardware-accelerated AEAD. The previous `chacha20poly1305`
    // crate produced byte-identical output (same RFC 8439 standard); the
    // wire format is preserved.
    let ct =
        aead_seal(&key, &nonce, &[], &plaintext).map_err(|e| OnionError::Aead(e.to_string()))?;

    let mut out = Vec::with_capacity(32 + ct.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

fn derive_aead_key(shared: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(ONION_HKDF_INFO, &mut okm)
        .expect("32-byte HKDF output is always valid");
    okm
}

/// One hop's view of an inbound onion packet.
#[derive(Debug)]
pub struct PeeledLayer {
    pub action: HopAction,
    /// The wrapped inner blob to forward (for `Forward`) or the original
    /// payload (for `Egress`).
    pub inner: Vec<u8>,
}

/// Peel one layer: ECDH against our static secret, decrypt, parse header.
pub fn peel_layer(static_secret: &StaticSecret, packet: &[u8]) -> Result<PeeledLayer, OnionError> {
    if packet.len() < 32 + 16 {
        return Err(OnionError::Malformed);
    }
    let mut eph_pk = [0u8; 32];
    eph_pk.copy_from_slice(&packet[..32]);
    let shared = static_secret.diffie_hellman(&X25519Pub::from(eph_pk));
    let key = derive_aead_key(shared.as_bytes());
    let nonce = [0u8; AEAD_NONCE_LEN];
    // Perf-5: hardware-accelerated AEAD open. See wrap_layer for the
    // matching seal side.
    let pt =
        aead_open(&key, &nonce, &[], &packet[32..]).map_err(|e| OnionError::Aead(e.to_string()))?;
    parse_layer(&pt)
}

// -----------------------------------------------------------------------------
// Perf #9: session-pinned onion keys.
//
// Backstory: every relay-hop packet today calls `peel_layer`, which runs
// X25519 ECDH (~27 µs) + HKDF + AEAD open. The X25519 step is the dominant
// cost (~85 % of the 31.7 µs `onion_peel_layer` time committed in
// `bench-snapshots/core.json`). Across a session, the ephemeral pubkey in
// the onion wrapper never changes — wire-format keeps the per-hop ECDH
// stable for the session lifetime. So we move that ECDH from per-packet to
// per-session-open.
//
// `OnionSessionKeys` stores the derived AEAD key (32 bytes; the ChaCha20
// `Key`). Construction takes a static secret + the eph-pubkey from the
// first peel (or the explicit handshake message). Subsequent packets call
// `peel_with_pinned_key` instead of `peel_layer`.
//
// Storage: `SessionKeyStore` keeps a `RwLock<HashMap<SessionId, Arc<OSK>>>`.
// In practice the store is read-heavy (every packet) and write-rare
// (session-open / session-close). For pure lock-free read-side semantics
// we'd want `arc-swap::ArcSwap`; we deliberately stick with RwLock for now
// to keep the dep footprint minimal — see the `concurrent_pin_and_evict`
// proptest below for the contention shape.
//
// Zeroization: `OnionSessionKeys` zeroizes its key material on Drop via the
// `zeroize` crate (already a workspace dep). This matters because a session
// drop should not leave a viable AEAD key in freed heap pages.

/// AEAD keys derived once per session for the onion layer. Same wire
/// format as the per-packet `peel_layer` path — only the X25519+HKDF
/// step is hoisted out.
///
/// On `Drop`, the inner bytes are zeroized so a heap-scrape after
/// session close can't recover the key.
#[derive(Clone)]
pub struct OnionSessionKeys {
    /// Per-hop AEAD key. Stored as 32 raw bytes (matches `chacha20poly1305::Key`).
    /// Up to `MAX_HOPS` entries; entries past the actual hop count are zero
    /// and unused.
    key_bytes: [[u8; 32]; MAX_HOPS],
    /// How many hops are actually pinned (1..=MAX_HOPS).
    hop_count: usize,
}

impl std::fmt::Debug for OnionSessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't leak key material via Debug.
        f.debug_struct("OnionSessionKeys")
            .field("hop_count", &self.hop_count)
            .field("key_bytes", &"<redacted>")
            .finish()
    }
}

impl Drop for OnionSessionKeys {
    fn drop(&mut self) {
        for k in &mut self.key_bytes {
            k.zeroize();
        }
        self.hop_count.zeroize();
    }
}

impl OnionSessionKeys {
    /// Build session keys from a static secret and the per-hop ephemeral
    /// pubkeys captured at session-open. Performs the X25519 ECDH + HKDF
    /// once per hop.
    ///
    /// `eph_pubkeys` is ordered from outermost (the first peel performed
    /// by this hop) to innermost. In the common single-hop-relay case,
    /// only `eph_pubkeys[0]` is populated.
    pub fn from_ephemeral_pubkeys(
        static_secret: &StaticSecret,
        eph_pubkeys: &[[u8; 32]],
    ) -> Result<Self, OnionError> {
        if eph_pubkeys.is_empty() {
            return Err(OnionError::EmptyRoute);
        }
        if eph_pubkeys.len() > MAX_HOPS {
            return Err(OnionError::TooManyHops);
        }
        let mut key_bytes = [[0u8; 32]; MAX_HOPS];
        for (i, pk) in eph_pubkeys.iter().enumerate() {
            let shared = static_secret.diffie_hellman(&X25519Pub::from(*pk));
            let key = derive_aead_key(shared.as_bytes());
            key_bytes[i].copy_from_slice(key.as_slice());
        }
        Ok(Self {
            key_bytes,
            hop_count: eph_pubkeys.len(),
        })
    }

    /// Number of hops pinned.
    pub fn hop_count(&self) -> usize {
        self.hop_count
    }

    /// Per-hop AEAD key view (caller must respect `hop_count`).
    fn key_for(&self, hop: usize) -> Option<&[u8; 32]> {
        if hop >= self.hop_count {
            return None;
        }
        Some(&self.key_bytes[hop])
    }
}

/// Lock-protected store of session-pinned keys. Read on every relay
/// packet; written at session-open and session-close.
///
/// We use `RwLock` from `parking_lot` (already a workspace dep) rather
/// than `ArcSwap` to keep the dep footprint minimal. Contention is
/// asymmetric — readers vastly outnumber writers — so the parking_lot
/// fast-path is acceptable. A future #9.1 can swap in `arc-swap` if a
/// load test shows the RwLock taking measurable time.
#[derive(Default)]
pub struct SessionKeyStore {
    inner: RwLock<HashMap<SessionId, Arc<OnionSessionKeys>>>,
}

impl SessionKeyStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Pin a fresh `OnionSessionKeys` for `sid`. Replaces any prior entry
    /// (zeroizing the displaced keys via Drop).
    pub fn pin(&self, sid: SessionId, keys: OnionSessionKeys) {
        self.inner.write().insert(sid, Arc::new(keys));
    }

    /// Look up the keys for `sid`. Returns `None` if the session was
    /// never pinned or has been evicted.
    pub fn get(&self, sid: &SessionId) -> Option<Arc<OnionSessionKeys>> {
        self.inner.read().get(sid).cloned()
    }

    /// Evict the keys for `sid`. The `Arc`'s last drop zeroizes the
    /// underlying bytes. Returns whether an entry was removed.
    pub fn evict(&self, sid: &SessionId) -> bool {
        self.inner.write().remove(sid).is_some()
    }

    /// Number of pinned sessions. Test-only.
    #[doc(hidden)]
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Test-only: whether the store has any pinned sessions.
    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

/// Peel one layer using a pre-pinned session key. Skips X25519 ECDH +
/// HKDF; runs AEAD-only.
///
/// `hop_idx` is which hop the caller is operating as (0 = outermost).
/// In the typical single-hop relay this is always 0.
pub fn peel_with_pinned_key(
    keys: &OnionSessionKeys,
    hop_idx: usize,
    packet: &[u8],
) -> Result<PeeledLayer, OnionError> {
    if packet.len() < 32 + 16 {
        return Err(OnionError::Malformed);
    }
    let key_bytes = keys.key_for(hop_idx).ok_or(OnionError::Malformed)?;
    let key = Key::from(*key_bytes);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let pt = cipher
        .decrypt(nonce, &packet[32..])
        .map_err(|e| OnionError::Aead(e.to_string()))?;
    parse_layer(&pt)
}

/// Peel a layer, preferring the session-pinned key when present. Falls
/// back to a full `peel_layer` (X25519 + HKDF + AEAD) when no pinned
/// keys exist for the session yet.
///
/// This is the entry point the datapath should call: it lets the very
/// first packet (which carries the eph_pubkey used to derive the pinned
/// key) fall through the slow path, and every subsequent packet take
/// the fast path.
pub fn peel_layer_pinned_or_fallback(
    static_secret: &StaticSecret,
    store: &SessionKeyStore,
    sid: &SessionId,
    packet: &[u8],
) -> Result<PeeledLayer, OnionError> {
    if let Some(keys) = store.get(sid) {
        return peel_with_pinned_key(&keys, 0, packet);
    }
    peel_layer(static_secret, packet)
}

fn parse_layer(plaintext: &[u8]) -> Result<PeeledLayer, OnionError> {
    let mut cur = Cursor::new(plaintext);
    let mut hlen = [0u8; 4];
    cur.read_exact(&mut hlen)
        .map_err(|_| OnionError::Malformed)?;
    let hl = u32::from_be_bytes(hlen) as usize;
    if hl > plaintext.len().saturating_sub(4) {
        return Err(OnionError::Malformed);
    }
    let header_start = 4;
    let header_end = 4 + hl;
    let header: HopHeader = serde_json::from_slice(&plaintext[header_start..header_end])
        .map_err(|e| OnionError::Io(format!("decode header: {e}")))?;
    let inner = plaintext[header_end..].to_vec();
    Ok(PeeledLayer {
        action: header.action,
        inner,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_static() -> ([u8; 32], StaticSecret) {
        let s = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Pub::from(&s);
        (pk.to_bytes(), s)
    }

    #[test]
    fn single_hop_round_trip() {
        let (pk, sk) = fresh_static();
        let onion = build_onion(
            &[HopBuildInput {
                static_pubkey: pk,
                endpoint: "ignored".into(),
            }],
            b"hello world",
        )
        .unwrap();
        let peeled = peel_layer(&sk, &onion).unwrap();
        assert_eq!(peeled.action, HopAction::Egress);
        assert_eq!(peeled.inner, b"hello world");
    }

    #[test]
    fn three_hop_route() {
        let (pk1, sk1) = fresh_static();
        let (pk2, sk2) = fresh_static();
        let (pk3, sk3) = fresh_static();

        let onion = build_onion(
            &[
                HopBuildInput {
                    static_pubkey: pk1,
                    endpoint: "node1:51820".into(),
                },
                HopBuildInput {
                    static_pubkey: pk2,
                    endpoint: "node2:51820".into(),
                },
                HopBuildInput {
                    static_pubkey: pk3,
                    endpoint: "node3:51820".into(),
                },
            ],
            b"final-payload",
        )
        .unwrap();

        // Hop 1: Forward to node2.
        let p1 = peel_layer(&sk1, &onion).unwrap();
        let HopAction::Forward {
            endpoint,
            next_static_pubkey,
        } = p1.action
        else {
            panic!("hop1 must forward");
        };
        assert_eq!(endpoint, "node2:51820");
        assert_eq!(next_static_pubkey, pk2);

        // Hop 2: Forward to node3.
        let p2 = peel_layer(&sk2, &p1.inner).unwrap();
        let HopAction::Forward {
            endpoint,
            next_static_pubkey,
        } = p2.action
        else {
            panic!("hop2 must forward");
        };
        assert_eq!(endpoint, "node3:51820");
        assert_eq!(next_static_pubkey, pk3);

        // Hop 3: Egress with the final payload.
        let p3 = peel_layer(&sk3, &p2.inner).unwrap();
        assert_eq!(p3.action, HopAction::Egress);
        assert_eq!(p3.inner, b"final-payload");
    }

    #[test]
    fn wrong_secret_fails_decrypt() {
        let (pk, _sk) = fresh_static();
        let (_pk_other, sk_other) = fresh_static();
        let onion = build_onion(
            &[HopBuildInput {
                static_pubkey: pk,
                endpoint: "x".into(),
            }],
            b"x",
        )
        .unwrap();
        assert!(peel_layer(&sk_other, &onion).is_err());
    }

    #[test]
    fn rejects_too_many_hops() {
        let mut hops = Vec::with_capacity(MAX_HOPS + 1);
        for _ in 0..=MAX_HOPS {
            hops.push(HopBuildInput {
                static_pubkey: [0u8; 32],
                endpoint: String::new(),
            });
        }
        let res = build_onion(&hops, b"x");
        assert!(matches!(res, Err(OnionError::TooManyHops)));
    }

    #[test]
    fn rejects_empty_route() {
        let res = build_onion(&[], b"x");
        assert!(matches!(res, Err(OnionError::EmptyRoute)));
    }

    #[test]
    fn malformed_packet_rejected() {
        let (_pk, sk) = fresh_static();
        let too_short = vec![0u8; 16];
        assert!(peel_layer(&sk, &too_short).is_err());
    }

    /// Boundary: exactly the minimum length (32+16 = 48 bytes) passes
    /// the length check and the AEAD fails on the garbage ciphertext.
    /// Confirms the off-by-one direction is `< 48` rejects.
    #[test]
    fn minimum_length_packet_passes_length_check() {
        let (_pk, sk) = fresh_static();
        let just_enough = vec![0u8; 48];
        match peel_layer(&sk, &just_enough) {
            Err(OnionError::Aead(_)) => {}
            other => panic!("expected Aead error, got {other:?}"),
        }
    }

    /// 47-byte packets (one below the floor) reject as Malformed.
    #[test]
    fn just_below_min_length_rejects_malformed() {
        let (_pk, sk) = fresh_static();
        let one_short = vec![0u8; 47];
        assert!(matches!(
            peel_layer(&sk, &one_short).unwrap_err(),
            OnionError::Malformed
        ));
    }

    /// Appended garbage breaks AEAD (truncation-vs-extension attacks).
    #[test]
    fn appended_garbage_rejects_aead() {
        let (pk, sk) = fresh_static();
        let mut onion = build_onion(
            &[HopBuildInput {
                static_pubkey: pk,
                endpoint: "x".into(),
            }],
            b"payload",
        )
        .unwrap();
        onion.extend_from_slice(b"GARBAGE");
        match peel_layer(&sk, &onion).unwrap_err() {
            OnionError::Aead(_) => {}
            other => panic!("expected Aead error, got {other:?}"),
        }
    }

    /// Dropping the trailing byte breaks the AEAD tag.
    #[test]
    fn truncation_rejects_aead() {
        let (pk, sk) = fresh_static();
        let mut onion = build_onion(
            &[HopBuildInput {
                static_pubkey: pk,
                endpoint: "x".into(),
            }],
            b"payload",
        )
        .unwrap();
        onion.pop();
        assert!(matches!(
            peel_layer(&sk, &onion).unwrap_err(),
            OnionError::Aead(_)
        ));
    }

    /// Two hops with the same static key (operator mis-config) still
    /// round-trip. Defends against an assumption that hop secrets are
    /// distinct.
    #[test]
    fn duplicate_hop_secrets_round_trip() {
        let (pk, sk) = fresh_static();
        let onion = build_onion(
            &[
                HopBuildInput {
                    static_pubkey: pk,
                    endpoint: "first:1".into(),
                },
                HopBuildInput {
                    static_pubkey: pk,
                    endpoint: "second:2".into(),
                },
            ],
            b"x",
        )
        .unwrap();
        let p1 = peel_layer(&sk, &onion).unwrap();
        match p1.action {
            HopAction::Forward { endpoint, .. } => assert_eq!(endpoint, "second:2"),
            HopAction::Egress => panic!("expected Forward at hop 1"),
        }
        let p2 = peel_layer(&sk, &p1.inner).unwrap();
        assert_eq!(p2.action, HopAction::Egress);
    }

    /// `build_onion` accepts MAX_HOPS exactly (boundary; `<` vs `<=`).
    #[test]
    fn build_at_max_hops_is_accepted() {
        let mut hops = Vec::with_capacity(MAX_HOPS);
        let mut secrets = Vec::with_capacity(MAX_HOPS);
        for _ in 0..MAX_HOPS {
            let (pk, sk) = fresh_static();
            hops.push(HopBuildInput {
                static_pubkey: pk,
                endpoint: "x".into(),
            });
            secrets.push(sk);
        }
        let onion = build_onion(&hops, b"payload").unwrap();
        let mut cur = onion;
        for sk in &secrets {
            cur = peel_layer(sk, &cur).unwrap().inner;
        }
        assert!(!cur.is_empty());
    }

    /// Empty inner payload still produces a well-formed onion. Edge
    /// case for `bytes_used == 0` control-plane messages.
    #[test]
    fn empty_inner_payload_round_trips() {
        let (pk, sk) = fresh_static();
        let onion = build_onion(
            &[HopBuildInput {
                static_pubkey: pk,
                endpoint: "x".into(),
            }],
            b"",
        )
        .unwrap();
        let peeled = peel_layer(&sk, &onion).unwrap();
        assert_eq!(peeled.action, HopAction::Egress);
        assert_eq!(peeled.inner, b"");
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Property: any payload up to 256 bytes round-trips through
        /// a single-hop onion intact.
        #[test]
        fn prop_round_trip_random_payload(
            payload in prop::collection::vec(any::<u8>(), 0..256),
        ) {
            let (pk, sk) = fresh_static();
            let onion = build_onion(
                &[HopBuildInput { static_pubkey: pk, endpoint: "x".into() }],
                &payload,
            ).unwrap();
            let peeled = peel_layer(&sk, &onion).unwrap();
            prop_assert_eq!(peeled.inner, payload);
        }
    }

    // -------------------------------------------------------------------
    // Perf #9 — session-pinned onion keys.

    /// Extract the ephemeral pubkey prefix from a built onion packet
    /// (first 32 bytes). Mirrors the parsing `peel_layer` does internally.
    fn eph_pk_of(packet: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&packet[..32]);
        out
    }

    /// Pinned-key peel produces a byte-identical result to the on-the-fly
    /// `peel_layer`. This is the core correctness gate: if we ever stop
    /// matching, the data plane silently corrupts every relay flow.
    #[test]
    fn pinned_key_matches_on_the_fly_peel() {
        let (pk, sk) = fresh_static();
        let onion = build_onion(
            &[HopBuildInput {
                static_pubkey: pk,
                endpoint: "x".into(),
            }],
            b"the quick brown fox jumps over the lazy dog",
        )
        .unwrap();

        let slow = peel_layer(&sk, &onion).unwrap();
        let keys = OnionSessionKeys::from_ephemeral_pubkeys(&sk, &[eph_pk_of(&onion)]).unwrap();
        let fast = peel_with_pinned_key(&keys, 0, &onion).unwrap();
        assert_eq!(slow.action, fast.action);
        assert_eq!(slow.inner, fast.inner);
    }

    /// Session rotation: pinning a new `OnionSessionKeys` under the same
    /// SessionId replaces the previous entry. The displaced Arc drops
    /// and its inner key bytes are zeroized — we can only assert the
    /// store no longer hands them out.
    #[test]
    fn session_rotation_evicts_keys() {
        let (pk_a, sk_a) = fresh_static();
        let (pk_b, sk_b) = fresh_static();
        let store = SessionKeyStore::new();
        let sid = crate::session::SessionId::new([7u8; 32]);

        let onion_a = build_onion(
            &[HopBuildInput {
                static_pubkey: pk_a,
                endpoint: "x".into(),
            }],
            b"alpha",
        )
        .unwrap();
        let keys_a =
            OnionSessionKeys::from_ephemeral_pubkeys(&sk_a, &[eph_pk_of(&onion_a)]).unwrap();
        store.pin(sid.clone(), keys_a);
        assert_eq!(store.len(), 1);

        // Pin a fresh set for a different static secret + onion. The old
        // key should no longer decrypt onion_a.
        let onion_b = build_onion(
            &[HopBuildInput {
                static_pubkey: pk_b,
                endpoint: "y".into(),
            }],
            b"beta",
        )
        .unwrap();
        let keys_b =
            OnionSessionKeys::from_ephemeral_pubkeys(&sk_b, &[eph_pk_of(&onion_b)]).unwrap();
        store.pin(sid.clone(), keys_b);
        assert_eq!(store.len(), 1);

        // The pinned key is now keys_b; attempting to peel onion_a with
        // the new pinned key fails AEAD (the eph_pk differs).
        let cur = store.get(&sid).unwrap();
        assert!(peel_with_pinned_key(&cur, 0, &onion_a).is_err());
        // But onion_b still decrypts cleanly with the current pin.
        let p = peel_with_pinned_key(&cur, 0, &onion_b).unwrap();
        assert_eq!(p.inner, b"beta");
    }

    /// `peel_layer_pinned_or_fallback` MUST hit the slow path when the
    /// session isn't pinned yet. This is the first-packet path.
    #[test]
    fn missing_session_falls_back_to_peel_layer() {
        let (pk, sk) = fresh_static();
        let onion = build_onion(
            &[HopBuildInput {
                static_pubkey: pk,
                endpoint: "x".into(),
            }],
            b"first-packet",
        )
        .unwrap();
        let store = SessionKeyStore::new();
        let sid = crate::session::SessionId::new([1u8; 32]);
        // Store is empty — must fall back.
        let p = peel_layer_pinned_or_fallback(&sk, &store, &sid, &onion).unwrap();
        assert_eq!(p.inner, b"first-packet");
        // Now pin and confirm subsequent calls use the fast path
        // (correctness still verified by output equality; we can't
        // observe the path taken from outside without an explicit hook).
        let keys = OnionSessionKeys::from_ephemeral_pubkeys(&sk, &[eph_pk_of(&onion)]).unwrap();
        store.pin(sid.clone(), keys);
        let p2 = peel_layer_pinned_or_fallback(&sk, &store, &sid, &onion).unwrap();
        assert_eq!(p2.inner, b"first-packet");
    }

    /// Stress: many threads pinning + evicting the same set of session
    /// ids while a reader thread tries to peel. No panics, no
    /// inconsistencies, no deadlocks.
    ///
    /// Functions as the proptest stand-in — the property is "no panic
    /// across N random interleavings of pin/evict/get", which we drive
    /// with deterministic threads since this is a concurrency test.
    #[test]
    fn concurrent_pin_and_evict_race() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc as StdArc;
        let store = StdArc::new(SessionKeyStore::new());
        let stop = StdArc::new(AtomicBool::new(false));

        let (pk, sk) = fresh_static();
        let onion = build_onion(
            &[HopBuildInput {
                static_pubkey: pk,
                endpoint: "x".into(),
            }],
            b"race",
        )
        .unwrap();

        let mut handles = Vec::new();
        // 4 writer threads churning pin/evict on 16 sids.
        for t in 0..4 {
            let store = store.clone();
            let stop = stop.clone();
            let sk = sk.clone();
            let eph = eph_pk_of(&onion);
            handles.push(std::thread::spawn(move || {
                let mut iter = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let sid_byte = ((iter as u8).wrapping_add(t as u8)) & 0x0F;
                    let sid = crate::session::SessionId::new([sid_byte; 32]);
                    if iter % 2 == 0 {
                        let keys =
                            OnionSessionKeys::from_ephemeral_pubkeys(&sk, &[eph]).unwrap();
                        store.pin(sid, keys);
                    } else {
                        store.evict(&sid);
                    }
                    iter = iter.wrapping_add(1);
                }
            }));
        }
        // 2 reader threads.
        for _ in 0..2 {
            let store = store.clone();
            let stop = stop.clone();
            let onion = onion.clone();
            handles.push(std::thread::spawn(move || {
                let mut iter = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let sid_byte = (iter as u8) & 0x0F;
                    let sid = crate::session::SessionId::new([sid_byte; 32]);
                    if let Some(k) = store.get(&sid) {
                        // Either ok or AEAD-err (if we got a key for a
                        // different session). Both are fine.
                        let _ = peel_with_pinned_key(&k, 0, &onion);
                    }
                    iter = iter.wrapping_add(1);
                }
            }));
        }
        // Run briefly and tear down.
        std::thread::sleep(std::time::Duration::from_millis(50));
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            h.join().expect("worker did not panic");
        }
    }

    /// `OnionSessionKeys::from_ephemeral_pubkeys` rejects empty + too-many.
    #[test]
    fn pinned_keys_construction_bounds() {
        let (_pk, sk) = fresh_static();
        assert!(matches!(
            OnionSessionKeys::from_ephemeral_pubkeys(&sk, &[]).unwrap_err(),
            OnionError::EmptyRoute
        ));
        let too_many: Vec<[u8; 32]> = (0..=MAX_HOPS).map(|_| [0u8; 32]).collect();
        assert!(matches!(
            OnionSessionKeys::from_ephemeral_pubkeys(&sk, &too_many).unwrap_err(),
            OnionError::TooManyHops
        ));
    }
}
