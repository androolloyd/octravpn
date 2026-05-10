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

use std::io::{Cursor, Read};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce, Key,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pub, StaticSecret};

pub const MAX_HOPS: usize = 3;
pub const ONION_HKDF_INFO: &[u8] = b"octravpn-onion-v1";

#[derive(Debug, thiserror::Error)]
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

fn wrap_layer(
    static_pk: &[u8; 32],
    header: &[u8],
    inner: &[u8],
) -> Result<Vec<u8>, OnionError> {
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = X25519Pub::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&X25519Pub::from(*static_pk));

    let key = derive_aead_key(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(&[0u8; 12]);

    let mut plaintext = Vec::with_capacity(4 + header.len() + inner.len());
    plaintext.extend_from_slice(&(header.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(header);
    plaintext.extend_from_slice(inner);

    let ct = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| OnionError::Aead(e.to_string()))?;

    let mut out = Vec::with_capacity(32 + ct.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

fn derive_aead_key(shared: &[u8]) -> Key {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = [0u8; 32];
    hk.expand(ONION_HKDF_INFO, &mut okm)
        .expect("32-byte HKDF output is always valid");
    Key::from(okm)
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
pub fn peel_layer(
    static_secret: &StaticSecret,
    packet: &[u8],
) -> Result<PeeledLayer, OnionError> {
    if packet.len() < 32 + 16 {
        return Err(OnionError::Malformed);
    }
    let mut eph_pk = [0u8; 32];
    eph_pk.copy_from_slice(&packet[..32]);
    let shared = static_secret.diffie_hellman(&X25519Pub::from(eph_pk));
    let key = derive_aead_key(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let pt = cipher
        .decrypt(nonce, &packet[32..])
        .map_err(|e| OnionError::Aead(e.to_string()))?;
    parse_layer(&pt)
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
        match p1.action {
            HopAction::Forward { endpoint, next_static_pubkey } => {
                assert_eq!(endpoint, "node2:51820");
                assert_eq!(next_static_pubkey, pk2);
            }
            _ => panic!("hop1 must forward"),
        }

        // Hop 2: Forward to node3.
        let p2 = peel_layer(&sk2, &p1.inner).unwrap();
        match p2.action {
            HopAction::Forward { endpoint, next_static_pubkey } => {
                assert_eq!(endpoint, "node3:51820");
                assert_eq!(next_static_pubkey, pk3);
            }
            _ => panic!("hop2 must forward"),
        }

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
            &[HopBuildInput { static_pubkey: pk, endpoint: "x".into() }],
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
}
