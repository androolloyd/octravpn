//! NTOR-style handshake for the obfs4-modelled transport.
//!
//! # Goal
//!
//! Establish a one-way ChaCha20-Poly1305 key in each direction
//! (`tx_key` / `rx_key`) plus a per-direction starting counter, using
//! one round trip:
//!
//! ```text
//!   client → server: X || mac1 || pad
//!   server → client: Y || auth || pad
//! ```
//!
//! where:
//!
//! - `X = x · G`           — client ephemeral X25519 pubkey
//! - `Y = y · G`            — server ephemeral X25519 pubkey
//! - `mac1 = HMAC-SHA256(node_id, "obfs4-octravpn-mac1" || X)`
//!   keyed by the 20-byte `node_id` the operator distributes. This is
//!   the **probe-resistance gate**: a probe that doesn't know
//!   `node_id` cannot forge `mac1`, so the server drops the packet
//!   silently and is indistinguishable from a closed port.
//! - `ecdh_e = y · X` (server) = `x · Y` (client) — ephemeral DH
//! - `ecdh_s = identity_secret · X` (server) = `x · identity_pubkey`
//!   (client) — identity DH; ties the session to the long-term bridge
//!   key so a passive eavesdropper who later compromises the
//!   ephemeral has no path to past traffic via the identity alone
//!   (forward secrecy comes from `ecdh_e`).
//! - `secret = HKDF-SHA256(salt = node_id, ikm = ecdh_e || ecdh_s,
//!                         info = "obfs4-octravpn-v1")` → 96 bytes
//!   split into `tx_key (32) || rx_key (32) || auth_key (32)`.
//! - `auth = HMAC-SHA256(auth_key, "obfs4-octravpn-auth"
//!                                 || Y || X || node_id
//!                                 || identity_pubkey)` — the server
//!   proves knowledge of `identity_secret` (because `ecdh_s` is only
//!   computable with it) without leaking it.
//!
//! The client validates `auth` in constant time; mismatch ⇒ abort.
//!
//! # Wire layout
//!
//! Both handshake messages share the same envelope:
//!
//! ```text
//!   [32-byte X25519 pubkey] [32-byte MAC/auth] [variable random padding]
//! ```
//!
//! The receiver knows where each field ends because the X25519 pubkey
//! and the MAC are fixed-length. Padding length is chosen uniformly
//! in `[MIN_PAD, MAX_PAD]` so the on-wire size of the *handshake*
//! itself is length-randomised (matters because the handshake is one
//! datagram, and a static 64-byte handshake would itself be a
//! signature).
//!
//! # Replay
//!
//! Each handshake uses a fresh ephemeral X25519 keypair on both
//! sides. A replayed client handshake derives the same `secret` (the
//! server's ephemeral is regenerated), so the server's next reply
//! produces a session under a key the original client cannot use —
//! the replay attacker holds the original `X` but not `x`, so they
//! can never decrypt subsequent server frames. We accept the wasted
//! round trip; we do not maintain a replay cache.

use std::convert::TryInto;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::bridge::{BridgeCredentials, BridgeIdentity, NODE_ID_LEN};

/// Domain tag prefix for the handshake MAC. Distinct from the auth
/// tag prefix so a confused-deputy attacker can't reuse one as the
/// other.
const MAC1_PREFIX: &[u8] = b"obfs4-octravpn-mac1";
/// Domain tag prefix for the auth tag computed by the server.
const AUTH_PREFIX: &[u8] = b"obfs4-octravpn-auth";
/// HKDF "info" string. Bumping this is the migration handle for any
/// future incompatible change to the derivation order.
const KDF_INFO: &[u8] = b"obfs4-octravpn-v1";

/// Minimum / maximum handshake padding, in bytes. The actual padding
/// length is uniform in `[MIN_PAD, MAX_PAD]`.
const MIN_PAD: usize = 16;
const MAX_PAD: usize = 256;

/// Public-key half of a handshake message: `[X || mac1]` or
/// `[Y || auth]`. Sized exactly 64 bytes — the padding tail is
/// variable and not counted here.
pub const HANDSHAKE_FIXED_LEN: usize = 32 + 32;

/// Maximum bytes the receiver must be willing to read for one
/// handshake message: fixed 64 + max padding.
pub const HANDSHAKE_MAX_LEN: usize = HANDSHAKE_FIXED_LEN + MAX_PAD;

/// Errors raised by the handshake path.
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// The incoming handshake was shorter than the 64-byte minimum.
    #[error("handshake message too short: {0} bytes (need ≥ {HANDSHAKE_FIXED_LEN})")]
    TooShort(usize),
    /// `mac1` did not validate. Probe-resistance: callers MUST NOT
    /// reply when this fires.
    #[error("mac1 mismatch (caller likely lacks bridge node_id)")]
    BadMac,
    /// Server `auth` tag did not validate; the client and server
    /// disagree on identity key or KDF binding.
    #[error("auth tag mismatch (wrong identity pubkey or KDF binding)")]
    BadAuth,
}

/// Per-direction session keys produced by a successful handshake.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Key used to seal outbound frames.
    pub tx_key: [u8; 32],
    /// Key used to open inbound frames.
    pub rx_key: [u8; 32],
}

/// Client-side handshake state. Holds the ephemeral X25519 secret as
/// a [`StaticSecret`] (rather than [`EphemeralSecret`]) so we can
/// perform two DH operations: one against the server ephemeral and
/// one against the bridge identity pubkey. The secret is generated
/// fresh per handshake and is zeroized on drop; it does not leak as
/// long-term key material.
pub struct ClientHandshake {
    creds: BridgeCredentials,
    ephemeral_secret: StaticSecret,
    ephemeral_public: PublicKey,
}

impl ClientHandshake {
    /// Begin a client handshake.
    pub fn start(creds: BridgeCredentials) -> Self {
        let ephemeral_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        Self {
            creds,
            ephemeral_secret,
            ephemeral_public,
        }
    }

    /// Serialise the client → server message.
    pub fn message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(HANDSHAKE_MAX_LEN);
        msg.extend_from_slice(self.ephemeral_public.as_bytes());
        let mac = compute_mac1(&self.creds.node_id, self.ephemeral_public.as_bytes());
        msg.extend_from_slice(&mac);
        append_pad(&mut msg);
        msg
    }

    /// Validate the server's reply and derive session keys.
    pub fn finalize(self, server_msg: &[u8]) -> Result<SessionKeys, HandshakeError> {
        if server_msg.len() < HANDSHAKE_FIXED_LEN {
            return Err(HandshakeError::TooShort(server_msg.len()));
        }
        let y_bytes: [u8; 32] = server_msg[..32].try_into().unwrap();
        let server_auth: [u8; 32] = server_msg[32..64].try_into().unwrap();
        let server_pub = PublicKey::from(y_bytes);

        // ecdh_e = x · Y  ;  ecdh_s = x · identity_pubkey
        let ecdh_e = self.ephemeral_secret.diffie_hellman(&server_pub);
        let ecdh_s = self
            .ephemeral_secret
            .diffie_hellman(&self.creds.identity_pubkey);

        let (tx_key, rx_key, auth_key) = derive_keys(
            &self.creds.node_id,
            ecdh_e.as_bytes(),
            ecdh_s.as_bytes(),
            /*is_client=*/ true,
        );

        let expected_auth = compute_auth(
            &auth_key,
            server_pub.as_bytes(),
            self.ephemeral_public.as_bytes(),
            &self.creds.node_id,
            self.creds.identity_pubkey.as_bytes(),
        );
        if expected_auth.ct_eq(&server_auth).unwrap_u8() == 0 {
            return Err(HandshakeError::BadAuth);
        }
        Ok(SessionKeys { tx_key, rx_key })
    }
}

/// Server-side handshake. Stateless: each call consumes the client
/// message, validates `mac1`, and produces both the reply bytes and
/// the derived session keys.
pub struct ServerHandshake<'a> {
    identity: &'a BridgeIdentity,
}

impl<'a> ServerHandshake<'a> {
    /// Wrap a bridge identity for handling incoming handshakes.
    pub fn new(identity: &'a BridgeIdentity) -> Self {
        Self { identity }
    }

    /// Consume a client handshake message; on success return
    /// `(reply_bytes, session_keys)`. On `BadMac`, callers MUST drop
    /// the packet silently and not send any reply.
    pub fn respond(
        &self,
        client_msg: &[u8],
    ) -> Result<(Vec<u8>, SessionKeys), HandshakeError> {
        if client_msg.len() < HANDSHAKE_FIXED_LEN {
            return Err(HandshakeError::TooShort(client_msg.len()));
        }
        let x_bytes: [u8; 32] = client_msg[..32].try_into().unwrap();
        let client_mac: [u8; 32] = client_msg[32..64].try_into().unwrap();
        let client_pub = PublicKey::from(x_bytes);

        // mac1 = HMAC(node_id, MAC1_PREFIX || X)
        let expected_mac = compute_mac1(&self.identity.node_id, &x_bytes);
        if expected_mac.ct_eq(&client_mac).unwrap_u8() == 0 {
            return Err(HandshakeError::BadMac);
        }

        // Server ephemeral.
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        // ecdh_e = y · X ; ecdh_s = identity_secret · X
        let ecdh_e = server_secret.diffie_hellman(&client_pub);
        let ecdh_s = self.identity.identity_secret.diffie_hellman(&client_pub);

        let (tx_key, rx_key, auth_key) = derive_keys(
            &self.identity.node_id,
            ecdh_e.as_bytes(),
            ecdh_s.as_bytes(),
            /*is_client=*/ false,
        );

        let identity_pub = PublicKey::from(&self.identity.identity_secret);
        let auth = compute_auth(
            &auth_key,
            server_public.as_bytes(),
            client_pub.as_bytes(),
            &self.identity.node_id,
            identity_pub.as_bytes(),
        );

        let mut reply = Vec::with_capacity(HANDSHAKE_MAX_LEN);
        reply.extend_from_slice(server_public.as_bytes());
        reply.extend_from_slice(&auth);
        append_pad(&mut reply);
        Ok((reply, SessionKeys { tx_key, rx_key }))
    }
}

// ----- Internals -----

fn compute_mac1(node_id: &[u8; NODE_ID_LEN], client_ephemeral: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(node_id).expect("hmac accepts any key len");
    mac.update(MAC1_PREFIX);
    mac.update(client_ephemeral);
    mac.finalize().into_bytes().into()
}

fn compute_auth(
    auth_key: &[u8; 32],
    server_pub: &[u8; 32],
    client_pub: &[u8; 32],
    node_id: &[u8; NODE_ID_LEN],
    identity_pub: &[u8; 32],
) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(auth_key).expect("hmac accepts any key len");
    mac.update(AUTH_PREFIX);
    mac.update(server_pub);
    mac.update(client_pub);
    mac.update(node_id);
    mac.update(identity_pub);
    mac.finalize().into_bytes().into()
}

/// Derive `(tx_key, rx_key, auth_key)` from the two DH secrets via
/// HKDF-SHA256. `is_client` swaps the role-tagged direction labels so
/// that what the client sends with `tx_key` the server reads with the
/// same key as its `rx_key`.
fn derive_keys(
    node_id: &[u8; NODE_ID_LEN],
    ecdh_e: &[u8; 32],
    ecdh_s: &[u8; 32],
    is_client: bool,
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ecdh_e);
    ikm[32..].copy_from_slice(ecdh_s);

    let hk = Hkdf::<Sha256>::new(Some(node_id.as_slice()), &ikm);
    let mut okm = [0u8; 96];
    hk.expand(KDF_INFO, &mut okm).expect("96 ≤ 255*32");

    // Slot layout: [0..32] = c2s_key, [32..64] = s2c_key, [64..96] = auth_key.
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    let mut auth = [0u8; 32];
    c2s.copy_from_slice(&okm[..32]);
    s2c.copy_from_slice(&okm[32..64]);
    auth.copy_from_slice(&okm[64..]);

    let (tx, rx) = if is_client { (c2s, s2c) } else { (s2c, c2s) };
    (tx, rx, auth)
}

fn append_pad(msg: &mut Vec<u8>) {
    let pad_len = rand::thread_rng().gen_range(MIN_PAD..=MAX_PAD);
    let start = msg.len();
    msg.resize(start + pad_len, 0);
    rand::thread_rng().fill_bytes(&mut msg[start..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (BridgeIdentity, BridgeCredentials) {
        let id = BridgeIdentity::generate();
        let creds = id.credentials();
        (id, creds)
    }

    #[test]
    fn round_trip_derives_matched_keys() {
        let (id, creds) = pair();
        let client = ClientHandshake::start(creds);
        let c_msg = client.message();

        let server = ServerHandshake::new(&id);
        let (s_msg, server_keys) = server.respond(&c_msg).expect("server respond");

        let client_keys = client.finalize(&s_msg).expect("client finalize");

        // client.tx == server.rx and vice versa.
        assert_eq!(client_keys.tx_key, server_keys.rx_key);
        assert_eq!(client_keys.rx_key, server_keys.tx_key);
        // tx and rx within a single peer must differ (else identical
        // sequence counters in both directions would cause nonce reuse).
        assert_ne!(client_keys.tx_key, client_keys.rx_key);
    }

    #[test]
    fn handshake_padding_is_random_length() {
        let (_id, creds) = pair();
        let mut seen_lens = std::collections::HashSet::new();
        for _ in 0..32 {
            let c = ClientHandshake::start(creds.clone());
            seen_lens.insert(c.message().len());
        }
        // 32 fresh handshakes should cover at least a few distinct
        // lengths (range [16..=256] padding → 241 possible lengths).
        assert!(
            seen_lens.len() > 4,
            "padding produced only {} distinct lengths in 32 trials",
            seen_lens.len()
        );
    }

    #[test]
    fn wrong_node_id_fails_silently() {
        let (real_id, _real_creds) = pair();
        // An attacker who doesn't know the real node_id mints a
        // bogus credentials struct.
        let bogus_id = BridgeIdentity::generate();
        let bogus_creds = bogus_id.credentials();
        // Splice in the real identity pubkey but with the wrong node_id;
        // the server is keyed on its own node_id so mac1 will mismatch.
        let mut bogus = bogus_creds;
        bogus.identity_pubkey = real_id.credentials().identity_pubkey;

        let attacker = ClientHandshake::start(bogus);
        let c_msg = attacker.message();
        let server = ServerHandshake::new(&real_id);
        match server.respond(&c_msg) {
            Err(HandshakeError::BadMac) => {}
            Err(other) => panic!("expected BadMac, got {other:?}"),
            Ok(_) => panic!("expected BadMac, got Ok"),
        }
    }

    #[test]
    fn wrong_identity_pubkey_fails_at_client_auth() {
        let (real_id, real_creds) = pair();
        // Client receives a credentials struct with the right node_id
        // but the wrong identity pubkey (e.g. operator was MITM'd).
        let mut bad_creds = real_creds;
        let other = BridgeIdentity::generate();
        bad_creds.identity_pubkey = other.credentials().identity_pubkey;

        let client = ClientHandshake::start(bad_creds);
        let c_msg = client.message();
        let server = ServerHandshake::new(&real_id);
        let (s_msg, _) = server.respond(&c_msg).expect("mac1 still passes");
        match client.finalize(&s_msg) {
            Err(HandshakeError::BadAuth) => {}
            Err(other) => panic!("expected BadAuth, got {other:?}"),
            Ok(_) => panic!("expected BadAuth, got Ok"),
        }
    }

    #[test]
    fn short_handshake_rejected() {
        let (id, _) = pair();
        let server = ServerHandshake::new(&id);
        assert!(matches!(
            server.respond(&[0u8; 16]),
            Err(HandshakeError::TooShort(16))
        ));
    }

    // -------------------------------------------------------------------
    // 100 random handshakes → matched keys on both sides.
    // -------------------------------------------------------------------

    #[test]
    fn handshake_round_trip_100_random_identities() {
        // Stress the DH + KDF + MAC paths with 100 fresh
        // (client_ephemeral, server_ephemeral, node_id, identity_pubkey)
        // tuples. Every successful round trip MUST derive matched keys.
        for i in 0..100 {
            let (id, creds) = pair();
            let client = ClientHandshake::start(creds);
            let c_msg = client.message();
            let server = ServerHandshake::new(&id);
            let (s_msg, server_keys) = match server.respond(&c_msg) {
                Ok(v) => v,
                Err(e) => panic!("respond iter {i}: {e:?}"),
            };
            let client_keys = match client.finalize(&s_msg) {
                Ok(v) => v,
                Err(e) => panic!("finalize iter {i}: {e:?}"),
            };
            assert_eq!(client_keys.tx_key, server_keys.rx_key, "iter {i}");
            assert_eq!(client_keys.rx_key, server_keys.tx_key, "iter {i}");
            assert_ne!(client_keys.tx_key, client_keys.rx_key, "iter {i}");
        }
    }

    // -------------------------------------------------------------------
    // mac1 binding: a flipped bit anywhere in mac1 yields BadMac.
    // -------------------------------------------------------------------

    #[test]
    fn mac1_tampering_is_rejected() {
        let (id, creds) = pair();
        let client = ClientHandshake::start(creds);
        let mut c_msg = client.message();
        // Flip a bit inside the mac1 region (offset 32..64).
        c_msg[40] ^= 0x08;
        let server = ServerHandshake::new(&id);
        match server.respond(&c_msg) {
            Err(HandshakeError::BadMac) => {}
            Err(other) => panic!("expected BadMac after mac1 tamper, got {other:?}"),
            Ok(_) => panic!("expected BadMac, got Ok"),
        }
    }

    #[test]
    fn ephemeral_tampering_is_rejected() {
        // Flipping a byte in the ephemeral pubkey invalidates mac1
        // (mac1 = HMAC(node_id, prefix || X)).
        let (id, creds) = pair();
        let client = ClientHandshake::start(creds);
        let mut c_msg = client.message();
        c_msg[5] ^= 0x10; // inside the 32-byte X region
        let server = ServerHandshake::new(&id);
        assert!(matches!(server.respond(&c_msg), Err(HandshakeError::BadMac)));
    }

    // -------------------------------------------------------------------
    // Padding: lengths bounded by [MIN_PAD, MAX_PAD], visible spread.
    // -------------------------------------------------------------------

    #[test]
    fn handshake_padding_bounded() {
        let (_id, creds) = pair();
        for _ in 0..64 {
            let c = ClientHandshake::start(creds.clone());
            let msg = c.message();
            assert!(msg.len() >= HANDSHAKE_FIXED_LEN + MIN_PAD);
            assert!(msg.len() <= HANDSHAKE_MAX_LEN);
        }
    }

    #[test]
    fn handshake_padding_has_meaningful_spread() {
        // 64 trials over 241 possible lengths should produce ≥16
        // distinct sizes in practice (collision prob is tiny). If this
        // ever fires, the RNG seam is hosed — investigate.
        let (_id, creds) = pair();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            seen.insert(ClientHandshake::start(creds.clone()).message().len());
        }
        assert!(
            seen.len() >= 16,
            "padding has weak spread: only {} distinct sizes in 64 trials",
            seen.len()
        );
    }

    // -------------------------------------------------------------------
    // Negative: server reply tampering → BadAuth.
    // -------------------------------------------------------------------

    #[test]
    fn server_auth_tag_tampering_yields_bad_auth() {
        let (id, creds) = pair();
        let client = ClientHandshake::start(creds);
        let c_msg = client.message();
        let server = ServerHandshake::new(&id);
        let (mut s_msg, _sk) = server.respond(&c_msg).unwrap_or_else(|e| panic!("respond: {e:?}"));
        s_msg[48] ^= 0x40; // flip bit in the 32-byte auth region
        match client.finalize(&s_msg) {
            Err(HandshakeError::BadAuth) => {}
            Err(other) => panic!("expected BadAuth, got {other:?}"),
            Ok(_) => panic!("expected BadAuth, got Ok"),
        }
    }

    #[test]
    fn server_ephemeral_pubkey_tampering_yields_bad_auth() {
        // If a MITM substitutes the server ephemeral pubkey Y, the
        // ecdh_e value on the client side changes and the derived
        // auth_key differs → BadAuth.
        let (id, creds) = pair();
        let client = ClientHandshake::start(creds);
        let c_msg = client.message();
        let server = ServerHandshake::new(&id);
        let (mut s_msg, _sk) = server.respond(&c_msg).unwrap_or_else(|e| panic!("respond: {e:?}"));
        s_msg[10] ^= 0x01;
        match client.finalize(&s_msg) {
            Err(HandshakeError::BadAuth) => {}
            Err(other) => panic!("expected BadAuth, got {other:?}"),
            Ok(_) => panic!("expected BadAuth, got Ok"),
        }
    }

    // -------------------------------------------------------------------
    // Short server reply: TooShort.
    // -------------------------------------------------------------------

    #[test]
    fn short_server_reply_rejected_by_client() {
        let (_id, creds) = pair();
        let client = ClientHandshake::start(creds);
        let res = client.finalize(&[0u8; 32]);
        assert!(matches!(res, Err(HandshakeError::TooShort(32))));
    }

    // -------------------------------------------------------------------
    // Each client handshake uses a fresh ephemeral pubkey.
    // -------------------------------------------------------------------

    #[test]
    fn client_handshake_ephemeral_pubkeys_are_unique() {
        let (_id, creds) = pair();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let c = ClientHandshake::start(creds.clone());
            let msg = c.message();
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&msg[..32]);
            assert!(seen.insert(pk), "ephemeral pubkey re-used across handshakes");
        }
    }

    // -------------------------------------------------------------------
    // BridgeIdentity::from_bytes restores the same credentials.
    // -------------------------------------------------------------------

    #[test]
    fn bridge_identity_from_bytes_round_trips_handshake() {
        // Generate a bridge, persist its raw bytes, then restore. The
        // restored identity must produce a valid handshake with a
        // client holding the original credentials.
        let id = BridgeIdentity::generate();
        let node_id = id.node_id;
        let secret_bytes: [u8; 32] = id.identity_secret.to_bytes();
        let creds = id.credentials();
        let restored = BridgeIdentity::from_bytes(node_id, secret_bytes);
        // Restored identity_pubkey must match.
        let restored_pk = x25519_dalek::PublicKey::from(&restored.identity_secret);
        assert_eq!(restored_pk.as_bytes(), creds.identity_pubkey.as_bytes());

        // End-to-end handshake against the restored identity.
        let client = ClientHandshake::start(creds);
        let c_msg = client.message();
        let server = ServerHandshake::new(&restored);
        let (s_msg, sk) = match server.respond(&c_msg) {
            Ok(v) => v,
            Err(e) => panic!("respond: {e:?}"),
        };
        let ck = match client.finalize(&s_msg) {
            Ok(v) => v,
            Err(e) => panic!("finalize: {e:?}"),
        };
        assert_eq!(ck.tx_key, sk.rx_key);
    }
}
