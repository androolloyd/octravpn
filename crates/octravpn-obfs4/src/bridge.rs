//! Bridge identity material. An OctraVPN obfs4 bridge publishes:
//!
//!   - `node_id`           — 20-byte secret token (the operator distributes
//!                           this to authorised clients out of band, e.g.
//!                           printed on the operator's `oct://` URL)
//!   - `identity_pubkey`   — long-term X25519 pubkey; the server holds the
//!                           private half on disk
//!
//! Clients are configured with `(node_id, identity_pubkey)`. The
//! handshake's `mac1` is keyed by `node_id`, so a probe that does not
//! know `node_id` cannot pass the first MAC check — the server drops
//! the packet silently and remains indistinguishable from a closed
//! UDP port (probe-resistance).

use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

/// Length of the bridge `node_id` token, in bytes. obfs4 uses 20; we
/// match for parity.
pub const NODE_ID_LEN: usize = 20;

/// Server-side bridge keys. Holds the long-term identity private key
/// and the `node_id`. Operators mint this at bridge-bring-up time and
/// distribute the public half (see [`BridgeCredentials`]) to clients.
#[derive(ZeroizeOnDrop)]
pub struct BridgeIdentity {
    /// 20-byte secret token. Used to key the handshake MAC.
    pub node_id: [u8; NODE_ID_LEN],
    /// Long-term X25519 private key.
    pub identity_secret: StaticSecret,
}

impl BridgeIdentity {
    /// Generate a fresh bridge identity. Operators run this once per
    /// bridge node and persist the result.
    pub fn generate() -> Self {
        let mut node_id = [0u8; NODE_ID_LEN];
        rand::thread_rng().fill_bytes(&mut node_id);
        Self {
            node_id,
            identity_secret: StaticSecret::random_from_rng(rand::thread_rng()),
        }
    }

    /// Restore a bridge identity from raw bytes. Validates that the
    /// secret is well-formed (32 bytes of seed material).
    pub fn from_bytes(node_id: [u8; NODE_ID_LEN], identity_secret_bytes: [u8; 32]) -> Self {
        Self {
            node_id,
            identity_secret: StaticSecret::from(identity_secret_bytes),
        }
    }

    /// Publish the public half — what gets handed to clients.
    pub fn credentials(&self) -> BridgeCredentials {
        BridgeCredentials {
            node_id: self.node_id,
            identity_pubkey: PublicKey::from(&self.identity_secret),
        }
    }
}

/// Client-side bridge credentials. The operator publishes this blob
/// (typically encoded as hex or base64 in the `oct://` URL). It is
/// **not** secret in the cryptographic sense — knowing it doesn't let
/// you decrypt traffic — but it *is* gated: the `node_id` is required
/// to even pass the handshake MAC, so a wide-net DPI scan cannot
/// fingerprint bridges by attempting handshakes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeCredentials {
    /// 20-byte `node_id`, hex-encoded on the wire / TOML.
    #[serde(with = "hex_serde")]
    pub node_id: [u8; NODE_ID_LEN],
    /// Long-term identity pubkey for ECDH in the NTOR handshake.
    #[serde(with = "x25519_pubkey_serde")]
    pub identity_pubkey: PublicKey,
}

mod hex_serde {
    use serde::{de::Error as _, Deserialize, Deserializer, Serialize as _, Serializer};

    pub(super) fn serialize<const N: usize, S: Serializer>(
        bytes: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        ::hex::encode(bytes).serialize(s)
    }

    pub(super) fn deserialize<'de, const N: usize, D: Deserializer<'de>>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let v = ::hex::decode(&s).map_err(D::Error::custom)?;
        if v.len() != N {
            return Err(D::Error::custom(format!(
                "expected {N}-byte hex value, got {}",
                v.len()
            )));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

mod x25519_pubkey_serde {
    use serde::{de::Error as _, Deserialize, Deserializer, Serialize as _, Serializer};
    use x25519_dalek::PublicKey;

    pub(super) fn serialize<S: Serializer>(pk: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        ::hex::encode(pk.as_bytes()).serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        let s = String::deserialize(d)?;
        let v = ::hex::decode(&s).map_err(D::Error::custom)?;
        if v.len() != 32 {
            return Err(D::Error::custom(format!(
                "x25519 pubkey must be 32 bytes, got {}",
                v.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(PublicKey::from(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_round_trip() {
        let id = BridgeIdentity::generate();
        let creds = id.credentials();
        assert_eq!(creds.node_id, id.node_id);
        // Identity pubkey equals g^identity_secret.
        let pk = PublicKey::from(&id.identity_secret);
        assert_eq!(pk.as_bytes(), creds.identity_pubkey.as_bytes());
    }

    #[test]
    fn credentials_serde_round_trip() {
        let id = BridgeIdentity::generate();
        let creds = id.credentials();
        let toml = ::toml::to_string(&creds).unwrap();
        let back: BridgeCredentials = ::toml::from_str(&toml).unwrap();
        assert_eq!(back.node_id, creds.node_id);
        assert_eq!(back.identity_pubkey.as_bytes(), creds.identity_pubkey.as_bytes());
    }
}
