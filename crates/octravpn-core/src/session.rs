//! Session types shared between node and client.
//!
//! These are the Rust analogues of the Applied program's `Session` and
//! `ValidatorRecord` structs. The on-chain program is the source of
//! truth; these structs are how we hold the values in memory after
//! they're decoded from JSON-RPC `contract_call` returns.

use serde::{Deserialize, Serialize};

use crate::{address::Address, sig::PublicKey};

/// 32-byte session id returned from `open_session`. The chain derives it
/// as `sha256(self_addr || epoch || nonce || client_session_pubkey)`.
///
/// `Ord` / `PartialOrd` use the lexicographic byte order; the only
/// in-tree consumer is the receipt journal's `BTreeMap` (P1-8/9), where
/// the ordering is irrelevant (set semantics — we just need a stable
/// `Eq + Ord`). Don't rely on the ordering for protocol-level decisions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SessionId([u8; 32]);

impl SessionId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Wrap a v1 chain-side u64 session id as a 32-byte id by
    /// big-endian encoding into the first 8 bytes, zero-padding the
    /// rest. Cryptographic uses of `SessionId` (onion-stream key
    /// derivation, replay tags) keep working — the extra 24 bytes
    /// are just deterministic padding.
    pub fn from_u64(id: u64) -> Self {
        let mut buf = [0u8; 32];
        buf[..8].copy_from_slice(&id.to_be_bytes());
        Self(buf)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Decode this id as the v1 AML's u64 form. Returns `None` if
    /// the trailing 24 bytes are non-zero — i.e. if this id was not
    /// constructed by `from_u64`.
    pub fn as_u64(&self) -> Option<u64> {
        if self.0[8..].iter().any(|b| *b != 0) {
            return None;
        }
        let mut head = [0u8; 8];
        head.copy_from_slice(&self.0[..8]);
        Some(u64::from_be_bytes(head))
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let v = hex::decode(s).ok()?;
        if v.len() != 32 {
            return None;
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&v);
        Some(Self(id))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// 32-byte Pedersen blinding scalar (raw bytes; the `Scalar` is reduced
/// mod-l in the verifier when needed). The same value is used for the
/// route commitment and the receipt accumulator entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Blind([u8; 32]);

impl Blind {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// In-memory mirror of the on-chain `EndpointRecord`.
///
///   - `wg_pubkey` is the X25519 noise key for the WireGuard tunnel.
///   - `receipt_pubkey` is the ed25519 key the node co-signs receipts with
///     (separate from `wg_pubkey` so we don't reuse the same private
///     scalar across protocols).
///   - `view_pubkey` is the stealth view key the client uses to derive
///     refund / payout outputs.
///
/// Bond / liveness / slashing are delegated to the Octra protocol layer:
/// an endpoint is "active" iff `active == true` AND the chain still
/// considers it an Octra validator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointRecord {
    pub addr: Address,
    pub active: bool,
    pub endpoint: String,
    pub wg_pubkey: PublicKey,
    pub receipt_pubkey: PublicKey,
    pub view_pubkey: [u8; 32],
    pub region: String,
    pub price_per_mb: u64,
    pub registered_at: u64,
    pub reputation: i64,
}

/// Back-compat alias so older imports keep compiling during the rename.
pub type ValidatorRecord = EndpointRecord;

/// Per-hop opening data passed to `settle_session`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteOpening {
    pub node_addr: Address,
    pub blind: Blind,
    pub split_bps: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenSessionParams {
    pub route_commit: Vec<[u8; 32]>,
    pub client_session_pubkey: PublicKey,
    pub deposit: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Open,
    Settled,
    Refunded,
    Slashed,
}

impl SessionState {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Open),
            1 => Some(Self::Settled),
            2 => Some(Self::Refunded),
            3 => Some(Self::Slashed),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every documented chain-side session state decodes to its named
    /// Rust variant. Catches drift between AML constants and this enum.
    #[test]
    fn session_state_decodes_each_known_value() {
        assert_eq!(SessionState::from_u8(0), Some(SessionState::Open));
        assert_eq!(SessionState::from_u8(1), Some(SessionState::Settled));
        assert_eq!(SessionState::from_u8(2), Some(SessionState::Refunded));
        assert_eq!(SessionState::from_u8(3), Some(SessionState::Slashed));
    }

    /// Out-of-range bytes produce `None` — an unknown state must NOT
    /// silently coerce to `Open` (which would let settlement run on a
    /// bogus state).
    #[test]
    fn session_state_unknown_returns_none() {
        for v in 4u8..=255u8 {
            assert!(SessionState::from_u8(v).is_none());
        }
    }

    /// `SessionId::from_u64` puts the u64 in the first 8 bytes (BE),
    /// zero-pads the rest, and `as_u64` recovers it.
    #[test]
    fn session_id_u64_round_trip() {
        let id = SessionId::from_u64(0xCAFE_F00D_DEAD_BEEF);
        assert_eq!(id.as_u64(), Some(0xCAFE_F00D_DEAD_BEEF));
        let bytes = id.as_bytes();
        assert_eq!(&bytes[..8], &0xCAFE_F00D_DEAD_BEEFu64.to_be_bytes());
        assert!(bytes[8..].iter().all(|&b| b == 0));
    }

    /// A SessionId whose trailing 24 bytes are NOT zero must NOT be
    /// claimed as a v1 u64-encoded id (cross-namespace defence).
    #[test]
    fn session_id_as_u64_rejects_padded_value() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[31] = 1;
        let id = SessionId::new(bytes);
        assert_eq!(id.as_u64(), None);
    }

    /// Hex round-trip: encode then decode yields the same SessionId.
    #[test]
    fn session_id_hex_round_trip() {
        let id = SessionId::new([0xAB; 32]);
        let h = id.to_hex();
        assert_eq!(h.len(), 64);
        assert_eq!(SessionId::from_hex(&h), Some(id));
    }

    /// Hex parsing rejects wrong-length input and non-hex chars
    /// — catches silent acceptance of malformed RPC params.
    #[test]
    fn session_id_from_hex_rejects_malformed() {
        assert!(SessionId::from_hex("00").is_none());
        assert!(SessionId::from_hex(&"g".repeat(64)).is_none());
        assert!(SessionId::from_hex(&"00".repeat(33)).is_none());
    }

    /// `as_bytes` and `into_bytes` agree byte-for-byte (no codec
    /// drift between borrow / consume forms).
    #[test]
    fn session_id_as_bytes_matches_into_bytes() {
        let id = SessionId::new([7u8; 32]);
        let borrowed = *id.as_bytes();
        let owned = id.into_bytes();
        assert_eq!(borrowed, owned);
    }

    /// `Blind::to_hex` is lowercase (wire format depends on this).
    #[test]
    fn blind_hex_encoding_is_lowercase() {
        let b = Blind::new([0xAB; 32]);
        assert_eq!(b.to_hex(), "ab".repeat(32));
    }

    /// `SessionState` JSON is snake_case (matches RPC).
    #[test]
    fn session_state_json_is_snake_case() {
        let j = serde_json::to_string(&SessionState::Refunded).unwrap();
        assert_eq!(j, "\"refunded\"");
        let back: SessionState = serde_json::from_str(&j).unwrap();
        assert_eq!(back, SessionState::Refunded);
    }

    /// Boundary: `from_u64(0)` round-trips to 0.
    #[test]
    fn session_id_from_u64_zero_round_trips() {
        let id = SessionId::from_u64(0);
        assert_eq!(id.as_u64(), Some(0));
        assert_eq!(id.as_bytes(), &[0u8; 32]);
    }

    /// Boundary: `from_u64(u64::MAX)` round-trips (no overflow).
    #[test]
    fn session_id_from_u64_max_round_trips() {
        let id = SessionId::from_u64(u64::MAX);
        assert_eq!(id.as_u64(), Some(u64::MAX));
    }
}
