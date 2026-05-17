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
