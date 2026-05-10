//! Session types shared between node and client.
//!
//! These are the Rust analogues of the Applied program's `Session` and
//! `ValidatorRecord` structs. The on-chain program is the source of
//! truth; these structs are how we hold the values in memory after
//! they're decoded from JSON-RPC `contract_call` returns.

use serde::{Deserialize, Serialize};

use crate::{address::Address, sig::PublicKey};

/// 32-byte session id returned from `open_session`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
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

/// In-memory mirror of the on-chain `ValidatorRecord`.
///
///   - `wg_pubkey` is the X25519 noise key for the WireGuard tunnel and
///     also the public key the node co-signs receipts under (so the on-
///     chain `slash_double_sign` evidence path matches).
///   - `view_pubkey` is the stealth view key the client uses to derive a
///     refund stealth output (and the validator uses for payouts).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub addr: Address,
    pub bond: u64,
    pub endpoint: String,
    pub wg_pubkey: PublicKey,
    pub view_pubkey: [u8; 32],
    pub region: String,
    pub price_per_mb: u64,
    pub registered_at: u64,
    pub last_attest_epoch: u64,
    pub jailed_at: u64,
    pub reputation: i64,
}

impl ValidatorRecord {
    pub fn is_active(&self, current_epoch: u64, attest_grace: u64) -> bool {
        self.bond > 0
            && self.jailed_at == 0
            && current_epoch <= self.last_attest_epoch + attest_grace
    }
}

/// Per-hop opening data passed to `settle_session`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteOpening {
    pub node_addr: Address,
    pub blind: [u8; 32],
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
