//! Octra address handling — real codec.
//!
//! Per [docs/octra-research.md], an Octra address is:
//!
//! ```text
//! display = "oct" + LeftPad('1', Base58(SHA256(ed25519_pubkey)), 44)
//! ```
//!
//!   - Single SHA-256 of the 32-byte Ed25519 public key.
//!   - Bitcoin-alphabet Base58 (no checksum), padded with `'1'` to 44 chars.
//!   - Display always 47 chars total: `"oct" + 44 base58 chars`.
//!
//! The 32-byte canonical form **is** the SHA-256 digest of the pubkey
//! (recoverable by base58-decoding the substring after `"oct"`).
//!
//! Source of truth: `octra-labs/wallet-gen/src/server.ts`,
//! `webcli/wallet.hpp`.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{CoreError, CoreResult};

pub const ADDRESS_LEN: usize = 32;
pub const ADDRESS_PREFIX: &str = "oct";
pub const ADDRESS_TOTAL_LEN: usize = 47; // "oct" + 44 base58 chars
pub const ADDRESS_BODY_LEN: usize = 44;

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    raw: [u8; ADDRESS_LEN],
    display: String,
}

impl Address {
    /// Build an address from an Ed25519 wallet pubkey (32 bytes).
    pub fn from_pubkey(pubkey: &[u8; 32]) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(pubkey);
        let raw: [u8; 32] = h.finalize().into();
        let body = bs58::encode(raw).into_string();
        // Left-pad with '1' to reach 44 chars (Octra convention).
        let padded = format!("{body:1>44}").replace(' ', "1");
        let padded = if padded.len() == ADDRESS_BODY_LEN {
            padded
        } else {
            // bs58 of 32 bytes is at most 44 chars; pad on the left
            // with '1' (which is base58-zero) to reach 44.
            let mut s = String::with_capacity(ADDRESS_BODY_LEN);
            for _ in body.len()..ADDRESS_BODY_LEN {
                s.push('1');
            }
            s.push_str(&body);
            s
        };
        let display = format!("{ADDRESS_PREFIX}{padded}");
        Self { raw, display }
    }

    /// Parse a textual `oct...` address. Returns the 32-byte canonical
    /// form (== SHA-256(pubkey)) plus the display string.
    pub fn from_display(display: impl Into<String>) -> Self {
        let display = display.into();
        // Best-effort decode: if the format matches, recover the real
        // canonical 32 bytes via base58. Otherwise fall back to a
        // hash of the display so we never panic on malformed input.
        match Self::try_from_display(&display) {
            Ok(a) => a,
            Err(_) => Self {
                raw: hash_display(&display),
                display,
            },
        }
    }

    /// Strict version: returns `Err` if the display string isn't a
    /// valid Octra address.
    pub fn try_from_display(display: &str) -> CoreResult<Self> {
        if !display.starts_with(ADDRESS_PREFIX) {
            return Err(CoreError::InvalidEncoding(format!(
                "address missing 'oct' prefix: {display}"
            )));
        }
        if display.len() != ADDRESS_TOTAL_LEN {
            return Err(CoreError::InvalidLength {
                expected: ADDRESS_TOTAL_LEN,
                actual: display.len(),
            });
        }
        let body = &display[ADDRESS_PREFIX.len()..];
        let trimmed = body.trim_start_matches('1');
        let decoded = bs58::decode(trimmed)
            .into_vec()
            .map_err(|e| CoreError::InvalidEncoding(format!("base58 decode: {e}")))?;
        // After stripping leading-'1's, the decoded length is between
        // 1 and 32 bytes. Pad on the left with zeros to 32.
        if decoded.len() > ADDRESS_LEN {
            return Err(CoreError::InvalidLength {
                expected: ADDRESS_LEN,
                actual: decoded.len(),
            });
        }
        let mut raw = [0u8; ADDRESS_LEN];
        let off = ADDRESS_LEN - decoded.len();
        raw[off..].copy_from_slice(&decoded);
        Ok(Self {
            raw,
            display: display.to_string(),
        })
    }

    pub fn from_parts(raw: [u8; ADDRESS_LEN], display: impl Into<String>) -> Self {
        Self {
            raw,
            display: display.into(),
        }
    }

    /// 32-byte canonical form (= SHA-256(pubkey)).
    pub fn as_bytes(&self) -> &[u8; ADDRESS_LEN] {
        &self.raw
    }

    /// Textual `oct...` form for JSON-RPC / display.
    pub fn display(&self) -> &str {
        &self.display
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Address")
            .field("display", &self.display)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display)
    }
}

fn hash_display(s: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_pubkey_round_trip() {
        let pk = [7u8; 32];
        let a = Address::from_pubkey(&pk);
        assert!(a.display().starts_with("oct"));
        assert_eq!(a.display().len(), ADDRESS_TOTAL_LEN);
        let parsed = Address::try_from_display(a.display()).unwrap();
        assert_eq!(parsed.as_bytes(), a.as_bytes());
    }

    #[test]
    fn try_from_display_rejects_bad_prefix() {
        let r = Address::try_from_display("xxx0000000000000000000000000000000000000000000000");
        assert!(r.is_err());
    }

    #[test]
    fn try_from_display_rejects_wrong_length() {
        let r = Address::try_from_display("octABC");
        assert!(r.is_err());
    }

    #[test]
    fn from_display_fallback_does_not_panic() {
        // Random non-Octra string still constructs (best-effort fallback)
        // so legacy callers using sha256(display) keep working.
        let _ = Address::from_display("not a real address");
    }
}
