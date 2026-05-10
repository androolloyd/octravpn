//! Octra address handling.
//!
//! Octra addresses are documented as `oct...` strings in the developer docs.
//! On the wire we treat them as opaque byte strings; only when we receive
//! them from the JSON-RPC do we keep the textual form. The internal
//! 32-byte canonical form is used for hashing into commitments.

use serde::{Deserialize, Serialize};
use std::fmt;

pub const ADDRESS_LEN: usize = 32;

/// Canonical 32-byte representation of an Octra address. The textual form
/// (`oct...`) is preserved alongside for display.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    pub raw: [u8; ADDRESS_LEN],
    pub display: String,
}

impl Address {
    pub fn new(raw: [u8; ADDRESS_LEN], display: impl Into<String>) -> Self {
        Self {
            raw,
            display: display.into(),
        }
    }

    /// Parse from the JSON-RPC textual form. The encoding scheme is
    /// the documented `oct` prefix plus a base-encoded payload; the
    /// concrete decoding is delegated to a hash for cases where we
    /// only need a stable 32-byte identity (e.g. when committing to
    /// the address inside a Pedersen commitment). For RPC calls we
    /// always send the original `display` string back over the wire.
    pub fn from_display(display: impl Into<String>) -> Self {
        let display = display.into();
        let raw = sha256_32(display.as_bytes());
        Self { raw, display }
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Address").field("display", &self.display).finish()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display)
    }
}

fn sha256_32(b: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}
