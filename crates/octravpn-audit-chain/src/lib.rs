//! Audit-log HMAC chain-step primitive.
//!
//! The node writes the tamper-evident audit log; the analytics reader
//! verifies it. Both sides MUST compute the chain MAC byte-for-byte the
//! same way, so [`chain_step`] lives here — depended on by both crates —
//! rather than being re-implemented in each. A divergence between a
//! re-implemented writer and verifier would either break verification of
//! a valid log or, worse, let a forged one pass; a single shared
//! function makes that class of bug impossible.
//!
//! This crate is deliberately tiny (only `hmac` + `sha2`) so the
//! otherwise-lean `octravpn-analytics` indexer can depend on it without
//! pulling in the node's or core's heavier dependency graph.
//!
//! ## Wire format
//!
//! Each audit-log line is a JSON object with three string fields:
//!   - `record_json` — canonical bytes of the inner `AuditRecord`
//!   - `prev_mac`    — hex(32) MAC of the prior line (64 zeros for the
//!                     first line of a daily file)
//!   - `mac`         — hex(32) of `HMAC-SHA256(key, prev_mac || record_json)`
//!
//! [`chain_step`] computes that inner MAC.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// One step of the audit-log HMAC chain:
/// `HMAC-SHA256(key, prev_mac || record_bytes)`.
///
/// The single source of truth for both the node writer
/// (`octravpn-node`'s `audit::AuditLog`) and the analytics verifier
/// (`octravpn-analytics`'s `audit_reader`). Changing what this produces
/// rotates the on-disk chain format — every prior audit log stops
/// verifying — so the known-answer test below pins the output.
#[must_use]
pub fn chain_step(key: &[u8; 32], prev_mac: &[u8; 32], record_bytes: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(prev_mac);
    mac.update(record_bytes);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_keyed_and_prev_sensitive() {
        let key = [0x42u8; 32];
        let prev = [0u8; 32];
        let a = chain_step(&key, &prev, b"hello");
        assert_eq!(a, chain_step(&key, &prev, b"hello"), "deterministic");
        assert_ne!(
            a,
            chain_step(&[0x43u8; 32], &prev, b"hello"),
            "key-sensitive"
        );
        assert_ne!(
            a,
            chain_step(&key, &[1u8; 32], b"hello"),
            "prev-mac-sensitive"
        );
    }

    /// Known-answer vector. Pins the exact MAC bytes so any change to the
    /// computation (domain separator, field order, hash) is caught — the
    /// verifiability of every on-disk audit log depends on this output
    /// never silently changing.
    #[test]
    fn known_answer_vector() {
        let mac = chain_step(&[0u8; 32], &[0u8; 32], b"octra-audit");
        assert_eq!(
            hex::encode(mac),
            "aaf2dbb938bb8410a37ecb5548edc1bf17ce67b7df898247b786e8d0135c2213"
        );
    }
}
