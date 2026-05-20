//! Forward-compat enforcement for public `#[non_exhaustive]` error
//! enums in `octravpn-core`.
//!
//! Audit blocker E-1 (`docs/audit/2026-05-20-concurrency-error-config-audit.md`)
//! required every public error enum to carry `#[non_exhaustive]` so
//! that downstream crates cannot tie themselves to the current variant
//! list — adding a new variant to one of these enums is supposed to
//! stay a non-breaking change.
//!
//! This file lives in `tests/` (an integration-test crate), which is a
//! *separate* crate from `octravpn-core`. That matters: `#[non_exhaustive]`
//! is only observable from outside the defining crate. The cross-crate
//! match below would not compile if any of these enums lost the
//! attribute — the compiler would object to the missing `_ =>` arm.
//!
//! If a future variant is added to one of these enums, this test keeps
//! compiling (no recompile needed); if the attribute is dropped, the
//! `_ =>` arm becomes an `unreachable_patterns` warning that the
//! workspace `unused_must_use = "deny"` policy escalates.

#![allow(clippy::needless_pass_by_value)] // intentional: matching consumes the value

use octravpn_core::{
    onion::OnionError, receipt::ReceiptError, receipt_journal::JournalError,
    v3_members::V3MembersError, v3_policy::V3PolicyError, v3_state_root::StateRootError,
};

/// Sentinel: every public `Error` enum below is matched with a
/// wildcard arm. The compiler only allows this *if* the enum is
/// `#[non_exhaustive]` (otherwise the wildcard would be flagged as
/// `unreachable_patterns` — which this module denies, so the test
/// crate would fail to build if any enum lost the attribute).
#[deny(unreachable_patterns)]
#[test]
fn public_error_enums_are_non_exhaustive() {
    fn check_onion(e: OnionError) -> &'static str {
        match e {
            OnionError::EmptyRoute => "empty",
            OnionError::TooManyHops => "many",
            OnionError::Aead(_) => "aead",
            OnionError::Io(_) => "io",
            OnionError::Malformed => "mal",
            _ => "future",
        }
    }
    assert_eq!(check_onion(OnionError::EmptyRoute), "empty");

    fn check_receipt(e: ReceiptError) -> &'static str {
        match e {
            ReceiptError::NonMonotonicSeq { .. } => "seq",
            ReceiptError::BadClientSig => "client",
            ReceiptError::BadNodeSig => "node",
            ReceiptError::Core(_) => "core",
            _ => "future",
        }
    }
    assert_eq!(check_receipt(ReceiptError::BadNodeSig), "node");

    fn check_journal(e: JournalError) -> &'static str {
        match e {
            JournalError::Io(_) => "io",
            JournalError::BadMagic { .. } => "magic",
            JournalError::Truncated { .. } => "trunc",
            JournalError::ChecksumMismatch { .. } => "cksum",
            JournalError::SeqNotMonotonic { .. } => "seq",
            _ => "future",
        }
    }
    assert_eq!(
        check_journal(JournalError::BadMagic { path: "/x".into() }),
        "magic"
    );

    fn check_v3_policy(e: V3PolicyError) -> &'static str {
        match e {
            V3PolicyError::UnsupportedVersion { .. } => "ver",
            V3PolicyError::BadWgPubkeyLength { .. } => "wglen",
            V3PolicyError::BadWgPubkeyEncoding(_) => "wgenc",
            V3PolicyError::BadWgPubkeyDecodedLength { .. } => "wgdec",
            V3PolicyError::EmptyEndpoint => "ep",
            V3PolicyError::EmptyRegion => "reg",
            V3PolicyError::BadHashLength { .. } => "hlen",
            V3PolicyError::BadHashEncoding { .. } => "henc",
            V3PolicyError::Serde(_) => "serde",
            _ => "future",
        }
    }
    assert_eq!(check_v3_policy(V3PolicyError::EmptyEndpoint), "ep");

    fn check_v3_members(e: V3MembersError) -> &'static str {
        match e {
            V3MembersError::UnsupportedVersion { .. } => "ver",
            V3MembersError::BadIpSaltLength { .. } => "saltlen",
            V3MembersError::BadIpSaltEncoding => "saltenc",
            V3MembersError::EmptyWallet { .. } => "empty",
            V3MembersError::BadWalletPrefix { .. } => "pref",
            V3MembersError::BadWgPubkeyLength { .. } => "wglen",
            V3MembersError::BadWgPubkeyEncoding { .. } => "wgenc",
            V3MembersError::BadWgPubkeyDecodedLength { .. } => "wgdec",
            V3MembersError::DuplicateWallet { .. } => "dup",
            V3MembersError::Serde(_) => "serde",
            _ => "future",
        }
    }
    assert_eq!(
        check_v3_members(V3MembersError::BadIpSaltEncoding),
        "saltenc"
    );

    fn check_state_root(e: StateRootError) -> &'static str {
        match e {
            StateRootError::UnsupportedVersion { .. } => "ver",
            StateRootError::BadHashLength { .. } => "hlen",
            StateRootError::BadHashEncoding { .. } => "henc",
            StateRootError::EmptyCircleId => "circle",
            StateRootError::EmptyRegion => "reg",
            StateRootError::Serde(_) => "serde",
            _ => "future",
        }
    }
    assert_eq!(check_state_root(StateRootError::EmptyCircleId), "circle");
}
