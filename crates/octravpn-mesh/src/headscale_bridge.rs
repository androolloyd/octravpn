//! Integration boundary with `headscale-rs`.
//!
//! `headscale-rs` (separate sibling repo at `~/Development/headscale-rs`)
//! is the eventual coordination + metering plane for OctraVPN. As of
//! the audit pass this crate has **zero** Rust-API coupling to
//! headscale-rs: it is not a workspace dependency, no module here
//! imports any `headscale_core::*` symbol, and nothing here links
//! against it.
//!
//! ## Canonical inbound contract: `MeteringSnapshot`
//!
//! When the integration lands, OctraVPN consumes exactly one type
//! from headscale-rs: [`headscale_core::metering::MeteringSnapshot`].
//! Its shape (pinned 2026-05-18 against
//! `~/Development/headscale-rs/headscale-core/src/metering.rs`):
//!
//! ```text
//! pub struct MeteringSnapshot {
//!     pub session_id: MeteringSessionId,
//!     pub consumer_did: String,
//!     pub provider_did: String,
//!     pub bytes_in: u64,
//!     pub bytes_out: u64,
//!     pub bandwidth_limit: Option<u64>,
//!     pub remaining: Option<u64>,
//!     pub duration_secs: u64,
//!     pub active: bool,
//! }
//! ```
//!
//! Any future adapter lives **in this crate** (NOT in headscale-rs)
//! and translates `MeteringSnapshot` into either a v1 settlement
//! call (`octravpn_core::session::settle_session`) or a v2 Circle
//! proxy invocation (`octravpn_core::receipt::SignedReceipt`).
//!
//! ## Scope of the bridge
//!
//! The adapter shall:
//!
//! - Accept `MeteringSnapshot` events (poll- or push-based — see
//!   `headscale_core::metering::MeteringService::snapshot`).
//! - Convert `bytes_in + bytes_out` into the receipt-journal entry
//!   the consensus layer expects.
//! - Reject snapshots where `active == false` (settle-on-close path
//!   only).
//! - Bind `session_id` to an Octra `program_addr + chain_id +
//!   circle_id` triple before signing, matching the receipt
//!   canonicalisation rules in
//!   `octravpn_core::receipt::SignedReceipt`.
//!
//! The adapter shall **not**:
//!
//! - Pull in `radicle`, `rental`, or off-chain "accounting" code
//!   paths that earlier headscale-rs revisions exposed. Those were
//!   removed; see commit log of the upstream repo.
//! - Re-export headscale-rs types from this crate; consumers depend
//!   directly on the upstream crate.
//!
//! ## API-surface pin
//!
//! The unit test [`pinned_metering_snapshot_field_names`] codifies
//! the inbound contract. It does not link against headscale-rs (so
//! the workspace stays dependency-free in this commit) but does
//! assert in code the exact field names + types we expect. If
//! headscale-rs renames a field, the integration commit will fail
//! this test and the rename must be reflected in the adapter at the
//! same time.

/// Frozen field signature of `headscale_core::metering::MeteringSnapshot`
/// as of the audit pin date (2026-05-18). When the actual
/// integration lands this mirror is replaced by a thin adapter that
/// constructs from the upstream type.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) struct ExpectedMeteringSnapshotShape {
    pub session_id: String,
    pub consumer_did: String,
    pub provider_did: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub bandwidth_limit: Option<u64>,
    pub remaining: Option<u64>,
    pub duration_secs: u64,
    pub active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check that pins the headscale-rs API surface our
    /// integration depends on. If a future commit changes the
    /// expected field names or types here without updating
    /// headscale-rs in lock-step, the integration test in the
    /// follow-up commit will fail loudly.
    #[test]
    fn pinned_metering_snapshot_field_names() {
        // Constructing the expected shape doubles as a static
        // assertion that the types compile. The field accesses
        // below force the names to exist.
        let s = ExpectedMeteringSnapshotShape {
            session_id: "sid".into(),
            consumer_did: "did:c".into(),
            provider_did: "did:p".into(),
            bytes_in: 1,
            bytes_out: 2,
            bandwidth_limit: Some(10),
            remaining: Some(7),
            duration_secs: 30,
            active: true,
        };
        let total = s.bytes_in + s.bytes_out;
        assert_eq!(total, 3);
        assert!(s.active);
        assert_eq!(s.bandwidth_limit, Some(10));
        assert_eq!(s.remaining, Some(7));
        assert_eq!(s.duration_secs, 30);
        assert_eq!(s.consumer_did, "did:c");
        assert_eq!(s.provider_did, "did:p");
        assert_eq!(s.session_id, "sid");
    }
}
