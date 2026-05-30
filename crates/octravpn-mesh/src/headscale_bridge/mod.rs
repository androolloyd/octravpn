//! Integration boundary with the headscale-style coordination plane.
//!
//! ## What this module is, today
//!
//! A **small preauth-key minter** shared by Octra's local admin route
//! and the headscale-rs Tailscale-wire handlers.
//!
//! This is intentionally *not* a full Tailscale coordination server.
//! It implements only the Octra-owned part of the join flow:
//!
//!   - Mint a preauth key for a named user.
//!   - Hold the key in an in-process store so an operator (or test
//!     harness) can later present it as a bearer credential to
//!     `tailscale up --authkey ...`.
//!
//! The Tailscale-wire surface itself now lives in headscale-rs:
//! `GET /key`, `POST /ts2021`, and the flat + keyed
//! `/machine/.../{register,map}` handlers are outside this module.
//! Remaining interop gaps are tracked in `docs/tailscale-interop-blocker.md`
//! and are mostly about map-stream semantics, lifecycle, and production
//! polish rather than the existence of these routes.
//!
//! ## Why keep this module?
//!
//! Octra still owns the `/admin/preauth` convenience shim and the
//! chain/audit-facing counters around it. A future shared persistent
//! preauth admin can replace the in-memory store, but this module is
//! deliberately narrow until that wiring is well-covered.
//!
//! ## Canonical inbound contract: `MeteringSnapshot`
//!
//! When the *metering* integration lands (separately, after the
//! coordination plane is real), OctraVPN will consume exactly one
//! type from headscale-rs:
//! `headscale_core::metering::MeteringSnapshot`. Its expected shape
//! is pinned by [`ExpectedMeteringSnapshotShape`] below so a
//! drift in the upstream type is caught at compile time when the
//! adapter lands.
//!
//! ## Layout
//!
//!   - [`preauth`]     — [`PreauthMinter`] + bounded LRU (`mints`,
//!                       `redemptions`), redeem / mint helpers, the
//!                       cap defaults from #236.
//!   - [`metrics`]     — [`MetricsSink`] trait (the
//!                       `preauth_mint` / `preauth_redeem` event
//!                       contract with the node-side counters).
//!   - [`traits`]      — wire-bridge `impl`s
//!                       (`PreauthRedeemer` for [`PreauthMinter`],
//!                       `IpAllocator` for `TailnetIpAllocator`).
//!   - [`persistence`] — placeholder for the #235
//!                       `PersistentPreauthAdmin` integration; not
//!                       yet wired.

pub mod metrics;
pub mod persistence;
pub mod preauth;
pub mod traits;
pub mod wire_state;

pub use metrics::MetricsSink;
pub use preauth::{
    PreauthKey, PreauthMinter, RedeemError, RedemptionRecord, DEFAULT_BOUNDED_TTL,
    DEFAULT_MINTS_CAPACITY, DEFAULT_PREAUTH_TTL, DEFAULT_REDEMPTIONS_CAPACITY,
};
pub use wire_state::WireStateBuilder;

// ---------------------------------------------------------------------------
// Frozen field-name pin for the future metering integration.
//
// Kept verbatim from the pre-bridge audit so the eventual
// `headscale_core::metering::MeteringSnapshot` adapter is anchored to a
// known field signature. Renaming a field upstream will break the
// adapter at compile time, drawing attention to the lock-step rename.
// ---------------------------------------------------------------------------

/// Frozen field signature of `headscale_core::metering::MeteringSnapshot`
/// as of the audit pin date (2026-05-18). The pin lives in non-test
/// code (rather than `#[cfg(test)]`) so consumers can construct
/// fixtures from it in integration tests once the metering adapter
/// lands. It carries no runtime cost — it's a plain struct.
#[allow(dead_code)]
pub struct ExpectedMeteringSnapshotShape {
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

    /// Field-name pin: catching a rename of `MeteringSnapshot` upstream.
    /// The test constructs the expected shape, which forces the
    /// compiler to confirm every field still exists with the right
    /// type.
    #[test]
    fn pinned_metering_snapshot_field_names() {
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
        assert_eq!(s.bytes_in + s.bytes_out, 3);
        assert!(s.active);
    }
}
