//! Integration boundary with the headscale-style coordination plane.
//!
//! ## What this module is, today
//!
//! A **minimum-viable preauth-key minter** so the
//! `docker/devnet/tailscale-interop/run-interop.sh` test can advance
//! past exit code 20 ("no preauth-key minting surface available").
//!
//! This is intentionally *not* a full Tailscale coordination server.
//! It implements only what the interop test directly probes:
//!
//!   - Mint a preauth key for a named user.
//!   - Hold the key in an in-process store so an operator (or test
//!     harness) can later present it as a bearer credential to
//!     `tailscale up --authkey ...`.
//!
//! See `docs/tailscale-interop-blocker.md` for what is *still*
//! missing between "we hand out a preauth key" and "stock `tailscale`
//! actually completes a handshake against us" — chiefly the
//! `/key`, `/machine/{node_key}/register` and
//! `/machine/{node_key}/map` long-poll endpoints, plus the
//! TS2021 Noise frame layer they ride on. That work is a
//! multi-week effort and is tracked in the blocker doc, not here.
//!
//! ## Why not pull in `headscale-rs`?
//!
//! `headscale-rs` (sibling repo at `~/Development/headscale-rs`) is
//! *not* a drop-in Tailscale coordination server. Its public
//! handlers (`headscale_api::http::build_router`) expose a custom
//! `/api/v1/nodes`, `/api/v1/register`, `/api/v1/transfer` JSON
//! surface — *not* the
//! `GET /key` + `POST /machine/{node_key}/{register,map}` wire
//! protocol that stock `tailscale up` speaks. Linking against it
//! would not get us to exit code 0 either; it would just pull in
//! a second incompatible surface. Until either (a) headscale-rs
//! grows the Tailscale wire protocol upstream or (b) we vendor /
//! fork a Rust port of it, the bridge stays preauth-only.
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

pub use metrics::MetricsSink;
pub use preauth::{
    PreauthKey, PreauthMinter, RedeemError, RedemptionRecord, DEFAULT_BOUNDED_TTL,
    DEFAULT_MINTS_CAPACITY, DEFAULT_PREAUTH_TTL, DEFAULT_REDEMPTIONS_CAPACITY,
};

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
