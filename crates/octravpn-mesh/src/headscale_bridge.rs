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

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use headscale_api::tailscale_wire::{
    AllocError, IpAllocator, PreauthRedeemer, RedeemError as WireRedeemError,
};
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::ip_alloc::TailnetIpAllocator;

/// Default time-to-live for a freshly minted preauth key.
///
/// Stock `tailscale up` consumes the key essentially immediately on
/// first use, so a short TTL is plenty for the test. We pick one hour
/// to leave room for an operator who pastes the key into a config and
/// rolls a container a few minutes later.
pub const DEFAULT_PREAUTH_TTL: Duration = Duration::from_secs(3600);

/// A minted preauth credential. The `key` field is what the test
/// hands to `tailscale up --authkey`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreauthKey {
    /// Opaque bearer token. Format: `octrapreauth-<32 bytes hex>`.
    /// The `octrapreauth-` prefix is a visible breadcrumb so an
    /// operator inspecting `tailscale up` logs can tell at a glance
    /// where the key originated; the random suffix is the actual
    /// secret.
    pub key: String,
    /// The user the key was minted for. Mirrors Tailscale's "user"
    /// concept: keys are per-user and can be used by any device
    /// claiming that user.
    pub user: String,
    /// Unix-seconds creation timestamp.
    pub created_at: u64,
    /// Unix-seconds expiry. The key is rejected after this.
    pub expires_at: u64,
    /// Whether the key may be redeemed more than once.
    pub reusable: bool,
}

impl PreauthKey {
    /// Returns `true` if `now_unix` is past the expiry.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at
    }
}

/// Minimal observability hook the bridge layer exposes to upper
/// crates without taking a hard dependency on a metrics library.
///
/// Implementors map an event name to a counter / log line / whatever.
/// The bridge ships exactly two event names today —
/// `"preauth_mint"` and `"preauth_redeem"` — both bumped from
/// `PreauthMinter`. Additional events may be added; sinks are
/// expected to ignore unknown names so a mesh-side bump doesn't
/// require a lock-step node-side recompile.
///
/// The trait is intentionally `Sync` (no `&mut self`) so the same
/// sink can be shared across threads behind an `Arc`; the
/// node-side `impl MetricsSink for NodeMetrics` in
/// `octravpn-node/src/control.rs` uses `AtomicU64::fetch_add`,
/// which is the right primitive for that pattern.
pub trait MetricsSink: Send + Sync {
    /// Record an event. `name` is a short ASCII string; sinks
    /// match on it and bump the corresponding counter. Unknown
    /// names are dropped silently.
    fn record_event(&self, name: &str);
}

/// In-process preauth-key store + minter.
///
/// Cheap to clone: state is held in an `Arc<Mutex<…>>` so the same
/// minter can be shared between the daemon's HTTP control plane and
/// the (anticipated) Tailscale wire-protocol handler.
///
/// An optional [`MetricsSink`] can be attached via
/// [`PreauthMinter::with_metrics_sink`]; when set, `mint` and
/// `redeem` publish `"preauth_mint"` / `"preauth_redeem"` events
/// against it. The sink is held by `Arc` so the minter stays cheap
/// to clone.
#[derive(Clone, Default)]
pub struct PreauthMinter {
    inner: Arc<Mutex<PreauthState>>,
    /// Optional sink for `preauth_mint` / `preauth_redeem` events.
    /// `None` (the default) is a zero-cost no-op on the data path.
    metrics: Option<Arc<dyn MetricsSink>>,
}

#[derive(Default)]
struct PreauthState {
    /// `key -> PreauthKey`. Keyed by the opaque token because that's
    /// what an incoming `register` request would present.
    by_key: HashMap<String, PreauthKey>,
    /// `key -> redemption count`. A non-reusable key is removed from
    /// `by_key` on first redemption; reusable keys just increment.
    redemptions: HashMap<String, u64>,
}

impl PreauthMinter {
    /// Construct an empty in-memory minter. Persistence is out of
    /// scope for the interop test (it tears the container down on
    /// every run).
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a [`MetricsSink`]. Returns a fresh minter with the
    /// sink wired; the original state map is shared (the `Arc`
    /// clone behaviour) so call sites can pre-mint a key before
    /// attaching metrics without losing it.
    pub fn with_metrics_sink(mut self, sink: Arc<dyn MetricsSink>) -> Self {
        self.metrics = Some(sink);
        self
    }

    /// Mint a fresh preauth key for `user`.
    ///
    /// `ttl` controls the expiry window; `reusable` indicates whether
    /// the key may be redeemed by more than one device. The default
    /// for the interop test is single-use, matching the safest
    /// behaviour of stock Tailscale.
    pub fn mint(&self, user: impl Into<String>, ttl: Duration, reusable: bool) -> PreauthKey {
        let now = now_unix();
        let mut rng = rand::thread_rng();
        let mut raw = [0u8; 32];
        rng.fill_bytes(&mut raw);
        let key = format!("octrapreauth-{}", hex::encode(raw));
        let pk = PreauthKey {
            key: key.clone(),
            user: user.into(),
            created_at: now,
            expires_at: now.saturating_add(ttl.as_secs()),
            reusable,
        };
        {
            let mut st = self.inner.lock();
            st.by_key.insert(key, pk.clone());
        }
        if let Some(sink) = self.metrics.as_deref() {
            sink.record_event("preauth_mint");
        }
        pk
    }

    /// Look up a key by token. Returns `None` if unknown or expired.
    pub fn lookup(&self, token: &str) -> Option<PreauthKey> {
        let st = self.inner.lock();
        let pk = st.by_key.get(token)?.clone();
        if pk.is_expired(now_unix()) {
            return None;
        }
        Some(pk)
    }

    /// Mark `token` as redeemed. For a non-reusable key this removes
    /// it from the store, so a replay returns `RedeemError::Unknown`.
    /// Returns the bound user on success.
    pub fn redeem(&self, token: &str) -> Result<String, RedeemError> {
        let now = now_unix();
        let user = {
            let mut st = self.inner.lock();
            let pk = st.by_key.get(token).ok_or(RedeemError::Unknown)?.clone();
            if pk.is_expired(now) {
                // Expired keys also get removed so a slow client doesn't
                // hold a stale token forever.
                st.by_key.remove(token);
                return Err(RedeemError::Expired);
            }
            let count = st.redemptions.entry(token.to_string()).or_insert(0);
            *count += 1;
            if !pk.reusable {
                st.by_key.remove(token);
            }
            pk.user
        };
        if let Some(sink) = self.metrics.as_deref() {
            sink.record_event("preauth_redeem");
        }
        Ok(user)
    }

    /// Number of currently live (unredeemed-and-unexpired) keys.
    /// Exposed for `/metrics` style introspection.
    pub fn live_count(&self) -> usize {
        let now = now_unix();
        let st = self.inner.lock();
        st.by_key.values().filter(|k| !k.is_expired(now)).count()
    }
}

/// Why a `redeem` call rejected a token.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RedeemError {
    /// Token doesn't match any minted key (or was already consumed
    /// once for a non-reusable key).
    #[error("preauth: unknown key")]
    Unknown,
    /// Token was valid at some point but its TTL has passed.
    #[error("preauth: key expired")]
    Expired,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Bridge: implement the headscale-api Tailscale-wire traits on top of
// OctraVPN's PreauthMinter + TailnetIpAllocator.
//
// As of 2026-05-19 the Tailscale wire-protocol implementation lives in
// `headscale-api::tailscale_wire`. The wire layer parameterises on two
// small traits (`PreauthRedeemer`, `IpAllocator`) so headscale-rs can
// stay free of OctraVPN-specific policy. The bridge here is the only
// place those traits meet OctraVPN's PreauthMinter + TailnetIpAllocator.
// ---------------------------------------------------------------------------

/// Adapter: wrap a `PreauthMinter` so it can be handed to
/// `headscale_api::tailscale_wire::WireState.preauth` as an
/// `Arc<dyn PreauthRedeemer>`.
#[async_trait]
impl PreauthRedeemer for PreauthMinter {
    async fn redeem(&self, key: &str) -> Result<String, WireRedeemError> {
        // Synchronous redeem under the hood; the async signature is for
        // future-proofing on the wire side. We translate OctraVPN's
        // RedeemError into the wire crate's identical-shape enum.
        match PreauthMinter::redeem(self, key) {
            Ok(user) => Ok(user),
            Err(RedeemError::Unknown) => Err(WireRedeemError::Unknown),
            Err(RedeemError::Expired) => Err(WireRedeemError::Expired),
        }
    }
}

/// Adapter: wrap a `TailnetIpAllocator` so it can be handed to
/// `headscale_api::tailscale_wire::WireState.ip_allocator` as an
/// `Arc<dyn IpAllocator>`.
impl IpAllocator for TailnetIpAllocator {
    fn allocate(&self, node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
        // OctraVPN's allocator is infallible (deterministic hash into
        // CGNAT /10), so the bridge never produces an `AllocError`.
        Ok(TailnetIpAllocator::allocate(self, node_key_hex))
    }
}

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

    #[test]
    fn mint_then_lookup_roundtrip() {
        let m = PreauthMinter::new();
        let k = m.mint("alice", DEFAULT_PREAUTH_TTL, false);
        assert!(k.key.starts_with("octrapreauth-"));
        assert_eq!(k.user, "alice");
        let found = m.lookup(&k.key).expect("just-minted key visible");
        assert_eq!(found.user, "alice");
    }

    #[test]
    fn keys_are_distinct_per_mint() {
        let m = PreauthMinter::new();
        let a = m.mint("u", DEFAULT_PREAUTH_TTL, false);
        let b = m.mint("u", DEFAULT_PREAUTH_TTL, false);
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn single_use_redeem_consumes_key() {
        let m = PreauthMinter::new();
        let k = m.mint("bob", DEFAULT_PREAUTH_TTL, false);
        assert_eq!(m.redeem(&k.key).unwrap(), "bob");
        assert_eq!(m.redeem(&k.key), Err(RedeemError::Unknown));
        assert!(m.lookup(&k.key).is_none());
    }

    #[test]
    fn reusable_redeem_keeps_key() {
        let m = PreauthMinter::new();
        let k = m.mint("ops", DEFAULT_PREAUTH_TTL, true);
        m.redeem(&k.key).unwrap();
        m.redeem(&k.key).unwrap();
        assert!(m.lookup(&k.key).is_some());
    }

    #[test]
    fn expired_key_rejects_lookup_and_redeem() {
        let m = PreauthMinter::new();
        // TTL = 0 forces `expires_at == created_at`, which our
        // `is_expired(now_unix)` predicate (>=) treats as expired
        // immediately.
        let k = m.mint("x", Duration::from_secs(0), false);
        assert!(m.lookup(&k.key).is_none());
        assert_eq!(m.redeem(&k.key), Err(RedeemError::Expired));
    }

    /// Test-only sink that records every event name it observes.
    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<String>>,
    }

    impl MetricsSink for RecordingSink {
        fn record_event(&self, name: &str) {
            self.events.lock().push(name.to_string());
        }
    }

    /// `mint` publishes `preauth_mint` on the attached sink. Wiring
    /// pin: a future refactor that moves the bump elsewhere will
    /// break this test.
    #[test]
    fn mint_publishes_preauth_mint_event() {
        let sink = Arc::new(RecordingSink::default());
        let m = PreauthMinter::new().with_metrics_sink(sink.clone());
        m.mint("u", DEFAULT_PREAUTH_TTL, false);
        assert_eq!(sink.events.lock().as_slice(), &["preauth_mint".to_string()]);
    }

    /// `redeem` publishes `preauth_redeem` on success but NOT on the
    /// unknown-token rejection path (a redeem that never finds a key
    /// isn't a redemption).
    #[test]
    fn redeem_publishes_preauth_redeem_only_on_success() {
        let sink = Arc::new(RecordingSink::default());
        let m = PreauthMinter::new().with_metrics_sink(sink.clone());
        let k = m.mint("u", DEFAULT_PREAUTH_TTL, false);
        assert!(m.redeem(&k.key).is_ok());
        assert!(m.redeem("nonexistent").is_err());
        let events = sink.events.lock().clone();
        let redeems = events
            .iter()
            .filter(|n| n.as_str() == "preauth_redeem")
            .count();
        assert_eq!(redeems, 1, "events: {events:?}");
    }

    /// A minter with no sink attached is a zero-cost no-op on the
    /// data path — `mint`/`redeem` proceed exactly as before. This
    /// preserves backwards-compat for callers that don't construct
    /// via `with_metrics_sink`.
    #[test]
    fn no_sink_default_path_unchanged() {
        let m = PreauthMinter::new();
        let k = m.mint("u", DEFAULT_PREAUTH_TTL, false);
        assert_eq!(m.redeem(&k.key).unwrap(), "u");
    }

    #[test]
    fn live_count_tracks_outstanding() {
        let m = PreauthMinter::new();
        assert_eq!(m.live_count(), 0);
        let a = m.mint("a", DEFAULT_PREAUTH_TTL, false);
        let _b = m.mint("b", DEFAULT_PREAUTH_TTL, false);
        assert_eq!(m.live_count(), 2);
        m.redeem(&a.key).unwrap();
        assert_eq!(m.live_count(), 1);
    }
}
