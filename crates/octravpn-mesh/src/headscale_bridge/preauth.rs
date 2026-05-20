//! Preauth-key minter + bounded LRU audit log.
//!
//! This submodule owns the high-collision area of the headscale bridge:
//! [`PreauthMinter`], the FIFO + idle-TTL bounded [`BoundedMap`]s it
//! holds, and the [`PreauthKey`] / [`RedeemError`] / [`RedemptionRecord`]
//! types that make up the redeem contract.
//!
//! ## Cap defaults
//!
//! The bounded LRU defaults that other agents have repeatedly collided
//! on (see #236 and the modularize-* territories):
//!
//!   - [`DEFAULT_MINTS_CAPACITY`]        = `100_000` entries
//!   - [`DEFAULT_REDEMPTIONS_CAPACITY`]  = `100_000` entries
//!   - [`DEFAULT_BOUNDED_TTL`]           = `30 days` idle-TTL
//!   - [`DEFAULT_PREAUTH_TTL`]           = `1 hour` per-key expiry
//!
//! The #236 invariant: a key evicted from `mints` (capacity OR idle-TTL)
//! MUST map to [`RedeemError::Unknown`] on a subsequent `redeem`,
//! exactly the same shape a never-minted token returns. Reusable keys
//! persist across audit-map eviction — the `mints` map is the
//! authoritative single-use enforcement source, not `redemptions`.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use octravpn_core::bounded::BoundedMap;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::metrics::MetricsSink;

/// Default time-to-live for a freshly minted preauth key.
///
/// Stock `tailscale up` consumes the key essentially immediately on
/// first use, so a short TTL is plenty for the test. We pick one hour
/// to leave room for an operator who pastes the key into a config and
/// rolls a container a few minutes later.
pub const DEFAULT_PREAUTH_TTL: Duration = Duration::from_secs(3600);

/// Default hard cap on outstanding minted keys held in the `mints`
/// map. At ~150 bytes per entry this caps RAM at ~15 MB worst case.
/// When the cap is hit, the oldest entry is FIFO-evicted; a subsequent
/// redeem of an evicted key returns [`RedeemError::Unknown`] — the
/// same error a never-minted token returns.
pub const DEFAULT_MINTS_CAPACITY: usize = 100_000;

/// Default hard cap on the post-redemption audit log held in the
/// `redemptions` map. Sized to match `DEFAULT_MINTS_CAPACITY` so a
/// burst of redemptions can't blow past the mints cap while the audit
/// trail catches up.
pub const DEFAULT_REDEMPTIONS_CAPACITY: usize = 100_000;

/// Default idle-TTL for both `mints` and `redemptions`. A 30-day
/// window matches the typical Tailscale preauth-key lifetime and is
/// generous enough that legitimate slow-roll deployments don't lose
/// their audit trail. The window is an *idle* TTL (refreshed on
/// `get`/`modify`); a key that's never re-touched ages out at the
/// nominal 30-day mark.
pub const DEFAULT_BOUNDED_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Post-redemption audit record stored in `PreauthMinter::redemptions`.
///
/// The bounded map carries one of these per token that has *ever*
/// been redeemed. It is intentionally *not* the authoritative
/// single-use enforcement mechanism — that role belongs to `mints`,
/// where a non-reusable key is removed on first redeem so a
/// second `lookup`/`redeem` returns [`RedeemError::Unknown`]. The
/// record is kept for audit/observability only and is safe to drop
/// under capacity or TTL pressure.
#[derive(Clone, Debug)]
pub struct RedemptionRecord {
    /// Wall-clock timestamp of the redemption. Useful for an
    /// after-the-fact audit query "when was this token used?".
    pub redeemed_at: SystemTime,
    /// The user the underlying preauth key was bound to. Stored here
    /// because by the time an auditor consults this map the
    /// corresponding `mints` entry may already have been removed
    /// (single-use) or evicted (TTL/cap).
    pub user: String,
}

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

/// In-process preauth-key store + minter.
///
/// Cheap to clone: state is held in `Arc`s so the same minter can be
/// shared between the daemon's HTTP control plane and the
/// (anticipated) Tailscale wire-protocol handler.
///
/// ## Bounded memory
///
/// Both backing maps are [`BoundedMap`]s with a hard capacity cap
/// (FIFO eviction on overflow) and an idle-TTL sweep. Defaults:
/// 100k entries each, 30-day idle-TTL. Use [`PreauthMinter::with_capacity`]
/// or [`PreauthMinter::with_ttl`] to tune. When `mints` evicts a
/// token (cap or TTL), a subsequent `lookup`/`redeem` returns
/// `None` / [`RedeemError::Unknown`] — the same shape the caller
/// would see for a token that was never minted. This is the correct
/// audit behaviour: an evicted key MUST NOT become redeemable
/// again. The `redemptions` map is purely an audit/observability
/// trail and is safe to drop under pressure; it does *not*
/// authoritatively enforce single-use (that role belongs to `mints`,
/// from which a non-reusable key is removed on first redeem).
///
/// An optional [`MetricsSink`] can be attached via
/// [`PreauthMinter::with_metrics_sink`]; when set, `mint` and
/// `redeem` publish `"preauth_mint"` / `"preauth_redeem"` events
/// against it. The sink is held by `Arc` so the minter stays cheap
/// to clone.
#[derive(Clone)]
pub struct PreauthMinter {
    /// Test-and-act serialization for the redeem critical section.
    /// The inner `BoundedMap`s carry their own locks, but the
    /// `lookup → conditional remove → record` sequence in `redeem`
    /// must be observed atomically by competing threads; this outer
    /// mutex guards that sequence.
    seq: Arc<Mutex<()>>,
    /// `key -> PreauthKey`. Keyed by the opaque token because that's
    /// what an incoming `register` request would present. Bounded:
    /// FIFO-evicts on capacity, idle-TTL-evicts on `sweep()`.
    mints: Arc<BoundedMap<String, PreauthKey>>,
    /// `key -> RedemptionRecord`. One entry per redeemed token.
    /// Bounded: same FIFO + idle-TTL story as `mints`. Eviction is
    /// safe — this map is audit-only, not the authoritative
    /// single-use enforcement source.
    redemptions: Arc<BoundedMap<String, RedemptionRecord>>,
    /// Optional sink for `preauth_mint` / `preauth_redeem` events.
    /// `None` (the default) is a zero-cost no-op on the data path.
    metrics: Option<Arc<dyn MetricsSink>>,
}

impl Default for PreauthMinter {
    fn default() -> Self {
        Self {
            seq: Arc::new(Mutex::new(())),
            mints: Arc::new(BoundedMap::new(DEFAULT_MINTS_CAPACITY, DEFAULT_BOUNDED_TTL)),
            redemptions: Arc::new(BoundedMap::new(
                DEFAULT_REDEMPTIONS_CAPACITY,
                DEFAULT_BOUNDED_TTL,
            )),
            metrics: None,
        }
    }
}

impl PreauthMinter {
    /// Construct an empty in-memory minter with default bounds
    /// ([`DEFAULT_MINTS_CAPACITY`] / [`DEFAULT_REDEMPTIONS_CAPACITY`]
    /// entries, [`DEFAULT_BOUNDED_TTL`] idle-TTL on both maps).
    /// Persistence is out of scope for the interop test (it tears
    /// the container down on every run).
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a minter with custom hard-capacity caps on the
    /// `mints` and `redemptions` bounded maps; TTL stays at the
    /// default [`DEFAULT_BOUNDED_TTL`]. Useful for a node whose
    /// expected key volume diverges from the canonical 100k/100k
    /// default — e.g. a small home node tuning down to 1k/1k, or a
    /// production coordinator tuning up to 1M/1M.
    pub fn with_capacity(mints_capacity: usize, redemptions_capacity: usize) -> Self {
        Self {
            seq: Arc::new(Mutex::new(())),
            mints: Arc::new(BoundedMap::new(mints_capacity, DEFAULT_BOUNDED_TTL)),
            redemptions: Arc::new(BoundedMap::new(redemptions_capacity, DEFAULT_BOUNDED_TTL)),
            metrics: None,
        }
    }

    /// Construct a minter with custom idle-TTLs on the `mints` and
    /// `redemptions` bounded maps; capacities stay at the defaults
    /// [`DEFAULT_MINTS_CAPACITY`] / [`DEFAULT_REDEMPTIONS_CAPACITY`].
    /// Useful for a test harness that wants aggressive eviction
    /// (e.g. milliseconds instead of 30 days) without rewriting the
    /// capacity story.
    pub fn with_ttl(mints_ttl: Duration, redemptions_ttl: Duration) -> Self {
        Self {
            seq: Arc::new(Mutex::new(())),
            mints: Arc::new(BoundedMap::new(DEFAULT_MINTS_CAPACITY, mints_ttl)),
            redemptions: Arc::new(BoundedMap::new(
                DEFAULT_REDEMPTIONS_CAPACITY,
                redemptions_ttl,
            )),
            metrics: None,
        }
    }

    /// Attach a [`MetricsSink`]. Returns a fresh minter with the
    /// sink wired; the original state maps are shared (the `Arc`
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
        self.mints.insert(key, pk.clone());
        if let Some(sink) = self.metrics.as_deref() {
            sink.record_event("preauth_mint");
        }
        pk
    }

    /// Look up a key by token. Returns `None` if unknown or expired.
    /// An evicted key (capacity or TTL) is indistinguishable from a
    /// never-minted one — both return `None`.
    pub fn lookup(&self, token: &str) -> Option<PreauthKey> {
        let key = token.to_string();
        let pk = self.mints.get(&key)?;
        if pk.is_expired(now_unix()) {
            return None;
        }
        Some(pk)
    }

    /// Mark `token` as redeemed. For a non-reusable key this removes
    /// it from the store, so a replay returns `RedeemError::Unknown`.
    /// Returns the bound user on success.
    ///
    /// If the token has been evicted from `mints` (capacity or
    /// idle-TTL) the call returns `RedeemError::Unknown` — the
    /// same error a never-minted token returns. This is the
    /// intentional audit behaviour: an evicted single-use key must
    /// not become re-redeemable, and the `mints` BoundedMap is the
    /// single authoritative source for that property.
    pub fn redeem(&self, token: &str) -> Result<String, RedeemError> {
        let now = now_unix();
        let key = token.to_string();
        let user = {
            // Serialize the test-and-act window: another thread
            // racing on the same single-use token must not observe
            // the key as redeemable between our `get` and `remove`.
            let _guard = self.seq.lock();
            let pk = self.mints.get(&key).ok_or(RedeemError::Unknown)?;
            if pk.is_expired(now) {
                // Expired keys also get removed so a slow client doesn't
                // hold a stale token forever.
                self.mints.remove(&key);
                return Err(RedeemError::Expired);
            }
            if !pk.reusable {
                self.mints.remove(&key);
            }
            let record = RedemptionRecord {
                redeemed_at: SystemTime::now(),
                user: pk.user.clone(),
            };
            // Insert (or overwrite) the audit record. Eviction
            // behaviour on overflow is FIFO via BoundedMap.
            self.redemptions.insert(key, record);
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
        self.mints
            .snapshot()
            .into_iter()
            .filter(|(_, k)| !k.is_expired(now))
            .count()
    }

    /// Force an idle-TTL sweep on both bounded maps. Returns
    /// `(mints_evicted, redemptions_evicted)`. Intended to be called
    /// from a periodic background task; not required for correctness
    /// (capacity FIFO bounds growth even without sweeps), only for
    /// freeing memory held by abandoned-but-not-yet-evicted entries.
    pub fn sweep_expired(&self) -> (usize, usize) {
        (self.mints.sweep(), self.redemptions.sweep())
    }

    /// Snapshot of the redemption audit log. The returned vec is a
    /// clone of every live `(token, record)` pair at call time. Sized
    /// by the redemptions capacity cap (default 100k), so this is
    /// bounded — but still O(n) and locks the redemptions map; use
    /// sparingly.
    pub fn redemption_audit(&self) -> Vec<(String, RedemptionRecord)> {
        self.redemptions.snapshot()
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

pub(super) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ------------------------------------------------------------------
    // Bounded-memory tests (E5 fix). See `/tmp/simplify-efficiency.md`
    // for the original finding — both `mints` and `redemptions` were
    // unbounded `HashMap`s and would grow without limit over a node's
    // lifetime. They're now `BoundedMap`s with FIFO-on-overflow + idle-TTL.
    // ------------------------------------------------------------------

    /// Capacity cap on `mints` evicts the oldest entry when a fresh
    /// mint would push the map past its bound. The evicted token's
    /// lookup MUST return `None` — i.e. it looks like a never-minted
    /// key, not like a redeemed-and-stored one.
    #[test]
    fn mints_capacity_evicts_oldest() {
        let m = PreauthMinter::with_capacity(2, 100);
        let a = m.mint("a", DEFAULT_PREAUTH_TTL, false);
        let b = m.mint("b", DEFAULT_PREAUTH_TTL, false);
        let c = m.mint("c", DEFAULT_PREAUTH_TTL, false);
        // a was the oldest; FIFO eviction kicks it out.
        assert!(m.lookup(&a.key).is_none(), "oldest mint should be evicted");
        assert!(m.lookup(&b.key).is_some());
        assert!(m.lookup(&c.key).is_some());
    }

    /// An evicted single-use key MUST NOT become re-redeemable. The
    /// caller sees `RedeemError::Unknown` — exactly the error a
    /// never-minted token would produce.
    #[test]
    fn evicted_key_redeem_returns_unknown() {
        let m = PreauthMinter::with_capacity(1, 100);
        let evicted = m.mint("alice", DEFAULT_PREAUTH_TTL, false);
        // This mint pushes `evicted` out of the bounded map.
        let _kept = m.mint("bob", DEFAULT_PREAUTH_TTL, false);
        assert_eq!(
            m.redeem(&evicted.key),
            Err(RedeemError::Unknown),
            "evicted single-use key must NOT be redeemable"
        );
    }

    /// Idle-TTL sweep on `mints` drops abandoned (never-redeemed)
    /// entries past the TTL window.
    #[test]
    fn mints_idle_ttl_sweeps() {
        // Aggressive TTL so the test completes in milliseconds.
        let m = PreauthMinter::with_ttl(Duration::from_millis(30), Duration::from_secs(60));
        let k = m.mint("u", DEFAULT_PREAUTH_TTL, false);
        std::thread::sleep(Duration::from_millis(60));
        let (mints_evicted, _) = m.sweep_expired();
        assert_eq!(mints_evicted, 1, "idle mint should sweep");
        assert!(m.lookup(&k.key).is_none(), "swept key is gone");
    }

    /// A key TTL-evicted from `mints` mirrors the capacity-evicted
    /// behaviour: re-presenting it returns `Unknown`, not `Expired`
    /// — there's no surviving entry to consult `expires_at` on.
    #[test]
    fn ttl_evicted_key_redeem_returns_unknown() {
        let m = PreauthMinter::with_ttl(Duration::from_millis(30), Duration::from_secs(60));
        let k = m.mint("u", DEFAULT_PREAUTH_TTL, false);
        std::thread::sleep(Duration::from_millis(60));
        m.sweep_expired();
        assert_eq!(m.redeem(&k.key), Err(RedeemError::Unknown));
    }

    /// Capacity cap on `redemptions` evicts older audit records when
    /// a fresh redeem would overflow. Crucially, eviction of an
    /// older audit record DOES NOT make its (single-use) key
    /// redeemable again — `mints` is the authoritative source.
    #[test]
    fn redemptions_capacity_evicts_oldest() {
        let m = PreauthMinter::with_capacity(100, 2);
        let a = m.mint("a", DEFAULT_PREAUTH_TTL, false);
        let b = m.mint("b", DEFAULT_PREAUTH_TTL, false);
        let c = m.mint("c", DEFAULT_PREAUTH_TTL, false);
        m.redeem(&a.key).unwrap();
        m.redeem(&b.key).unwrap();
        m.redeem(&c.key).unwrap();
        let audit: std::collections::HashMap<String, RedemptionRecord> =
            m.redemption_audit().into_iter().collect();
        assert_eq!(audit.len(), 2, "redemptions cap holds at 2");
        assert!(
            !audit.contains_key(&a.key),
            "oldest redemption audit FIFO-evicted"
        );
        assert!(audit.contains_key(&b.key));
        assert!(audit.contains_key(&c.key));

        // Critically: even though `a`'s audit record was evicted,
        // re-presenting the token still returns Unknown — `mints`
        // removed the entry on first redeem (single-use).
        assert_eq!(m.redeem(&a.key), Err(RedeemError::Unknown));
    }

    /// A reusable key keeps producing successful redeems across
    /// redemption-audit eviction. The audit log is best-effort under
    /// capacity pressure; the *redeemability* of the key is gated by
    /// `mints` (which retains the reusable key) and is independent
    /// of any single audit record.
    #[test]
    fn reusable_key_redeems_across_audit_eviction() {
        // Tiny redemptions cap so the audit log overflows quickly.
        let m = PreauthMinter::with_capacity(100, 1);
        let k = m.mint("ops", DEFAULT_PREAUTH_TTL, true);
        // Five redeems against a single reusable key — every one
        // succeeds, even though the audit map only retains the
        // most-recent record.
        for _ in 0..5 {
            assert_eq!(m.redeem(&k.key).unwrap(), "ops");
        }
        let audit = m.redemption_audit();
        assert!(
            audit.len() <= 1,
            "redemptions cap of 1 holds even across 5 redeems"
        );
        // And the key itself is still live in `mints`.
        assert!(m.lookup(&k.key).is_some(), "reusable key still live");
    }

    /// Idle-TTL sweep on `redemptions` drops audit records past the
    /// TTL window. Verifies the same fix on the second bounded map.
    #[test]
    fn redemptions_idle_ttl_sweeps() {
        let m = PreauthMinter::with_ttl(Duration::from_secs(60), Duration::from_millis(30));
        let k = m.mint("u", DEFAULT_PREAUTH_TTL, true);
        m.redeem(&k.key).unwrap();
        assert_eq!(m.redemption_audit().len(), 1);
        std::thread::sleep(Duration::from_millis(60));
        let (_, red_evicted) = m.sweep_expired();
        assert_eq!(red_evicted, 1, "idle audit record should sweep");
        assert_eq!(m.redemption_audit().len(), 0);
    }

    /// The redemption audit record carries the bound user even after
    /// the underlying `mints` entry has been removed (single-use).
    /// This is what makes the audit trail useful after the fact.
    #[test]
    fn redemption_record_preserves_user() {
        let m = PreauthMinter::new();
        let k = m.mint("alice", DEFAULT_PREAUTH_TTL, false);
        m.redeem(&k.key).unwrap();
        assert!(m.lookup(&k.key).is_none(), "single-use mint removed");
        let audit: std::collections::HashMap<String, RedemptionRecord> =
            m.redemption_audit().into_iter().collect();
        let rec = audit.get(&k.key).expect("audit record present");
        assert_eq!(rec.user, "alice");
    }
}
