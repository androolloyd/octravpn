//! Observability hook for the headscale bridge.
//!
//! Exposes the [`MetricsSink`] trait that upper crates (notably
//! `octravpn-node/src/control.rs`'s `NodeMetrics`) implement to receive
//! `"preauth_mint"` / `"preauth_redeem"` events from
//! [`super::preauth::PreauthMinter`]. The trait is intentionally tiny so
//! the mesh layer doesn't take a hard dependency on a metrics library —
//! the node side wires it through `AtomicU64::fetch_add` counters.

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parking_lot::Mutex;

    use super::*;
    use crate::headscale_bridge::preauth::{PreauthMinter, DEFAULT_PREAUTH_TTL};

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

    /// `with_capacity` and `with_metrics_sink` compose cleanly — the
    /// builder chain works in either order without losing state. This
    /// pins the production wiring pattern in `hub.rs`.
    #[test]
    fn with_capacity_chains_with_metrics_sink() {
        let sink = Arc::new(RecordingSink::default());
        let m = PreauthMinter::with_capacity(8, 8).with_metrics_sink(sink.clone());
        let k = m.mint("u", DEFAULT_PREAUTH_TTL, false);
        m.redeem(&k.key).unwrap();
        let events = sink.events.lock().clone();
        assert_eq!(
            events,
            vec!["preauth_mint".to_string(), "preauth_redeem".to_string()]
        );
    }
}
