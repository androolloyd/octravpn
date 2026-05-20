//! `NodeMetrics` — Prometheus-exported counters bumped by every handler.
//! All `AtomicU64` so the data plane never blocks on a mutex. Convention:
//! `_total`-suffixed fields are monotonic counters (`fetch_add`);
//! unsuffixed fields are gauges (`store`). The wire-byte serializer
//! in [`super::handlers::metrics`] concatenates `octravpn_<field_name>`
//! and emits one `# HELP` / `# TYPE` / value triple per field.

use std::sync::atomic::{AtomicU64, Ordering};

/// Lightweight counters exposed via the /metrics endpoint. Kept as
/// AtomicU64 to avoid lock contention on the data plane.
///
/// Counters (suffix `_total`) only ever increase with `fetch_add`.
/// Gauges are unsuffixed and use `store`. The companion dashboards in
/// `deploy/observability/grafana/*.json` plot these by name; keep the
/// field name and the Prometheus name aligned (the serializer
/// concatenates `octravpn_<field_name>`).
#[derive(Default)]
pub(crate) struct NodeMetrics {
    pub announces_total: AtomicU64,
    pub state_lookups_total: AtomicU64,
    pub receipts_signed_total: AtomicU64,
    pub started_at_unix: AtomicU64,
    /// Unix timestamp of the most recent successful on-chain
    /// attestation refresh. Set by the hub's attestation loop.
    pub last_attestation_unix: AtomicU64,
    // ------------------------------------------------------------
    // Slashing surface. The on-chain `slash_double_sign` call is
    // built by `chain_v3::build_slash_double_sign_call`; the daemon
    // does not yet *submit* that call on its own (no equivocation
    // detector wired up), so the counter is bumped by
    // `record_slash_double_sign` whenever an operator-side tool
    // dispatches the slash. Once the equivocation detector lands,
    // its call site replaces the manual surface.
    pub slash_double_sign_total: AtomicU64,
    // ------------------------------------------------------------
    // Preauth surface (Tailscale interop bridge).
    pub preauth_mints_total: AtomicU64,
    pub preauth_redemptions_total: AtomicU64,
    // ------------------------------------------------------------
    // Chain RPC surface. Bumped by the hub's validator-health and
    // attestation loops on every RPC round-trip; `_errors_total` is
    // a subset of `_requests_total` (every error is also a request).
    pub rpc_requests_total: AtomicU64,
    pub rpc_errors_total: AtomicU64,
    // ------------------------------------------------------------
    // WireGuard handshake outcomes. Bumped from `tunnel::Server`
    // off the `Tunn::decapsulate` result variants. `success_total`
    // counts handshake-response writes (the typed signal boringtun
    // emits when the noise handshake completes); `fail_total`
    // counts `TunnResult::Err`.
    pub wg_handshake_success_total: AtomicU64,
    pub wg_handshake_fail_total: AtomicU64,
    // ------------------------------------------------------------
    // Session lifecycle. `opens_total` is bumped at each
    // `POST /session`; `closes_total` increments by N when the
    // sweeper evicts N idle sessions; `no_shows_total` is reserved
    // for the (not-yet-implemented) settlement-side cross-check
    // where a client never returns a countersigned receipt — see
    // dashboard panel `settled-vs-no-show ratio` for the TODO.
    pub session_opens_total: AtomicU64,
    pub session_closes_total: AtomicU64,
    pub session_no_shows_total: AtomicU64,
    // ------------------------------------------------------------
    // Tailnet gauges. Set by the `/metrics` handler on every scrape
    // (read-only snapshot from `WireState`), not by data-plane
    // fast paths. `ip_allocator_used` mirrors `tailnet_member_count`
    // (every registered machine consumes one allocated IP); the
    // allocator itself is stateless, so capacity is the static
    // `TailnetIpAllocator::host_capacity()` value.
    pub tailnet_member_count: AtomicU64,
    pub ip_allocator_used: AtomicU64,
    pub ip_allocator_capacity: AtomicU64,
}

impl NodeMetrics {
    /// Record that a `slash_double_sign` call was dispatched. Public
    /// at crate scope so an operator tool (e.g. an equivocation
    /// detector) can call it without going through the chain layer.
    #[allow(dead_code)]
    pub(crate) fn record_slash_double_sign(&self) {
        self.slash_double_sign_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a chain RPC request outcome. `ok=true` bumps only
    /// `rpc_requests_total`; `ok=false` bumps both. Symmetric so
    /// callers don't need conditional code.
    pub(crate) fn record_rpc(&self, ok: bool) {
        self.rpc_requests_total.fetch_add(1, Ordering::Relaxed);
        if !ok {
            self.rpc_errors_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a WireGuard handshake outcome. `success=true` bumps
    /// the success counter; `success=false` bumps the fail counter.
    pub(crate) fn record_wg_handshake(&self, success: bool) {
        if success {
            self.wg_handshake_success_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.wg_handshake_fail_total.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Bridge from `octravpn-mesh`'s `MetricsSink` trait to our concrete
/// `NodeMetrics`. Keeps the dependency direction one-way: mesh knows
/// nothing about node metrics, but node-side callers can pass an
/// `Arc<NodeMetrics>` wherever a mesh API expects a `MetricsSink`.
impl octravpn_mesh::headscale_bridge::MetricsSink for NodeMetrics {
    fn record_event(&self, name: &str) {
        match name {
            "preauth_mint" => {
                self.preauth_mints_total.fetch_add(1, Ordering::Relaxed);
            }
            "preauth_redeem" => {
                self.preauth_redemptions_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            // Unknown event names are dropped — additive design so
            // mesh-side code can publish new events without
            // requiring a node-side recompile.
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// The `MetricsSink` impl on `NodeMetrics` translates a
    /// `"preauth_redeem"` event to a counter bump. This is the path
    /// the headscale-api wire register handler exercises in
    /// production.
    #[test]
    fn metrics_sink_translates_preauth_events() {
        let m = Arc::new(NodeMetrics::default());
        let sink: Arc<dyn octravpn_mesh::MetricsSink> = m.clone();
        sink.record_event("preauth_mint");
        sink.record_event("preauth_redeem");
        sink.record_event("preauth_redeem");
        // Unknown event names must be ignored (additive design).
        sink.record_event("definitely_not_a_real_event");
        assert_eq!(m.preauth_mints_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.preauth_redemptions_total.load(Ordering::Relaxed), 2);
    }

    /// `record_rpc(true)` only bumps the request counter;
    /// `record_rpc(false)` bumps both. Pinning the symmetric API.
    #[test]
    fn record_rpc_counts_errors_as_subset() {
        let m = NodeMetrics::default();
        m.record_rpc(true);
        m.record_rpc(true);
        m.record_rpc(false);
        assert_eq!(m.rpc_requests_total.load(Ordering::Relaxed), 3);
        assert_eq!(m.rpc_errors_total.load(Ordering::Relaxed), 1);
    }

    /// `record_wg_handshake(true|false)` routes to the correct
    /// counter. Trivial but pins the dispatch.
    #[test]
    fn record_wg_handshake_dispatches() {
        let m = NodeMetrics::default();
        m.record_wg_handshake(true);
        m.record_wg_handshake(true);
        m.record_wg_handshake(false);
        assert_eq!(m.wg_handshake_success_total.load(Ordering::Relaxed), 2);
        assert_eq!(m.wg_handshake_fail_total.load(Ordering::Relaxed), 1);
    }

    /// `record_slash_double_sign` is a one-line incrementer; pin its
    /// behaviour so an accidental refactor (e.g. moving the bump
    /// behind a feature flag) is caught by CI.
    #[test]
    fn record_slash_double_sign_bumps_counter() {
        let m = NodeMetrics::default();
        m.record_slash_double_sign();
        m.record_slash_double_sign();
        assert_eq!(m.slash_double_sign_total.load(Ordering::Relaxed), 2);
    }
}
