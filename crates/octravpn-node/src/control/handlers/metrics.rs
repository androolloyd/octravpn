//! `GET /metrics` — Prometheus text-format exposition. Bearer-gated by
//! `ControlState::bearer_metrics` (Strict policy: 503 + descriptive
//! body when unconfigured, 401 + empty body for wrong bearer). Body is
//! one hand-rolled `format!` over [`super::super::metrics::NodeMetrics`];
//! `tests::metrics_handler_emits_every_new_field` pins that no field
//! is silently dropped.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::{extract::State, response::IntoResponse};

use crate::control::state::ControlState;

/// Prometheus text format. Bearer-gated by default — operators must
/// set `[control].metrics_token` for the endpoint to serve scrapes.
/// Returns 503 (not 404) when unconfigured so a misconfigured Prometheus
/// surfaces a clear "endpoint disabled" error rather than silently
/// 404'ing.
pub(crate) async fn metrics(
    State(s): State<Arc<ControlState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if let Err(resp) = s.bearer_metrics().check(&headers) {
        return resp;
    }
    let m = &s.metrics;
    // Snapshot wire-state-derived gauges (member_count + IP allocator).
    // Reads only — no mutation of the wire layer. When `wire_state` is
    // unset (the common case for a node without the Tailscale-interop
    // bridge), both gauges stay at 0, which is the correct "no tailnet
    // attached" value.
    if let Some(ws) = s.wire_state.as_ref() {
        let n = ws.machines.len() as u64;
        m.tailnet_member_count.store(n, Ordering::Relaxed);
        m.ip_allocator_used.store(n, Ordering::Relaxed);
        // Allocator capacity is the static host count of the CGNAT
        // /10 slice the allocator hands out from. The `IpAllocator`
        // trait does not expose capacity, so we read the concrete
        // constant from `TailnetIpAllocator` directly.
        m.ip_allocator_capacity.store(
            u64::from(octravpn_mesh::TailnetIpAllocator::host_capacity()),
            Ordering::Relaxed,
        );
    }

    let body = format!(
        "# HELP octravpn_announces_total Sessions announced via control plane.\n\
         # TYPE octravpn_announces_total counter\n\
         octravpn_announces_total {announces}\n\
         # HELP octravpn_state_lookups_total /session/:id GETs.\n\
         # TYPE octravpn_state_lookups_total counter\n\
         octravpn_state_lookups_total {state_lookups}\n\
         # HELP octravpn_receipts_signed_total Node-signed receipt proposals returned.\n\
         # TYPE octravpn_receipts_signed_total counter\n\
         octravpn_receipts_signed_total {receipts_signed}\n\
         # HELP octravpn_bytes_served_total Cumulative bytes traversed (in+out).\n\
         # TYPE octravpn_bytes_served_total counter\n\
         octravpn_bytes_served_total {bytes_served}\n\
         # HELP octravpn_active_sessions Current sessions tracked by control plane.\n\
         # TYPE octravpn_active_sessions gauge\n\
         octravpn_active_sessions {active_sessions}\n\
         # HELP octravpn_last_attestation_unix Unix time of last successful attestation.\n\
         # TYPE octravpn_last_attestation_unix gauge\n\
         octravpn_last_attestation_unix {last_attest}\n\
         # HELP octravpn_uptime_seconds Process uptime.\n\
         # TYPE octravpn_uptime_seconds counter\n\
         octravpn_uptime_seconds {uptime}\n\
         # HELP octravpn_slash_double_sign_total slash_double_sign calls dispatched.\n\
         # TYPE octravpn_slash_double_sign_total counter\n\
         octravpn_slash_double_sign_total {slash}\n\
         # HELP octravpn_preauth_mints_total Tailscale-bridge preauth keys minted.\n\
         # TYPE octravpn_preauth_mints_total counter\n\
         octravpn_preauth_mints_total {pa_mints}\n\
         # HELP octravpn_preauth_redemptions_total Tailscale-bridge preauth redemptions.\n\
         # TYPE octravpn_preauth_redemptions_total counter\n\
         octravpn_preauth_redemptions_total {pa_redeems}\n\
         # HELP octravpn_rpc_requests_total Chain RPC requests attempted.\n\
         # TYPE octravpn_rpc_requests_total counter\n\
         octravpn_rpc_requests_total {rpc_req}\n\
         # HELP octravpn_rpc_errors_total Chain RPC requests that returned an error.\n\
         # TYPE octravpn_rpc_errors_total counter\n\
         octravpn_rpc_errors_total {rpc_err}\n\
         # HELP octravpn_wg_handshake_success_total WireGuard handshake completions.\n\
         # TYPE octravpn_wg_handshake_success_total counter\n\
         octravpn_wg_handshake_success_total {wg_ok}\n\
         # HELP octravpn_wg_handshake_fail_total WireGuard decapsulation errors.\n\
         # TYPE octravpn_wg_handshake_fail_total counter\n\
         octravpn_wg_handshake_fail_total {wg_fail}\n\
         # HELP octravpn_session_opens_total Sessions accepted by POST /session.\n\
         # TYPE octravpn_session_opens_total counter\n\
         octravpn_session_opens_total {sess_open}\n\
         # HELP octravpn_session_closes_total Sessions evicted by the idle sweeper.\n\
         # TYPE octravpn_session_closes_total counter\n\
         octravpn_session_closes_total {sess_close}\n\
         # HELP octravpn_session_no_shows_total Sessions ended without a client countersign.\n\
         # TYPE octravpn_session_no_shows_total counter\n\
         octravpn_session_no_shows_total {sess_no_show}\n\
         # HELP octravpn_tailnet_member_count Machines registered in the Tailscale-wire bridge.\n\
         # TYPE octravpn_tailnet_member_count gauge\n\
         octravpn_tailnet_member_count {tn_members}\n\
         # HELP octravpn_ip_allocator_used Number of CGNAT IPs currently allocated.\n\
         # TYPE octravpn_ip_allocator_used gauge\n\
         octravpn_ip_allocator_used {ip_used}\n\
         # HELP octravpn_ip_allocator_capacity Static host-range capacity of the CGNAT allocator.\n\
         # TYPE octravpn_ip_allocator_capacity gauge\n\
         octravpn_ip_allocator_capacity {ip_cap}\n\
         # HELP octravpn_audit_inline_fallback_total Audit writes that fell back to inline sync-fsync because the batched flusher queue was full (disk stall signal).\n\
         # TYPE octravpn_audit_inline_fallback_total counter\n\
         octravpn_audit_inline_fallback_total {audit_inline_fb}\n",
        announces = m.announces_total.load(Ordering::Relaxed),
        state_lookups = m.state_lookups_total.load(Ordering::Relaxed),
        receipts_signed = m.receipts_signed_total.load(Ordering::Relaxed),
        bytes_served = s.router.total_bytes(),
        active_sessions = s.sessions.len(),
        last_attest = m.last_attestation_unix.load(Ordering::Relaxed),
        uptime = octravpn_core::util::now_unix_secs()
            .saturating_sub(m.started_at_unix.load(Ordering::Relaxed)),
        slash = m.slash_double_sign_total.load(Ordering::Relaxed),
        pa_mints = m.preauth_mints_total.load(Ordering::Relaxed),
        pa_redeems = m.preauth_redemptions_total.load(Ordering::Relaxed),
        rpc_req = m.rpc_requests_total.load(Ordering::Relaxed),
        rpc_err = m.rpc_errors_total.load(Ordering::Relaxed),
        wg_ok = m.wg_handshake_success_total.load(Ordering::Relaxed),
        wg_fail = m.wg_handshake_fail_total.load(Ordering::Relaxed),
        sess_open = m.session_opens_total.load(Ordering::Relaxed),
        sess_close = m.session_closes_total.load(Ordering::Relaxed),
        sess_no_show = m.session_no_shows_total.load(Ordering::Relaxed),
        tn_members = m.tailnet_member_count.load(Ordering::Relaxed),
        ip_used = m.ip_allocator_used.load(Ordering::Relaxed),
        ip_cap = m.ip_allocator_capacity.load(Ordering::Relaxed),
        // Audit-flusher backpressure counter. Read directly off the
        // `AuditLog` handle (its `Arc<AuditCounters>` is lock-free,
        // so a disk-stalled flusher cannot block this scrape). When
        // `[audit]` is disabled the gauge is zero, which is the
        // correct "no fallback possible" value.
        audit_inline_fb = s
            .audit
            .as_ref()
            .map_or(0, crate::audit::AuditLog::inline_fallback_total),
    );
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::state::ControlState;
    use crate::onion::OnionRouter;
    use axum::http::{HeaderValue, StatusCode};
    use octravpn_core::{bounded::BoundedMap, sig::KeyPair};

    /// `/metrics` returns 503 when `[control].metrics_token` is unset
    /// (the default). Operators must configure a token in production.
    #[tokio::test]
    async fn metrics_default_returns_503() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let headers = axum::http::HeaderMap::new();
        let resp = metrics(State(state), headers).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Token configured + wrong bearer → 401.
    #[tokio::test]
    async fn metrics_rejects_wrong_token() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(
            ControlState::new(node_kp, router, allowlist)
                .with_metrics_token(Some("expected".to_string())),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong"),
        );
        let resp = metrics(State(state), headers).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Token configured + right bearer → 200 with Prometheus exposition.
    #[tokio::test]
    async fn metrics_accepts_correct_token() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(
            ControlState::new(node_kp, router, allowlist)
                .with_metrics_token(Some("expected".to_string())),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer expected"),
        );
        let resp = metrics(State(state), headers).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Every new metric name shows up in the Prometheus exposition
    /// output. The serializer is hand-rolled (one big `format!`); the
    /// test pins that no field was lost in a future refactor.
    #[tokio::test]
    async fn metrics_handler_emits_every_new_field() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(
            ControlState::new(node_kp, router, allowlist)
                .with_metrics_token(Some("test-token".to_string())),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-token"),
        );
        let resp = metrics(State(state), headers).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        for needle in [
            "octravpn_slash_double_sign_total ",
            "octravpn_preauth_mints_total ",
            "octravpn_preauth_redemptions_total ",
            "octravpn_rpc_requests_total ",
            "octravpn_rpc_errors_total ",
            "octravpn_wg_handshake_success_total ",
            "octravpn_wg_handshake_fail_total ",
            "octravpn_session_opens_total ",
            "octravpn_session_closes_total ",
            "octravpn_session_no_shows_total ",
            "octravpn_tailnet_member_count ",
            "octravpn_ip_allocator_used ",
            "octravpn_ip_allocator_capacity ",
            "octravpn_audit_inline_fallback_total ",
        ] {
            assert!(
                text.contains(needle),
                "/metrics body missing {needle}; body=\n{text}"
            );
        }
    }
}
