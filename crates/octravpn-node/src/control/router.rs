//! Route table — single place new HTTP endpoints register. Append
//! `.route(…)` to `limited_routes` (rate-limited, common case) or
//! `unlimited` (long-lived / SSE). SSE lives outside the per-IP token
//! bucket the [`crate::rate_limit`] middleware enforces, otherwise one
//! connect starves every other endpoint.

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use octravpn_mesh::tailscale_wire_embedded_control_router;

use super::handlers;
use super::state::ControlState;

/// Build the fully-configured axum router for this `ControlState`.
///
/// The route table is the single source of truth for the
/// control-plane HTTP surface; every byte-on-wire test in
/// [`super::handlers::*::tests`] exercises one of these routes.
//
// `state` is consumed by `Router::with_state` (which takes its
// argument by value), so taking the `Arc` by value matches the
// downstream API. `&Arc<ControlState>` would require an extra
// `.clone()` per route.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn router_axum(state: Arc<ControlState>) -> Router {
    use axum::middleware;

    // Rate-limited surface: the regular request/response endpoints.
    // `/health` and `/metrics` are mounted inside this router but
    // are bypassed at the middleware level by
    // `crate::rate_limit::classify` (so they reply under load even
    // when an attacker has drained a per-class bucket). When
    // `[control.rate_limit].enabled = false` the layer is omitted
    // entirely — no per-request overhead.
    let limited_routes = Router::new()
        .route("/session", post(handlers::session::announce))
        .route("/session/:id", get(handlers::receipt::get_state))
        .route("/health", get(handlers::health::health))
        .route("/metrics", get(handlers::metrics::metrics))
        // Preauth-minting surface for the Tailscale-interop bridge.
        // Token-gated: returns 404 when `admin_token` is unset so
        // an external scanner can't confirm the endpoint exists.
        // See `docs/tailscale-interop-blocker.md` for what this
        // does *not* (yet) deliver — chiefly the real Tailscale
        // wire protocol behind `/key` + `/machine/{node_key}/…`.
        .route("/admin/preauth", post(handlers::preauth::mint_preauth))
        // Wallet-native device enrollment. Both routes 404 when this
        // node isn't hosting a tailnet (`ControlState::enroll` is
        // `None`), so the surface stays invisible unless configured.
        .route("/enroll/challenge", get(handlers::enroll::challenge))
        .route("/enroll", post(handlers::enroll::enroll));
    let limited = if state.rate_limit_cfg.enabled {
        let rate_limiter = crate::rate_limit::RateLimiter::from_cfg(&state.rate_limit_cfg);
        limited_routes
            .layer(middleware::from_fn_with_state(
                rate_limiter,
                crate::rate_limit::rate_limit_layer,
            ))
            .with_state(state.clone())
    } else {
        limited_routes.with_state(state.clone())
    };

    // SSE surface, mounted on a separate sub-router merged in
    // *outside* the rate-limit layer. Rationale: SSE is a single
    // long-lived request; counting it against a per-IP token
    // budget would either (a) starve other endpoints after one
    // connect, or (b) require per-route exemption logic the token
    // bucket doesn't model cleanly. A separate `Router::merge`
    // gives us the exemption with one line and zero conditional
    // middleware. The endpoint is read-only (subscribers cannot
    // publish), and the bus itself caps memory via its broadcast
    // capacity, so the abuse surface is bounded.
    let unlimited = Router::new()
        .route("/events", get(handlers::events::events_sse))
        .with_state(state.clone());

    let mut merged = limited.merge(unlimited);

    // Tailscale-wire surface (PRs 1-4). Mounted unconditionally
    // when `wire_state` is populated; absent otherwise so the
    // routes don't reply to unrelated probes. The Hub mounts only
    // stock-client wire paths here; `/health`, `/metrics`, and
    // operator diagnostics remain owned by Octra's control plane.
    if let Some(ws) = state.wire_state.clone() {
        merged = merged.merge(tailscale_wire_embedded_control_router(ws));
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use octravpn_core::{bounded::BoundedMap, sig::KeyPair};
    use octravpn_mesh::{ip_alloc::TailnetIpAllocator, PreauthMinter, ServerNoiseKey};
    use std::{sync::Arc, time::Duration};
    use tower::ServiceExt;

    fn control_state_with_wire() -> Arc<ControlState> {
        let dir = tempfile::tempdir().unwrap();
        let server_noise_key = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let wire_state = octravpn_mesh::WireStateBuilder::new(
            server_noise_key,
            Arc::new(PreauthMinter::new()),
            Arc::new(TailnetIpAllocator::new("router-test")),
            Arc::new(octravpn_mesh::MachineRegistry::new()),
            Arc::new(octravpn_mesh::policy::PolicyStore::new()),
            octravpn_mesh::tailscale_wire::DerpMapStore::shared(
                octravpn_mesh::tailscale_wire::DerpMap::default(),
            ),
        )
        .build();

        let state = ControlState::new(
            Arc::new(KeyPair::generate()),
            Arc::new(crate::onion::OnionRouter::new()),
            Arc::new(BoundedMap::new(10, Duration::from_secs(60))),
        )
        .with_rate_limit_cfg(crate::rate_limit::RateLimitCfg {
            enabled: false,
            ..Default::default()
        })
        .with_wire_state(Some(wire_state));

        Arc::new(state)
    }

    #[tokio::test]
    async fn wire_router_mounts_public_paths_without_shadowing_octra_health() {
        let app = control_state_with_wire().router_axum();

        let key_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/key?v=113")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(key_resp.status(), StatusCode::OK);

        let health_resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health_resp.status(), StatusCode::OK);
        let body = to_bytes(health_resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "warming up");
        assert!(json.get("uptime_s").is_some());
        assert!(json.get("last_attestation_unix").is_some());
    }
}
