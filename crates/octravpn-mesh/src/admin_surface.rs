//! Unified admin-router builder shared by the full Hub daemon AND the
//! Hub-free `mesh serve` shape.
//!
//! The wire-protocol admin routes (`/api/v1/machines`, `/api/v1/policy`,
//! `/api/v1/preauthkeys`, …) are implemented in
//! [`headscale_api::admin::router`]. Both control-plane shells in
//! octravpn-node need the same surface, but with two extra concerns
//! layered on top of the upstream router:
//!
//!   1. **Byte-stable 404 (Audit-3 H-1 invariant).** External probes
//!      MUST not be able to tell whether the admin token is configured.
//!      The headscale admin auth returns `401` for API requests with
//!      no/bad bearer; we wrap the whole router in an
//!      [`octravpn_core::bearer::BearerCheck::hidden`] middleware so
//!      every reject reason emits `(404, NGINX_404_BODY)` — same shape
//!      `/events` + `/admin/preauth` already use.
//!
//!   2. **Single source of truth.** The full Hub builds [`AdminState`]
//!      from the `[control]` config block; `mesh serve` builds it from
//!      its own CLI args + env. Both call [`build_admin_router`] with
//!      that state, so the on-wire shape never drifts between the two
//!      shells.
//!
//! ## What is NOT in the unified router
//!
//! Routes whose implementation requires the *full* Hub assembly
//! (chain RPC, PVAC sidecar, wallet keypair) stay on the
//! `ControlState` side of `octravpn-node`. Specifically:
//!
//!   - `/session`, `/session/:id` — need the wallet keypair to sign
//!     receipts and the chain RPC to verify the open-tx.
//!   - `/events` SSE — needs the in-process `EventBus`.
//!   - `/metrics` — exposes Hub-internal NodeMetrics counters.
//!   - The Tailscale-wire surface (`/key`, `/ts2021`, `/machine/...`)
//!     is mounted by `tailscale_wire_router` independently of this
//!     admin surface; both shells already mount it.
//!
//! Those gaps are intentional and documented in
//! `docs/operators/mesh-admin.md`.

use std::sync::Arc;

use axum::Router;
use octravpn_core::bearer::{bearer_middleware, BearerCheck};

/// Re-export so consumers don't need to depend on `headscale_api`
/// transitively just to construct the admin state.
pub use headscale_api::admin::{AdminState, AdminStateBuilder};

/// Build the unified admin router.
///
/// `admin_token` MUST match the token embedded in `state.auth` — the
/// outer [`BearerCheck::hidden`] middleware uses it to emit a
/// byte-stable 404 for every reject reason, and the inner upstream
/// router re-checks the same token before letting the handler run.
/// Both checks pass for the same `Bearer <token>` request, so a
/// correctly-credentialled call lands at the upstream handler exactly
/// once.
///
/// When `admin_token` is `None` the function returns an empty router —
/// no routes are mounted, so a request to `/api/v1/machines` (or any
/// other admin URI) hits the *outer* axum router's 404 fallback. This
/// matches the `/admin/preauth` "endpoint hidden when token unset"
/// behaviour that `BearerCheck::hidden` already documents.
pub fn build_admin_router(state: AdminState, admin_token: Option<Arc<str>>) -> Router {
    let Some(tok) = admin_token else {
        // No token ⇒ no admin surface. Returning an empty router keeps
        // the caller code site-symmetric (always `.merge(build_admin_router(...))`)
        // and lets the outer axum router emit the same 404-shaped
        // response a non-existent route would emit anyway.
        return Router::new();
    };
    let check = BearerCheck::hidden(Some(tok));
    let inner = headscale_api::admin::router(state);
    // Layer the bearer middleware on the merged router. Every request
    // to any admin path goes through `bearer_middleware` first; on
    // reject the upstream handlers never run.
    Router::new()
        .merge(inner)
        .layer(axum::middleware::from_fn_with_state(
            check,
            bearer_middleware,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    fn dummy_state(token: &str) -> AdminState {
        AdminState::builder()
            .bearer_token(token)
            .users(headscale_api::admin::UserRegistry::new())
            .machines(Arc::new(headscale_api::admin::WireMachineAdmin::new(
                Arc::new(crate::MachineRegistry::new()),
            )))
            .preauth(Arc::new(headscale_api::admin::InMemoryPreauthAdmin::new()))
            .derp_regions(0)
            .policy(crate::policy::PolicyStore::new())
            .build()
    }

    /// No admin token configured ⇒ the function returns an empty
    /// `Router`, so a request to `/api/v1/machines` falls through to
    /// the outer router's 404 fallback (no panic, no route match).
    #[tokio::test]
    async fn no_token_returns_empty_router() {
        let r = build_admin_router(dummy_state(""), None);
        // Wrap in an outer router so the unmatched path resolves to a
        // 404 the way an axum app would in production.
        let app = Router::new().merge(r);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/machines")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Token configured, no bearer header ⇒ byte-stable 404 from the
    /// outer `BearerCheck::hidden` middleware (NOT 401 from the inner
    /// admin auth — that would leak token presence).
    #[tokio::test]
    async fn missing_bearer_returns_byte_stable_404() {
        let app = build_admin_router(dummy_state("tok-1"), Some(Arc::from("tok-1")));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/machines")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(resp.into_body(), 64).await.unwrap();
        assert_eq!(body.as_ref(), octravpn_core::bearer::NGINX_404_BODY);
    }

    /// Wrong bearer ⇒ same byte-stable 404. The outer middleware
    /// short-circuits before the inner admin auth ever runs.
    #[tokio::test]
    async fn wrong_bearer_returns_byte_stable_404() {
        let app = build_admin_router(dummy_state("tok-1"), Some(Arc::from("tok-1")));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/machines")
                    .header("authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(resp.into_body(), 64).await.unwrap();
        assert_eq!(body.as_ref(), octravpn_core::bearer::NGINX_404_BODY);
    }

    /// Correct bearer ⇒ both the outer + inner auth gates pass, and
    /// the request reaches the upstream handler (200 OK on the empty
    /// machine registry — handler returns an empty JSON array).
    #[tokio::test]
    async fn correct_bearer_reaches_upstream_handler() {
        let app = build_admin_router(dummy_state("tok-1"), Some(Arc::from("tok-1")));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/machines")
                    .header("authorization", "Bearer tok-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
