//! `POST /admin/preauth` — mint a Tailscale-style preauth key.
//! Bearer-gated by `ControlState::bearer_admin` (Hidden policy: 404 +
//! [`octravpn_core::bearer::NGINX_404_BODY`] for every failure mode).
//! CLI surface `octravpn-node mesh mint-preauth` shares the same
//! [`octravpn_mesh::PreauthMinter`] held on `ControlState` so a
//! `docker exec` can mint without provisioning the bearer.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, Json};
use octravpn_mesh::DEFAULT_PREAUTH_TTL;
use serde::{Deserialize, Serialize};

use crate::control::state::ControlState;

/// Request body for `POST /admin/preauth`. The `user` field mirrors
/// Tailscale's notion of a "user" — a label that gets bound into the
/// minted credential, used later by the (not-yet-implemented)
/// register handler to attribute a joining device.
#[derive(Debug, Deserialize)]
pub(crate) struct MintPreauthRequest {
    /// User label to bind the key to. Defaults to `"default"` so the
    /// interop test can `curl -d '{}'` and still get a usable key.
    #[serde(default = "default_user")]
    user: String,
    /// Whether the key may be redeemed by more than one device.
    /// Defaults to `false` (single-use) — the safer Tailscale-equivalent
    /// behaviour.
    #[serde(default)]
    reusable: bool,
}

fn default_user() -> String {
    "default".to_string()
}

#[derive(Debug, Serialize)]
pub(crate) struct MintPreauthResponse {
    /// The preauth token. Pass this to `tailscale up --authkey ...`.
    key: String,
    /// User the key is bound to.
    user: String,
    /// Unix-seconds expiry.
    expires_at: u64,
    /// Whether the key is reusable.
    reusable: bool,
}

/// Mint a preauth key.
///
/// Auth: bearer token from `[control].admin_token` (or
/// `OCTRAVPN_ADMIN_TOKEN` if the field is unset and the env-var is
/// present — handled at Hub-init time, not here). Hidden behind 404
/// when no token is configured.
pub(crate) async fn mint_preauth(
    State(s): State<Arc<ControlState>>,
    headers: axum::http::HeaderMap,
    body: Option<Json<MintPreauthRequest>>,
) -> impl IntoResponse {
    // Bearer gate (Hidden policy): every failure returns 404 +
    // `NGINX_404_BODY`. The check returns the rejection response
    // ready-to-go, so we propagate it as-is.
    if let Err(resp) = s.bearer_admin().check(&headers) {
        return resp;
    }
    // Tolerate an empty body — curl-without-data is a common
    // operator habit; we just mint a key for the default user.
    let req = match body {
        Some(Json(b)) => b,
        None => MintPreauthRequest {
            user: default_user(),
            reusable: false,
        },
    };
    let pk = s
        .preauth_minter
        .mint(req.user, DEFAULT_PREAUTH_TTL, req.reusable);
    // Bump the mint counter here rather than inside PreauthMinter so
    // a node-local CLI mint (which also goes through `mint()` directly)
    // doesn't double-count when the bridge eventually wires its own
    // MetricsSink — the MetricsSink path is currently disabled at the
    // PreauthMinter constructor for control-plane-minted keys.
    s.metrics
        .preauth_mints_total
        .fetch_add(1, Ordering::Relaxed);
    Json(MintPreauthResponse {
        key: pk.key,
        user: pk.user,
        expires_at: pk.expires_at,
        reusable: pk.reusable,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::state::ControlState;
    use crate::onion::OnionRouter;
    use axum::http::{HeaderValue, StatusCode};
    use octravpn_core::{bounded::BoundedMap, sig::KeyPair};

    /// `/admin/preauth` is 404 when no `admin_token` is configured —
    /// the endpoint must be undetectable from outside in default
    /// mode, mirroring the `/events` design.
    #[tokio::test]
    async fn admin_preauth_hidden_without_token() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer anything"),
        );
        let resp = mint_preauth(State(state), headers, None)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// With the token configured, a correct bearer mints a key; a
    /// missing or wrong bearer still returns 404 (not 401) so an
    /// external scanner can't tell the endpoint exists.
    #[tokio::test]
    async fn admin_preauth_token_gates_minting() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(
            ControlState::new(node_kp, router, allowlist).with_admin_token(Some("secret".into())),
        );

        // Missing → 404.
        {
            let resp = mint_preauth(State(state.clone()), axum::http::HeaderMap::new(), None)
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
        // Wrong → 404.
        {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer wrong"),
            );
            let resp = mint_preauth(State(state.clone()), headers, None)
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
        // Right → 200 + minted key.
        {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer secret"),
            );
            let resp = mint_preauth(
                State(state.clone()),
                headers,
                Some(Json(MintPreauthRequest {
                    user: "alice".into(),
                    reusable: false,
                })),
            )
            .await
            .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(v["key"].as_str().unwrap().starts_with("octrapreauth-"));
            assert_eq!(v["user"].as_str().unwrap(), "alice");
            assert!(!v["reusable"].as_bool().unwrap());
        }
    }

    /// `mint_preauth` bumps `preauth_mints_total` exactly once on a
    /// successful mint. The token-gate is held at the handler so we
    /// only test the happy path here; the 404 paths are exercised by
    /// `admin_preauth_hidden_without_token` / `…_token_gates_minting`
    /// above and confirmed not to bump the counter.
    #[tokio::test]
    async fn mint_preauth_bumps_counter() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(
            ControlState::new(node_kp, router, allowlist).with_admin_token(Some("secret".into())),
        );
        let before = state.metrics.preauth_mints_total.load(Ordering::Relaxed);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        let resp = mint_preauth(
            State(state.clone()),
            headers,
            Some(Json(MintPreauthRequest {
                user: "alice".into(),
                reusable: false,
            })),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            state.metrics.preauth_mints_total.load(Ordering::Relaxed),
            before + 1
        );
    }

    /// A 404 mint path (no token configured) must NOT bump the
    /// counter — the increment lives after the auth check.
    #[tokio::test]
    async fn mint_preauth_404_does_not_bump_counter() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let before = state.metrics.preauth_mints_total.load(Ordering::Relaxed);
        let resp = mint_preauth(State(state.clone()), axum::http::HeaderMap::new(), None)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            state.metrics.preauth_mints_total.load(Ordering::Relaxed),
            before
        );
    }
}
