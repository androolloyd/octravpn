//! Shared hidden admin surface. API handlers accept the configured bootstrap
//! bearer or a durable Headscale API key. HTML keeps the static bearer gate.
use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Router,
};
use octravpn_core::bearer::{BearerCheck, NGINX_404_BODY};

pub use headscale_api::admin::{AdminState, AdminStateBuilder};

/// No bootstrap token disables the entire admin surface, including stored keys.
/// API authorization stays in Headscale, so key revocation is checked on every
/// request. Failed authorization keeps the same empty 404 as an absent route.
pub fn build_admin_router(state: AdminState, admin_token: Option<Arc<str>>) -> Router {
    let hidden = Router::new()
        .route("/api/v1", axum::routing::any(hidden_route))
        .route("/api/v1/*path", axum::routing::any(hidden_route))
        .route("/admin", axum::routing::any(hidden_route))
        .route("/admin/*path", axum::routing::any(hidden_route));
    let Some(token) = admin_token else {
        return hidden.route("/admin/", axum::routing::any(hidden_route));
    };
    let gate = AdminGate {
        check: BearerCheck::hidden(Some(token)),
        keys: state.api_keys.clone(),
    };
    headscale_api::admin::router(state)
        .merge(hidden)
        .layer(axum::middleware::from_fn_with_state(gate, hidden_auth))
}

async fn hidden_route() -> Response {
    (StatusCode::NOT_FOUND, NGINX_404_BODY).into_response()
}

#[derive(Clone)]
struct AdminGate {
    check: BearerCheck,
    keys: Arc<dyn headscale_api::admin::ApiKeyAdmin>,
}

async fn hidden_auth(State(gate): State<AdminGate>, mut request: Request, next: Next) -> Response {
    if request.uri().path().starts_with("/api/v1/") {
        let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
        let bearer = values
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        if !bearer.is_some_and(|token| !token.is_empty() && token.len() <= 1024)
            || values.next().is_some()
        {
            return (StatusCode::NOT_FOUND, NGINX_404_BODY).into_response();
        }
        if gate.check.check(request.headers()).is_err()
            && !gate.keys.validate(bearer.expect("validated bearer")).await
        {
            return (StatusCode::NOT_FOUND, NGINX_404_BODY).into_response();
        }
        // API routes require a bearer even if an admin browser session exists.
        request.headers_mut().remove(header::COOKIE);
        let response = next.run(request).await;
        if response.status() == StatusCode::UNAUTHORIZED {
            return (StatusCode::NOT_FOUND, NGINX_404_BODY).into_response();
        }
        response
    } else {
        match gate.check.check(request.headers()) {
            Ok(()) => next.run(request).await,
            Err(response) => response,
        }
    }
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

    /// No admin token configured keeps the entire namespace hidden, even
    /// when the wire listener has a public fallback.
    #[tokio::test]
    async fn no_token_hides_admin_namespace() {
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

    #[tokio::test]
    async fn api_rejects_cookies_and_ambiguous_authorization() {
        let state = dummy_state("tok-1");
        let login = headscale_api::admin::router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("token=tok-1"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let cookie = login.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let app = build_admin_router(state, Some(Arc::from("tok-1")));
        for (bearer, duplicate) in [(None, false), (Some("wrong"), false), (Some("tok-1"), true)] {
            let mut request = Request::builder()
                .uri("/api/v1/machines")
                .header("cookie", &cookie);
            if let Some(bearer) = bearer {
                request = request.header("authorization", format!("Bearer {bearer}"));
            }
            if duplicate {
                request = request.header("authorization", "Bearer other");
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                to_bytes(response.into_body(), 64).await.unwrap().as_ref(),
                NGINX_404_BODY
            );
        }
    }
}
