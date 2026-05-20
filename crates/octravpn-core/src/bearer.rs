//! Bearer-token gating for HTTP control routes.
//!
//! Cross-cutting extraction (XC-1 in `docs/refactor-plan-2026-05-20.md`):
//! the hand-rolled `headers.get(AUTHORIZATION) → strip_prefix("Bearer ")
//! → constant_time_eq_str(want)` recipe used to be duplicated across
//! every bearer-gated control-plane handler in
//! `crates/octravpn-node/src/control.rs`. This module is the single
//! source of truth for the byte-stable response shapes those handlers
//! emit, so a future audit can verify "every authenticated route in
//! the workspace returns the same bytes on the wire" by inspecting one
//! file.
//!
//! ## Two policies
//!
//! ### `BearerPolicy::Strict { disabled_body }` — operator-facing surface.
//!
//! When the operator hasn't configured a token, the endpoint replies
//! `503 Service Unavailable` with a human-readable explanation body.
//! Used by `/metrics`: a Prometheus scrape must see a clear "endpoint
//! disabled" error rather than silently 404'ing, otherwise a
//! misconfiguration looks like a dead node. Wrong-token requests with
//! a configured token get `401 Unauthorized` + empty body.
//!
//! ### `BearerPolicy::Hidden` — undetectable surface.
//!
//! When the operator hasn't configured a token, the endpoint replies
//! `404 Not Found` with [`NGINX_404_BODY`] (currently the empty byte
//! slice). External scanners cannot tell the route exists. Wrong-token
//! requests get the same `404` + same body — there's no way from
//! outside to distinguish "endpoint disabled" from "wrong bearer". Used
//! by `/events` (SSE) and `/admin/preauth`.
//!
//! ## NGINX_404_BODY
//!
//! Historically this constant pointed at
//! `headscale-api::tailscale_wire::knock::NGINX_404_BODY` — the
//! upstream Headscale `knock` module exported the canonical bytes its
//! own hidden routes used so the wire shape was unified.
//!
//! The embedded `headscale-rs` repo was dropped (`d6b3930 gitignore
//! .claude/worktrees + drop embedded-repo refs`), so this module is
//! now itself the source of truth. The bytes are intentionally empty
//! — an external probe sees no body at all, matching nginx's default
//! response for routes that aren't mounted. Any change to this
//! constant changes the wire shape of every `Hidden` endpoint
//! workspace-wide; do not modify without coordinating with the
//! operator monitoring profile.

use std::sync::Arc;

use axum::{
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

/// Byte-stable body for `404` responses on `Hidden`-policy routes.
///
/// Empty bytes match the default nginx 404 shape an external scanner
/// expects to see for a non-existent route. The constant lives at the
/// crate root of `octravpn-core` so every consumer (node, analytics,
/// future client portal) references the same bytes.
pub const NGINX_404_BODY: &[u8] = b"";

/// Bearer-token gating policy.
///
/// The two variants pin the two response shapes the workspace uses;
/// adding a third variant requires a documented operator playbook
/// reason (see `docs/refactor-plan-2026-05-20.md` § XC-1).
#[derive(Clone, Debug)]
pub enum BearerPolicy {
    /// Visible-when-disabled.
    ///
    /// Returns `503 Service Unavailable` + `disabled_body` (a
    /// human-readable static string) when the operator hasn't
    /// configured a token. Returns `401 Unauthorized` + empty body
    /// when the token is configured but the request bearer is
    /// missing/wrong.
    Strict {
        /// Body bytes returned alongside the `503` when no token is
        /// configured. Held as a static string so the response shape
        /// is interned at compile time and cannot drift per-request.
        disabled_body: &'static str,
    },
    /// Hidden-when-disabled. Returns `404 Not Found` + [`NGINX_404_BODY`]
    /// for every failure mode (no token configured, missing header,
    /// wrong token). External observers cannot tell the route exists.
    Hidden,
}

/// One bearer-auth check, sharing the same constant-time compare and
/// the same Authorization-header parsing rules across every consumer.
///
/// Clone is cheap (one `Arc<str>` clone + an enum copy). Held inside
/// `ControlState` and similar structs so each route can call
/// [`Self::check`] without re-reading its policy from disk.
#[derive(Clone, Debug)]
pub struct BearerCheck {
    /// `None` means the operator hasn't configured a token; the
    /// `policy` decides whether the route reveals that fact (`Strict`
    /// → `503`) or hides it (`Hidden` → `404`).
    token: Option<Arc<str>>,
    policy: BearerPolicy,
}

impl BearerCheck {
    /// Construct a `Strict`-policy check. `disabled_body` is the
    /// `503` body to return when `token` is `None`.
    pub fn strict(token: Option<Arc<str>>, disabled_body: &'static str) -> Self {
        Self {
            token,
            policy: BearerPolicy::Strict { disabled_body },
        }
    }

    /// Construct a `Hidden`-policy check. All failure modes return
    /// `404 Not Found` + [`NGINX_404_BODY`].
    pub fn hidden(token: Option<Arc<str>>) -> Self {
        Self {
            token,
            policy: BearerPolicy::Hidden,
        }
    }

    /// Test whether the operator has configured a token. Useful for
    /// startup diagnostics ("operator forgot to set
    /// `[control].metrics_token`") and for handlers that want to
    /// branch on configured-ness before doing expensive prep work.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.token.is_some()
    }

    /// Check the bearer for one request.
    ///
    /// Returns `Ok(())` if the request is authorized; `Err(resp)`
    /// otherwise, where `resp` is the byte-stable rejection the
    /// handler MUST return directly (no further processing).
    ///
    /// ## Response matrix
    ///
    /// | token configured | header present | header matches | `Strict` | `Hidden` |
    /// |------------------|----------------|----------------|----------|----------|
    /// | no               | -              | -              | 503      | 404      |
    /// | yes              | no             | -              | 401      | 404      |
    /// | yes              | yes            | no             | 401      | 404      |
    /// | yes              | yes            | yes            | OK       | OK       |
    // `Response` carries a body which is itself a boxed enum; clippy's
    // `result_large_err` flags the ~128-byte size, but the rejection
    // path is cold (one allocation per failed auth check) and boxing
    // it here would obscure the fact that the body is byte-stable.
    // The handler's hot path is `Ok(())` which is zero-sized.
    #[allow(clippy::result_large_err)]
    pub fn check(&self, headers: &HeaderMap) -> Result<(), Response> {
        let Some(want) = self.token.as_deref() else {
            return Err(self.disabled_response());
        };
        let got = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        if got.is_some_and(|tok| constant_time_eq_str(tok, want)) {
            Ok(())
        } else {
            Err(self.wrong_token_response())
        }
    }

    /// Response shape when `token` is `None`. Public so tests in
    /// other crates can pin the bytes-on-wire.
    fn disabled_response(&self) -> Response {
        match self.policy {
            BearerPolicy::Strict { disabled_body } => {
                (StatusCode::SERVICE_UNAVAILABLE, disabled_body).into_response()
            }
            BearerPolicy::Hidden => (StatusCode::NOT_FOUND, NGINX_404_BODY).into_response(),
        }
    }

    /// Response shape when `token` is `Some` but the request's bearer
    /// is missing/wrong.
    fn wrong_token_response(&self) -> Response {
        match self.policy {
            BearerPolicy::Strict { .. } => (StatusCode::UNAUTHORIZED, "").into_response(),
            BearerPolicy::Hidden => (StatusCode::NOT_FOUND, NGINX_404_BODY).into_response(),
        }
    }
}

/// Constant-time string equality. Doesn't short-circuit on byte
/// content, but strings with different lengths can't be equal — we
/// return `false` up front and skip the loop. The remaining
/// comparison is byte-by-byte `XOR-and-OR` accumulated into a single
/// `u8` so the time to compare two equal-length strings is constant.
///
/// Public at module scope so consumers that need the same primitive
/// for non-bearer comparisons (e.g. an HMAC tag check) don't grow a
/// second copy.
#[must_use]
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `axum::middleware::from_fn_with_state` adapter. Apply with
/// `.route_layer(axum::middleware::from_fn_with_state(check.clone(),
/// bearer_middleware))` to gate a single route or sub-router behind
/// a `BearerCheck`. Most current consumers call [`BearerCheck::check`]
/// directly inside their handler because they need to interleave
/// other state lookups; this entrypoint exists so a future
/// "bearer-only" route can be one line.
///
/// On `Ok` the inner handler runs; on `Err` the short-circuit
/// response is returned directly. The middleware never panics and
/// never consumes the request body on the rejection path — a wrong
/// bearer is rejected before the handler sees the body, matching
/// nginx-style auth gates.
pub async fn bearer_middleware(
    axum::extract::State(check): axum::extract::State<BearerCheck>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let headers = req.headers().clone();
    match check.check(&headers) {
        Ok(()) => next.run(req).await,
        Err(resp) => resp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn hdrs(auth: Option<&'static str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = auth {
            h.insert(AUTHORIZATION, HeaderValue::from_static(v));
        }
        h
    }

    /// Strict policy with no token configured returns `503` and the
    /// configured disabled-body bytes — the operator-visible
    /// misconfiguration signal `/metrics` relies on.
    #[tokio::test]
    async fn strict_no_token_returns_503_with_body() {
        let check = BearerCheck::strict(None, "metrics endpoint disabled");
        let err = check.check(&hdrs(None)).expect_err("must reject");
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(err.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"metrics endpoint disabled");
    }

    /// Strict policy with token configured + wrong bearer returns
    /// `401` and an empty body. Pins the `/metrics` wrong-token
    /// surface bytes-for-bytes.
    #[tokio::test]
    async fn strict_wrong_bearer_returns_401_empty() {
        let check = BearerCheck::strict(Some(Arc::from("right")), "disabled");
        for h in [hdrs(None), hdrs(Some("Bearer wrong")), hdrs(Some("not-a-bearer"))] {
            let err = check.check(&h).expect_err("must reject");
            assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
            let body = axum::body::to_bytes(err.into_body(), 4096).await.unwrap();
            assert!(body.is_empty(), "401 body must be empty, got {body:?}");
        }
    }

    /// Hidden policy with no token configured returns `404` and the
    /// canonical [`NGINX_404_BODY`] (empty bytes). Pins the
    /// `/events` / `/admin/preauth` undetectable-route shape.
    #[tokio::test]
    async fn hidden_no_token_returns_404_with_nginx_body() {
        let check = BearerCheck::hidden(None);
        let err = check
            .check(&hdrs(Some("Bearer anything")))
            .expect_err("must reject");
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(err.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], NGINX_404_BODY);
    }

    /// Hidden policy with token configured but wrong/missing bearer
    /// also returns `404` + [`NGINX_404_BODY`] — externally
    /// indistinguishable from the disabled case.
    #[tokio::test]
    async fn hidden_wrong_bearer_returns_404_indistinguishable() {
        let check = BearerCheck::hidden(Some(Arc::from("right")));
        for h in [hdrs(None), hdrs(Some("Bearer wrong"))] {
            let err = check.check(&h).expect_err("must reject");
            assert_eq!(err.status(), StatusCode::NOT_FOUND);
            let body = axum::body::to_bytes(err.into_body(), 4096).await.unwrap();
            assert_eq!(&body[..], NGINX_404_BODY);
        }
    }

    /// Either policy with the right `Bearer <token>` header passes
    /// the gate (returns `Ok(())`). Pins the success path.
    #[test]
    fn correct_bearer_passes_for_both_policies() {
        let strict = BearerCheck::strict(Some(Arc::from("s3cret")), "disabled");
        let hidden = BearerCheck::hidden(Some(Arc::from("s3cret")));
        let h = hdrs(Some("Bearer s3cret"));
        assert!(strict.check(&h).is_ok());
        assert!(hidden.check(&h).is_ok());
        // Length-mismatched bearers fail the constant-time compare.
        let wrong = hdrs(Some("Bearer s3cretX"));
        assert!(strict.check(&wrong).is_err());
        assert!(hidden.check(&wrong).is_err());
        // The free-standing helper backs both policies; sanity-check it.
        assert!(constant_time_eq_str("abc", "abc"));
        assert!(!constant_time_eq_str("abc", "abd"));
        assert!(!constant_time_eq_str("abc", "abcd"));
        assert!(constant_time_eq_str("", ""));
    }
}
