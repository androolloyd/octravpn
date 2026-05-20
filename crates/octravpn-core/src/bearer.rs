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
//! ## Unified policy (post audit-3 H-1)
//!
//! Historically the module exposed two policies: `Strict` (returned
//! `503` + a human-readable disabled-body when no token was
//! configured; `401` + empty body for a wrong bearer) and `Hidden`
//! (returned `404` + [`NGINX_404_BODY`] for every failure mode).
//!
//! The audit found the `Strict` shape leaked **token-presence vs
//! absence** to an unauthenticated scanner: a `503` body of `b"metrics
//! endpoint disabled: set [control].metrics_token in node.toml"` is
//! discoverable evidence that the route exists, the operator hasn't
//! configured it yet, and the exact TOML key the operator needs to
//! set. A correctly configured node with a wrong bearer instead
//! returned `(401, "")`, so a passive probe distinguishes
//! "unconfigured" from "configured-but-wrong-token".
//!
//! Both variants now collapse to the same `Hidden` behaviour: **every
//! reject reason returns `(404, NGINX_404_BODY)`**. The unconfigured
//! case is surfaced to the operator as a `tracing::warn!` log line at
//! boot (see `octravpn_node::hub::spawn` and `BearerCheck::warn_if_unconfigured`)
//! so a misconfigured Prometheus shows up in the operator's logs
//! rather than on the wire.
//!
//! The `BearerPolicy` enum + the legacy `BearerCheck::strict` /
//! `BearerCheck::hidden` constructors are retained so call sites keep
//! compiling, but they all route to the same byte-stable reject path.
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
//! constant changes the wire shape of every bearer-gated endpoint
//! workspace-wide; do not modify without coordinating with the
//! operator monitoring profile.

use std::sync::Arc;

use axum::{
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

/// Byte-stable body for `404` responses on every reject path.
///
/// Empty bytes match the default nginx 404 shape an external scanner
/// expects to see for a non-existent route. The constant lives at the
/// crate root of `octravpn-core` so every consumer (node, analytics,
/// future client portal) references the same bytes.
pub const NGINX_404_BODY: &[u8] = b"";

/// Bearer-token gating policy.
///
/// Post-audit-3-H-1 both variants emit the same wire bytes on reject
/// (`(404, NGINX_404_BODY)`); the enum is preserved so call sites that
/// constructed a `Strict` check keep compiling and so the operator can
/// branch on policy intent at boot (a `Strict` check whose token is
/// unconfigured logs a warning, a `Hidden` check stays silent — see
/// [`BearerCheck::warn_if_unconfigured`]).
#[derive(Clone, Debug)]
pub enum BearerPolicy {
    /// Operator-facing endpoint that *should* be configured. The wire
    /// reject path is identical to `Hidden`; the only difference is
    /// that [`BearerCheck::warn_if_unconfigured`] emits a `tracing::warn!`
    /// when the token is `None`, so the operator's logs surface the
    /// misconfiguration.
    Strict {
        /// Static label for the boot-time warn message (e.g.
        /// `"metrics endpoint disabled: set [control].metrics_token in node.toml"`).
        /// Used only for the log line — never written on the wire.
        warn_label: &'static str,
    },
    /// Truly hidden endpoint. No warn log on boot — the operator may
    /// intentionally leave the endpoint disabled (e.g. `/events` on a
    /// non-observability node).
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
    /// `None` means the operator hasn't configured a token. Every
    /// reject path (regardless of policy) emits the same byte-stable
    /// `(404, NGINX_404_BODY)` response so external probes cannot
    /// distinguish "endpoint disabled" from "wrong bearer".
    token: Option<Arc<str>>,
    policy: BearerPolicy,
}

impl BearerCheck {
    /// Construct a `Strict`-policy check. `warn_label` is the message
    /// [`Self::warn_if_unconfigured`] emits at boot when the token is
    /// `None` — never written on the wire.
    pub fn strict(token: Option<Arc<str>>, warn_label: &'static str) -> Self {
        Self {
            token,
            policy: BearerPolicy::Strict { warn_label },
        }
    }

    /// Construct a `Hidden`-policy check. All failure modes return
    /// `404 Not Found` + [`NGINX_404_BODY`] and no boot warning is
    /// emitted when the token is unset.
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

    /// Emit a boot-time warning when the policy is `Strict` and no
    /// token is configured. The warning is the *only* way an operator
    /// learns about a misconfigured `/metrics`-style endpoint — the
    /// wire never reveals the configuration state. Call once at boot
    /// (`Hub::spawn_control_plane`) per check; idempotent and
    /// allocation-free in the happy path.
    pub fn warn_if_unconfigured(&self) {
        if let (None, BearerPolicy::Strict { warn_label }) = (&self.token, &self.policy) {
            tracing::warn!("{warn_label}");
        }
    }

    /// Check the bearer for one request.
    ///
    /// Returns `Ok(())` if the request is authorized; `Err(resp)`
    /// otherwise, where `resp` is the byte-stable rejection the
    /// handler MUST return directly (no further processing).
    ///
    /// ## Response matrix (unified post audit-3 H-1)
    ///
    /// | token configured | header present | header matches | response             |
    /// |------------------|----------------|----------------|----------------------|
    /// | no               | -              | -              | `(404, NGINX_404_BODY)` |
    /// | yes              | no             | -              | `(404, NGINX_404_BODY)` |
    /// | yes              | yes            | no             | `(404, NGINX_404_BODY)` |
    /// | yes              | yes            | yes            | `Ok(())`             |
    ///
    /// Both `Strict` and `Hidden` policies emit the same bytes for
    /// every reject reason; the `Strict` policy only differs in that
    /// [`Self::warn_if_unconfigured`] logs a misconfiguration warning
    /// at boot.
    // `Response` carries a body which is itself a boxed enum; clippy's
    // `result_large_err` flags the ~128-byte size, but the rejection
    // path is cold (one allocation per failed auth check) and boxing
    // it here would obscure the fact that the body is byte-stable.
    // The handler's hot path is `Ok(())` which is zero-sized.
    #[allow(clippy::result_large_err)]
    pub fn check(&self, headers: &HeaderMap) -> Result<(), Response> {
        let Some(want) = self.token.as_deref() else {
            return Err(reject_response());
        };
        let got = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        if got.is_some_and(|tok| constant_time_eq_str(tok, want)) {
            Ok(())
        } else {
            Err(reject_response())
        }
    }
}

/// The one byte-stable rejection response every bearer-gated route
/// emits on any failure: `404 Not Found` + [`NGINX_404_BODY`]. Kept as
/// a free-standing function so all reject paths are visibly the same
/// expression at the call site — there is no `match policy` branch
/// that could silently drift.
fn reject_response() -> Response {
    (StatusCode::NOT_FOUND, NGINX_404_BODY).into_response()
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
    use sha2::{Digest, Sha256};

    fn hdrs(auth: Option<&'static str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = auth {
            h.insert(AUTHORIZATION, HeaderValue::from_static(v));
        }
        h
    }

    /// Drain a rejection response into `(status, sha256(body))` — the
    /// byte-stable fingerprint we pin across every reject reason. A
    /// hash (not raw bytes) so the assertion in
    /// `bearer_failure_byte_identical_across_all_reject_reasons` is
    /// one `assert_eq!` on `[u8; 32]` regardless of body length.
    async fn fingerprint(resp: Response) -> (StatusCode, [u8; 32]) {
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .expect("response body must read");
        let mut h = Sha256::new();
        h.update(&body);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        (status, out)
    }

    /// **Audit-3 H-1**: every reject reason — token unset, header
    /// missing, wrong scheme, wrong token, wrong-token-length — must
    /// emit byte-identical bytes (same status, same body, same hash).
    /// The previous `Strict` 503-with-text leaked configuration state
    /// to an unauthenticated scanner; we now collapse on the
    /// `(404, NGINX_404_BODY)` shape. Both `strict` and `hidden`
    /// constructors share the wire shape.
    #[tokio::test]
    async fn bearer_failure_byte_identical_across_all_reject_reasons() {
        // Reasons to check, against both policy variants:
        // * no token configured (operator forgot to set the toml key)
        // * configured + no Authorization header
        // * configured + wrong scheme ("not-a-bearer")
        // * configured + wrong token, same length
        // * configured + wrong token, different length
        let cases_no_token = [hdrs(None), hdrs(Some("Bearer anything"))];
        let configured_strict =
            BearerCheck::strict(Some(Arc::from("right")), "metrics disabled label");
        let configured_hidden = BearerCheck::hidden(Some(Arc::from("right")));
        let unconfigured_strict = BearerCheck::strict(None, "metrics disabled label");
        let unconfigured_hidden = BearerCheck::hidden(None);
        let configured_cases = [
            hdrs(None),
            hdrs(Some("not-a-bearer")),
            hdrs(Some("Bearer wrong")),
            hdrs(Some("Bearer wrongX")),
        ];

        let mut fingerprints = Vec::new();
        for hs in &cases_no_token {
            for chk in [&unconfigured_strict, &unconfigured_hidden] {
                let r = chk.check(hs).expect_err("unconfigured must reject");
                fingerprints.push(fingerprint(r).await);
            }
        }
        for hs in &configured_cases {
            for chk in [&configured_strict, &configured_hidden] {
                let r = chk.check(hs).expect_err("wrong-bearer must reject");
                fingerprints.push(fingerprint(r).await);
            }
        }

        // Every entry must be (404, sha256(b"")) — pin to the precise
        // bytes so a future drift fails this test before it reaches
        // the wire.
        let want_status = StatusCode::NOT_FOUND;
        let want_hash = {
            let mut h = Sha256::new();
            h.update(NGINX_404_BODY);
            let mut o = [0u8; 32];
            o.copy_from_slice(&h.finalize());
            o
        };
        for (st, hash) in &fingerprints {
            assert_eq!(*st, want_status, "all rejects must be 404");
            assert_eq!(*hash, want_hash, "all reject bodies must hash identically");
        }
    }

    /// The success path is unchanged: a `Bearer <correct-token>`
    /// header passes both `strict` and `hidden` checks, and
    /// `BearerCheck::check` returns `Ok(())` so the inner handler
    /// runs.
    #[test]
    fn bearer_pass_returns_inner_handler_response() {
        let strict = BearerCheck::strict(Some(Arc::from("s3cret")), "metrics label");
        let hidden = BearerCheck::hidden(Some(Arc::from("s3cret")));
        let h = hdrs(Some("Bearer s3cret"));
        assert!(
            strict.check(&h).is_ok(),
            "strict must accept the configured bearer"
        );
        assert!(
            hidden.check(&h).is_ok(),
            "hidden must accept the configured bearer"
        );
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

    /// `BearerCheck::warn_if_unconfigured` is a no-op when the token
    /// is configured (regardless of policy) and when the policy is
    /// `Hidden`; otherwise it emits a `tracing::warn!`. The log
    /// emission itself is exercised only by integration tests that
    /// install a subscriber — here we just pin the no-panic, no-op
    /// shape and that the method is safe to call repeatedly.
    #[test]
    fn warn_if_unconfigured_is_idempotent_noop_when_safe() {
        BearerCheck::strict(Some(Arc::from("ok")), "lbl").warn_if_unconfigured();
        BearerCheck::hidden(None).warn_if_unconfigured();
        BearerCheck::hidden(Some(Arc::from("ok"))).warn_if_unconfigured();
        // Strict + unconfigured emits exactly one warn per call; the
        // test subscriber isn't installed here, so we just call twice
        // to confirm no panic.
        let chk = BearerCheck::strict(None, "metrics disabled label");
        chk.warn_if_unconfigured();
        chk.warn_if_unconfigured();
    }
}
