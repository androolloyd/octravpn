//! axum routes for the `oct://` browser portal.
//!
//! Route table:
//!
//!   GET  /                  — index page with URL bar
//!   GET  /go?u=<oct-url>    — redirects to /o/<b64> (browser-form action)
//!   GET  /o/{b64url}        — primary asset viewer (HTML render)
//!   GET  /raw?u=<oct-url>   — raw bytes + Content-Type for `curl`/`wget`
//!                             optional: `&token=<hex>` to bypass the
//!                             confirm gate; `&dl=1` adds
//!                             Content-Disposition: attachment
//!   GET  /api/resolve?u=    — JSON metadata (size + mime) without rendering
//!   GET  /confirm?u=<…>     — confirm-on-first-fetch interstitial
//!                             `?accept=cli` issues a token as JSON
//!                             without mutating approval state
//!   POST /approve           — body: `circle=<…>&token=<…>&next=<…>`
//!   POST /unseal            — interactive unseal: body
//!                             `circle=<…>&passphrase=<…>&next=<…>`
//!                             validates once, caches per-circle in
//!                             process memory, redirects to `next`.
//!   GET  /healthz           — liveness probe (always 200)
//!
//! **Decision log.**
//! * Sandbox: every `text/html` response is wrapped in
//!   `<iframe sandbox="allow-popups" srcdoc="…">`. No `allow-scripts`,
//!   no `allow-same-origin`. `allow-popups` is kept so a hyperlink in
//!   the asset can navigate the *parent* (the portal) — the parent
//!   captures the click and routes it back through `/go`, which
//!   re-enters the security gate. SVG is *not* sandboxed-rendered
//!   inline (script-bearing SVG is a thing) — we serve it as a real
//!   `image/svg+xml` so the browser's image renderer handles it (no
//!   script execution there).
//! * Confirm tokens: HMAC-SHA256 over `circle_id` keyed by a per-process
//!   32-byte secret (generated at startup with `OsRng`). Token format
//!   is `hex(hmac)`; the form re-submits the circle id verbatim so the
//!   server can re-derive the HMAC. The secret never leaves process
//!   memory, so a portal restart invalidates all outstanding tokens —
//!   intentional (re-confirm after restart).
//! * Confirm storage: in-memory `BTreeSet<String>` of circle ids; not
//!   persisted across restarts. Per the design doc this is per-session.
//! * Tunnel-down handling: chain errors are caught and rendered as a
//!   structured error card — NOT a 500. The error message includes the
//!   underlying RPC error text so the operator can diagnose.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    commands::open_url::parse_oct_url,
    portal::{
        chain::{AssetCache, FetchAssetError, PassphraseSource, PortalChain},
        mime::SniffedMime,
        static_assets::{INDEX_BODY, PAGE_SHELL},
    },
};

type HmacSha256 = Hmac<Sha256>;

/// Per-circle interactive unseal cache. Built when the operator submits
/// a passphrase via `POST /unseal` and the chain successfully decrypts
/// at least one sealed asset for that circle.
///
/// **Lifecycle.** In-memory only. Survives only the portal's process
/// lifetime — same model as the approval `allow_set`. A portal restart
/// re-prompts. We deliberately do NOT serialize this to disk; persisting
/// would turn the cache into a key-material file that survives
/// password-protected user sessions.
type UnsealCache = Arc<Mutex<BTreeMap<String, Arc<Zeroizing<String>>>>>;

/// Shared portal state. Cheaply cloneable (everything inside is `Arc`
/// or a small Copy).
#[derive(Clone)]
pub(crate) struct PortalState {
    pub chain: PortalChain,
    pub allow_set: Arc<Mutex<BTreeSet<String>>>,
    pub hmac_secret: Arc<[u8; 32]>,
    /// Per-circle passphrases collected via the interactive unseal
    /// form. Falls back to `chain.configured_passphrase()` on miss.
    pub unseal_cache: UnsealCache,
    /// Plaintext-asset cache keyed by `(circle_id, canonical_path)`.
    /// Shared `Arc` with `PortalChain` — every fetch path consults the
    /// same map. Capacity / TTL are picked at chain construction; see
    /// `chain::DEFAULT_ASSET_CACHE_CAPACITY` + `DEFAULT_ASSET_CACHE_TTL`.
    /// Exposed on the state for future debug surfaces and for tests
    /// asserting cache hit/miss behavior; production fetch paths read
    /// it via `chain.asset_cache()`.
    #[allow(dead_code)]
    pub asset_cache: Arc<AssetCache>,
}

/// [`PassphraseSource`] adapter that consults the portal's per-circle
/// unseal cache first, then the boot-time configured passphrase.
pub(crate) struct UnsealCachePassphrase {
    cache: UnsealCache,
    fallback: Option<Arc<Zeroizing<String>>>,
}

impl PassphraseSource for UnsealCachePassphrase {
    fn passphrase_for(&self, circle_id: &str) -> Option<Arc<Zeroizing<String>>> {
        if let Ok(guard) = self.cache.lock() {
            if let Some(pp) = guard.get(circle_id) {
                return Some(Arc::clone(pp));
            }
        }
        self.fallback.clone()
    }
}

impl PortalState {
    pub(crate) fn new(chain: PortalChain) -> Self {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let asset_cache = chain.asset_cache();
        Self {
            chain,
            allow_set: Arc::new(Mutex::new(BTreeSet::new())),
            hmac_secret: Arc::new(secret),
            unseal_cache: Arc::new(Mutex::new(BTreeMap::new())),
            asset_cache,
        }
    }

    /// Build a cache-aware passphrase source for use with
    /// [`PortalChain::fetch_with_source`].
    fn passphrase_source(&self) -> UnsealCachePassphrase {
        UnsealCachePassphrase {
            cache: Arc::clone(&self.unseal_cache),
            fallback: self.chain.configured_passphrase(),
        }
    }

    /// Record an unseal cache hit for `circle_id`. Public for tests +
    /// the `POST /unseal` handler.
    pub(crate) fn record_unseal(&self, circle_id: &str, pp: Arc<Zeroizing<String>>) {
        if let Ok(mut g) = self.unseal_cache.lock() {
            g.insert(circle_id.to_string(), pp);
        }
    }

    /// Build an approval token for `circle_id`. Hex-encoded HMAC-SHA256.
    pub(crate) fn token_for(&self, circle_id: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(self.hmac_secret.as_ref())
            .expect("HMAC accepts any 32B key");
        mac.update(circle_id.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Constant-time verify an approval token against the live HMAC.
    pub(crate) fn token_valid(&self, circle_id: &str, supplied_hex: &str) -> bool {
        let Ok(supplied) = hex::decode(supplied_hex) else {
            return false;
        };
        let mut mac = HmacSha256::new_from_slice(self.hmac_secret.as_ref())
            .expect("HMAC accepts any 32B key");
        mac.update(circle_id.as_bytes());
        mac.verify_slice(&supplied).is_ok()
    }

    pub(crate) fn is_allowed(&self, circle_id: &str) -> bool {
        self.allow_set
            .lock()
            .map(|s| s.contains(circle_id))
            .unwrap_or(false)
    }

    pub(crate) fn allow(&self, circle_id: &str) {
        if let Ok(mut s) = self.allow_set.lock() {
            s.insert(circle_id.to_string());
        }
    }
}

pub(crate) fn router(state: PortalState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/go", get(go))
        .route("/o/:b64", get(view_asset))
        .route("/raw", get(raw_asset))
        .route("/api/resolve", get(api_resolve))
        .route("/confirm", get(confirm_page))
        .route("/approve", post(approve))
        .route("/unseal", post(unseal))
        .route("/healthz", get(healthz))
        .with_state(state)
}

// ─── route handlers ───────────────────────────────────────────────────

async fn healthz() -> &'static str {
    "ok"
}

async fn index() -> Html<String> {
    Html(render_shell("octra portal", "", INDEX_BODY))
}

#[derive(Deserialize)]
struct GoQuery {
    u: String,
}

async fn go(Query(q): Query<GoQuery>) -> Response {
    if parse_oct_url(&q.u).is_err() {
        return error_page(StatusCode::BAD_REQUEST, &q.u, "not a valid oct:// URL");
    }
    let b64 = B64URL.encode(q.u.as_bytes());
    Redirect::to(&format!("/o/{b64}")).into_response()
}

#[derive(Deserialize)]
struct ResolveQuery {
    u: String,
}

async fn api_resolve(State(state): State<PortalState>, Query(q): Query<ResolveQuery>) -> Response {
    let parsed = match parse_oct_url(&q.u) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let cached = match state
        .chain
        .fetch_with_source_sniffed(&parsed.circle_id, &parsed.path, &state.passphrase_source())
        .await
    {
        Ok(c) => c,
        Err(e) => {
            let (status, hint) = match &e {
                FetchAssetError::MissingPassphrase { .. } | FetchAssetError::DecryptFailed { .. } => (
                    StatusCode::PRECONDITION_FAILED,
                    "set OCTRAVPN_SEALED_PASSPHRASE or [v2].sealed_passphrase to decrypt sealed circle assets.",
                ),
                _ => (
                    StatusCode::BAD_GATEWAY,
                    "is the tunnel up? portal requires the VPN session to reach circle_asset RPC.",
                ),
            };
            return (
                status,
                Json(json!({
                    "error": e.to_string(),
                    "circle_id": parsed.circle_id,
                    "path": parsed.path,
                    "hint": hint,
                })),
            )
                .into_response();
        }
    };
    Json(json!({
        "circle_id": parsed.circle_id,
        "path": parsed.path,
        "size": cached.bytes.len(),
        "mime": cached.mime.content_type(),
        "renderable": cached.mime.renderable(),
        "allowed": state.is_allowed(&parsed.circle_id),
    }))
    .into_response()
}

async fn view_asset(State(state): State<PortalState>, Path(b64): Path<String>) -> Response {
    let Ok(raw) = B64URL.decode(b64.as_bytes()) else {
        return error_page(StatusCode::BAD_REQUEST, "", "bad base64 in URL");
    };
    let url = match std::str::from_utf8(&raw) {
        Ok(s) => s.to_string(),
        Err(_) => return error_page(StatusCode::BAD_REQUEST, "", "url is not valid UTF-8"),
    };
    let parsed = match parse_oct_url(&url) {
        Ok(p) => p,
        Err(e) => return error_page(StatusCode::BAD_REQUEST, &url, &e.to_string()),
    };

    // Confirm gate.
    if !state.is_allowed(&parsed.circle_id) {
        return confirm_interstitial(&state, &url, &parsed.circle_id);
    }

    // Fetch via the cache-aware passphrase source so a prior /unseal
    // submission for this circle is honored. The sniffed variant
    // also reuses the cached MIME on hits — no re-sniff per request.
    let cached = match state
        .chain
        .fetch_with_source_sniffed(&parsed.circle_id, &parsed.path, &state.passphrase_source())
        .await
    {
        Ok(c) => c,
        Err(e) => return fetch_error_page(&state, &url, &parsed.circle_id, e),
    };

    render_bytes(&url, (*cached.bytes).clone(), cached.mime)
}

#[derive(Deserialize)]
struct ConfirmQuery {
    u: String,
    /// When `accept=cli`, issue the approval token directly as JSON
    /// instead of rendering the browser interstitial. The token has the
    /// same provenance (HMAC-SHA256 over circle_id) and same privilege
    /// — there is no separate `cli` scope. The caller still has to
    /// present the token on `/raw`; GET never mutates approval state.
    #[serde(default)]
    accept: Option<String>,
}

async fn confirm_page(State(state): State<PortalState>, Query(q): Query<ConfirmQuery>) -> Response {
    let parsed = match parse_oct_url(&q.u) {
        Ok(p) => p,
        Err(e) => return error_page(StatusCode::BAD_REQUEST, &q.u, &e.to_string()),
    };
    if matches!(q.accept.as_deref(), Some("cli")) {
        // CLI-friendly path: mint a bearer token and return JSON.
        // State changes stay behind POST /approve; GET is safe to
        // prefetch and cannot be used as a browser CSRF gadget.
        let token = state.token_for(&parsed.circle_id);
        return Json(json!({
            "circle_id": parsed.circle_id,
            "token": token,
            "approved": false,
            "note": "retry the raw URL with &token=<hex>; browser approval requires POST /approve",
        }))
        .into_response();
    }
    confirm_interstitial(&state, &q.u, &parsed.circle_id)
}

#[derive(Deserialize)]
struct ApproveForm {
    circle: String,
    token: String,
    next: String,
}

async fn approve(State(state): State<PortalState>, Form(form): Form<ApproveForm>) -> Response {
    if !state.token_valid(&form.circle, &form.token) {
        return (StatusCode::UNAUTHORIZED, "bad approval token").into_response();
    }
    state.allow(&form.circle);
    Redirect::to(&form.next).into_response()
}

// ─── /raw  ────────────────────────────────────────────────────────────
//
// Raw-bytes gateway for `curl` / `wget` / shell scripts. Same auth
// surface as `/o/<b64>` — confirm + unseal cache — but the response
// body is unframed: no PAGE_SHELL, no <iframe>, just the bytes plus a
// `Content-Type` derived from the existing MIME sniffer.

#[derive(Deserialize)]
struct RawQuery {
    u: String,
    /// Approval token (hex HMAC-SHA256 over `circle_id`). When present
    /// and valid, the confirm gate is bypassed without mutating the
    /// in-memory `allow_set`. Useful for short-lived scripts that
    /// don't want to dirty server state.
    #[serde(default)]
    token: Option<String>,
    /// `?dl=1` forces a `Content-Disposition: attachment` header with
    /// a filename derived from the URL's last path component.
    #[serde(default)]
    dl: Option<String>,
}

async fn raw_asset(State(state): State<PortalState>, Query(q): Query<RawQuery>) -> Response {
    let parsed = match parse_oct_url(&q.u) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string(), "url": q.u})),
            )
                .into_response();
        }
    };

    // Confirm gate. Same logic as `/o/<b64>` but returns a 412 JSON
    // body rather than the HTML interstitial — tooling needs a
    // machine-readable hint, not a page to click through.
    let approved_by_token = match q.token.as_deref() {
        Some(t) => state.token_valid(&parsed.circle_id, t),
        None => false,
    };
    if !approved_by_token && !state.is_allowed(&parsed.circle_id) {
        let approve_url = format!("/confirm?u={}&accept=cli", urlencode_query_value(&q.u),);
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({
                "error": "circle not approved",
                "circle_id": parsed.circle_id,
                "approve_url": approve_url,
                "hint": "GET the approve_url to mint a one-shot token, then retry with &token=<hex>",
            })),
        )
            .into_response();
    }

    // Fetch via the cache-aware source so unseal-cached passphrases
    // work. Sniffed variant keeps the cached MIME so we don't re-sniff
    // per hit.
    let cached = match state
        .chain
        .fetch_with_source_sniffed(&parsed.circle_id, &parsed.path, &state.passphrase_source())
        .await
    {
        Ok(c) => c,
        Err(e) => return raw_error_response(&parsed.circle_id, &parsed.path, &e),
    };
    let mime = cached.mime;
    let bytes = (*cached.bytes).clone();

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime.content_type())
        .header(header::CONTENT_LENGTH, bytes.len().to_string());

    // ?dl=1 → force Save-As with a filename pulled from the URL's
    // last path component. Quotation pattern matches RFC 6266 § 4.1
    // ABNF for token + quoted-string filenames; we escape inner
    // double-quotes to avoid header truncation.
    if matches!(q.dl.as_deref(), Some("1" | "true")) {
        let filename = last_path_component(&parsed.path);
        let safe = filename.replace('"', "");
        builder = builder.header(
            header::CONTENT_DISPOSITION,
            format!(r#"attachment; filename="{safe}""#),
        );
    } else if matches!(mime, SniffedMime::OctetStream) {
        // Defensive: octet-stream bytes still get a filename so curl
        // -OJ pulls a sane name even without `&dl=1`. Don't force the
        // attachment disposition though — operators who curl into a
        // pipe still want inline.
        let filename = last_path_component(&parsed.path);
        let safe = filename.replace('"', "");
        builder = builder.header(
            header::CONTENT_DISPOSITION,
            format!(r#"inline; filename="{safe}""#),
        );
    }

    match builder.body(Body::from(bytes)) {
        Ok(r) => r,
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("response build: {e}")})),
        )
            .into_response(),
    }
}

fn raw_error_response(circle_id: &str, path: &str, err: &FetchAssetError) -> Response {
    let (status, code) = match err {
        FetchAssetError::MissingPassphrase { .. } | FetchAssetError::DecryptFailed { .. } => {
            (StatusCode::PRECONDITION_FAILED, "sealed_decrypt_failed")
        }
        FetchAssetError::NotPublished { .. } => (StatusCode::NOT_FOUND, "not_published"),
        FetchAssetError::Rpc { .. } => (StatusCode::BAD_GATEWAY, "rpc"),
    };
    (
        status,
        Json(json!({
            "error": err.to_string(),
            "code": code,
            "circle_id": circle_id,
            "path": path,
            "hint": match err {
                FetchAssetError::MissingPassphrase { .. } | FetchAssetError::DecryptFailed { .. } =>
                    "open the URL in a browser to use the interactive unseal form, or set OCTRAVPN_SEALED_PASSPHRASE before launching `octravpn portal`",
                _ => "is the tunnel up? raw endpoint requires the VPN session to reach circle_asset RPC.",
            },
        })),
    )
        .into_response()
}

fn last_path_component(path: &str) -> String {
    path.rsplit('/')
        .find(|s| !s.is_empty())
        .map_or_else(|| "circle-asset.bin".into(), ToString::to_string)
}

/// Percent-encode a value safely for embedding in a query string.
/// Used by the `/raw` 412 to construct an `approve_url` the operator
/// can fetch verbatim with `curl`.
fn urlencode_query_value(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

// ─── /unseal  ─────────────────────────────────────────────────────────
//
// Interactive unseal flow. The operator submits a passphrase for a
// specific circle; we attempt a single decrypt against a known asset
// (the circle's canonical resource key) and, on success, cache the
// passphrase in memory keyed by circle_id. Subsequent fetches for the
// same circle bypass the form.
//
// Single-attempt semantics. We do NOT iterate passphrases. The form's
// `<input type="password">` is operator-driven; nothing here amplifies
// a guessed passphrase into an oracle. Submission rate-limiting is
// the operator's concern (loopback access ≈ login).
//
// Cache lifecycle. In-memory only, tied to portal process. Restart →
// re-prompt. Identical to the approval `allow_set`.

#[derive(Deserialize)]
struct UnsealForm {
    /// Circle id to unseal. The form posts this verbatim back to the
    /// server so the cache key matches what `/o/<b64>` would request.
    circle: String,
    /// Submitted passphrase. Treated as ASCII-trimmed but otherwise
    /// opaque; we don't normalize Unicode.
    passphrase: String,
    /// Post-unseal redirect target. Typically the `/o/<b64>` URL the
    /// operator originally visited.
    next: String,
}

async fn unseal(State(state): State<PortalState>, Form(form): Form<UnsealForm>) -> Response {
    let pp_trimmed = form.passphrase.trim();
    if pp_trimmed.is_empty() {
        return unseal_form_page(
            &state,
            &form.circle,
            &form.next,
            Some("passphrase is empty"),
        );
    }
    let candidate = Arc::new(Zeroizing::new(pp_trimmed.to_string()));

    // Validate by attempting to decrypt the operator's canonical
    // resource-key fixture. Falls back to `/policy.json` if that miss
    // - documented in chain.rs as "the validation fetch is itself
    // capped at one decrypt try".
    let validated = state
        .chain
        .try_decrypt_with_passphrase(&form.circle, "/state-root.json", Arc::clone(&candidate))
        .await;
    let validated = match validated {
        Ok(_) => Ok(()),
        Err(FetchAssetError::NotPublished { .. }) => {
            // No state-root.json published; try /policy.json instead.
            state
                .chain
                .try_decrypt_with_passphrase(&form.circle, "/policy.json", Arc::clone(&candidate))
                .await
                .map(|_| ())
        }
        Err(e) => Err(e),
    };

    match validated {
        Ok(()) => {
            state.record_unseal(&form.circle, candidate);
            // Treat redirect target conservatively — only allow same-origin
            // /o/<b64> or /raw redirects, fall back to the index otherwise.
            let target = sanitize_next(&form.next);
            Redirect::to(&target).into_response()
        }
        Err(FetchAssetError::MissingPassphrase { .. }) => {
            // The asset isn't sealed — we have no way to validate the
            // submitted passphrase. Still cache it (operator's intent
            // is clear) and redirect.
            state.record_unseal(&form.circle, candidate);
            let target = sanitize_next(&form.next);
            Redirect::to(&target).into_response()
        }
        Err(FetchAssetError::DecryptFailed { .. }) => unseal_form_page(
            &state,
            &form.circle,
            &form.next,
            Some("wrong passphrase, try again"),
        ),
        Err(other) => {
            // RPC failure / not published for both anchors — surface
            // the error without revealing whether the passphrase was
            // even tried. The operator can re-attempt once the chain
            // is reachable again.
            unseal_form_page(
                &state,
                &form.circle,
                &form.next,
                Some(&format!("could not validate passphrase: {other}")),
            )
        }
    }
}

/// Render the unseal form, optionally with an error banner. Used both
/// for the GET-style render (from `passphrase_error_page`) and for the
/// re-render after a failed `POST /unseal`.
fn unseal_form_page(
    state: &PortalState,
    circle_id: &str,
    next_url: &str,
    error: Option<&str>,
) -> Response {
    let banner = match error {
        Some(msg) => format!(
            r#"<p class="error" role="alert"><strong>Unseal failed:</strong> {}</p>"#,
            html_escape(msg),
        ),
        None => String::new(),
    };
    let configured = state.chain.configured_passphrase().is_some();
    let configured_hint = if configured {
        r#"<p class="hint">The portal's boot-time passphrase is set but didn't decrypt this circle — try the operator's circle-specific passphrase here.</p>"#
    } else {
        r#"<p class="hint">No boot-time passphrase is configured; submit the operator's sealed-policy passphrase to view this circle.</p>"#
    };
    let body = format!(
        r#"<div class="confirm-card">
<h2>Unlock this circle</h2>
<p>This circle's assets are sealed. The portal needs the operator's passphrase to decrypt them.</p>
<p>Circle: <code>{circle}</code></p>
{configured_hint}
{banner}
<form action="/unseal" method="post" autocomplete="off">
<input type="hidden" name="circle" value="{circle}">
<input type="hidden" name="next" value="{next}">
<label for="pp">Passphrase</label>
<input id="pp" name="passphrase" type="password" autofocus required>
<button type="submit">Unlock</button>
</form>
<p class="hint">The passphrase is cached in memory for the lifetime of this portal process — restart re-prompts. It is never written to disk.</p>
</div>"#,
        circle = html_escape(circle_id),
        next = html_escape(next_url),
        banner = banner,
        configured_hint = configured_hint,
    );
    let status = if error.is_some() {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::PRECONDITION_FAILED
    };
    let html = render_shell("Unlock circle", next_url, &body);
    (status, Html(html)).into_response()
}

/// Restrict the post-unseal redirect to known-safe in-portal paths.
/// Anything else (absolute URL, scheme, foreign host) collapses to `/`.
fn sanitize_next(next: &str) -> String {
    if next.starts_with("/o/")
        || next.starts_with("/raw")
        || next.starts_with("/api/")
        || next == "/"
        || next.starts_with("/?")
    {
        next.to_string()
    } else {
        "/".to_string()
    }
}

// ─── helpers ──────────────────────────────────────────────────────────

// `clippy::literal_string_with_formatting_args` mis-fires on these
// `String::replace` placeholders because they look like `format!` slots.
// They're literal `{title}`/`{url}`/`{inner}` substrings in the
// hand-written HTML in `static_assets.rs`. Allow the lint per-function.
#[allow(clippy::literal_string_with_formatting_args)]
fn render_shell(title: &str, url: &str, inner: &str) -> String {
    PAGE_SHELL
        .replace("{title}", &html_escape(title))
        .replace("{url}", &html_escape(url))
        .replace("{inner}", inner)
}

fn confirm_interstitial(state: &PortalState, url: &str, circle_id: &str) -> Response {
    let token = state.token_for(circle_id);
    let next_b64 = B64URL.encode(url.as_bytes());
    let next_path = format!("/o/{next_b64}");
    let body = format!(
        r#"<div class="confirm-card">
<h2>Approve this circle?</h2>
<p>This is the first time this portal session has been asked to fetch from circle:</p>
<p><code>{circle}</code></p>
<p>Requested asset: <code>{url}</code></p>
<p>Approving lets the portal fetch <em>any</em> asset path from this circle for the rest of this session. The approval does NOT persist across portal restarts.</p>
<form action="/approve" method="post">
<input type="hidden" name="circle" value="{circle}">
<input type="hidden" name="token" value="{token}">
<input type="hidden" name="next" value="{next_path}">
<button type="submit">Approve and fetch</button>
</form>
</div>"#,
        circle = html_escape(circle_id),
        url = html_escape(url),
        token = html_escape(&token),
        next_path = html_escape(&next_path),
    );
    Html(render_shell("Approve circle?", url, &body)).into_response()
}

/// Dispatch a [`FetchAssetError`] to the appropriate sandboxed error
/// page. Sealed-asset decrypt failures now route to the interactive
/// unseal form (POST /unseal) instead of the old static 412 hint; every
/// other variant flows through the existing tunnel-down 502 renderer.
fn fetch_error_page(
    state: &PortalState,
    url: &str,
    circle_id: &str,
    err: FetchAssetError,
) -> Response {
    match err {
        FetchAssetError::MissingPassphrase { .. } | FetchAssetError::DecryptFailed { .. } => {
            // Render the interactive unseal form pre-filled with this
            // circle id. On submit, the operator's passphrase goes
            // through `POST /unseal` and we redirect them back here.
            unseal_form_page(state, circle_id, url, None)
        }
        other => tunnel_error_page(url, &other.to_string()),
    }
}

fn tunnel_error_page(url: &str, message: &str) -> Response {
    let body = format!(
        r#"<div class="confirm-card">
<h2 class="error">Couldn't fetch asset</h2>
<p>The portal couldn't reach the chain RPC. Likely causes:</p>
<ul>
<li>VPN tunnel is down — bring it up with <code>octravpn connect-v2 …</code></li>
<li>RPC endpoint unreachable</li>
<li>Asset doesn't exist at the requested path</li>
</ul>
<p>Underlying error:</p>
<pre>{err}</pre>
<p>URL: <code>{url}</code></p>
</div>"#,
        url = html_escape(url),
        err = html_escape(message),
    );
    let html = render_shell("Fetch failed", url, &body);
    (StatusCode::BAD_GATEWAY, Html(html)).into_response()
}

fn error_page(status: StatusCode, url: &str, message: &str) -> Response {
    let body = format!(
        r#"<div class="confirm-card">
<h2 class="error">Request rejected</h2>
<p>{msg}</p>
<p>URL: <code>{url}</code></p>
</div>"#,
        msg = html_escape(message),
        url = html_escape(url),
    );
    let html = render_shell("Error", url, &body);
    (status, Html(html)).into_response()
}

fn render_bytes(url: &str, bytes: Vec<u8>, mime: SniffedMime) -> Response {
    match mime {
        SniffedMime::Png
        | SniffedMime::Jpeg
        | SniffedMime::Gif
        | SniffedMime::Webp
        | SniffedMime::Svg => render_image(url, &bytes, mime),
        SniffedMime::Pdf => render_raw(url, &bytes, mime),
        SniffedMime::Json => render_json(url, &bytes),
        SniffedMime::Html => render_sandboxed_html(url, &bytes),
        SniffedMime::PlainText => render_plain_text(url, &bytes),
        SniffedMime::OctetStream => render_save_as(url, bytes),
    }
}

fn render_image(url: &str, bytes: &[u8], mime: SniffedMime) -> Response {
    // Inline as base64 data URI so we don't have to plumb a separate
    // /asset/<id> route for the raw bytes. ~33% size bloat is fine for
    // policy-size assets (4k bucket).
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let body = format!(
        r#"<img class="asset" src="data:{ct};base64,{b64}" alt="circle asset">"#,
        ct = mime.content_type(),
    );
    Html(render_shell("image", url, &body)).into_response()
}

fn render_raw(url: &str, bytes: &[u8], mime: SniffedMime) -> Response {
    // For PDF we serve a download link rather than embed (cross-browser
    // PDF rendering is a mess and embedding a PDF can execute JS in
    // some viewers).
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let body = format!(
        r#"<p>Asset is a {ct} ({size} bytes). PDFs are not embedded inline — download to view.</p>
<p><a download="circle-asset" href="data:{ct};base64,{b64}">Download</a></p>"#,
        ct = mime.content_type(),
        size = bytes.len(),
    );
    Html(render_shell("download", url, &body)).into_response()
}

fn render_json(url: &str, bytes: &[u8]) -> Response {
    // Pretty-print as text. We DON'T parse-and-rerender to keep the
    // exact byte sequence visible if the operator wants to verify a
    // content-addressed hash.
    let text = std::str::from_utf8(bytes).unwrap_or("<invalid UTF-8>");
    let pretty = serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| serde_json::to_string_pretty(&v).ok())
        .unwrap_or_else(|| text.to_string());
    let body = format!("<pre>{}</pre>", html_escape(&pretty));
    Html(render_shell("json", url, &body)).into_response()
}

fn render_sandboxed_html(url: &str, bytes: &[u8]) -> Response {
    let html = std::str::from_utf8(bytes).unwrap_or("<invalid UTF-8 in HTML payload>");
    let body = format!(
        r#"<iframe class="sandbox-frame" sandbox="allow-popups" srcdoc="{srcdoc}"></iframe>"#,
        srcdoc = attr_escape(html),
    );
    Html(render_shell("html (sandboxed)", url, &body)).into_response()
}

fn render_plain_text(url: &str, bytes: &[u8]) -> Response {
    let text = std::str::from_utf8(bytes).unwrap_or("<invalid UTF-8>");
    let body = format!("<pre>{}</pre>", html_escape(text));
    Html(render_shell("text", url, &body)).into_response()
}

fn render_save_as(url: &str, bytes: Vec<u8>) -> Response {
    // Serve as octet-stream with a content-disposition so the browser
    // pops a Save-As dialog. We could render a chrome page instead but
    // operators who arrived here intentionally (curl, save-link, etc.)
    // shouldn't have to click again.
    let len = bytes.len();
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            SniffedMime::OctetStream.content_type(),
        )
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"circle-asset.bin\"",
        )
        .header(header::CONTENT_LENGTH, len.to_string())
        .body(Body::from(bytes));
    match resp {
        Ok(r) => r,
        Err(e) => error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            url,
            &format!("response build: {e}"),
        ),
    }
}

/// Escape `<>&"'` for HTML body text.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape for use inside an HTML attribute value (double-quoted).
/// Same as body escape — already double-quoted attributes are safe with
/// `&quot;`. We keep them separate so the intent is grep-able.
fn attr_escape(s: &str) -> String {
    html_escape(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::mime::sniff;
    use axum::http::Request;
    use octravpn_core::rpc::RpcClient;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    /// Build a portal state with no real RPC — uses a bogus endpoint so
    /// any fetch call surfaces as an RPC error. The tests that need a
    /// working RPC layer use a stub mock server.
    fn state_no_chain() -> PortalState {
        let rpc = RpcClient::new("http://127.0.0.1:1");
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        PortalState::new(chain)
    }

    async fn body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn index_renders() {
        let app = router(state_no_chain());
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("oct://"));
        assert!(body.contains("<form"));
    }

    #[tokio::test]
    async fn healthz_replies_ok() {
        let app = router(state_no_chain());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "ok");
    }

    #[tokio::test]
    async fn sandbox_html_response_has_sandbox_attribute() {
        let bytes = b"<!DOCTYPE html><html><body>hi</body></html>".to_vec();
        let mime = sniff(&bytes);
        let resp = render_bytes("oct://circleX/index.html", bytes, mime);
        let body = body_string(resp).await;
        assert!(
            body.contains(r#"sandbox="allow-popups""#),
            "expected sandbox attribute, got: {body}",
        );
        assert!(!body.contains("allow-scripts"));
        assert!(!body.contains("allow-same-origin"));
    }

    #[tokio::test]
    async fn confirm_required_for_new_circle() {
        // First-time fetch for an unknown circle returns the confirm
        // page (200 HTML) — NOT the asset.
        let state = state_no_chain();
        let app = router(state.clone());
        let url = "oct://circleNEW/policy.json";
        let b64 = B64URL.encode(url.as_bytes());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/o/{b64}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("Approve this circle?"), "got: {body}");
        // Importantly: no fetch happened.
        assert!(!state.is_allowed("circleNEW"));
    }

    #[tokio::test]
    async fn approval_token_round_trips() {
        let state = state_no_chain();
        let app = router(state.clone());
        let circle = "circleApprove";
        let token = state.token_for(circle);

        // Valid token → 303 redirect, circle added to allow_set.
        let form_body = format!(
            "circle={c}&token={t}&next=/o/abc",
            c = urlenc(circle),
            t = urlenc(&token),
        );
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/approve")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.status().is_redirection(),
            "expected redirect, got {}",
            resp.status()
        );
        assert!(state.is_allowed(circle));

        // Invalid token → 401 and circle remains *previously* allowed
        // (but the bad token doesn't add a new one).
        let bad = format!(
            "circle={c}&token=deadbeef&next=/o/abc",
            c = urlenc("circleOther"),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/approve")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(bad))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(!state.is_allowed("circleOther"));
    }

    #[tokio::test]
    async fn tunnel_down_serves_clear_error() {
        // No RPC server is listening on 127.0.0.1:1 → fetch errors.
        // Approve the circle so we get past the confirm gate.
        let state = state_no_chain();
        state.allow("circleTUN");
        let app = router(state);
        let url = "oct://circleTUN/policy.json";
        let b64 = B64URL.encode(url.as_bytes());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/o/{b64}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body = body_string(resp).await;
        assert!(body.contains("Couldn&#39;t fetch asset") || body.contains("Couldn't fetch asset"));
        assert!(body.contains("VPN tunnel is down") || body.contains("tunnel"));
        // No raw stack trace / panic backtrace.
        assert!(!body.to_lowercase().contains("panic"));
    }

    /// Tiny form-urlencoder for test bodies only. Production handlers
    /// use axum's `Form<…>` extractor.
    fn urlenc(s: &str) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char);
                }
                _ => {
                    let _ = write!(out, "%{b:02X}");
                }
            }
        }
        out
    }

    /// Smoke that the mocked-chain branch returns the bytes verbatim.
    /// Uses a real (loopback) axum stub instead of mocking inside
    /// `RpcClient` so we exercise the wire path.
    #[tokio::test]
    async fn resolve_returns_bytes_via_mocked_chain() {
        // Spawn a tiny axum server that pretends to be the chain RPC.
        let mock_app: Router = Router::new().route(
            "/",
            post(
                |axum::Json(req): axum::Json<serde_json::Value>| async move {
                    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                    let id = req.get("id").cloned().unwrap_or(json!(1));
                    if method == "circle_asset_ciphertext_by_resource_key" {
                        let payload = b"plain text from the chain RPC";
                        let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "ciphertext_b64": b64,
                                "plaintext_hash": "0".repeat(64),
                                "key_id": "default",
                            }
                        }))
                    } else {
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": { "code": -32601, "message": "method not found" },
                        }))
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mock_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, mock_app).await.unwrap();
        });
        // Give the listener a tick to be ready.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let rpc = RpcClient::new(format!("http://{mock_addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let state = PortalState::new(chain);
        state.allow("circleMOCK");
        let app = router(state);

        // /api/resolve must report the size + mime.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/resolve?u={}",
                        urlenc("oct://circleMOCK/policy.txt")
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            body.get("size").and_then(serde_json::Value::as_u64),
            Some(29)
        );
        assert!(body
            .get("mime")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .starts_with("text/plain"));

        // /o/<b64> must return 200 with the bytes embedded in the page.
        let url = "oct://circleMOCK/policy.txt";
        let b64 = B64URL.encode(url.as_bytes());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/o/{b64}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(
            body.contains("plain text from the chain RPC"),
            "expected bytes in body: {body}",
        );
    }

    // ─── /raw + /unseal + /confirm?accept=cli  ────────────────────────

    /// Mock RPC factory that returns a single sealed envelope under
    /// any resource key — good enough for these route tests because
    /// the chain RPC layer is exercised by `portal::chain::tests`.
    async fn spawn_sealed_rpc(
        circle_id: &str,
        passphrase: &str,
        plaintext: &[u8],
    ) -> (SocketAddr, String, String) {
        use octravpn_core::circle::{encrypt_sealed_bytes, PaddingClass};
        let (ct_b64, ph_hex) = encrypt_sealed_bytes(
            circle_id,
            "default",
            passphrase,
            plaintext,
            PaddingClass::None,
        )
        .unwrap();
        let result = json!({
            "ciphertext_b64": ct_b64,
            "plaintext_hash": ph_hex,
            "key_id": "default",
        });
        let result_arc = Arc::new(result);
        let app: Router = Router::new().route(
            "/",
            post(move |Json(req): Json<serde_json::Value>| {
                let result = Arc::clone(&result_arc);
                async move {
                    let id = req.get("id").cloned().unwrap_or(json!(1));
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": (*result).clone(),
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        (addr, ct_b64, ph_hex)
    }

    #[tokio::test]
    async fn raw_endpoint_gates_on_unapproved_circle_with_412() {
        let state = state_no_chain();
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/raw?u={}", urlenc("oct://circRAW/policy.json")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("circle not approved")
        );
        assert!(body.get("approve_url").is_some());
    }

    #[tokio::test]
    async fn confirm_accept_cli_returns_token_json_without_allowing_circle() {
        let state = state_no_chain();
        let app = router(state.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/confirm?u={}&accept=cli",
                        urlenc("oct://circCLI/policy.json"),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert!(body.get("token").and_then(|v| v.as_str()).is_some());
        assert_eq!(
            body.get("approved").and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert!(!state.is_allowed("circCLI"));
    }

    #[tokio::test]
    async fn raw_endpoint_serves_bytes_after_token_approval() {
        let (addr, _ct, _ph) =
            spawn_sealed_rpc("circRAWAUTH", "open-sesame", b"raw plain bytes").await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0).with_passphrase("open-sesame");
        let state = PortalState::new(chain);
        let token = state.token_for("circRAWAUTH");
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/raw?u={}&token={}",
                        urlenc("oct://circRAWAUTH/policy.json"),
                        urlenc(&token),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Content-Type from sniff — "raw plain bytes" is UTF-8 text.
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(ct.starts_with("text/plain"), "got CT: {ct}");
        let body = body_string(resp).await;
        assert_eq!(body, "raw plain bytes");
    }

    #[tokio::test]
    async fn raw_endpoint_dl_param_sets_attachment_disposition() {
        let (addr, _ct, _ph) = spawn_sealed_rpc("circDL", "pp", b"raw download bytes").await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0).with_passphrase("pp");
        let state = PortalState::new(chain);
        state.allow("circDL");
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/raw?u={}&dl=1",
                        urlenc("oct://circDL/folder/asset.txt"),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cd = resp
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(cd.starts_with("attachment;"), "got CD: {cd}");
        assert!(cd.contains("asset.txt"), "got CD: {cd}");
    }

    #[tokio::test]
    async fn raw_endpoint_412_on_sealed_without_passphrase() {
        let (addr, _ct, _ph) = spawn_sealed_rpc("circSEAL", "right", b"plain").await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        // No passphrase configured → MissingPassphrase.
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let state = PortalState::new(chain);
        state.allow("circSEAL");
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/raw?u={}", urlenc("oct://circSEAL/policy.json"),))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(
            body.get("code").and_then(|v| v.as_str()),
            Some("sealed_decrypt_failed"),
        );
    }

    #[tokio::test]
    async fn unseal_form_round_trips_with_correct_passphrase() {
        let (addr, _ct, _ph) =
            spawn_sealed_rpc("circUNSEAL", "operator-pass", b"decrypted body").await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let state = PortalState::new(chain);
        state.allow("circUNSEAL"); // pre-approve so we focus on unseal
        let app = router(state.clone());
        // Submit the correct passphrase.
        let form = format!(
            "circle={c}&passphrase={p}&next={n}",
            c = urlenc("circUNSEAL"),
            p = urlenc("operator-pass"),
            n = urlenc("/o/abc"),
        );
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/unseal")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.status().is_redirection(),
            "expected redirect, got {}",
            resp.status(),
        );
        // Cache hit: the source returns the cached passphrase.
        let source = state.passphrase_source();
        assert!(source.passphrase_for("circUNSEAL").is_some());
    }

    #[tokio::test]
    async fn unseal_form_rerenders_with_error_on_wrong_passphrase() {
        let (addr, _ct, _ph) = spawn_sealed_rpc("circBAD", "right-pass", b"decrypted body").await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let state = PortalState::new(chain);
        let app = router(state.clone());
        let form = format!(
            "circle={c}&passphrase={p}&next={n}",
            c = urlenc("circBAD"),
            p = urlenc("wrong-pass"),
            n = urlenc("/o/abc"),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/unseal")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_string(resp).await;
        assert!(body.contains("wrong passphrase"), "body: {body}");
        // Cache miss: nothing got stored.
        let source = state.passphrase_source();
        assert!(source.passphrase_for("circBAD").is_none());
    }

    #[tokio::test]
    async fn unseal_form_rejects_empty_passphrase() {
        let state = state_no_chain();
        let app = router(state);
        let form = format!(
            "circle={c}&passphrase=&next={n}",
            c = urlenc("circEMPTY"),
            n = urlenc("/o/abc"),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/unseal")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_string(resp).await;
        assert!(body.contains("passphrase is empty"), "body: {body}");
    }

    #[tokio::test]
    async fn sanitize_next_clamps_off_origin_targets() {
        assert_eq!(sanitize_next("/o/abc"), "/o/abc");
        assert_eq!(sanitize_next("/raw?u=foo"), "/raw?u=foo");
        assert_eq!(sanitize_next("/api/resolve?u=foo"), "/api/resolve?u=foo");
        assert_eq!(sanitize_next("/"), "/");
        // Off-origin / scheme attacks collapse to root.
        assert_eq!(sanitize_next("https://evil/"), "/");
        assert_eq!(sanitize_next("//evil/"), "/");
        assert_eq!(sanitize_next("javascript:alert(1)"), "/");
    }

    #[test]
    fn last_path_component_picks_final_segment() {
        assert_eq!(last_path_component("/policy.json"), "policy.json");
        assert_eq!(last_path_component("/a/b/c.txt"), "c.txt");
        assert_eq!(last_path_component("/"), "circle-asset.bin");
    }

    #[test]
    fn passphrase_error_page_renders_interactive_form() {
        // The sealed-decrypt path now renders the unseal form, not a
        // static 412. Smoke test that critical pieces are present.
        let state = state_no_chain();
        let err = FetchAssetError::MissingPassphrase {
            circle_id: "circFORM".into(),
            path: "/policy.json".into(),
        };
        let resp = fetch_error_page(&state, "oct://circFORM/policy.json", "circFORM", err);
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        let body = futures_executor_block_on(body_string(resp));
        assert!(body.contains(r#"action="/unseal""#), "body: {body}");
        assert!(body.contains(r#"name="passphrase""#), "body: {body}");
        assert!(body.contains("circFORM"));
    }

    /// Tiny block_on helper for the sync `passphrase_error_page` test.
    /// Uses a fresh single-thread runtime so it doesn't tangle with
    /// the outer `#[tokio::test]` runtimes.
    fn futures_executor_block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    // ── Phase-Z extra route coverage ─────────────────────────────────

    /// Helper: spawn a mock RPC that serves `plaintext` for any
    /// `circle_asset_ciphertext_by_resource_key` call. Returns the
    /// listening address.
    async fn spawn_plain_rpc(plaintext: &[u8]) -> SocketAddr {
        let payload = plaintext.to_vec();
        let app: Router = Router::new().route(
            "/",
            post(move |Json(req): Json<serde_json::Value>| {
                let payload = payload.clone();
                async move {
                    let id = req.get("id").cloned().unwrap_or(json!(1));
                    let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "ciphertext_b64": b64,
                            "plaintext_hash": "0".repeat(64),
                            "key_id": "default",
                        }
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        addr
    }

    fn state_with_addr(addr: SocketAddr) -> PortalState {
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        PortalState::new(chain)
    }

    // ── /go endpoint ─────────────────────────────────────────────────

    #[tokio::test]
    async fn go_redirects_to_b64_for_valid_url() {
        let app = router(state_no_chain());
        let url = "oct://circGo/policy.json";
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/go?u={}", urlenc(url)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.status().is_redirection());
        let loc = resp
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(loc.starts_with("/o/"));
    }

    #[tokio::test]
    async fn go_400s_for_bad_url() {
        let app = router(state_no_chain());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/go?u={}", urlenc("not-an-oct-url")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_string(resp).await;
        assert!(body.contains("oct://"));
    }

    // ── /o/<b64> bad-input paths ─────────────────────────────────────

    #[tokio::test]
    async fn view_asset_400s_on_bad_base64() {
        let app = router(state_no_chain());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/o/!!!-not-base64-!!!")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_string(resp).await;
        assert!(body.contains("bad base64"));
    }

    #[tokio::test]
    async fn view_asset_400s_on_non_utf8_url() {
        // base64url-encode raw 0xFF bytes — decodes successfully but
        // isn't valid UTF-8 for the URL.
        let bad = B64URL.encode([0xff, 0xfe, 0xfd]);
        let app = router(state_no_chain());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/o/{bad}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn view_asset_400s_on_bad_oct_url() {
        let url = "https://not-oct/x";
        let app = router(state_no_chain());
        let b64 = B64URL.encode(url.as_bytes());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/o/{b64}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── /api/resolve ─────────────────────────────────────────────────

    #[tokio::test]
    async fn api_resolve_returns_metadata_for_plaintext_asset() {
        let addr = spawn_plain_rpc(b"hello from resolve").await;
        let state = state_with_addr(addr);
        state.allow("circRESOLVE");
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/resolve?u={}",
                        urlenc("oct://circRESOLVE/x.txt")
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(
            body.get("circle_id").and_then(|v| v.as_str()),
            Some("circRESOLVE")
        );
        assert_eq!(body.get("path").and_then(|v| v.as_str()), Some("/x.txt"));
        assert_eq!(
            body.get("size").and_then(serde_json::Value::as_u64),
            Some(18)
        );
        assert!(body
            .get("mime")
            .and_then(|v| v.as_str())
            .unwrap()
            .starts_with("text/plain"));
        assert_eq!(
            body.get("renderable").and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }

    #[tokio::test]
    async fn api_resolve_rejects_bad_url() {
        let app = router(state_no_chain());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/resolve?u={}", urlenc("not-oct")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert!(body.get("error").is_some());
    }

    #[tokio::test]
    async fn api_resolve_502_when_rpc_unreachable() {
        // No chain → RPC fails → 502 BAD_GATEWAY.
        let state = state_no_chain();
        state.allow("circDOWN");
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/resolve?u={}", urlenc("oct://circDOWN/x.txt")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(
            body.get("hint")
                .and_then(|v| v.as_str())
                .map(|s| s.contains("tunnel")),
            Some(true),
        );
    }

    #[tokio::test]
    async fn api_resolve_412_when_sealed_without_passphrase() {
        let (addr, _ct, _ph) = spawn_sealed_rpc("circRESOLVE412", "secret", b"plain").await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        // No passphrase configured → MissingPassphrase.
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let state = PortalState::new(chain);
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/resolve?u={}",
                        urlenc("oct://circRESOLVE412/x.txt")
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    // ── /confirm interactive HTML path ───────────────────────────────

    #[tokio::test]
    async fn confirm_renders_html_interstitial_for_browser() {
        let app = router(state_no_chain());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/confirm?u={}",
                        urlenc("oct://circCONF/policy.json")
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("Approve this circle?"));
        assert!(body.contains("circCONF"));
        // Hidden token field for HMAC.
        assert!(body.contains(r#"name="token""#));
    }

    #[tokio::test]
    async fn confirm_400s_on_bad_url() {
        let app = router(state_no_chain());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/confirm?u={}", urlenc("bogus")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── /approve form ────────────────────────────────────────────────

    #[tokio::test]
    async fn approve_rejects_invalid_hex_token() {
        let state = state_no_chain();
        let app = router(state.clone());
        let form = format!(
            "circle={c}&token={t}&next=/",
            c = urlenc("circHEX"),
            t = "not-hex-at-all",
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/approve")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(!state.is_allowed("circHEX"));
    }

    // ── /healthz: always 200 ─────────────────────────────────────────

    #[tokio::test]
    async fn healthz_is_independent_of_chain_state() {
        // Even with an unreachable chain endpoint, /healthz answers OK.
        let state = state_no_chain();
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── sandbox attribute on each render path ────────────────────────

    #[tokio::test]
    async fn json_render_serves_pretty_pre_block() {
        let bytes = br#"{"a":1,"b":[2,3]}"#.to_vec();
        let resp = render_bytes("oct://c/x.json", bytes, sniff(b"{\"a\":1}"));
        let body = body_string(resp).await;
        assert!(body.contains("<pre>"));
        // Pretty-printed: keys on separate lines.
        assert!(body.contains("\"a\":") || body.contains("&quot;a&quot;"));
    }

    #[tokio::test]
    async fn image_render_emits_data_uri() {
        let png: Vec<u8> = b"\x89PNG\r\n\x1a\n"
            .iter()
            .chain(std::iter::repeat(&0u8).take(32))
            .copied()
            .collect();
        let resp = render_bytes("oct://c/img.png", png.clone(), sniff(&png));
        let body = body_string(resp).await;
        assert!(
            body.contains(r#"src="data:image/png;base64,"#),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn plain_text_render_uses_pre() {
        let bytes = b"some plain text\nwith newlines".to_vec();
        let resp = render_bytes("oct://c/x.txt", bytes, SniffedMime::PlainText);
        let body = body_string(resp).await;
        assert!(body.contains("<pre>"));
        assert!(body.contains("some plain text"));
        // HTML escaping is in place — even though there's no <, & should
        // not appear bare unless escaped.
        let bytes2 = b"line with <script>".to_vec();
        let resp = render_bytes("oct://c/x.txt", bytes2, SniffedMime::PlainText);
        let body = body_string(resp).await;
        assert!(body.contains("&lt;script&gt;"), "must HTML-escape");
    }

    #[tokio::test]
    async fn html_render_is_inside_sandboxed_iframe() {
        let bytes = b"<html><body><script>alert(1)</script></body></html>".to_vec();
        let resp = render_bytes("oct://c/x.html", bytes, SniffedMime::Html);
        let body = body_string(resp).await;
        assert!(body.contains(r#"sandbox="allow-popups""#));
        // The script payload is embedded as srcdoc (escaped) — must not
        // appear bare.
        assert!(!body.contains("<script>alert(1)</script>"));
        assert!(body.contains("&lt;script&gt;"));
    }

    #[tokio::test]
    async fn octet_stream_render_sets_save_as_headers() {
        // 0xFF 0xFE 0xFD is not valid UTF-8, no magic — OctetStream.
        let bytes = vec![0xff, 0xfe, 0xfd, 0x00, 0x01, 0x02];
        let mime = sniff(&bytes);
        assert_eq!(mime, SniffedMime::OctetStream);
        let resp = render_bytes("oct://c/x.bin", bytes, mime);
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
        assert_eq!(ct.to_str().unwrap(), "application/octet-stream");
        let cd = resp.headers().get(header::CONTENT_DISPOSITION).unwrap();
        assert!(cd.to_str().unwrap().contains("attachment"));
    }

    #[tokio::test]
    async fn svg_render_emits_data_uri_image() {
        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>".to_vec();
        let mime = sniff(&svg);
        assert_eq!(mime, SniffedMime::Svg);
        let resp = render_bytes("oct://c/x.svg", svg, mime);
        let body = body_string(resp).await;
        assert!(body.contains(r#"src="data:image/svg+xml;base64,"#));
    }

    // ── /raw bytes and Content-Type ─────────────────────────────────

    #[tokio::test]
    async fn raw_endpoint_serves_plaintext_with_text_mime() {
        let addr = spawn_plain_rpc(b"raw plaintext text bytes").await;
        let state = state_with_addr(addr);
        state.allow("circRP");
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/raw?u={}", urlenc("oct://circRP/asset.txt")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("text/plain"));
        let body = body_string(resp).await;
        assert_eq!(body, "raw plaintext text bytes");
    }

    #[tokio::test]
    async fn raw_endpoint_400s_on_bad_url() {
        let app = router(state_no_chain());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/raw?u={}", urlenc("nope")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn raw_endpoint_502_when_rpc_unreachable() {
        let state = state_no_chain();
        state.allow("circRD");
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/raw?u={}", urlenc("oct://circRD/asset.txt")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(body.get("code").and_then(|v| v.as_str()), Some("rpc"));
    }

    #[tokio::test]
    async fn raw_endpoint_octet_stream_sets_inline_disposition() {
        // Non-UTF8 bytes → OctetStream → defensive inline+filename
        // even without `&dl=1`.
        let raw_bytes: Vec<u8> = (0..16)
            .map(|i| (i * 13 + 7) as u8)
            .chain([0xff, 0xfe])
            .collect();
        // Spawn a stub that ships these exact bytes.
        let payload = raw_bytes.clone();
        let app_mock: Router = Router::new().route(
            "/",
            post(move |Json(req): Json<serde_json::Value>| {
                let payload = payload.clone();
                async move {
                    let id = req.get("id").cloned().unwrap_or(json!(1));
                    let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "ciphertext_b64": b64,
                            "plaintext_hash": "0".repeat(64),
                            "key_id": "default",
                        }
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mock_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app_mock).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;

        let state = state_with_addr(mock_addr);
        state.allow("circOCT");
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/raw?u={}", urlenc("oct://circOCT/blob.bin")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cd = resp
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cd.starts_with("inline;"));
        assert!(cd.contains("blob.bin"));
    }

    // ── PortalState helpers ─────────────────────────────────────────

    #[test]
    fn token_round_trip_passes_with_correct_hmac() {
        let state = state_no_chain();
        let t = state.token_for("circT");
        assert!(state.token_valid("circT", &t));
        // Wrong circle id breaks the verify.
        assert!(!state.token_valid("circOTHER", &t));
        // Wrong hex breaks the verify.
        assert!(!state.token_valid("circT", "not-hex"));
        assert!(!state.token_valid("circT", "deadbeef"));
    }

    #[test]
    fn record_unseal_round_trip_through_passphrase_source() {
        let state = state_no_chain();
        let pp = Arc::new(Zeroizing::new("hello".to_string()));
        state.record_unseal("circU", Arc::clone(&pp));
        let src = state.passphrase_source();
        let got = src.passphrase_for("circU").unwrap();
        assert_eq!(got.as_str(), "hello");
        // Missing circle falls back to the chain configured passphrase
        // (None here).
        assert!(src.passphrase_for("circMISS").is_none());
    }

    #[test]
    fn allow_set_isolates_circles() {
        let state = state_no_chain();
        state.allow("circA");
        assert!(state.is_allowed("circA"));
        assert!(!state.is_allowed("circB"));
    }

    // ── unseal: edge shapes ─────────────────────────────────────────

    #[tokio::test]
    async fn unseal_with_only_whitespace_passphrase_is_rejected() {
        let state = state_no_chain();
        let app = router(state);
        let form = format!(
            "circle={c}&passphrase={p}&next=/",
            c = urlenc("circWS"),
            p = urlenc("   \t  "),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/unseal")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_string(resp).await;
        assert!(body.contains("passphrase is empty"));
    }

    #[tokio::test]
    async fn unseal_redirect_clamps_to_root_for_offsite_next() {
        // Even with valid passphrase, an offsite `next=` must collapse
        // to `/`.
        let (addr, _ct, _ph) = spawn_sealed_rpc("circREDIR", "pp", b"plain bytes").await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let state = PortalState::new(chain);
        let app = router(state.clone());
        let form = format!(
            "circle={c}&passphrase={p}&next={n}",
            c = urlenc("circREDIR"),
            p = urlenc("pp"),
            n = urlenc("https://evil.example/steal"),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/unseal")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.status().is_redirection());
        let loc = resp
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(loc, "/", "off-site redirect must clamp to root");
    }

    // ── sanitize_next exhaustive ────────────────────────────────────

    #[test]
    fn sanitize_next_accepts_all_in_origin_prefixes() {
        for ok in &[
            "/o/abc",
            "/o/xyz/123",
            "/raw",
            "/raw?u=x&token=y",
            "/api/resolve",
            "/api/resolve?u=x",
            "/",
            "/?foo=bar",
        ] {
            assert_eq!(sanitize_next(ok), *ok, "{ok} must be preserved");
        }
    }

    #[test]
    fn sanitize_next_clamps_all_offsite_shapes() {
        for bad in &[
            "http://evil.example/x",
            "https://evil/",
            "//evil/",
            "/x",
            "/static",
            "javascript:alert(1)",
            "data:text/plain,hi",
            "ftp://x",
            "x",
            "",
        ] {
            assert_eq!(sanitize_next(bad), "/", "{bad} must clamp to /");
        }
    }

    // ── last_path_component edge cases ──────────────────────────────

    #[test]
    fn last_path_component_handles_trailing_slash() {
        assert_eq!(last_path_component("/foo/"), "foo");
        assert_eq!(last_path_component("/foo/bar/"), "bar");
    }

    #[test]
    fn last_path_component_strips_repeated_slashes() {
        assert_eq!(last_path_component("/a//b"), "b");
        assert_eq!(last_path_component("///"), "circle-asset.bin");
    }

    // ── urlencode_query_value: pinned format ─────────────────────────

    #[test]
    fn urlencode_query_value_preserves_safe_chars() {
        let s = urlencode_query_value("abcXYZ0123-_.~");
        assert_eq!(s, "abcXYZ0123-_.~");
    }

    #[test]
    fn urlencode_query_value_encodes_special_chars() {
        let s = urlencode_query_value("a b/c?d&e=f");
        assert_eq!(s, "a%20b%2Fc%3Fd%26e%3Df");
    }
}
