//! axum routes for the `oct://` browser portal.
//!
//! Route table:
//!
//!   GET  /                — index page with URL bar
//!   GET  /go?u=<oct-url>  — redirects to /o/<b64> (browser-form action)
//!   GET  /o/{b64url}      — primary asset viewer
//!   GET  /api/resolve?u=  — JSON metadata (size + mime) without rendering
//!   GET  /confirm?u=<…>   — confirm-on-first-fetch interstitial
//!   POST /approve         — body: `circle=<…>&token=<…>&next=<…>`
//!   GET  /healthz         — liveness probe (always 200)
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
    collections::BTreeSet,
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

use crate::{
    commands::open_url::parse_oct_url,
    portal::{
        chain::{FetchAssetError, PortalChain},
        mime::{sniff, SniffedMime},
        static_assets::{INDEX_BODY, PAGE_SHELL},
    },
};

type HmacSha256 = Hmac<Sha256>;

/// Shared portal state. Cheaply cloneable (everything inside is `Arc`
/// or a small Copy).
#[derive(Clone)]
pub(crate) struct PortalState {
    pub chain: PortalChain,
    pub allow_set: Arc<Mutex<BTreeSet<String>>>,
    pub hmac_secret: Arc<[u8; 32]>,
}

impl PortalState {
    pub(crate) fn new(chain: PortalChain) -> Self {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        Self {
            chain,
            allow_set: Arc::new(Mutex::new(BTreeSet::new())),
            hmac_secret: Arc::new(secret),
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
        .route("/api/resolve", get(api_resolve))
        .route("/confirm", get(confirm_page))
        .route("/approve", post(approve))
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

async fn api_resolve(
    State(state): State<PortalState>,
    Query(q): Query<ResolveQuery>,
) -> Response {
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
    let bytes = match state
        .chain
        .fetch_circle_asset_bytes(&parsed.circle_id, &parsed.path)
        .await
    {
        Ok(b) => b,
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
    let mime = sniff(&bytes);
    Json(json!({
        "circle_id": parsed.circle_id,
        "path": parsed.path,
        "size": bytes.len(),
        "mime": mime.content_type(),
        "renderable": mime.renderable(),
        "allowed": state.is_allowed(&parsed.circle_id),
    }))
    .into_response()
}

async fn view_asset(
    State(state): State<PortalState>,
    Path(b64): Path<String>,
) -> Response {
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

    // Fetch.
    let bytes = match state
        .chain
        .fetch_circle_asset_bytes(&parsed.circle_id, &parsed.path)
        .await
    {
        Ok(b) => b,
        Err(e) => return fetch_error_page(&url, e),
    };

    render_bytes(&url, bytes)
}

async fn confirm_page(
    State(state): State<PortalState>,
    Query(q): Query<GoQuery>,
) -> Response {
    let parsed = match parse_oct_url(&q.u) {
        Ok(p) => p,
        Err(e) => return error_page(StatusCode::BAD_REQUEST, &q.u, &e.to_string()),
    };
    confirm_interstitial(&state, &q.u, &parsed.circle_id)
}

#[derive(Deserialize)]
struct ApproveForm {
    circle: String,
    token: String,
    next: String,
}

async fn approve(
    State(state): State<PortalState>,
    Form(form): Form<ApproveForm>,
) -> Response {
    if !state.token_valid(&form.circle, &form.token) {
        return (StatusCode::UNAUTHORIZED, "bad approval token").into_response();
    }
    state.allow(&form.circle);
    Redirect::to(&form.next).into_response()
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
/// page. Sealed-asset decrypt failures get a dedicated 412 page; every
/// other variant flows through the existing tunnel-down 502 renderer.
fn fetch_error_page(url: &str, err: FetchAssetError) -> Response {
    match err {
        FetchAssetError::MissingPassphrase { .. } | FetchAssetError::DecryptFailed { .. } => {
            passphrase_error_page(url, &err)
        }
        other => tunnel_error_page(url, &other.to_string()),
    }
}

/// 412 page for the two passphrase-related decrypt failures. Body text
/// tells the operator exactly which env var / config field to set, and
/// deliberately does NOT echo any ciphertext bytes.
fn passphrase_error_page(url: &str, err: &FetchAssetError) -> Response {
    let title = match err {
        FetchAssetError::MissingPassphrase { .. } => "Passphrase not configured",
        // Default covers DecryptFailed and (unreachable) other variants;
        // the dispatcher only sends decrypt-related errors here.
        _ => "Cannot decrypt sealed asset",
    };
    let body = format!(
        r#"<div class="confirm-card">
<h2 class="error">{title}</h2>
<p>Cannot decrypt asset: the operator's sealed-policy passphrase isn't configured locally. Set <code>OCTRAVPN_SEALED_PASSPHRASE</code> or <code>[v2].sealed_passphrase</code> in your <code>client.toml</code>.</p>
<p>If you already set one, it doesn't match the passphrase used to seal this asset.</p>
<p>Circle: <code>{circle}</code></p>
<p>Asset: <code>{path}</code></p>
<p>URL: <code>{url}</code></p>
</div>"#,
        title = html_escape(title),
        circle = html_escape(err.circle_id()),
        path = html_escape(err.path()),
        url = html_escape(url),
    );
    let html = render_shell(title, url, &body);
    (StatusCode::PRECONDITION_FAILED, Html(html)).into_response()
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

fn render_bytes(url: &str, bytes: Vec<u8>) -> Response {
    let mime = sniff(&bytes);
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
        .header(header::CONTENT_TYPE, SniffedMime::OctetStream.content_type())
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
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
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
        let resp = render_bytes("oct://circleX/index.html", bytes);
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
                    .header(
                        header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
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
                    .header(
                        header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
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
            post(|axum::Json(req): axum::Json<serde_json::Value>| async move {
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
            }),
        );
        let listener =
            tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
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
            &axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap(),
        )
        .unwrap();
        assert_eq!(body.get("size").and_then(serde_json::Value::as_u64), Some(29));
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
}
