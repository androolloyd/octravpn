//! A local HTTP bridge for system browsers. Every URL carries a fixed read scope.
use crate::{
    application::{ApplicationHost, Bridge, Context, Request, Review},
    render, AssetResolver, Error, OctUrl, Provenance, MAX_ASSET_BYTES,
};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, OriginalUri, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{net::IpAddr, sync::Arc};

mod gateway;
pub use gateway::Gateway;

#[derive(Clone)]
pub struct Browser {
    resolver: Arc<dyn AssetResolver>,
    provenance: Provenance,
    scope: String,
    prefix: String,
    application: Option<Arc<Bridge>>,
}
impl Browser {
    pub fn new(resolver: Arc<dyn AssetResolver>, prefix: &str) -> Result<Self, Error> {
        if !(prefix.is_empty()
            || prefix.starts_with('/')
                && !prefix.ends_with('/')
                && prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_-".contains(&b)))
        {
            return Err(Error::Invalid("invalid browser mount prefix".into()));
        }
        let provenance = resolver.provenance();
        let scope = provenance.id();
        Ok(Self {
            resolver,
            provenance,
            scope,
            prefix: prefix.into(),
            application: None,
        })
    }
    /// Explicit host capability. The host must independently enforce wallet,
    /// execution and submission policy; browser approval is not chain finality.
    pub fn with_application(mut self, host: Arc<dyn ApplicationHost>) -> Result<Self, Error> {
        if !matches!(self.provenance, Provenance::Canonical(_)) {
            return Err(Error::Invalid(
                "Circle applications require a canonical snapshot".into(),
            ));
        }
        self.application = Some(Arc::new(Bridge::new(host)));
        Ok(self)
    }
    pub fn view_url(&self, url: &OctUrl) -> String {
        render::route(&self.prefix, &self.scope, "view", url)
    }
    pub fn asset_url(&self, url: &OctUrl) -> String {
        render::route(&self.prefix, &self.scope, "asset", url)
    }
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }
    pub fn router(self) -> Router {
        Router::new()
            .route("/", get(home))
            .route("/open", get(open))
            .route("/view/:scope/:circle/", get(view))
            .route("/view/:scope/:circle/*path", get(view))
            .route("/asset/:scope/:circle/", get(asset))
            .route("/asset/:scope/:circle/*path", get(asset))
            .route("/document/:scope/:circle/", get(document))
            .route("/document/:scope/:circle/*path", get(document))
            .route("/app/request", post(app_request))
            .route("/app/review", post(app_review))
            .route("/app/close", post(app_close))
            .layer(DefaultBodyLimit::max(super::application::MAX_REQUEST))
            .with_state(self)
    }
    fn parse_route(&self, original: &str, kind: &str) -> Result<OctUrl, Error> {
        let prefix = format!("{}/{kind}/{}/", self.prefix, self.scope);
        let path = original
            .strip_prefix(&prefix)
            .ok_or(Error::SnapshotChanged)?;
        OctUrl::parse(&format!("oct://{path}"))
    }
}

fn origin(headers: &HeaderMap) -> Result<String, Error> {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Error::Invalid("loopback Host required".into()))?;
    let authority = host
        .parse::<axum::http::uri::Authority>()
        .map_err(|_| Error::Invalid("invalid Host".into()))?;
    let hostname = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let ip = hostname
        .parse::<IpAddr>()
        .map_err(|_| Error::Invalid("browser requires a loopback Host".into()))?;
    if !ip.is_loopback()
        || host.contains('@')
        || authority.port().is_some() && authority.port_u16().is_none()
    {
        return Err(Error::Invalid("browser requires a loopback Host".into()));
    }
    let hostname = match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let port = authority
        .port_u16()
        .map_or(String::new(), |port| format!(":{port}"));
    Ok(format!("http://{hostname}{port}"))
}

fn secure(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    response
}
fn shell(title: &str, body: &str) -> Response {
    const SCRIPT: &str = include_str!("shell.js");
    let script_hash = STANDARD.encode(Sha256::digest(SCRIPT.as_bytes()));
    let html = format!("<!doctype html><html><head><meta charset=utf-8><meta name=viewport content=\"width=device-width\"><title>{}</title><style>body{{margin:0;background:#101820;color:#e8f1f2;font:16px system-ui}}header,main{{padding:16px}}a{{color:#70d6c1}}iframe{{border:0;width:100%;height:calc(100vh - 140px);background:white}}code{{overflow-wrap:anywhere}}input{{width:70%}}</style></head><body>{body}<script>{SCRIPT}</script></body></html>", render::escape(title));
    let mut response = Html(html).into_response();
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(&format!("default-src 'none'; script-src 'sha256-{script_hash}'; style-src 'unsafe-inline'; frame-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")).expect("fixed shell CSP"));
    secure(response)
}
fn failure(error: &Error) -> Response {
    let status = match &error {
        Error::NotFound => StatusCode::NOT_FOUND,
        Error::Sealed | Error::ApprovalRequired { .. } => StatusCode::PRECONDITION_FAILED,
        Error::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        Error::Unavailable(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::BAD_REQUEST,
    };
    let extra = match &error {
        Error::ApprovalRequired { approval_url }
            if approval_url.starts_with('/')
                && !approval_url.starts_with("//")
                && !approval_url.contains('\\')
                && !approval_url.chars().any(char::is_control) =>
        {
            format!(
                "<p><a href=\"{}\" target=_top>Review Circle access</a></p>",
                render::escape(approval_url)
            )
        }
        _ => String::new(),
    };
    let mut response = shell(
        "Circle unavailable",
        &format!(
            "<main><h1>Circle unavailable</h1><p>{}</p>{extra}</main>",
            render::escape(&error.to_string())
        ),
    );
    *response.status_mut() = status;
    response
}
async fn home(State(browser): State<Browser>, headers: HeaderMap) -> Response {
    if let Err(error) = origin(&headers) {
        return failure(&error);
    }
    shell("Octra", &format!("<main><h1>Browse Circles</h1><form action=\"{}/open\"><input name=u placeholder=\"oct://circle/path\" required><button>Open</button></form></main>", browser.prefix))
}
#[derive(Deserialize)]
struct OpenQuery {
    u: String,
}
async fn open(
    State(browser): State<Browser>,
    headers: HeaderMap,
    Query(query): Query<OpenQuery>,
) -> Response {
    if let Err(error) = origin(&headers) {
        return failure(&error);
    }
    match OctUrl::parse(&query.u) {
        Ok(url) => secure(Redirect::to(&browser.view_url(&url)).into_response()),
        Err(error) => failure(&error),
    }
}
async fn view(
    State(browser): State<Browser>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let origin = match origin(&headers) {
        Ok(origin) => origin,
        Err(error) => return failure(&error),
    };
    let url = match browser.parse_route(&uri.to_string(), "view") {
        Ok(url) => url,
        Err(error) => return failure(&error),
    };
    let provenance = match &browser.provenance {
        Provenance::Canonical(snapshot) => format!(
            "Epoch {} · {}",
            snapshot.epoch,
            render::escape(&snapshot.state_root)
        ),
        Provenance::UnpinnedRpc => "RPC response · snapshot not verified".into(),
    };
    let (asset, sandbox, controls) = if let Some(bridge) = &browser.application {
        let token = match bridge.open(
            Context {
                circle_id: url.circle_id.clone(),
                provenance: browser.provenance.clone(),
            },
            origin,
        ) {
            Ok(token) => token,
            Err(error) => return failure(&error),
        };
        let controls = format!("<section id=\"circle-host\" data-token=\"{token}\" data-api=\"{}/app\" data-navigation=\"{}/view/{}/\"><p id=\"app-status\"></p><dialog id=\"circle-review\"><h2>Review Circle call</h2><pre id=\"review-intent\" style=\"white-space:pre-wrap;overflow-wrap:anywhere;max-height:60vh;overflow:auto\"></pre><button id=\"review-decline\" type=\"button\">Decline</button><button id=\"review-approve\" type=\"button\">Approve call</button></dialog></section>", browser.prefix, browser.prefix, browser.scope);
        (
            render::route(&browser.prefix, &browser.scope, "document", &url),
            "allow-scripts",
            controls,
        )
    } else {
        (
            browser.asset_url(&url),
            "allow-top-navigation-by-user-activation",
            String::new(),
        )
    };
    let asset = render::escape(&asset);
    shell("Octra Circle", &format!("<header><form action=\"{}/open\"><input aria-label=\"Octra address\" name=u value=\"{}\"><button>Open</button></form><p>{provenance}</p>{controls}</header><iframe id=\"circle-content\" title=\"Circle content\" sandbox=\"{sandbox}\" src=\"{asset}\"></iframe>",browser.prefix,render::escape(&url.as_string())))
}
async fn asset(
    State(browser): State<Browser>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    serve_asset(browser, headers, uri.to_string(), false).await
}
async fn document(
    State(browser): State<Browser>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    if browser.application.is_none() {
        return failure(&Error::NotFound);
    }
    serve_asset(browser, headers, uri.to_string(), true).await
}
async fn serve_asset(
    browser: Browser,
    headers: HeaderMap,
    uri: String,
    executable: bool,
) -> Response {
    let origin = match origin(&headers) {
        Ok(origin) => origin,
        Err(error) => return failure(&error),
    };
    let url = match browser.parse_route(&uri, if executable { "document" } else { "asset" }) {
        Ok(url) => url,
        Err(error) => return failure(&error),
    };
    resolved_asset(browser, origin, url, executable, false).await
}

async fn resolved_asset(
    browser: Browser,
    origin: String,
    url: OctUrl,
    executable: bool,
    gateway: bool,
) -> Response {
    let found = match browser.resolver.resolve(&url).await {
        Err(Error::NotFound) if url.is_directory() => match url.resolve("index.html") {
            Ok(index) => browser.resolver.resolve(&index).await,
            Err(error) => Err(error),
        },
        result => result,
    };
    let asset = match found {
        Ok(asset) => asset,
        Err(error) => return failure(&error),
    };
    if asset.provenance != browser.provenance {
        return failure(&Error::SnapshotChanged);
    }
    if asset.bytes.len() > MAX_ASSET_BYTES {
        return failure(&Error::TooLarge);
    }
    let content_type = asset
        .content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let is_html = content_type == "text/html";
    let bytes = if is_html {
        let rewritten = if gateway {
            render::rewrite_gateway(&asset.bytes, &url, &browser.scope)
        } else {
            let rewrite = if executable {
                render::rewrite_app
            } else {
                render::rewrite_html
            };
            rewrite(&asset.bytes, &url, &browser.prefix, &browser.scope)
        };
        match rewritten {
            Ok(bytes) => bytes,
            Err(error) => return failure(&error),
        }
    } else if content_type == "text/css" {
        match render::rewrite_stylesheet(
            &asset.bytes,
            &url,
            &browser.prefix,
            &browser.scope,
            gateway,
        ) {
            Ok(bytes) => bytes,
            Err(error) => return failure(&error),
        }
    } else {
        asset.bytes.to_vec()
    };
    // Restrict active or unknown formats to attachment. HTML alone passes the
    // bounded rewriter; SVG stays sandboxed even when opened as a document.
    let passive = is_html
        || browser.application.is_some()
            && matches!(
                content_type.as_str(),
                "text/javascript" | "application/javascript"
            )
        || matches!(
            content_type.as_str(),
            "text/css"
                | "text/plain"
                | "application/json"
                | "image/png"
                | "image/jpeg"
                | "image/gif"
                | "image/webp"
                | "image/svg+xml"
                | "image/avif"
                | "font/woff"
                | "font/woff2"
                | "audio/mpeg"
                | "audio/ogg"
                | "video/mp4"
                | "video/webm"
        );
    let mut response = Response::new(Body::from(bytes));
    let typ = if is_html {
        "text/html; charset=utf-8"
    } else if passive {
        &asset.content_type
    } else {
        "application/octet-stream"
    };
    let Ok(typ) = HeaderValue::from_str(typ) else {
        return failure(&Error::Invalid("invalid asset content type".into()));
    };
    response.headers_mut().insert(header::CONTENT_TYPE, typ);
    if !passive {
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"circle-asset\""),
        );
    }
    let csp = if gateway {
        render::public_asset_csp(&format!(
            "{origin}/snapshots/{}/{}/",
            browser.scope, url.circle_id
        ))
    } else {
        let csp = if executable && is_html {
            render::app_csp
        } else {
            render::asset_csp
        };
        csp(&origin, &browser.prefix, &browser.scope, &url.circle_id)
    };
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&csp).expect("validated CSP source"),
    );
    let mut response = secure(response);
    // The sandbox has an opaque origin. same-origin CORP would block its own
    // published CSS and images. Resource CSP still confines reads to this Circle
    // and snapshot; this route must not receive unauthorized private plaintext.
    response.headers_mut().insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("cross-origin"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    if gateway {
        if let Provenance::Canonical(snapshot) = &browser.provenance {
            for (key, value) in [
                ("x-octra-chain", snapshot.chain_id.clone()),
                ("x-octra-epoch", snapshot.epoch.to_string()),
                ("x-octra-state-root", snapshot.state_root.clone()),
            ] {
                let Ok(value) = HeaderValue::from_str(&value) else {
                    return failure(&Error::Invalid("invalid snapshot identity".into()));
                };
                response.headers_mut().insert(key, value);
            }
        }
    }
    response
}

fn app_auth(
    browser: &Browser,
    headers: &HeaderMap,
) -> Result<(Arc<Bridge>, String, String), Error> {
    let expected = origin(headers)?;
    if headers.get(header::ORIGIN).and_then(|h| h.to_str().ok()) != Some(expected.as_str()) {
        return Err(Error::Invalid(
            "same-origin browser request required".into(),
        ));
    }
    let token = headers
        .get("x-octra-session")
        .and_then(|h| h.to_str().ok())
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| Error::Invalid("Circle session required".into()))?;
    let bridge = browser.application.clone().ok_or(Error::NotFound)?;
    Ok((bridge, token.into(), expected))
}
fn app_reply(result: Result<serde_json::Value, Error>) -> Response {
    let (status, value) = match result {
        Ok(value) => (StatusCode::OK, value),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error": error.to_string()}),
        ),
    };
    secure((status, Json(value)).into_response())
}
async fn app_request(
    State(browser): State<Browser>,
    headers: HeaderMap,
    Json(request): Json<Request>,
) -> Response {
    let result = match app_auth(&browser, &headers) {
        Ok((bridge, token, origin)) => bridge.request(&token, &origin, request).await,
        Err(error) => Err(error),
    };
    app_reply(result)
}
async fn app_review(
    State(browser): State<Browser>,
    headers: HeaderMap,
    Json(review): Json<Review>,
) -> Response {
    let result = match app_auth(&browser, &headers) {
        Ok((bridge, token, origin)) => bridge.review(&token, &origin, review).await,
        Err(error) => Err(error),
    };
    app_reply(result)
}
async fn app_close(State(browser): State<Browser>, headers: HeaderMap) -> Response {
    app_reply(
        app_auth(&browser, &headers)
            .and_then(|(bridge, token, origin)| bridge.close(&token, &origin)),
    )
}
