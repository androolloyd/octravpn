//! Tailscale-style management web UI for OctraVPN.
//!
//! Axum server that:
//!   - Talks to a live Octra chain (or in-process mock) via JSON-RPC.
//!   - Serves an embedded single-page app with no JS framework.
//!   - Proxies an SSE event feed from a node's control plane so the
//!     UI can show live session activity.
//!
//! Auth: the UI binds to localhost by default. A signing wallet is
//! supplied via `--wallet`; write operations sign txs with it. For a
//! multi-user deployment, put the UI behind a reverse proxy with
//! authentication.

pub mod api;
pub mod state;

use std::sync::Arc;

use axum::{routing::get, Router};

pub use state::AdminState;

/// Build the full axum router with API + static SPA + SSE proxy.
pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles_css))
        .nest("/api", api::router())
        .with_state(state)
}

async fn index() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("assets/index.html"),
    )
}

async fn app_js() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        include_str!("assets/app.js"),
    )
}

async fn styles_css() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css")],
        include_str!("assets/styles.css"),
    )
}
