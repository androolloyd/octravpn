//! HTTP server: `/metrics`, `/analytics/series`, `/analytics/health`.
//!
//! Bearer-gated by default — mirrors the node's `/metrics` gate at
//! `octravpn-node/src/control.rs`. When `bearer_token` is `None` the
//! endpoints respond 503 rather than 404 so a mis-configured operator
//! sees a clear "endpoint disabled" signal instead of silently
//! getting nothing.

use std::{fmt::Write as _, net::SocketAddr, sync::Arc};

use axum::{
    extract::{Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;

use crate::{
    bucket::BucketWidth,
    indexer::{metric, IndexerState},
};

/// Constant-time string compare for bearer tokens. Matches the node's
/// helper at `control.rs::constant_time_eq_str`.
fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[derive(Clone)]
pub struct HttpState {
    pub indexer: Arc<IndexerState>,
    /// `Some(token)` ⇒ /metrics + /analytics/series require
    /// `Authorization: Bearer <token>`. `None` ⇒ endpoints return 503.
    pub bearer_token: Option<Arc<str>>,
    /// Wall-clock at server start; reported via /analytics/health.
    pub started_at_unix: u64,
}

impl HttpState {
    #[must_use]
    pub fn new(indexer: Arc<IndexerState>, bearer_token: Option<String>) -> Self {
        Self {
            indexer,
            bearer_token: bearer_token.map(Arc::from),
            started_at_unix: now_unix_secs(),
        }
    }

    /// Returns `Ok(())` if the request is authorized; `Err(response)`
    /// is the rejection the handler should return directly.
    ///
    /// The error variant is boxed so the `Result` stays small
    /// (`axum::Response` is ~128 bytes, which trips
    /// `clippy::result_large_err` at the workspace's `-D warnings`).
    fn check_auth(&self, headers: &HeaderMap) -> Result<(), Box<Response>> {
        let Some(want) = self.bearer_token.as_deref() else {
            return Err(Box::new(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "analytics endpoint disabled: set [analytics].bearer_token",
                )
                    .into_response(),
            ));
        };
        let got = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        if !got.is_some_and(|tok| ct_eq(tok, want)) {
            return Err(Box::new((StatusCode::UNAUTHORIZED, "").into_response()));
        }
        Ok(())
    }
}

/// Build the axum router. Exposed so the node hub can mount it on its
/// own listener if it wants (instead of using `serve`).
pub fn router(state: HttpState) -> Router {
    Router::new()
        .route("/metrics", get(prometheus_metrics))
        .route("/analytics/series", get(series))
        .route("/analytics/health", get(health))
        .with_state(state)
}

/// Bind + serve forever. Returns the bound `SocketAddr` via the oneshot
/// so the caller knows which port (when listening on `:0`).
pub async fn serve(
    listen_addr: &str,
    state: HttpState,
    ready: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    let local = listener.local_addr()?;
    if let Some(tx) = ready {
        let _ = tx.send(local);
    }
    tracing::info!(addr = %local, "octravpn-analytics http listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// /metrics
// ---------------------------------------------------------------------------

async fn prometheus_metrics(State(s): State<HttpState>, headers: HeaderMap) -> Response {
    if let Err(resp) = s.check_auth(&headers) {
        return *resp;
    }
    let mut body = String::new();
    // `write!` into String is infallible; the unwraps below silence
    // clippy::format_push_string without allocating per line.
    body.push_str(
        "# HELP octravpn_analytics_events_total Audit events ingested since process start.\n\
         # TYPE octravpn_analytics_events_total counter\n",
    );
    let _ = writeln!(
        body,
        "octravpn_analytics_events_total {}",
        s.indexer.total_events()
    );
    body.push_str(
        "# HELP octravpn_analytics_last_event_unix Timestamp of most-recent ingested event.\n\
         # TYPE octravpn_analytics_last_event_unix gauge\n",
    );
    let _ = writeln!(
        body,
        "octravpn_analytics_last_event_unix {}",
        s.indexer.last_event_ts()
    );
    // Per-metric, per-width totals over the retention window. The
    // exposition is `metric{window="1m"} value`.
    for m in metric::ALL {
        let _ = writeln!(
            body,
            "# HELP octravpn_analytics_{m} Total {m} events in the retention window.\n\
             # TYPE octravpn_analytics_{m} counter"
        );
        for w in BucketWidth::all() {
            let total = s.indexer.total(m, w);
            let _ = writeln!(
                body,
                "octravpn_analytics_{m}{{window=\"{label}\"}} {total}",
                label = w.label()
            );
        }
    }
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// /analytics/series
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SeriesQuery {
    metric: String,
    #[serde(default = "default_bucket")]
    bucket: String,
    #[serde(default)]
    from: Option<u64>,
    #[serde(default)]
    to: Option<u64>,
}

fn default_bucket() -> String {
    "5m".to_string()
}

async fn series(
    State(s): State<HttpState>,
    headers: HeaderMap,
    Query(q): Query<SeriesQuery>,
) -> Response {
    if let Err(resp) = s.check_auth(&headers) {
        return *resp;
    }
    let Some(width) = BucketWidth::parse(&q.bucket) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "unknown bucket; want one of 1m/5m/1h/1d"})),
        )
            .into_response();
    };
    if !metric::ALL.contains(&q.metric.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unknown metric",
                "want_one_of": metric::ALL,
            })),
        )
            .into_response();
    }
    let from = q.from.unwrap_or(0);
    let to = q.to.unwrap_or(u64::MAX);
    let points = s.indexer.series_in(&q.metric, width, from, to);
    let points_json: Vec<_> = points
        .into_iter()
        .map(|(ts, v)| json!({ "ts": ts, "value": v }))
        .collect();
    Json(json!({
        "metric": q.metric,
        "bucket": width.label(),
        "from": from,
        "to": if to == u64::MAX { 0 } else { to },
        "points": points_json,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// /analytics/health
// ---------------------------------------------------------------------------

async fn health(State(s): State<HttpState>) -> Response {
    let now = now_unix_secs();
    let uptime = now.saturating_sub(s.started_at_unix);
    let chain = s.indexer.chain_status();
    let last_event = s.indexer.last_event_ts();
    let last_ingest_age = if s.indexer.last_ingest_wall_unix() == 0 {
        None
    } else {
        Some(now.saturating_sub(s.indexer.last_ingest_wall_unix()))
    };
    let body = json!({
        "status": "ok",
        "uptime_s": uptime,
        "events_ingested": s.indexer.total_events(),
        "last_event_unix": last_event,
        "last_ingest_age_s": last_ingest_age,
        "chain": {
            "files_scanned": chain.files,
            "verified_lines": chain.verified_lines,
            "first_break": chain.first_break.as_ref().map(|(f, r)| json!({"file": f, "reason": r})),
        },
    });
    Json(body).into_response()
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{event::AnalyticsEvent, indexer::Indexer};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn make_state(token: Option<&str>) -> (HttpState, Indexer) {
        let idx = Indexer::new();
        let s = HttpState::new(idx.state.clone(), token.map(str::to_string));
        (s, idx)
    }

    #[tokio::test]
    async fn metrics_returns_503_when_unconfigured() {
        let (s, _) = make_state(None);
        let app = router(s);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn metrics_rejects_wrong_bearer() {
        let (s, _) = make_state(Some("expected"));
        let app = router(s);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header(AUTHORIZATION, "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn metrics_serves_prometheus_text_on_correct_bearer() {
        let (s, idx) = make_state(Some("ok"));
        idx.state.ingest(&AnalyticsEvent::SessionOpen {
            ts_unix: 1,
            session_id: "a".into(),
        });
        let app = router(s);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header(AUTHORIZATION, "Bearer ok")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("octravpn_analytics_sessions_opened{window=\"1m\"} 1"));
        assert!(body.contains("octravpn_analytics_events_total 1"));
    }

    #[tokio::test]
    async fn series_returns_json_points() {
        let (s, idx) = make_state(Some("ok"));
        for ts in [0, 60, 120, 180] {
            idx.state.ingest(&AnalyticsEvent::SessionOpen {
                ts_unix: ts,
                session_id: "s".into(),
            });
        }
        let app = router(s);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/analytics/series?metric=sessions_opened&bucket=1m")
                    .header(AUTHORIZATION, "Bearer ok")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["metric"], "sessions_opened");
        assert_eq!(v["bucket"], "1m");
        assert_eq!(v["points"].as_array().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn series_rejects_unknown_metric_and_bucket() {
        let (s, _) = make_state(Some("ok"));
        let app = router(s);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/analytics/series?metric=bogus&bucket=1m")
                    .header(AUTHORIZATION, "Bearer ok")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/analytics/series?metric=sessions_opened&bucket=17m")
                    .header(AUTHORIZATION, "Bearer ok")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn health_is_unauthenticated_and_returns_json() {
        let (s, _) = make_state(None);
        let app = router(s);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/analytics/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "ok");
    }
}
