//! HTTP-surface tests for `octravpn-analytics`. These complement the
//! inline `http::tests` module by covering:
//!
//!   - All 3 endpoints (`/metrics`, `/analytics/series`, `/analytics/health`)
//!     under the bearer-token gate matrix: missing → 503, wrong → 401,
//!     right → 200.
//!   - Prometheus-text validation (regex-shape + every metric appears
//!     for every width).
//!   - `/analytics/series` JSON shape per the spec: `metric`, `bucket`,
//!     `from`, `to`, `points: [{ts, value}]`.
//!   - `/analytics/health` reflects chain-verify "first_break" verbatim.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{header::AUTHORIZATION, Request, StatusCode},
};
use http_body_util::BodyExt;
use octravpn_analytics::{
    bucket::BucketWidth,
    event::AnalyticsEvent,
    http::{router, HttpState},
    indexer::{metric, ChainVerifyStatus, Indexer, IndexerState},
};
use serde_json::Value;
use tower::ServiceExt;

fn make_state(token: Option<&str>) -> (HttpState, Indexer) {
    let idx = Indexer::new();
    let s = HttpState::new(idx.state.clone(), token.map(str::to_string));
    (s, idx)
}

// ─────────────────────────────────────────────────────────────────────────
// 1. Bearer-token gate matrix — all three endpoints.
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn metrics_503_when_token_unconfigured() {
    let (s, _) = make_state(None);
    let app = router(s);
    let resp = app
        .oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn series_503_when_token_unconfigured() {
    let (s, _) = make_state(None);
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/analytics/series?metric=sessions_opened&bucket=1m")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn health_is_always_open_no_bearer_required() {
    // /analytics/health is intentionally unauthenticated so external
    // probes (k8s liveness, load balancers) don't need the token.
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
}

#[tokio::test]
async fn metrics_401_on_wrong_bearer() {
    let (s, _) = make_state(Some("right"));
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
async fn series_401_on_wrong_bearer() {
    let (s, _) = make_state(Some("right"));
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/analytics/series?metric=sessions_opened&bucket=1m")
                .header(AUTHORIZATION, "Bearer nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn metrics_401_on_missing_authorization_header() {
    // No header at all when token IS configured ⇒ 401, not 503.
    let (s, _) = make_state(Some("tok"));
    let app = router(s);
    let resp = app
        .oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn metrics_401_on_malformed_authorization_no_bearer_prefix() {
    let (s, _) = make_state(Some("tok"));
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(AUTHORIZATION, "tok") // missing "Bearer " prefix
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn all_three_endpoints_200_on_correct_bearer() {
    let (s, _) = make_state(Some("ok"));
    let app = router(s);

    for uri in [
        "/metrics",
        "/analytics/series?metric=sessions_opened&bucket=1m",
        "/analytics/health",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(AUTHORIZATION, "Bearer ok")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "uri {uri} should be 200");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 2. Prometheus exposition shape.
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn prometheus_exposition_has_help_and_type_per_metric() {
    let (s, idx) = make_state(Some("t"));
    idx.state.ingest(&AnalyticsEvent::SessionOpen {
        ts_unix: 100,
        session_id: "a".into(),
    });
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(AUTHORIZATION, "Bearer t")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();

    // Every documented metric appears with a `# HELP` + `# TYPE` block.
    for m in metric::ALL {
        let help_tag = format!("# HELP octravpn_analytics_{m}");
        let type_tag = format!("# TYPE octravpn_analytics_{m}");
        assert!(
            body.contains(&help_tag),
            "missing `{help_tag}` in:\n{body}"
        );
        assert!(
            body.contains(&type_tag),
            "missing `{type_tag}` in:\n{body}"
        );
        // Every width label appears as a metric line.
        for w in BucketWidth::all() {
            let line = format!("octravpn_analytics_{m}{{window=\"{}\"}}", w.label());
            assert!(
                body.contains(&line),
                "missing per-width line `{line}` in:\n{body}"
            );
        }
    }
}

#[tokio::test]
async fn prometheus_exposition_metric_lines_match_regex() {
    // Quick promtool-style validation: every non-comment, non-blank line
    // matches `name(\{labels\})? value` with a numeric value.
    let (s, idx) = make_state(Some("t"));
    idx.state.ingest(&AnalyticsEvent::SessionOpen {
        ts_unix: 7,
        session_id: "z".into(),
    });
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(AUTHORIZATION, "Bearer t")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = String::from_utf8(
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    // Simple regex: `^[a-zA-Z_][a-zA-Z0-9_]*(\{[^}]*\})? [0-9]+$`.
    let line_ok = |line: &str| -> bool {
        let mut it = line.splitn(2, ' ');
        let Some(name_labels) = it.next() else {
            return false;
        };
        let Some(value) = it.next() else {
            return false;
        };
        // First part: name or name{labels}
        if !name_labels
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
        {
            return false;
        }
        if let Some(open) = name_labels.find('{') {
            if !name_labels.ends_with('}') {
                return false;
            }
            let name = &name_labels[..open];
            if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return false;
            }
        } else if !name_labels.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return false;
        }
        value.chars().all(|c| c.is_ascii_digit())
    };

    let mut metric_lines = 0;
    for line in body.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        assert!(line_ok(line), "promtool-style validation failed: `{line}`");
        metric_lines += 1;
    }
    // 2 top-level (events_total, last_event_unix) + len(ALL) * 4 widths.
    let expected = 2 + metric::ALL.len() * BucketWidth::all().len();
    assert_eq!(metric_lines, expected);
}

#[tokio::test]
async fn prometheus_content_type_is_text_plain_v004() {
    let (s, _) = make_state(Some("t"));
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(AUTHORIZATION, "Bearer t")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(ct.contains("text/plain"), "wrong content-type: {ct}");
    assert!(ct.contains("version=0.0.4"), "missing version: {ct}");
}

// ─────────────────────────────────────────────────────────────────────────
// 3. /analytics/series JSON shape.
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn series_json_shape_has_documented_fields() {
    let (s, idx) = make_state(Some("t"));
    idx.state.ingest(&AnalyticsEvent::SessionOpen {
        ts_unix: 60,
        session_id: "x".into(),
    });
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/analytics/series?metric=sessions_opened&bucket=1m&from=0&to=1000")
                .header(AUTHORIZATION, "Bearer t")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["metric"], "sessions_opened");
    assert_eq!(v["bucket"], "1m");
    assert_eq!(v["from"], 0);
    assert_eq!(v["to"], 1000);
    let points = v["points"].as_array().unwrap();
    assert_eq!(points.len(), 1);
    let p = &points[0];
    // Each point is `{ts, value}`.
    assert!(p["ts"].is_u64());
    assert!(p["value"].is_u64());
    assert_eq!(p["ts"], 60);
    assert_eq!(p["value"], 1);
}

#[tokio::test]
async fn series_default_bucket_is_5m_when_omitted() {
    let (s, idx) = make_state(Some("t"));
    idx.state.ingest(&AnalyticsEvent::SessionOpen {
        ts_unix: 60,
        session_id: "x".into(),
    });
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/analytics/series?metric=sessions_opened")
                .header(AUTHORIZATION, "Bearer t")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["bucket"], "5m");
}

#[tokio::test]
async fn series_to_max_renders_as_zero_in_response() {
    // Documented quirk: when `to` is omitted (interpreted as u64::MAX)
    // the response serializes it as 0 to keep the JSON compact.
    let (s, _) = make_state(Some("t"));
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/analytics/series?metric=sessions_opened&bucket=1m&from=100")
                .header(AUTHORIZATION, "Bearer t")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["from"], 100);
    assert_eq!(v["to"], 0);
}

#[tokio::test]
async fn series_bucket_alias_60s_and_24h_work() {
    let (s, _) = make_state(Some("t"));
    let app = router(s);
    for (alias, canonical) in [("60s", "1m"), ("24h", "1d")] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/analytics/series?metric=sessions_opened&bucket={alias}"
                    ))
                    .header(AUTHORIZATION, "Bearer t")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["bucket"], canonical,
            "alias {alias} should normalise to {canonical}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 4. /analytics/health under chain-verify break.
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_reflects_first_break_verbatim() {
    let (s, _) = make_state(None);
    // Inject a chain break into the state directly via the public surface.
    // We can't mutate `chain_status` from outside the crate, so go through
    // an audit file that fails verification.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit-2026-01-01.jsonl");
    // Empty file with a tampered record: any HMAC will fail under key=0.
    use std::io::Write;
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(
        f,
        r#"{{"record_json":"{{\"ts_unix\":1,\"kind\":\"announce\",\"session_id\":\"a\",\"extra\":null}}","prev_mac":"{}", "mac":"{}"}}"#,
        "0".repeat(64),
        "f".repeat(64), // garbage MAC
    )
    .unwrap();

    let idx = Indexer::new();
    let _ = idx.ingest_audit_log(&[0u8; 32], &path).unwrap();
    let cs = idx.state.chain_status();
    assert!(cs.first_break.is_some(), "expected first_break to be set");
    let (file, reason) = cs.first_break.clone().unwrap();
    assert_eq!(file, "audit-2026-01-01.jsonl");
    assert!(
        reason.contains("mac mismatch"),
        "first_break reason should describe mac mismatch, got: {reason}"
    );

    // Now drive /analytics/health and check it reports the break.
    let state = HttpState::new(idx.state.clone(), None);
    let app = router(state);
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
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let fb = &v["chain"]["first_break"];
    assert!(!fb.is_null(), "/analytics/health didn't surface first_break");
    assert_eq!(fb["file"], "audit-2026-01-01.jsonl");
    assert!(fb["reason"].as_str().unwrap().contains("mac mismatch"));

    // sanity: silence a clippy::let_underscore_must_use false-positive on
    // the unused `s` from earlier.
    let _ = s;
}

#[tokio::test]
async fn health_shows_zero_files_scanned_on_fresh_indexer() {
    // No audit files ingested → files_scanned=0, no first_break.
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
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["chain"]["files_scanned"], 0);
    assert!(v["chain"]["first_break"].is_null());
}

#[tokio::test]
async fn health_includes_events_ingested_counter() {
    let (s, idx) = make_state(None);
    for i in 0..3u64 {
        idx.state.ingest(&AnalyticsEvent::SessionOpen {
            ts_unix: i,
            session_id: format!("s{i}"),
        });
    }
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
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["events_ingested"], 3);
    // `last_ingest_age_s` should be a small number (we just ingested).
    assert!(v["last_ingest_age_s"].is_u64());
}

// ─────────────────────────────────────────────────────────────────────────
// 5. /metrics body sanity: events_total bumps with ingestion.
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn metrics_events_total_reflects_ingest_count() {
    let (s, idx) = make_state(Some("t"));
    for ts in 0..7u64 {
        idx.state.ingest(&AnalyticsEvent::SessionOpen {
            ts_unix: ts * 60,
            session_id: format!("s{ts}"),
        });
    }
    let app = router(s);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header(AUTHORIZATION, "Bearer t")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = String::from_utf8(
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    assert!(
        body.contains("octravpn_analytics_events_total 7"),
        "events_total didn't reflect 7 ingested: {body}"
    );
    assert!(body.contains("octravpn_analytics_last_event_unix"));
}

// ─────────────────────────────────────────────────────────────────────────
// 6. HttpState::new constructs cleanly with and without token.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn http_state_new_with_no_token_disables_bearer_gate() {
    let st = HttpState::new(Arc::new(IndexerState::default()), None);
    assert!(st.bearer_token.is_none());
    assert!(st.started_at_unix > 0);
}

#[test]
fn http_state_chain_status_default_is_clean() {
    let cs = ChainVerifyStatus::default();
    assert_eq!(cs.files, 0);
    assert!(cs.first_break.is_none());
}
