//! End-to-end: hand-roll a valid audit log file with the same chain
//! algorithm the node uses, ingest it through the indexer, then drive
//! the HTTP surface through `tower::ServiceExt::oneshot` and assert
//! the JSON time-series + Prometheus exposition match the fixture.
//!
//! No node-crate dependency; the chain step is re-implemented in
//! `octravpn_analytics::chain_step`, which matches the node's
//! `audit::chain_step` byte-for-byte.

use std::{fs, io::Write, path::Path};

use axum::body::Body;
use axum::http::{header::AUTHORIZATION, Request, StatusCode};
use http_body_util::BodyExt;
use octravpn_analytics::{
    chain_step, http::router as analytics_router, http::HttpState, indexer::metric, BucketWidth,
    Indexer,
};
use serde_json::{json, Value};
use tower::ServiceExt;

fn write_audit_file(path: &Path, key: &[u8; 32], records: &[Value]) {
    let mut f = fs::File::create(path).unwrap();
    let mut prev_mac = [0u8; 32];
    for rec in records {
        // Canonical record JSON: serde_json with no whitespace ⇒ the
        // node's writer produces identical bytes via
        // `serde_json::to_string`.
        let canonical = serde_json::to_string(rec).unwrap();
        let mac = chain_step(key, &prev_mac, canonical.as_bytes());
        let env = json!({
            "record_json": canonical,
            "prev_mac": hex::encode(prev_mac),
            "mac": hex::encode(mac),
        });
        writeln!(f, "{}", serde_json::to_string(&env).unwrap()).unwrap();
        prev_mac = mac;
    }
}

#[tokio::test]
async fn replay_audit_log_then_query_metric_counts() {
    let dir = tempfile::tempdir().unwrap();
    let key = [0xABu8; 32];

    // Mix of every event type the indexer cares about, spread across
    // two daily files so we also exercise the per-file chain reset.
    let day1 = vec![
        json!({"ts_unix": 1_700_000_000_u64, "kind": "announce", "session_id": "s1", "extra": null}),
        json!({"ts_unix": 1_700_000_010_u64, "kind": "announce", "session_id": "s2", "extra": null}),
        json!({"ts_unix": 1_700_000_020_u64, "kind": "receipt_signed", "session_id": "s1", "extra": {"seq": 1, "bytes_used": 1_000}}),
        json!({"ts_unix": 1_700_000_030_u64, "kind": "receipt_signed", "session_id": "s1", "extra": {"seq": 2, "bytes_used": 2_500}}),
        json!({"ts_unix": 1_700_000_040_u64, "kind": "preauth_mint", "session_id": null, "extra": null}),
        json!({"ts_unix": 1_700_000_050_u64, "kind": "slash_double_sign", "session_id": null, "extra": null}),
    ];
    let day2 = vec![
        json!({"ts_unix": 1_700_086_400_u64, "kind": "session_close", "session_id": "s2", "extra": null}),
        json!({"ts_unix": 1_700_086_500_u64, "kind": "settle_claim", "session_id": "s1", "extra": {"bytes_used": 0}}),
        json!({"ts_unix": 1_700_086_600_u64, "kind": "validator_health_ok", "session_id": null, "extra": null}),
    ];
    write_audit_file(&dir.path().join("audit-2023-11-14.jsonl"), &key, &day1);
    write_audit_file(&dir.path().join("audit-2023-11-15.jsonl"), &key, &day2);

    let indexer = Indexer::new();
    let scans = indexer.ingest_audit_dir(&key, dir.path()).unwrap();
    assert_eq!(scans.len(), 2);
    for s in &scans {
        assert!(
            s.is_clean(),
            "scan {} broke: {:?}",
            s.path.display(),
            s.break_reason
        );
    }

    // Direct counter assertions on the in-memory state.
    let s = &indexer.state;
    assert_eq!(s.total(metric::SESSIONS_OPENED, BucketWidth::OneDay), 2);
    assert_eq!(s.total(metric::SESSIONS_CLOSED, BucketWidth::OneDay), 1);
    assert_eq!(s.total(metric::RECEIPTS_SIGNED, BucketWidth::OneDay), 2);
    assert_eq!(s.total(metric::PREAUTH_MINTED, BucketWidth::OneDay), 1);
    assert_eq!(s.total(metric::SLASH_DOUBLE_SIGN, BucketWidth::OneDay), 1);
    assert_eq!(s.total(metric::SETTLE_CLAIMS, BucketWidth::OneDay), 1);
    assert_eq!(
        s.total(metric::VALIDATOR_HEALTH_PINGS, BucketWidth::OneDay),
        1
    );
    // Bytes settled: two receipts at 1_000 + 1_500 delta = 2_500.
    // settle_claim carried bytes_used = 0 so it adds nothing.
    assert_eq!(s.total(metric::BYTES_SETTLED, BucketWidth::OneDay), 2_500);

    // ----- HTTP surface ------------------------------------------------
    let state = HttpState::new(indexer.state.clone(), Some("t".into()));
    let app = analytics_router(state);

    // /analytics/series for sessions_opened at 1m should yield 2 buckets
    // (announce ts spans [1_700_000_000, 1_700_000_010) and a second
    // bucket — actually both fall in the SAME 1m bucket because
    // 1_700_000_000 / 60 == 1_700_000_010 / 60 (both round to
    // 28_333_333). Confirm.)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/analytics/series?metric=sessions_opened&bucket=1m")
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
    let points = v["points"].as_array().unwrap();
    let sum: u64 = points.iter().map(|p| p["value"].as_u64().unwrap()).sum();
    assert_eq!(sum, 2, "sessions_opened total across buckets must be 2");

    // /metrics — Prometheus text, scoped check on a specific line.
    let resp = app
        .clone()
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
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body.contains("octravpn_analytics_bytes_settled{window=\"1d\"} 2500"),
        "Prometheus exposition missing expected bytes_settled line; body:\n{body}"
    );
    assert!(
        body.contains("octravpn_analytics_slash_double_sign{window=\"1d\"} 1"),
        "Prometheus exposition missing slash line; body:\n{body}"
    );

    // /analytics/health reflects the chain-verify clean state.
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
    assert_eq!(v["chain"]["files_scanned"], 2);
    assert!(v["chain"]["first_break"].is_null());
    assert_eq!(
        v["chain"]["verified_lines"].as_u64().unwrap(),
        (day1.len() + day2.len()) as u64
    );
}
