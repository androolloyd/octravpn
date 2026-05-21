//! `GET /health` — liveness + attestation freshness probe.
//! Phases: warm-up (200 + `warming up`), no_attestation (503), stale
//! (503), else ok (200). No bearer — public so an external load
//! balancer can scrape without provisioning.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use crate::control::state::{ControlState, HEALTH_ATTESTATION_FRESHNESS_S, HEALTH_WARMUP_S};

pub(crate) async fn health(State(s): State<Arc<ControlState>>) -> impl IntoResponse {
    let now = octravpn_core::util::now_unix_secs();
    let started = s.metrics.started_at_unix.load(Ordering::Relaxed);
    let uptime = now.saturating_sub(started);
    let last_attest = s.metrics.last_attestation_unix.load(Ordering::Relaxed);

    if uptime < HEALTH_WARMUP_S {
        return Json(serde_json::json!({
            "status": "warming up",
            "uptime_s": uptime,
            "last_attestation_unix": last_attest,
        }))
        .into_response();
    }

    if last_attest == 0 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "no_attestation",
                "uptime_s": uptime,
            })),
        )
            .into_response();
    }

    let attest_age = now.saturating_sub(last_attest);
    if attest_age > HEALTH_ATTESTATION_FRESHNESS_S {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "attestation_stale",
                "uptime_s": uptime,
                "last_attestation_unix": last_attest,
                "attestation_age_s": attest_age,
                "freshness_threshold_s": HEALTH_ATTESTATION_FRESHNESS_S,
            })),
        )
            .into_response();
    }

    Json(serde_json::json!({
        "status": "ok",
        "uptime_s": uptime,
        "last_attestation_unix": last_attest,
    }))
    .into_response()
}
