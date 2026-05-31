//! `GET /enroll/challenge` + `POST /enroll` — wallet-native device
//! enrollment.
//!
//! Thin axum wrappers over [`crate::control::enroll::EnrollService`]; all
//! verification + member-set mutation lives there. Both routes 404 unless
//! the node hosts enrollment for a tailnet (`ControlState::enroll` is
//! `Some`), so an external probe can't distinguish "enrollment off" from
//! any other unconfigured surface.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use octravpn_core::enroll::EnrollRequest;
use serde::Deserialize;

use super::ApiError;
use crate::control::enroll::EnrollError;
use crate::control::state::ControlState;

/// Query params for `GET /enroll/challenge`. Only the wallet is needed —
/// the operator returns its tailnet/circle authoritatively in the
/// challenge, so a client cannot talk it into a tailnet it doesn't serve.
#[derive(Deserialize)]
pub(crate) struct ChallengeParams {
    wallet: String,
}

pub(crate) async fn challenge(
    State(s): State<Arc<ControlState>>,
    Query(p): Query<ChallengeParams>,
) -> impl IntoResponse {
    let Some(svc) = s.enroll.as_ref() else {
        return not_enabled();
    };
    let now = octravpn_core::util::now_unix_secs();
    Json(svc.issue_challenge(&p.wallet, now)).into_response()
}

pub(crate) async fn enroll(
    State(s): State<Arc<ControlState>>,
    Json(req): Json<EnrollRequest>,
) -> impl IntoResponse {
    let Some(svc) = s.enroll.as_ref() else {
        return not_enabled();
    };
    let now = octravpn_core::util::now_unix_secs();
    match svc.enroll(&req, now).await {
        Ok(resp) => {
            // Observability: a device joined. The wallet + IP are the
            // public identity the device just announced, not secrets.
            s.events.publish(crate::events::Event {
                ts_unix: now,
                kind: "device_enrolled".to_string(),
                payload: serde_json::json!({
                    "wallet": req.wallet_address(),
                    "ip": resp.assigned_ip,
                    "members_version": resp.members_version,
                }),
            });
            Json(resp).into_response()
        }
        Err(e) => {
            let (code, msg) = status_for(&e);
            (code, Json(ApiError::new(msg))).into_response()
        }
    }
}

fn not_enabled() -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        Json(ApiError::new("enrollment not enabled")),
    )
        .into_response()
}

/// Map a typed enrollment failure to an HTTP status. Exhaustive so a new
/// [`EnrollError`] variant forces a compile-time decision here rather than
/// silently defaulting to 500.
fn status_for(e: &EnrollError) -> (StatusCode, String) {
    match e {
        EnrollError::BadSignature
        | EnrollError::StaleNonce
        | EnrollError::NonceWalletMismatch => (StatusCode::UNAUTHORIZED, e.to_string()),
        EnrollError::WrongTailnet { .. }
        | EnrollError::WrongCircle { .. }
        | EnrollError::Members(_) => (StatusCode::BAD_REQUEST, e.to_string()),
        EnrollError::NotAuthorized(_) => (StatusCode::FORBIDDEN, e.to_string()),
        EnrollError::Store(_) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::state::ControlState;
    use crate::onion::OnionRouter;
    use octravpn_core::{bounded::BoundedMap, sig::KeyPair};

    /// With no enrollment service configured, `/enroll/challenge` 404s —
    /// the surface is invisible, not just disabled.
    #[tokio::test]
    async fn challenge_404s_when_enrollment_disabled() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let resp = challenge(
            State(state),
            Query(ChallengeParams {
                wallet: "octWhoever".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
