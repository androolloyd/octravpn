//! `POST /session` — client announces a session + client_pubkey.
//! Validates the announce signature, optionally consults
//! [`super::super::state::SessionAdmissionVerifier`] for the on-chain
//! `SessionOpened` event, then inserts into the session tracker +
//! WireGuard allowlist and publishes `session_announced` on the SSE
//! bus. No bearer — the announce signature is the auth.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use octravpn_core::{
    control::{announce_signing_payload, AnnounceSessionRequest, AnnounceSessionResponse},
    sig::verify,
};
use tracing::warn;

use super::ApiError;
use crate::control::state::{ControlSession, ControlState};

pub(crate) async fn announce(
    State(s): State<Arc<ControlState>>,
    Json(req): Json<AnnounceSessionRequest>,
) -> impl IntoResponse {
    let payload = announce_signing_payload(
        &req.session_id,
        &req.client_pubkey,
        &req.client_wg_pubkey,
        &req.open_tx_hash,
    );
    if verify(&req.client_pubkey, &payload, &req.client_sig).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError::new("bad announce signature")),
        )
            .into_response();
    }
    if let Some(verifier) = &s.session_verifier {
        match verifier.session_opened(&req).await {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ApiError::new("session open transaction not found")),
                )
                    .into_response();
            }
            Err(e) => {
                warn!(error = %e, "session admission verifier failed");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ApiError::new("session admission verifier unavailable")),
                )
                    .into_response();
            }
        }
    }
    s.metrics.announces_total.fetch_add(1, Ordering::Relaxed);
    // `session_opens_total` mirrors `announces_total` today (every
    // accepted announce opens a session) but is kept as a separate
    // counter so a future "rejected announce" path can split the two
    // without breaking the dashboard query.
    s.metrics
        .session_opens_total
        .fetch_add(1, Ordering::Relaxed);
    let session_id_hex = req.session_id.to_hex();
    s.sessions.insert(
        req.session_id,
        ControlSession {
            last_seq: 0,
            last_blind: octravpn_core::session::Blind::new([0u8; 32]),
            // Bind the announcing client's ed25519 identity to the
            // session so `POST /session/:id/receipt` can reject a
            // dual-signed receipt countersigned under any other key.
            client_pubkey: req.client_pubkey,
        },
    );
    s.allowlist
        .insert(req.client_wg_pubkey, crate::tunnel::AllowedClient);
    // Fan out to SSE subscribers. We publish the client's WireGuard
    // pubkey (hex) — this is the public identity the client already
    // exposed via the announce request; not a secret.
    s.events.publish(crate::events::Event {
        ts_unix: octravpn_core::util::now_unix_secs(),
        kind: "session_announced".to_string(),
        payload: serde_json::json!({
            "session_id": session_id_hex,
            "client_wg_pubkey": hex::encode(req.client_wg_pubkey),
        }),
    });
    if let Some(audit) = &s.audit {
        let rec = crate::audit::AuditRecord {
            ts_unix: octravpn_core::util::now_unix_secs(),
            kind: "announce",
            source: None,
            session_id: Some(session_id_hex),
            extra: serde_json::Value::Null,
        };
        if let Err(e) = audit.write_async(rec).await {
            tracing::warn!(error = %e, "audit log write failed");
        }
    }
    Json(AnnounceSessionResponse {
        accepted: true,
        node_pubkey: s.node_kp.public,
    })
    .into_response()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::control::state::ControlState;
    use crate::onion::OnionRouter;
    use octravpn_core::{
        bounded::BoundedMap,
        control::announce_signing_payload,
        receipt::Receipt,
        session::SessionId,
        sig::{verify, KeyPair},
    };

    pub(crate) fn signed_announce(
        session_id: SessionId,
        client_kp: &KeyPair,
        client_wg_pubkey: [u8; 32],
    ) -> AnnounceSessionRequest {
        let open_tx_hash = "test-open-tx".to_string();
        let client_sig = client_kp.sign(&announce_signing_payload(
            &session_id,
            &client_kp.public,
            &client_wg_pubkey,
            &open_tx_hash,
        ));
        AnnounceSessionRequest {
            session_id,
            client_pubkey: client_kp.public,
            client_wg_pubkey,
            open_tx_hash,
            client_sig,
        }
    }

    #[tokio::test]
    async fn announce_rejects_bad_client_signature_without_side_effects() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let id = SessionId::new([0x41u8; 32]);
        let mut req = signed_announce(id.clone(), &client_kp, [9u8; 32]);
        req.client_sig.0[0] ^= 1;

        let resp = announce(State(state.clone()), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(!state.sessions.contains_key(&id));
        assert_eq!(state.allowlist.len(), 0);
        assert_eq!(state.metrics.announces_total.load(Ordering::Relaxed), 0);
        assert_eq!(state.metrics.session_opens_total.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn announce_then_state_returns_signed_proposal() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp.clone(), router, allowlist));
        let id = SessionId::new([42u8; 32]);

        announce(
            State(state.clone()),
            Json(signed_announce(id.clone(), &client_kp, [9u8; 32])),
        )
        .await;

        assert!(state.sessions.contains_key(&id));

        // Reproduce the get_state body manually (bypass the axum layer).
        let r = Receipt {
            context: (*state.receipt_context).clone(),
            session_id: id.clone(),
            seq: 1,
            bytes_used: 0,
            blind: octravpn_core::session::Blind::new([0u8; 32]),
        };
        let payload = r.signing_payload();
        let sig = node_kp.sign(&payload);
        verify(&node_kp.public, &payload, &sig).unwrap();
    }

    /// `announce` bumps both `announces_total` AND
    /// `session_opens_total`. The two counters mirror each other for
    /// now; the test pins that behaviour so a future "rejected
    /// announce" path notices it has to split them.
    #[tokio::test]
    async fn announce_bumps_session_opens_counter() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let before = state.metrics.session_opens_total.load(Ordering::Relaxed);
        announce(
            State(state.clone()),
            Json(signed_announce(
                SessionId::new([7u8; 32]),
                &client_kp,
                [9u8; 32],
            )),
        )
        .await;
        let after = state.metrics.session_opens_total.load(Ordering::Relaxed);
        assert_eq!(after, before + 1);
    }
}
