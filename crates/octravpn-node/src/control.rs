//! HTTP control plane the exit node serves to clients.
//!
//! Endpoints (matching `octravpn_core::control` paths):
//!
//!   POST /session                    — announce a session; node co-signs
//!                                       future receipts under its WG key
//!   POST /session/{id}/receipt       — submit client-signed receipt;
//!                                       node co-signs and persists
//!   GET  /session/{id}               — return session state + latest
//!                                       dual-signed receipt
//!
//! The node uses its WG keypair (also the receipt-signing key — the same
//! key it registered on chain). Equivocation by signing two different
//! `bytes_used` values for the same `(session, seq)` is detectable by
//! the on-chain `slash_double_sign` path.

use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use octravpn_core::{
    control::{
        AnnounceSessionRequest, AnnounceSessionResponse, SessionStateResponse,
        SubmitReceiptRequest, SubmitReceiptResponse,
    },
    receipt::{Receipt, ReceiptError, SignedReceipt},
    session::SessionId,
    sig::{verify, KeyPair, PublicKey},
};
use parking_lot::RwLock;
use serde::Serialize;
use std::collections::HashMap;
use tracing::info;

use crate::onion::OnionRouter;

#[derive(Clone)]
pub struct ControlState {
    pub node_kp: Arc<KeyPair>,
    pub sessions: Arc<RwLock<HashMap<SessionId, ControlSession>>>,
    pub router: Arc<OnionRouter>,
}

pub struct ControlSession {
    pub client_pubkey: PublicKey,
    pub last_seq: u64,
    pub bytes_served: u64,
    pub latest: Option<SignedReceipt>,
}

impl ControlState {
    pub fn new(node_kp: Arc<KeyPair>, router: Arc<OnionRouter>) -> Self {
        Self {
            node_kp,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            router,
        }
    }

    pub fn router_axum(self: Arc<Self>) -> Router {
        let s = self;
        Router::new()
            .route("/session", post(announce))
            .route("/session/:id", get(get_state))
            .route("/session/:id/receipt", post(submit_receipt))
            .with_state(s)
    }
}

pub async fn serve(
    state: Arc<ControlState>,
    addr: SocketAddr,
) -> Result<()> {
    let router = state.router_axum();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(?addr, "control plane listening");
    axum::serve(listener, router).await?;
    Ok(())
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

impl ApiError {
    fn new(s: impl Into<String>) -> Self {
        Self { error: s.into() }
    }
}

async fn announce(
    State(s): State<Arc<ControlState>>,
    Json(req): Json<AnnounceSessionRequest>,
) -> impl IntoResponse {
    let mut g = s.sessions.write();
    g.insert(
        req.session_id.clone(),
        ControlSession {
            client_pubkey: req.client_pubkey,
            last_seq: 0,
            bytes_served: 0,
            latest: None,
        },
    );
    Json(AnnounceSessionResponse {
        accepted: true,
        node_pubkey: s.node_kp.public,
    })
    .into_response()
}

async fn submit_receipt(
    State(s): State<Arc<ControlState>>,
    Path(id_hex): Path<String>,
    Json(req): Json<SubmitReceiptRequest>,
) -> impl IntoResponse {
    let id = match SessionId::from_hex(&id_hex) {
        Some(i) => i,
        None => {
            return (StatusCode::BAD_REQUEST, Json(ApiError::new("bad id"))).into_response()
        }
    };
    if id != req.receipt.session_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("session id mismatch")),
        )
            .into_response();
    }

    // 1. Verify the client's signature against the announced pubkey.
    let payload = req.receipt.signing_payload();
    let mut g = s.sessions.write();
    let entry = match g.get_mut(&id) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiError::new("session not announced")),
            )
                .into_response()
        }
    };
    if entry.client_pubkey != req.client_pubkey {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError::new("wrong client pubkey")),
        )
            .into_response();
    }
    if let Err(e) = verify(&req.client_pubkey, &payload, &req.client_sig) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError::new(format!("client sig: {e}"))),
        )
            .into_response();
    }

    // 2. Equivocation defense: refuse to sign a *different* bytes_used
    //    for the same (session, seq) we already signed.
    if let Some(prev) = &entry.latest {
        if prev.receipt.seq == req.receipt.seq && prev.receipt != req.receipt {
            return (
                StatusCode::CONFLICT,
                Json(ApiError::new(
                    "equivocation refused: same seq, different receipt",
                )),
            )
                .into_response();
        }
    }
    if req.receipt.seq <= entry.last_seq && entry.last_seq != 0 {
        return (
            StatusCode::CONFLICT,
            Json(ApiError::new("non-monotonic seq")),
        )
            .into_response();
    }

    // 3. Co-sign as the node.
    let node_sig = s.node_kp.sign(&payload);
    let signed = SignedReceipt {
        receipt: req.receipt.clone(),
        client_pubkey: req.client_pubkey,
        client_sig: req.client_sig,
        node_pubkey: s.node_kp.public,
        node_sig,
    };
    if let Err(e) = signed.verify() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::new(format!("self-verify failed: {e}"))),
        )
            .into_response();
    }

    entry.last_seq = req.receipt.seq;
    entry.bytes_served = req.receipt.bytes_used;
    entry.latest = Some(signed.clone());

    Json(SubmitReceiptResponse { signed }).into_response()
}

async fn get_state(
    State(s): State<Arc<ControlState>>,
    Path(id_hex): Path<String>,
) -> impl IntoResponse {
    let id = match SessionId::from_hex(&id_hex) {
        Some(i) => i,
        None => {
            return (StatusCode::BAD_REQUEST, Json(ApiError::new("bad id"))).into_response()
        }
    };
    let g = s.sessions.read();
    let Some(entry) = g.get(&id) else {
        return (StatusCode::NOT_FOUND, Json(ApiError::new("not found"))).into_response();
    };
    Json(SessionStateResponse {
        last_seq: entry.last_seq,
        bytes_served: entry.bytes_served,
        latest: entry.latest.clone(),
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use octravpn_core::receipt::Receipt;

    #[tokio::test]
    async fn submit_receipt_co_signs() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let state = Arc::new(ControlState::new(node_kp.clone(), router.clone()));

        let id = SessionId([42u8; 32]);

        // Announce.
        {
            let _ = announce(
                State(state.clone()),
                Json(AnnounceSessionRequest {
                    session_id: id.clone(),
                    client_pubkey: client_kp.public,
                }),
            )
            .await;
        }

        // Build + submit a receipt.
        let r = Receipt {
            session_id: id.clone(),
            seq: 1,
            bytes_used: 2048,
            blind: [9u8; 32],
        };
        let payload = r.signing_payload();
        let client_sig = client_kp.sign(&payload);

        let req = SubmitReceiptRequest {
            receipt: r.clone(),
            client_pubkey: client_kp.public,
            client_sig,
        };
        // Use the inner submit_receipt directly with the raw id_hex path.
        let id_hex = id.to_hex();
        let _ = submit_receipt(State(state.clone()), Path(id_hex), Json(req)).await;

        // Confirm latest is dual-signed.
        let g = state.sessions.read();
        let entry = g.get(&id).unwrap();
        let signed = entry.latest.as_ref().unwrap();
        signed.verify().expect("dual-signed receipt verifies");
        assert_eq!(signed.receipt.bytes_used, 2048);
    }

    #[tokio::test]
    async fn equivocation_rejected() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let state = Arc::new(ControlState::new(node_kp, router));
        let id = SessionId([7u8; 32]);

        announce(
            State(state.clone()),
            Json(AnnounceSessionRequest {
                session_id: id.clone(),
                client_pubkey: client_kp.public,
            }),
        )
        .await;

        let make = |bytes: u64| {
            let r = Receipt {
                session_id: id.clone(),
                seq: 1,
                bytes_used: bytes,
                blind: [0u8; 32],
            };
            let p = r.signing_payload();
            let sig = client_kp.sign(&p);
            SubmitReceiptRequest {
                receipt: r,
                client_pubkey: client_kp.public,
                client_sig: sig,
            }
        };

        // First receipt: accepted.
        let _ = submit_receipt(State(state.clone()), Path(id.to_hex()), Json(make(100))).await;

        // Same seq, different bytes: must conflict.
        let resp =
            submit_receipt(State(state.clone()), Path(id.to_hex()), Json(make(200))).await;
        let r = resp.into_response();
        assert_eq!(r.status(), StatusCode::CONFLICT);
    }
}
