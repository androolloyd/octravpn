//! `GET /key` — return the server's Noise long-term public key.
//!
//! Wire format: `tailcfg.OverTLSPublicKeyResponse`
//! (`tailscale/tailcfg/tailcfg.go`). Only `PublicKey` is required for
//! a TS2021-capable client (capability version >= 39); older clients
//! also consume a `LegacyPublicKey` field, which we leave empty
//! because we have no legacy bridge.
//!
//! Stock `tailscale up` appends a `?v=<capver>` query parameter
//! advertising the client's capability version. We ignore it: the
//! key we return is identical regardless of the requested version,
//! and dispatching on the client's `v` is the responder's concern
//! (matters only for selecting the legacy vs new key, and we have
//! only one).
//!
//! ## Decision log
//!
//! - **JSON envelope, not raw hex.** The blocker doc's table says
//!   "curl returns hex key" but Tailscale's wire format is
//!   `{"publicKey": "mkey:<hex>"}`. We follow the upstream shape.
//!   A test asserts a real `tailscale up` parse path
//!   (`OverTLSPublicKeyResponse` deserialise) round-trips.

use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use super::WireState;

/// `GET /key` response.
///
/// JSON field tag: `PublicKey` (PascalCase) per upstream
/// `OverTLSPublicKeyResponse`. The `mkey:` prefix is part of the value
/// so a downstream parser uses the same code path as it would for any
/// other Tailscale machine key.
#[derive(Debug, Serialize, Deserialize)]
pub struct OverTLSPublicKeyResponse {
    /// Server's Noise X25519 public key, formatted as `mkey:<hex>`.
    #[serde(rename = "PublicKey")]
    pub public_key: String,
}

/// Optional `?v=<capver>` query parameter. We accept and discard it;
/// kept here so the handler signature is stable when we eventually
/// need to dispatch on it.
#[derive(Debug, Deserialize)]
pub struct KeyQuery {
    #[allow(dead_code)]
    #[serde(default)]
    pub v: Option<u32>,
}

pub async fn handle_key(
    State(state): State<WireState>,
    Query(_q): Query<KeyQuery>,
) -> impl IntoResponse {
    let body = OverTLSPublicKeyResponse {
        public_key: format!("mkey:{}", state.server_noise_key.public_hex()),
    };
    Json(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ip_alloc::TailnetIpAllocator,
        tailscale_wire::{
            noise::ServerNoiseKey, router, MachineRegistry, WireState,
        },
        PreauthMinter,
    };
    use axum::body::to_bytes;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn fixture_state() -> (WireState, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let state = WireState {
            server_noise_key: server,
            preauth: PreauthMinter::new(),
            ip_allocator: Arc::new(TailnetIpAllocator::new("interop-test")),
            machines: Arc::new(MachineRegistry::new()),
        };
        (state, dir)
    }

    #[tokio::test]
    async fn key_endpoint_returns_mkey_prefixed_hex() {
        let (state, _dir) = fixture_state();
        let expected_pub = state.server_noise_key.public_hex();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/key?v=39")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: OverTLSPublicKeyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.public_key, format!("mkey:{expected_pub}"));
    }

    #[tokio::test]
    async fn key_endpoint_accepts_no_query_param() {
        let (state, _dir) = fixture_state();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/key")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }
}
