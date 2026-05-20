//! `GET /events` — SSE stream of control-plane events. Bearer-gated
//! by `ControlState::bearer_events` (Hidden policy: 404 +
//! [`octravpn_core::bearer::NGINX_404_BODY`] for every failure mode).
//! Lagged subscribers see a `lag` SSE event rather than a silent drop.
//! Without the token gate the stream broadcasts every
//! `session_id ↔ client_wg_pubkey` mapping, defeating unlinkability.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::State,
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        IntoResponse,
    },
};
use futures_util::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::control::state::ControlState;

pub(crate) async fn events_sse(
    State(s): State<Arc<ControlState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if let Err(resp) = s.bearer_events().check(&headers) {
        return resp;
    }

    let rx = s.events.subscribe();
    let stream = BroadcastStream::new(rx).map(|item| {
        let ev = match item {
            Ok(ev) => ev,
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                crate::events::Event {
                    ts_unix: octravpn_core::util::now_unix_secs(),
                    kind: "lag".to_string(),
                    payload: serde_json::json!({ "skipped": n }),
                }
            }
        };
        // `json_data` serializes the event with serde_json. The bus
        // event already derives `Serialize`, so this can only fail if
        // the payload contains something unserializable — which is
        // never the case here (we only emit `serde_json::Value`).
        // Fall back to an empty data field on the theoretical error
        // path so the stream never aborts.
        let sse = SseEvent::default()
            .event(ev.kind.clone())
            .json_data(&ev)
            .unwrap_or_else(|_| SseEvent::default().data(""));
        Ok::<_, Infallible>(sse)
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::state::ControlState;
    use crate::onion::OnionRouter;
    use axum::http::{HeaderValue, StatusCode};
    use octravpn_core::{bounded::BoundedMap, sig::KeyPair};

    /// `/events` returns 404 when no token is configured, even if the
    /// caller supplies an `Authorization: Bearer …` header (the
    /// endpoint must be undetectable from outside in default mode).
    #[tokio::test]
    async fn events_sse_default_returns_not_found() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        // `ControlState::new` (test-only) sets events_token = None.
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer anything"),
        );
        let resp = events_sse(State(state), headers).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// `/events` returns 404 when the token is configured but the
    /// caller's Authorization header is missing or wrong. (We return
    /// 404 rather than 401 so external scanners can't confirm the
    /// endpoint exists.)
    #[tokio::test]
    async fn events_sse_rejects_wrong_token() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(
            ControlState::new(node_kp, router, allowlist)
                .with_events_token(Some("expected".to_string())),
        );
        // No header → 404.
        {
            let resp = events_sse(State(state.clone()), axum::http::HeaderMap::new()).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
        // Wrong token → 404.
        {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer wrong"),
            );
            let resp = events_sse(State(state.clone()), headers).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
        // Right token → OK (SSE stream starts).
        {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer expected"),
            );
            let resp = events_sse(State(state), headers).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }
}
