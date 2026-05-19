//! `POST /machine/{node_key}/map` — long-poll peer map.
//!
//! Returns a Tailscale-shape `MapResponse` containing the requesting
//! node's own assignment plus the other peer(s) currently registered
//! in the same tailnet. If only one peer is registered (this one), we
//! long-poll up to [`MAP_LONGPOLL_TIMEOUT`] waiting for a second peer
//! to join; on timeout we still return a valid (empty-peers) response
//! so the client doesn't error out.
//!
//! ## Decision log
//!
//! - **Single-response body, not the `Stream=true` ndjson framing.**
//!   See the note on `MapRequest.stream` in `wire.rs`. Long-term the
//!   client will require streaming chunks; for the interop test a
//!   single-shot response is enough.
//! - **Long-poll wake via `tokio::sync::Notify` on the registry.**
//!   Cheaper than a watch channel for the 2-peer test and the
//!   correctness story is simpler — every register notifies, every
//!   waiter wakes and recomputes the snapshot.
//! - **Timeout = 30s.** Stock `tailscale up` is patient (the upstream
//!   long-poll runs for many minutes), but 30s is enough for the
//!   second peer's `register` to land in the interop test's
//!   tight-loop. If the test times out at 30s the client retries the
//!   map call — same end result, slightly slower convergence.

use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Serialize;

use super::register::record_to_map_node;
use super::wire::{
    stable_id_from_key, strip_key_prefix, DerpMap, DnsConfig, MapNode, MapRequest, MapResponse,
};
use super::WireState;

/// How long we wait for a second peer to join before returning an
/// empty-peers `MapResponse`.
pub const MAP_LONGPOLL_TIMEOUT: Duration = Duration::from_secs(30);

/// MagicDNS domain emitted on every map response. Static for the
/// interop test.
const TAILNET_DOMAIN: &str = "octra.test";

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

pub async fn handle_map(
    State(state): State<WireState>,
    Path(node_key_path): Path<String>,
    body: Option<Json<MapRequest>>,
) -> impl IntoResponse {
    let Json(_req) = body.unwrap_or(Json(MapRequest::default()));

    let node_key_hex = match strip_key_prefix(&node_key_path) {
        Some(h) => h.to_string(),
        None => node_key_path.clone(),
    };

    // The caller must already have registered. If not, 404 — they need
    // to go through `/machine/{node_key}/register` first.
    let Some(own) = state.machines.get(&node_key_hex) else {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "machine not registered".into(),
            }),
        )
            .into_response();
    };

    // Long-poll if we're alone. Wake on any registry change, or after
    // the timeout. We re-check after each wake (a `Notify::notify_waiters`
    // wakes everyone, not just us; spurious wakes are fine).
    let notify = state.machines.notify.clone();
    let deadline = tokio::time::Instant::now() + MAP_LONGPOLL_TIMEOUT;
    while state.machines.len() < 2 {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        if tokio::time::timeout(remaining, wait_for_change(notify.clone()))
            .await
            .is_err()
        {
            break;
        }
    }

    // Build the response.
    let own_node = record_to_map_node(&own, TAILNET_DOMAIN);
    let mut peers: Vec<MapNode> = state
        .machines
        .all()
        .into_iter()
        .filter(|(k, _)| k != &node_key_hex)
        .map(|(_, rec)| record_to_map_node(&rec, TAILNET_DOMAIN))
        .collect();
    // Stable order so tests are deterministic.
    peers.sort_by_key(|n| n.id);

    let resp = MapResponse {
        key_expiry_extension: 0,
        node: own_node,
        peers,
        dns_config: DnsConfig::default(),
        derp_map: DerpMap::default(),
        domain: TAILNET_DOMAIN.into(),
        keep_alive: true,
    };
    let _ = stable_id_from_key(&node_key_hex); // tickle import-used assertion
    Json(resp).into_response()
}

async fn wait_for_change(notify: Arc<tokio::sync::Notify>) {
    notify.notified().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ip_alloc::TailnetIpAllocator,
        tailscale_wire::{
            noise::ServerNoiseKey, router, MachineRecord, MachineRegistry, WireState,
        },
        PreauthMinter,
    };
    use axum::body::to_bytes;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn fixture() -> (WireState, tempfile::TempDir) {
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

    fn insert_peer(state: &WireState, node_hex: &str, host: &str, last_octet: u8) {
        state.machines.upsert(
            node_hex.to_string(),
            MachineRecord {
                node_key_hex: node_hex.to_string(),
                machine_key_hex: String::new(),
                user: "u".into(),
                hostname: host.into(),
                ipv4: Ipv4Addr::new(100, 64, 0, last_octet),
            },
        );
    }

    #[tokio::test]
    async fn two_peer_map_includes_both() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        // own node has the requester's IP
        assert_eq!(mr.node.addresses[0], "100.64.0.10/32");
        assert_eq!(mr.peers.len(), 1);
        assert_eq!(mr.peers[0].addresses[0], "100.64.0.11/32");
        assert_eq!(mr.peers[0].name, "peer-b.octra.test");
        assert_eq!(mr.domain, "octra.test");
        assert!(mr.keep_alive);
    }

    #[tokio::test]
    async fn unregistered_node_gets_404() {
        let (state, _dir) = fixture();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{}/map", "ff".repeat(32)))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(b"{}".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Long-poll wakes when a second peer registers. We start the map
    /// request when only one peer exists, spawn a delayed insert of the
    /// second peer, and assert the map returns the joined view (not
    /// the timeout-fallback empty view).
    #[tokio::test]
    async fn long_poll_wakes_on_second_register() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);

        let state_for_spawn = state.clone();
        let b_clone = b.clone();
        let waker = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            insert_peer(&state_for_spawn, &b_clone, "peer-b", 11);
        });

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(b"{}".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        waker.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(mr.peers.len(), 1, "long-poll should have woken on B's register");
    }
}
