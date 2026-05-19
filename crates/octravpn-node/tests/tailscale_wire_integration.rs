//! Integration test for the Tailscale-wire surface mounted by
//! `octravpn-node`.
//!
//! Walks `/key` → (stub) `/ts2021` → `/machine/.../register` →
//! `/machine/.../map` via the axum `oneshot` service driver. This
//! exercises the same router the node mounts in production; the
//! plaintext-JSON gap on `/register` + `/map` (see
//! `crates/octravpn-mesh/src/tailscale_wire/mod.rs` decision log) is
//! still in play.

use axum::body::to_bytes;
use octravpn_mesh::{
    ip_alloc::TailnetIpAllocator,
    tailscale_wire::{key_handler::OverTLSPublicKeyResponse, MachineRegistry},
    tailscale_wire_router, PreauthMinter, ServerNoiseKey, WireState, DEFAULT_PREAUTH_TTL,
};
use std::sync::Arc;
use tempfile::tempdir;
use tower::ServiceExt;

fn build_state() -> (WireState, tempfile::TempDir) {
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
async fn key_then_register_then_map_round_trip() {
    let (state, _dir) = build_state();
    let pk = state.preauth.mint("alice", DEFAULT_PREAUTH_TTL, false);
    let server_pub = state.server_noise_key.public_hex();

    let app = tailscale_wire_router(state.clone());

    // /key
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/key?v=39")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
    let okr: OverTLSPublicKeyResponse = serde_json::from_slice(&raw).unwrap();
    assert_eq!(okr.public_key, format!("mkey:{server_pub}"));

    // /ts2021 stub returns 501 today — that's the documented gap.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/ts2021")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_IMPLEMENTED);

    // /machine/.../register (plaintext JSON path)
    let node_hex = "ab".repeat(32);
    let reg_body = serde_json::json!({
        "NodeKey": format!("nodekey:{node_hex}"),
        "Auth": { "AuthKey": pk.key },
        "Hostinfo": { "Hostname": "peer-a", "OS": "linux", "OSVersion": "6.6" },
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/machine/nodekey:{node_hex}/register"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&reg_body).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    // /machine/.../map — alone in the tailnet, so this will long-poll
    // up to its 30s timeout and return an empty peer list. We don't
    // want to block the test on that, so spin a second peer in via
    // the registry directly.
    let other_hex = "cd".repeat(32);
    state.machines.upsert(
        other_hex.clone(),
        octravpn_mesh::MachineRecord {
            node_key_hex: other_hex.clone(),
            machine_key_hex: String::new(),
            user: "bob".into(),
            hostname: "peer-b".into(),
            ipv4: std::net::Ipv4Addr::new(100, 64, 0, 99),
        },
    );

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/machine/nodekey:{node_hex}/map"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(b"{}".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
    let mr: octravpn_mesh::tailscale_wire::MapResponse =
        serde_json::from_slice(&raw).unwrap();
    assert_eq!(mr.peers.len(), 1);
    assert_eq!(mr.peers[0].name, "peer-b.octra.test");
}
