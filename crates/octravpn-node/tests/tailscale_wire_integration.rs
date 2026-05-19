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
    tailscale_wire::{
        controlbase::{Framed, FrameHeader, MsgType},
        key_handler::OverTLSPublicKeyResponse,
        MachineRegistry,
    },
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

    // /ts2021: without the `Upgrade: tailscale-control-protocol`
    // header the handler returns 400 — the documented "you POSTed,
    // but not as an upgrade" path. With the upgrade header but no
    // hyper OnUpgrade extension (which `tower::oneshot` can't
    // produce), it also returns 400 because the connection is not
    // upgradable in oneshot-mode. We assert both responses are 400 so
    // the test exercises the input-validation paths added in PR 2.
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
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);

    // With the upgrade header but no hijackable transport: still 400.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/ts2021")
                .header("upgrade", "tailscale-control-protocol")
                .header("connection", "upgrade")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);

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

/// Exercise the `drive_ts2021` framing path end-to-end against an
/// in-process Noise initiator. We feed a hand-crafted Initiation frame
/// over a duplex pipe; the responder is expected to read it, write a
/// Reply frame back, send the EarlyNoise prefix inside the Noise
/// transport, and then start h2.
///
/// We stop the test at the Reply step — proving the framing layer
/// responds correctly. Driving h2 on top would require a full client
/// connection (we have one in `cargo test -p octravpn-mesh tailscale_wire`
/// via NoiseStream round-trip; here we just want to assert the wire is
/// reachable).
#[tokio::test]
async fn ts2021_framing_responds_to_initiation() {
    use tokio::io::duplex;

    let (state, _dir) = build_state();
    let server_pub = state.server_noise_key.public_bytes();

    let (client_io, server_io) = duplex(64 * 1024);

    // Spawn the responder driver on the server side.
    let state_clone = state.clone();
    let server_task = tokio::spawn(async move {
        let _ =
            octravpn_mesh::tailscale_wire::noise::drive_ts2021(state_clone, server_io).await;
    });

    // Client side: build a snow initiator and send the Initiation frame.
    let mut init = state.server_noise_key.build_initiator(&server_pub).unwrap();
    let mut framed = Framed::new(client_io);
    let mut init_body = vec![0u8; 1024];
    let n = init.write_message(b"", &mut init_body).unwrap();
    init_body.truncate(n);
    framed
        .write_initiation(39, &init_body)
        .await
        .expect("write initiation");

    // Read the Reply frame and finish the initiator side of the Noise
    // handshake.
    let (hdr, reply_body) = framed.read_frame().await.expect("read reply");
    assert!(matches!(hdr, FrameHeader::Regular { msg_type: MsgType::Reply, .. }));
    let mut throw = vec![0u8; 1024];
    init.read_message(&reply_body, &mut throw).expect("noise reply decrypts");
    assert!(init.is_handshake_finished(), "initiator should be done after one round-trip");

    // Drop the framed socket — that closes the server task. We don't
    // drive h2 on top in this test; the existing unit tests cover the
    // NoiseStream layer.
    drop(framed);
    let _ = server_task.await;
}
