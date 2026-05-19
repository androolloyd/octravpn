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

fn build_state() -> (WireState, PreauthMinter, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
    let minter = PreauthMinter::new();
    let state = WireState {
        server_noise_key: server,
        preauth: Arc::new(minter.clone()),
        ip_allocator: Arc::new(TailnetIpAllocator::new("interop-test")),
        machines: Arc::new(MachineRegistry::new()),
        derp_map: Arc::new(octravpn_mesh::tailscale_wire::DerpMap::default()),
        policy: Arc::new(Default::default()),
    };
    (state, minter, dir)
}

#[tokio::test]
async fn key_then_register_then_map_round_trip() {
    let (state, minter, _dir) = build_state();
    let pk = minter.mint("alice", DEFAULT_PREAUTH_TTL, false);
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
        disco_key: None,
        endpoints: Vec::new(),
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

    let (state, _minter, _dir) = build_state();
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

/// Flat v1.78+ path: `POST /machine/register` with NodeKey in the body.
/// Exercises the wire-layer addition that closes P0-2.
#[tokio::test]
async fn flat_register_path_works_via_octravpn_node_router() {
    let (state, minter, _dir) = build_state();
    let pk = minter.mint("alice", DEFAULT_PREAUTH_TTL, false);
    let app = tailscale_wire_router(state.clone());

    let node_hex = "1a".repeat(32);
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
                .uri("/machine/register")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&reg_body).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    // Flat /machine/map with NodeKey in body.
    let other_hex = "2b".repeat(32);
    state.machines.upsert(
        other_hex.clone(),
        octravpn_mesh::MachineRecord {
            node_key_hex: other_hex.clone(),
            machine_key_hex: String::new(),
            user: "bob".into(),
            hostname: "peer-b".into(),
            ipv4: std::net::Ipv4Addr::new(100, 64, 0, 99),
        disco_key: None,
        endpoints: Vec::new(),
        },
    );

    let map_body = serde_json::json!({
        "NodeKey": format!("nodekey:{node_hex}"),
        "Version": 39,
    });
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/machine/map")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&map_body).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
    let mr: octravpn_mesh::tailscale_wire::MapResponse =
        serde_json::from_slice(&raw).unwrap();
    assert_eq!(mr.peers.len(), 1);
}

/// Wall-4 acceptance: drive the IK handshake to completion, swap to
/// the BE-nonce [`BeTransport`], write one Tailscale Record frame
/// from the client side, read it back on the server side through the
/// same `BeTransport` plumbing the production `drive_ts2021_be`
/// callers use.
///
/// This is the in-process proof that the cipher swap (snow → owned
/// BE-nonce transport) round-trips a record cleanly. The real
/// in-the-wild verification is `docker/devnet/tailscale-interop/run-interop.sh`.
#[tokio::test]
async fn ts2021_be_transport_round_trips_record() {
    use octravpn_mesh::tailscale_wire::be_transport::{
        BeNoiseStream, BeTransport, MAX_PLAINTEXT_PER_RECORD,
    };
    use snow::{params::NoiseParams, Builder};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    // Drive a snow IK handshake in-process so both sides have a
    // matched (k1, k2) pair to feed BeTransport.
    let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let resp_static = Builder::new(params.clone()).generate_keypair().unwrap();
    let init_static = Builder::new(params.clone()).generate_keypair().unwrap();

    let mut init = Builder::new(params.clone())
        .local_private_key(&init_static.private)
        .remote_public_key(&resp_static.public)
        .build_initiator()
        .unwrap();
    let mut resp = Builder::new(params.clone())
        .local_private_key(&resp_static.private)
        .build_responder()
        .unwrap();

    let mut m1 = [0u8; 1024];
    let n1 = init.write_message(b"", &mut m1).unwrap();
    let mut throw = [0u8; 1024];
    resp.read_message(&m1[..n1], &mut throw).unwrap();
    let mut m2 = [0u8; 1024];
    let n2 = resp.write_message(b"", &mut m2).unwrap();
    init.read_message(&m2[..n2], &mut throw).unwrap();
    assert!(init.is_handshake_finished());
    assert!(resp.is_handshake_finished());

    let (i_k1, i_k2) = init.dangerously_get_raw_split();
    let (r_k1, r_k2) = resp.dangerously_get_raw_split();
    assert_eq!(i_k1, r_k1);
    assert_eq!(i_k2, r_k2);

    // Build the two BeTransports + BeNoiseStreams over a duplex.
    let init_xport = BeTransport::from_split_initiator(i_k1, i_k2);
    let resp_xport = BeTransport::from_split_responder(r_k1, r_k2);
    let (a, b) = duplex(64 * 1024);
    let mut client = BeNoiseStream::new(a, init_xport);
    let mut server = BeNoiseStream::new(b, resp_xport);

    // Client writes one record; server reads it.
    let payload = b"ts2021-be: hello via Record frame";
    client.write_all(payload).await.unwrap();
    client.flush().await.unwrap();

    let mut got = vec![0u8; payload.len()];
    server.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    // Server writes back; client reads.
    let reply = b"ts2021-be: ack";
    server.write_all(reply).await.unwrap();
    server.flush().await.unwrap();
    let mut got2 = vec![0u8; reply.len()];
    client.read_exact(&mut got2).await.unwrap();
    assert_eq!(got2, reply);

    // Sanity: a larger payload that crosses the per-record boundary
    // still reassembles cleanly.
    let big: Vec<u8> = (0..(MAX_PLAINTEXT_PER_RECORD + 200))
        .map(|i| (i % 251) as u8)
        .collect();
    let big_clone = big.clone();
    let writer = tokio::spawn(async move {
        client.write_all(&big_clone).await.unwrap();
        client.flush().await.unwrap();
    });
    let mut buf = vec![0u8; big.len()];
    server.read_exact(&mut buf).await.unwrap();
    writer.await.unwrap();
    assert_eq!(buf, big);
}

/// PR 3 acceptance: Stream:true on `/machine/map` emits a fresh
/// `MapResponse` chunk when a second peer registers. Drives the
/// registry's `Notify::notify_waiters` path end-to-end against the
/// router `octravpn-node` actually mounts.
#[tokio::test(start_paused = true)]
async fn stream_true_emits_chunk_on_registry_change() {
    use http_body_util::BodyExt;
    use std::time::Duration;

    let (state, _minter, _dir) = build_state();
    let a_hex = "aa".repeat(32);
    let b_hex = "bb".repeat(32);
    // Seed peer-a so the `/map` handler doesn't 404.
    state.machines.upsert(
        a_hex.clone(),
        octravpn_mesh::MachineRecord {
            node_key_hex: a_hex.clone(),
            machine_key_hex: String::new(),
            user: "alice".into(),
            hostname: "peer-a".into(),
            ipv4: std::net::Ipv4Addr::new(100, 64, 0, 10),
        disco_key: None,
        endpoints: Vec::new(),
        },
    );

    let app = tailscale_wire_router(state.clone());
    let req_body = serde_json::json!({ "Stream": true, "Version": 39 });
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/machine/nodekey:{a_hex}/map"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&req_body).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let mut body = resp.into_body();
    // First chunk = initial MapResponse with 0 peers. Stream:true now
    // uses `[u32 LE size][zstd(JSON)]` framing (closing Wall 5; see
    // `docs/tailscale-interop-blocker.md` and the unit-level coverage
    // in `headscale-api::tailscale_wire::map`). Decode the chunk the
    // same way upstream `controlclient/direct.go::decodeMsg` does.
    let frame = BodyExt::frame(&mut body).await.unwrap().unwrap();
    let chunk = frame.into_data().unwrap();
    let size = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as usize;
    assert_eq!(chunk.len(), 4 + size, "framed chunk size mismatch");
    let json_bytes = zstd::bulk::decompress(&chunk[4..], 16 * 1024 * 1024)
        .expect("zstd-framed chunk decompresses");
    let first: octravpn_mesh::tailscale_wire::MapResponse =
        serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(first.peers.len(), 0);

    // `Notify::notify_waiters` only wakes *current* waiters — it
    // doesn't store permits. So we have to register the second-chunk
    // waiter *before* we upsert peer-b. Spawn the upsert from a
    // background task that wakes after a short virtual-time delay
    // (we're running under `tokio::time::pause`), then poll the
    // body. The stream's select! will be parked on `notified()`
    // when peer-b's `notify_waiters` fires.
    let state_for_spawn = state.clone();
    let b_hex_for_spawn = b_hex.clone();
    let spawn = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        state_for_spawn.machines.upsert(
            b_hex_for_spawn.clone(),
            octravpn_mesh::MachineRecord {
                node_key_hex: b_hex_for_spawn,
                machine_key_hex: String::new(),
                user: "bob".into(),
                hostname: "peer-b".into(),
                ipv4: std::net::Ipv4Addr::new(100, 64, 0, 11),
            disco_key: None,
            endpoints: Vec::new(),
            },
        );
    });

    let frame = BodyExt::frame(&mut body).await.unwrap().unwrap();
    spawn.await.unwrap();
    let chunk = frame.into_data().unwrap();
    let size = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as usize;
    assert_eq!(chunk.len(), 4 + size);
    let json_bytes = zstd::bulk::decompress(&chunk[4..], 16 * 1024 * 1024)
        .expect("zstd-framed chunk decompresses");
    let second: octravpn_mesh::tailscale_wire::MapResponse =
        serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(
        second.peers.len(),
        1,
        "stream should emit a fresh MapResponse on registry change"
    );
    assert_eq!(second.peers[0].addresses[0], "100.64.0.11/32");
}

/// Wall 6 regression guard: when `WireState.derp_map` is populated
/// with a non-empty fixture, the `/machine/map` response carries the
/// same regions/nodes through to the client. Stock `tailscale` v1.78+
/// gates `BackendState=Running` on a reachable DERP relay, and the
/// daemon refuses to advance past `Starting` if `MapResponse.DERPMap`
/// is empty (see `docs/tailscale-interop-blocker.md` 2026-05-19
/// §"Wall 6 closed"). This test pins the field-by-field shape.
#[tokio::test]
async fn map_response_includes_derp_map_when_configured() {
    use octravpn_mesh::tailscale_wire::{
        wire::{DerpMap, DerpRegion, DerpRegionNode},
        MachineRegistry,
    };
    use octravpn_mesh::{
        ip_alloc::TailnetIpAllocator, PreauthMinter, ServerNoiseKey, WireState,
    };

    let dir = tempdir().unwrap();
    let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
    let minter = PreauthMinter::new();
    // One-region DERP map mirroring the docker fixture
    // (`docker/devnet/tailscale-interop/derp-map.json`).
    let mut regions = std::collections::HashMap::new();
    regions.insert(
        1u16,
        DerpRegion {
            region_id: 1,
            region_code: "interop".into(),
            region_name: "Interop test region".into(),
            avoid: false,
            nodes: vec![DerpRegionNode {
                name: "1a".into(),
                region_id: 1,
                host_name: "derp-1".into(),
                ipv4: String::new(),
                ipv6: String::new(),
                derp_port: 443,
                stun_port: 0,
                stun_only: false,
                insecure_for_tests: true,
            }],
        },
    );
    let derp_map = DerpMap {
        regions,
        omit_default_regions: true,
    };
    let state = WireState {
        server_noise_key: server,
        preauth: Arc::new(minter.clone()),
        ip_allocator: Arc::new(TailnetIpAllocator::new("interop-test")),
        machines: Arc::new(MachineRegistry::new()),
        derp_map: Arc::new(derp_map),
        policy: Arc::new(Default::default()),
    };

    // Register a single peer and read its `/machine/map` view.
    let pk = minter.mint("alice", DEFAULT_PREAUTH_TTL, false);
    let app = tailscale_wire_router(state.clone());
    let node_hex = "ef".repeat(32);
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
                .uri("/machine/register")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&reg_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    // Inject a second peer so the long-poll returns immediately.
    let other_hex = "fe".repeat(32);
    state.machines.upsert(
        other_hex.clone(),
        octravpn_mesh::MachineRecord {
            node_key_hex: other_hex,
            machine_key_hex: String::new(),
            user: "bob".into(),
            hostname: "peer-b".into(),
            ipv4: std::net::Ipv4Addr::new(100, 64, 0, 99),
        disco_key: None,
        endpoints: Vec::new(),
        },
    );

    let map_body = serde_json::json!({
        "NodeKey": format!("nodekey:{node_hex}"),
        "Version": 39,
    });
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/machine/map")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&map_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();

    // Wire-shape assertions: the JSON must carry the upstream field
    // names byte-identically so the Go decoder reaches the populated
    // values (case-insensitive on the wire, but we pin the spelling
    // anyway).
    let raw_str = std::str::from_utf8(&raw).unwrap();
    assert!(raw_str.contains("\"DERPMap\""), "DERPMap field name present");
    assert!(raw_str.contains("\"Regions\""), "Regions inside DERPMap");
    assert!(raw_str.contains("\"RegionID\""));
    assert!(raw_str.contains("\"HostName\""));
    assert!(raw_str.contains("\"DERPPort\""));
    assert!(raw_str.contains("\"InsecureForTests\""));
    assert!(raw_str.contains("\"OmitDefaultRegions\""));

    let mr: octravpn_mesh::tailscale_wire::MapResponse =
        serde_json::from_slice(&raw).unwrap();
    assert!(mr.derp_map.omit_default_regions);
    let region = mr.derp_map.regions.get(&1).expect("region 1 present");
    assert_eq!(region.region_id, 1);
    assert_eq!(region.region_code, "interop");
    assert_eq!(region.nodes.len(), 1);
    let node = &region.nodes[0];
    assert_eq!(node.host_name, "derp-1");
    assert_eq!(node.derp_port, 443);
    assert!(node.insecure_for_tests);
}

/// Wall 7 — DiscoKey + Endpoints must round-trip through the
/// `octravpn-node`-mounted router. Mock a `/map` request from peer-a
/// carrying both fields, then poll peer-b's `/map` view and assert
/// peer-a's `MapNode` carries the same DiscoKey + Endpoints. Without
/// this round-trip, stock `tailscale`'s `wgengine.Reconfig` runs at
/// `0/0 peers` and `tailscale ping` returns `unknown peer` — the
/// docker-network end-to-end failure mode that closed at exit code 50
/// pre-fix.
#[tokio::test]
async fn map_response_round_trips_disco_key_and_endpoints() {
    let (state, minter, _dir) = build_state();
    let app = tailscale_wire_router(state.clone());

    // Register peer-a + peer-b via the wire router so the registry
    // sees the same MachineRecord shape stock `tailscale up` produces.
    let pk_a = minter.mint("alice", DEFAULT_PREAUTH_TTL, true);
    let pk_b = minter.mint("bob", DEFAULT_PREAUTH_TTL, true);
    let a_hex = "a1".repeat(32);
    let b_hex = "b2".repeat(32);

    for (hex, pk, host) in [
        (&a_hex, &pk_a.key, "peer-a"),
        (&b_hex, &pk_b.key, "peer-b"),
    ] {
        let body = serde_json::json!({
            "NodeKey": format!("nodekey:{hex}"),
            "Auth": { "AuthKey": pk },
            "Hostinfo": { "Hostname": host, "OS": "linux", "OSVersion": "6.6" },
        });
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "register {host} ok"
        );
    }

    // Peer-a's /map call carries DiscoKey + Endpoints — the moment
    // upstream stock-client crosses the post-handshake boundary.
    let disco_a = format!("discokey:{}", "1a".repeat(32));
    let endpoints_a = vec![
        "10.0.0.10:41641".to_string(),
        "[fe80::1]:41641".to_string(),
    ];
    let map_req_a = serde_json::json!({
        "Version": 39,
        "DiscoKey": &disco_a,
        "Endpoints": &endpoints_a,
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/machine/nodekey:{a_hex}/map"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&map_req_a).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    // MachineRecord on the registry must now carry the fields.
    let rec_a = state.machines.get(&a_hex).expect("peer-a registered");
    assert_eq!(rec_a.disco_key.as_deref(), Some(disco_a.as_str()));
    assert_eq!(rec_a.endpoints, endpoints_a);

    // Peer-b polls /map; its MapResponse.Peers[0] (== peer-a) must
    // carry DiscoKey + Endpoints byte-identical to what peer-a sent.
    let map_req_b = serde_json::json!({ "Version": 39 });
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/machine/nodekey:{b_hex}/map"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&map_req_b).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
    let raw_str = std::str::from_utf8(&raw).unwrap();
    assert!(
        raw_str.contains("\"DiscoKey\""),
        "DiscoKey tag present: {raw_str}"
    );
    assert!(
        raw_str.contains("\"Endpoints\""),
        "Endpoints tag present: {raw_str}"
    );
    let mr: octravpn_mesh::tailscale_wire::MapResponse =
        serde_json::from_slice(&raw).unwrap();
    assert_eq!(mr.peers.len(), 1, "peer-a visible to peer-b");
    let peer_a = &mr.peers[0];
    assert_eq!(peer_a.disco_key.as_deref(), Some(disco_a.as_str()));
    assert_eq!(peer_a.endpoints, endpoints_a);
}

