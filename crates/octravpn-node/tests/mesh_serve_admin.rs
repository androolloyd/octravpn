//! Integration test for the unified admin router mounted by both the
//! full Hub daemon AND the Hub-free `mesh serve` shape.
//!
//! Goal: prove that `octravpn-node mesh serve --admin-token <t>` exposes
//! the same `/api/v1/{machines,policy,...}` surface the full Hub would,
//! so the operator-facing `mesh status --remote …` / `mesh policy
//! get --remote …` CLI commands actually respond against a mesh-control
//! container running the standalone `mesh serve` shape.
//!
//! Tests:
//!   1. `mesh_serve_admin_router_mounted_when_token_present` — admin
//!      surface accepts authenticated `/api/v1/machines`.
//!   2. `mesh_serve_admin_router_returns_404_when_no_token_configured`
//!      — preserves Audit-3 H-1 byte-stable 404 invariant.
//!   3. `mesh_serve_mesh_status_returns_machine_registry_snapshot` —
//!      GET /api/v1/machines reflects the live wire roster.
//!   4. `mesh_serve_policy_get_returns_loaded_acl` — GET /api/v1/policy
//!      returns the loaded hujson doc.
//!   5. `mesh_serve_policy_set_persists_and_propagates` —
//!      PUT /api/v1/policy mutates the shared `PolicyStore`.
//!   6. `admin_router_byte_identical_under_hub_and_serve` — golden
//!      response shape regardless of which shell mounted the router.

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::Utc;
use octravpn_mesh::{
    admin_surface::build_admin_router,
    headscale_api::admin::{AdminState, InMemoryPreauthAdmin, UserRegistry, WireMachineAdmin},
    policy::PolicyStore,
    tailscale_wire::{MachineRecord, MachineRegistry},
};
use tower::ServiceExt;

const TOK: &str = "test-token-abcdef";

/// Build a `(AdminState, machines, policy)` tuple where the
/// MachineRegistry and PolicyStore are shared with the (notional)
/// wire layer the way `mesh serve` wires them.
fn build_state(token: &str) -> (AdminState, Arc<MachineRegistry>, PolicyStore) {
    let machines = Arc::new(MachineRegistry::new());
    let policy = PolicyStore::new();
    let state = AdminState::builder()
        .bearer_token(token.to_string())
        .users(UserRegistry::new())
        .machines(Arc::new(WireMachineAdmin::new(machines.clone())))
        .preauth(Arc::new(InMemoryPreauthAdmin::new()))
        .derp_regions(0)
        .policy(policy.clone())
        .build();
    (state, machines, policy)
}

fn upsert_peer(machines: &MachineRegistry, hostname: &str, ipv4: [u8; 4], user: &str) {
    let key_hex = format!("{:02x}{}", ipv4[3], "aa".repeat(31));
    machines.upsert(
        key_hex.clone(),
        MachineRecord::new_at(
            Utc::now(),
            key_hex,
            String::new(),
            user.into(),
            hostname.into(),
            std::net::Ipv4Addr::from(ipv4),
            false,
        ),
    );
}

#[tokio::test]
async fn mesh_serve_admin_router_mounted_when_token_present() {
    let (state, machines, _policy) = build_state(TOK);
    upsert_peer(&machines, "peer-1", [100, 64, 0, 10], "alice");
    let app = build_admin_router(state, Some(Arc::from(TOK)));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/machines")
                .header("authorization", format!("Bearer {TOK}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = v.as_array().expect("machines body is an array");
    assert_eq!(arr.len(), 1, "the upserted peer must show up");
    assert_eq!(arr[0]["name"], "peer-1");
}

#[tokio::test]
async fn mesh_serve_admin_router_returns_404_when_no_token_configured() {
    let (state, _machines, _policy) = build_state("");
    // None ⇒ empty router (no admin surface mounted at all). Wrap in
    // an outer router so unmatched paths resolve to the standard 404.
    let app = axum::Router::new().merge(build_admin_router(state, None));

    // Anonymous request — must NOT 200, must NOT 401. The 404 here
    // comes from the outer router's fallback (no route mounted), which
    // is the SAME on-wire effect as `BearerCheck::hidden`'s rejection
    // (status 404 + empty body) — Audit-3 H-1's invariant: external
    // probes can't tell whether the route exists or the token is
    // misconfigured.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/machines")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mesh_serve_mesh_status_returns_machine_registry_snapshot() {
    let (state, machines, _policy) = build_state(TOK);
    upsert_peer(&machines, "peer-1", [100, 64, 0, 10], "alice");
    upsert_peer(&machines, "peer-2", [100, 64, 0, 11], "bob");
    upsert_peer(&machines, "peer-3", [100, 64, 0, 12], "carol");

    let app = build_admin_router(state, Some(Arc::from(TOK)));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/machines")
                .header("authorization", format!("Bearer {TOK}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 3, "all three peers must appear");
    // sorted by hostname-then-id per WireMachineAdmin::list.
    assert_eq!(arr[0]["name"], "peer-1");
    assert_eq!(arr[1]["name"], "peer-2");
    assert_eq!(arr[2]["name"], "peer-3");
}

#[tokio::test]
async fn mesh_serve_policy_get_returns_loaded_acl() {
    let (state, _machines, policy) = build_state(TOK);
    // Pre-load a policy doc via the shared store (mimicking a prior PUT).
    let raw = r#"{
        // operator-loaded policy
        "acls": [
            {"action":"accept","src":["*"],"dst":["*:*"]}
        ]
    }"#;
    {
        let doc =
            octravpn_mesh::policy::parse_hujson_policy(raw).expect("test policy doc must parse");
        policy.set(doc, raw.to_string());
    }
    let app = build_admin_router(state, Some(Arc::from(TOK)));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/policy")
                .header("authorization", format!("Bearer {TOK}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["loaded"], serde_json::Value::Bool(true));
    let returned_raw = v["raw"].as_str().expect("raw field present");
    assert!(
        returned_raw.contains("operator-loaded policy"),
        "hujson comment must round-trip verbatim"
    );
}

#[tokio::test]
async fn mesh_serve_policy_set_persists_and_propagates() {
    let (state, _machines, policy) = build_state(TOK);
    let app = build_admin_router(state, Some(Arc::from(TOK)));

    let payload = r#"{
        "acls": []
    }"#;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/policy")
                .header("authorization", format!("Bearer {TOK}"))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string().into_bytes()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["applied"], serde_json::Value::Bool(true));

    // The shared store MUST now reflect the doc — the wire `/map`
    // long-poller wakes off the store's `Notify`, so this is the
    // signal that PUT actually propagated.
    assert!(
        policy.is_loaded(),
        "PolicyStore must reflect the PUT immediately"
    );

    // And a fresh GET must echo the same doc.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/policy")
                .header("authorization", format!("Bearer {TOK}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["loaded"], serde_json::Value::Bool(true));
    let returned_raw = v["raw"].as_str().unwrap();
    assert!(returned_raw.contains("acls"));
}

/// Both the full Hub and `mesh serve` mount the SAME
/// `build_admin_router` builder over an `AdminState` built from the
/// same trait objects. Building two independent routers from the same
/// state-shape (one for each notional shell) must produce
/// byte-identical responses on the same request.
#[tokio::test]
async fn admin_router_byte_identical_under_hub_and_serve() {
    // Hub-side state.
    let (hub_state, hub_machines, _hub_policy) = build_state(TOK);
    upsert_peer(&hub_machines, "peer-1", [100, 64, 0, 10], "alice");
    let hub_router = build_admin_router(hub_state, Some(Arc::from(TOK)));

    // Serve-side state, populated identically.
    let (serve_state, serve_machines, _serve_policy) = build_state(TOK);
    upsert_peer(&serve_machines, "peer-1", [100, 64, 0, 10], "alice");
    let serve_router = build_admin_router(serve_state, Some(Arc::from(TOK)));

    // Drive the same GET against both and compare status + body
    // verbatim. `WireMachineAdmin::render` stamps `last_seen` from
    // the upsert wall-clock so the two responses can drift on the
    // seconds digit; we sanity-check JSON structural equality
    // (ignoring `last_seen`) which is the user-visible contract.
    async fn fetch(r: axum::Router) -> (StatusCode, serde_json::Value) {
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/api/v1/machines")
                    .header("authorization", format!("Bearer {TOK}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    let (s1, mut v1) = fetch(hub_router).await;
    let (s2, mut v2) = fetch(serve_router).await;
    assert_eq!(s1, s2);
    // Strip the wall-clock-stamped fields before comparing.
    for arr in [&mut v1, &mut v2]
        .into_iter()
        .filter_map(|v| v.as_array_mut())
    {
        for m in arr.iter_mut() {
            if let Some(obj) = m.as_object_mut() {
                obj.remove("last_seen");
            }
        }
    }
    assert_eq!(v1, v2);
}
