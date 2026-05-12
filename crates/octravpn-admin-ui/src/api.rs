//! JSON API exposed to the embedded SPA.
//!
//! Read endpoints proxy `contract_call` reads on the OctraVPN program.
//! Write endpoints construct signed transactions using `state.wallet`
//! and submit via `octra_submit`. If no wallet is configured, write
//! endpoints return 401.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::AdminState;

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/version", get(version))
        .route("/identity", get(identity))
        .route("/tailnets", get(list_tailnets))
        .route("/tailnets/:id", get(get_tailnet))
        .route("/tailnets/:id/members", post(add_member))
        .route("/tailnets/:id/members/:addr", delete(remove_member))
        .route("/tailnets/:id/deposit", post(deposit))
        .route("/tailnets/:id/acl", put(update_acl))
        .route("/tailnets/:id/exits", post(configure_exit))
        .route("/endpoints", get(list_endpoints))
        .route("/endpoints/:addr", get(get_endpoint))
        .route("/acl/hash", post(compute_acl_hash))
}

// ---------------- shared helpers ----------------

#[derive(Debug, serde::Serialize)]
struct ApiError {
    error: String,
}

fn err(status: StatusCode, msg: impl Into<String>) -> axum::response::Response {
    (status, Json(ApiError { error: msg.into() })).into_response()
}

fn require_wallet(s: &AdminState) -> Result<&octravpn_core::sig::KeyPair, axum::response::Response> {
    s.wallet
        .as_ref()
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "no wallet configured; UI is read-only"))
}

async fn submit_signed(
    s: &AdminState,
    method: &str,
    params: Vec<Value>,
    value: u64,
) -> Result<Value, axum::response::Response> {
    let kp = require_wallet(s)?;
    let from = octravpn_core::address::Address::from_pubkey(&kp.public.0);
    let call = json!({
        "kind": "contract_call",
        "from": from.display(),
        "to": s.program_addr.display(),
        "method": method,
        "params": params,
        "value": value,
        "fee": 10u64,
        "nonce": 0u64,
    });
    let signed = octravpn_core::tx::sign_call(kp, call)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("sign: {e}")))?;
    s.rpc
        .submit(&signed)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("submit: {e}")))
        .map(|r| json!({ "hash": r.hash }))
}

// ---------------- handlers ----------------

async fn version() -> impl IntoResponse {
    Json(json!({
        "name": "octravpn-admin",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn identity(State(s): State<Arc<AdminState>>) -> impl IntoResponse {
    Json(json!({
        "caller": s.caller_addr(),
        "program": s.program_addr.display(),
        "writable": s.wallet.is_some(),
    }))
}

async fn list_tailnets(State(s): State<Arc<AdminState>>) -> impl IntoResponse {
    match s
        .rpc
        .contract_call(
            &s.program_addr,
            "list_tailnets",
            &[json!(0u64), json!(500u64)],
            None,
        )
        .await
    {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, format!("rpc: {e}")),
    }
}

async fn get_tailnet(
    State(s): State<Arc<AdminState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match s
        .rpc
        .contract_call(&s.program_addr, "get_tailnet", &[json!(id)], None)
        .await
    {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, format!("rpc: {e}")),
    }
}

#[derive(Deserialize)]
struct AddMemberReq {
    addr: String,
}

async fn add_member(
    State(s): State<Arc<AdminState>>,
    Path(id): Path<String>,
    Json(body): Json<AddMemberReq>,
) -> impl IntoResponse {
    match submit_signed(&s, "add_member", vec![json!(id), json!(body.addr)], 0).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => e,
    }
}

async fn remove_member(
    State(s): State<Arc<AdminState>>,
    Path((id, addr)): Path<(String, String)>,
) -> impl IntoResponse {
    match submit_signed(&s, "remove_member", vec![json!(id), json!(addr)], 0).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => e,
    }
}

#[derive(Deserialize)]
struct DepositReq {
    amount: u64,
}

async fn deposit(
    State(s): State<Arc<AdminState>>,
    Path(id): Path<String>,
    Json(body): Json<DepositReq>,
) -> impl IntoResponse {
    match submit_signed(&s, "deposit_to_tailnet", vec![json!(id)], body.amount).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => e,
    }
}

#[derive(Deserialize)]
struct AclReq {
    /// Either a `policy_hash` (64-char hex) directly OR a TOML `doc`
    /// the server hashes for you.
    policy_hash: Option<String>,
    doc: Option<String>,
}

async fn update_acl(
    State(s): State<Arc<AdminState>>,
    Path(id): Path<String>,
    Json(body): Json<AclReq>,
) -> impl IntoResponse {
    let hash = match (body.policy_hash, body.doc) {
        (Some(h), _) => h,
        (None, Some(toml_doc)) => match octravpn_mesh::AclDoc::from_toml(&toml_doc) {
            Ok(doc) => hex::encode(doc.policy_hash()),
            Err(e) => return err(StatusCode::BAD_REQUEST, format!("acl parse: {e}")),
        },
        (None, None) => return err(StatusCode::BAD_REQUEST, "policy_hash or doc required"),
    };
    match submit_signed(&s, "update_acl", vec![json!(id), json!(hash)], 0).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => e,
    }
}

#[derive(Deserialize)]
struct ExitReq {
    validator: String,
}

async fn configure_exit(
    State(s): State<Arc<AdminState>>,
    Path(id): Path<String>,
    Json(body): Json<ExitReq>,
) -> impl IntoResponse {
    match submit_signed(
        &s,
        "configure_tailnet_exit",
        vec![json!(id), json!(body.validator)],
        0,
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err(e) => e,
    }
}

async fn list_endpoints(State(s): State<Arc<AdminState>>) -> impl IntoResponse {
    match s
        .rpc
        .contract_call(
            &s.program_addr,
            "list_active_endpoints",
            &[json!(0u64), json!(500u64)],
            None,
        )
        .await
    {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, format!("rpc: {e}")),
    }
}

async fn get_endpoint(
    State(s): State<Arc<AdminState>>,
    Path(addr): Path<String>,
) -> impl IntoResponse {
    match s
        .rpc
        .contract_call(&s.program_addr, "get_endpoint", &[json!(addr)], None)
        .await
    {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, format!("rpc: {e}")),
    }
}

#[derive(Deserialize)]
struct AclHashReq {
    doc: String,
}

async fn compute_acl_hash(Json(body): Json<AclHashReq>) -> impl IntoResponse {
    match octravpn_mesh::AclDoc::from_toml(&body.doc) {
        Ok(doc) => Json(json!({
            "hash": hex::encode(doc.policy_hash()),
        }))
        .into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, format!("acl parse: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use tower::ServiceExt;

    fn ctx() -> Arc<AdminState> {
        AdminState::new(
            "inprocess://octPROG",
            "octPROG",
            None,
            None,
        )
    }

    #[tokio::test]
    async fn version_endpoint_returns_json() {
        let app = crate::router(ctx());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/version")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["name"], json!("octravpn-admin"));
    }

    #[tokio::test]
    async fn identity_reports_readonly_when_no_wallet() {
        let app = crate::router(ctx());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/identity")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["writable"], json!(false));
    }

    #[tokio::test]
    async fn compute_acl_hash_is_deterministic() {
        let app = crate::router(ctx());
        let doc = r#"version = 1
            [[rules]]
            action = "accept"
            src = ["*"]
            dst = ["*"]
        "#;
        let req = Request::builder()
            .method("POST")
            .uri("/api/acl/hash")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&json!({ "doc": doc })).unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        let hash = v["hash"].as_str().unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[tokio::test]
    async fn write_endpoints_401_without_wallet() {
        let app = crate::router(ctx());
        let req = Request::builder()
            .method("POST")
            .uri("/api/tailnets/abc/members")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&json!({ "addr": "octX" })).unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 401);
    }
}
