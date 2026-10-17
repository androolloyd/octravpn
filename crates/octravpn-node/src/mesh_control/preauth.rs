use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use octravpn_mesh::DEFAULT_PREAUTH_TTL;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
struct AdminCtx {
    stores: crate::mesh_store::MeshStore,
    token: Option<Arc<str>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct AdminReq {
    #[serde(default = "default_user")]
    user: String,
    #[serde(default)]
    reusable: bool,
    #[serde(default)]
    ttl_secs: Option<u64>,
}
fn default_user() -> String {
    "default".into()
}
impl Default for AdminReq {
    fn default() -> Self {
        Self {
            user: default_user(),
            reusable: false,
            ttl_secs: None,
        }
    }
}
#[derive(Serialize)]
struct AdminResp {
    key: String,
    user: String,
    expires_at: u64,
    reusable: bool,
}
async fn mint_handler(
    State(ctx): State<AdminCtx>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if let Err(response) =
        octravpn_core::bearer::BearerCheck::hidden(ctx.token.clone()).check(&headers)
    {
        return response;
    }
    let req = if body.is_empty() {
        AdminReq::default()
    } else {
        match serde_json::from_slice::<AdminReq>(&body) {
            Ok(request) => request,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid preauth request").into_response(),
        }
    };
    let Ok(pk) = ctx
        .stores
        .mint_for_user(
            req.user,
            req.ttl_secs.unwrap_or(DEFAULT_PREAUTH_TTL.as_secs()),
            req.reusable,
        )
        .await
    else {
        return (StatusCode::SERVICE_UNAVAILABLE, "preauth mint unavailable").into_response();
    };
    Json(AdminResp {
        key: pk.key,
        user: pk.user,
        expires_at: pk.expires_at,
        reusable: pk.reusable,
    })
    .into_response()
}
pub(super) fn router(stores: crate::mesh_store::MeshStore, token: Option<Arc<str>>) -> Router {
    let check = octravpn_core::bearer::BearerCheck::hidden(token.clone());
    Router::new()
        .route("/admin/preauth", post(mint_handler))
        .layer(axum::extract::DefaultBodyLimit::max(4096))
        .layer(axum::middleware::from_fn_with_state(
            check,
            octravpn_core::bearer::bearer_middleware,
        ))
        .with_state(AdminCtx { stores, token })
}
