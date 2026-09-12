//! HTTP control plane the exit node serves to clients.
//!
//! Originally one 2060-line `control.rs`; split per
//! `docs/refactor-plan-2026-05-20.md` candidate #2 (XC-1 cross-cutting)
//! so each new HTTP feature lands in its own file and contributors can
//! review the route table independently from any single handler.
//!
//! ## Adding a new HTTP route
//!
//! 1. Create a new file under [`handlers/`](self::handlers), define an
//!    `axum`-compatible handler fn that takes `State<Arc<ControlState>>`
//!    + whatever extractors the route needs.
//! 2. Register the handler in [`router::router_axum`] with one
//!    `.route("/path", method(handlers::module::handler))` line.
//! 3. Tests go inline in the handler's own file under
//!    `#[cfg(test)] mod tests`. Tests live next to the code they cover
//!    so a single PR touches one file per route.
//! 4. If the route is bearer-gated, either (a) pull a `BearerCheck` off
//!    `ControlState` (`s.bearer_metrics()` / `s.bearer_admin()` /
//!    `s.bearer_events()`) and call `.check(&headers)?`, or (b) wrap
//!    the route with `.route_layer(axum::middleware::from_fn_with_state(
//!    check, octravpn_core::bearer::bearer_middleware))`. The two
//!    routes are equivalent — pick (a) when the handler also reads
//!    other `ControlState` fields, (b) when the handler is auth-only.
//!
//! ## Module layout
//!
//! * [`state`] — `ControlState` + builder methods (`with_metrics_token`,
//!   `with_admin_token`, …). The shared mutable surface every handler
//!   reads.
//! * [`metrics`] — `NodeMetrics` (the AtomicU64 counters).
//! * [`router`] — `router_axum` route table.
//! * [`handlers`] — one file per route family.
//!
//! Re-exports below mirror the legacy pre-split API so
//! `crate::control::{ControlState, NodeMetrics, …}` keeps working for
//! [`crate::hub::Hub`], [`crate::tunnel`], and the rest of the node
//! crate without per-call-site edits.

pub(crate) mod enroll;
pub(crate) mod enroll_circle;
pub(crate) mod handlers;
pub(crate) mod metrics;
pub(crate) mod router;
pub(crate) mod state;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tracing::info;

pub(crate) use handlers::sweeper::run_sweeper;
pub(crate) use metrics::NodeMetrics;
pub(crate) use state::{
    ControlState, RelayLifecycleVerifier, SessionAdmissionVerifier, ShadowSigner,
};

pub(crate) async fn serve(state: Arc<ControlState>, addr: SocketAddr) -> Result<()> {
    let router = state.router_axum();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(?addr, "control plane listening");
    // `into_make_service_with_connect_info` propagates the client
    // SocketAddr into the rate-limit middleware via `ConnectInfo`.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
