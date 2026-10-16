// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Context, Document, Fault, Value};
use octra_node_runtime::{
    circle_view::Clock,
    program::view::{self, Plan},
};
use std::time::Duration;

struct Stop(Clock);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.stop();
    }
}
pub(super) async fn circle(
    host: &Context,
    doc: &Document,
    params: &Value,
    authenticated: bool,
) -> std::result::Result<Vec<u8>, Fault> {
    use octra_node_runtime::circle_rpc::view;
    let snapshot = host
        .node
        .snapshot()
        .map_err(|_| Fault::new(110, b"service unavailable"))?;
    let profile = host
        .executor
        .circle_profile(&snapshot, octra_node_runtime::circle_view::ReadKind::View)
        .await?;
    let clock = Clock::new(Duration::from_secs(10));
    let _stop = Stop(clock.clone());
    let deadline = tokio::time::Instant::from_std(clock.deadline());
    let doc = doc.clone();
    let params = params.clone();
    tokio::time::timeout_at(deadline, async {
        let captured = snapshot.clone();
        let plan = host
            .executor
            .read(move || view::Plan::prepare(captured.state(), &doc, &params, authenticated))
            .await?;
        let lease = host.executor.begin_circle_view()?;
        host.executor
            .circle_view(lease, clock, snapshot, profile, plan)
            .await
    })
    .await
    .unwrap_or_else(|_| Err(view::time_limit()))
}
pub(super) async fn call(
    host: &Context,
    doc: &Document,
    params: &Value,
) -> std::result::Result<Vec<u8>, Fault> {
    let plan = Plan::prepare(doc, params)?;
    let clock = Clock::new(Duration::from_secs(10));
    let _stop = Stop(clock.clone());
    let lease: crate::executor::ViewLease = host.executor.begin_view()?;
    let deadline = tokio::time::Instant::from_std(clock.deadline());
    tokio::time::timeout_at(deadline, async {
        let snapshot = host
            .node
            .snapshot()
            .map_err(|_| Fault::new(-32005, b"program snapshot unavailable"))?;
        host.executor
            .program_view(lease, clock, snapshot, plan)
            .await
    })
    .await
    .unwrap_or_else(|_| Err(view::time_limit()))
}
