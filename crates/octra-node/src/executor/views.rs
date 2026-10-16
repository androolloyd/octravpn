// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::Native;
use crate::Committed;
use octra_node_protocol::{circle_wasm::Error, rpc::Fault};
use octra_node_runtime::{
    circle_query::Query,
    circle_view::{self, Clock},
    program::view::{self, Plan},
};

pub(crate) struct ViewLease(tokio::sync::OwnedSemaphorePermit);
impl Native {
    /// Read-only host work has independent capacity and retains its permit if
    /// the HTTP future disappears while a blocking decoder is still running.
    pub(crate) async fn read<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> Result<T, Fault> + Send + 'static,
    ) -> Result<T, Fault> {
        let permit = self
            .reads
            .clone()
            .try_acquire_owned()
            .map_err(|_| Fault::new(110, b"service unavailable"))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            job()
        })
        .await
        .unwrap_or_else(|_| Err(Fault::new(110, b"service unavailable")))
    }
    pub(crate) fn circle_program(
        &self,
        kind: octra_node_runtime::circle_rpc::program::Read,
        authenticated: bool,
        snapshot: &Committed,
        profile: &circle_view::Profile,
        doc: &octra_node_protocol::native_json::Document,
        params: &octra_node_protocol::native_json::Value,
    ) -> Result<Vec<u8>, Fault> {
        octra_node_runtime::circle_rpc::program::read(
            kind,
            authenticated,
            &self.runtime,
            snapshot.state(),
            profile,
            doc,
            params,
        )
    }
    pub(crate) async fn circle_profile(
        &self,
        snapshot: &Committed,
        kind: circle_view::ReadKind,
    ) -> Result<circle_view::Profile, Fault> {
        circle_view::epoch(snapshot.state().get(&[b"meta", b"last_epoch"]), kind)
            .map_err(|error| Fault::new(-32000, error.to_string().as_bytes()))?;
        circle_view::canonical(&snapshot.assets, self.history.as_ref())
            .await
            .map_err(|error| Fault::new(-32005, error.to_string().as_bytes()))
    }
    pub(crate) fn begin_circle_view(&self) -> Result<ViewLease, Fault> {
        self.circle_views
            .clone()
            .try_acquire_owned()
            .map(ViewLease)
            .map_err(|_| Fault::new(-32005, b"circle view busy"))
    }
    pub(crate) async fn circle_view(
        &self,
        lease: ViewLease,
        clock: Clock,
        snapshot: Committed,
        profile: circle_view::Profile,
        plan: octra_node_runtime::circle_rpc::view::Plan,
    ) -> Result<Vec<u8>, Fault> {
        use octra_node_runtime::circle_rpc::view;
        let runtime = self.runtime.clone();
        let running = clock.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _lease = lease.0;
            if !running.running() {
                return Err(view::time_limit());
            }
            let query = Query::committed(&snapshot.assets, &profile)
                .map_err(|_| view::resources())?
                .with_runtime(&runtime)
                .with_clock(running.clone());
            let result = plan.execute(&query, snapshot.state());
            if running.expired() {
                Err(view::time_limit())
            } else {
                result
            }
        })
        .await
        .unwrap_or_else(|_| Err(view::resources()));
        if clock.expired() {
            Err(view::time_limit())
        } else {
            result
        }
    }
    pub(crate) fn begin_view(&self) -> Result<ViewLease, Fault> {
        self.views
            .clone()
            .try_acquire_owned()
            .map(ViewLease)
            .map_err(|_| Fault::new(-32005, b"Program view busy"))
    }
    pub(crate) async fn program_view(
        &self,
        lease: ViewLease,
        clock: Clock,
        snapshot: Committed,
        plan: Plan,
    ) -> Result<Vec<u8>, Fault> {
        circle_view::epoch(
            snapshot.state().get(&[b"meta", b"last_epoch"]),
            circle_view::ReadKind::Program,
        )
        .map_err(|_| Fault::new(-32005, b"program snapshot epoch invalid"))?;
        let profile = circle_view::canonical(&snapshot.assets, self.history.as_ref())
            .await
            .map_err(|error| Fault::new(-32005, error.to_string().as_bytes()))?;
        let runtime = self.runtime.clone();
        let running = clock.clone();
        let result = tokio::task::spawn_blocking(move || {
            // This permit outlives a timed-out or cancelled HTTP future.
            let _lease = lease.0;
            if !running.running() {
                return Err(view::time_limit());
            }
            let query = Query::committed(&snapshot.assets, &profile)
                .map_err(|_| view::resources())?
                .with_runtime(&runtime)
                .with_clock(running.clone());
            let receipt = query.program(
                plan.address(),
                plan.method(),
                plan.arguments(),
                plan.caller(),
                view::EFFORT_LIMIT,
            );
            if running.expired() {
                return Err(view::time_limit());
            }
            match receipt {
                Ok(receipt) => plan.response(snapshot.state(), receipt),
                Err(Error::Rejected(reason)) => Err(Fault::new(-32000, reason)),
                Err(Error::Unavailable(_)) => Err(view::resources()),
            }
        })
        .await
        .unwrap_or_else(|_| Err(view::resources()));
        if clock.expired() {
            Err(view::time_limit())
        } else {
            result
        }
    }
}
