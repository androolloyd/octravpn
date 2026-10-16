// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Exact native compute method routing. The runtime gateway owns the serving
//! identity, canonical epoch and signed caller/session authorization.
use octra_node_protocol::{
    native_json::{Document, Value},
    rpc::Fault,
};
use octra_node_runtime::compute_service::{rpc, Service};

#[derive(Clone, Copy)]
pub(super) enum Route {
    Submit,
    Status,
    Cancel,
}
pub(super) fn route(method: &[u8]) -> Option<Route> {
    if method == rpc::SUBMIT {
        Some(Route::Submit)
    } else if method == rpc::STATUS {
        Some(Route::Status)
    } else if method == rpc::CANCEL {
        Some(Route::Cancel)
    } else {
        None
    }
}
pub(super) async fn dispatch(
    route: Route,
    service: Option<&Service>,
    document: &Document,
    params: &Value,
) -> rpc::Result<Vec<u8>> {
    let Some(service) = service else {
        // Native RPC decodes the complete parameter shape before invoking its
        // service. Preserve that priority even on a host without the service.
        match route {
            Route::Submit => {
                rpc::request_of_params(document, params)?;
            }
            Route::Status => {
                rpc::read_of_params(document, params)?;
            }
            Route::Cancel => {
                rpc::cancellation_of_params(document, params)?;
            }
        }
        return Err(Fault::new(110, b"service unavailable").into());
    };
    match route {
        Route::Submit => rpc::submit(service, document, params).await,
        Route::Status => rpc::status(service, document, params).await,
        Route::Cancel => rpc::cancel(service, document, params).await,
    }
}
