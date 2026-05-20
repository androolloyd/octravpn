//! Per-route axum handlers. Each submodule owns exactly one route
//! family and its inline `#[cfg(test)]` tests. Shared JSON-error
//! envelope ([`ApiError`]) lives here so handlers can `use super::ApiError`
//! without reaching into a sibling submodule.

use serde::Serialize;

pub(crate) mod events;
pub(crate) mod health;
pub(crate) mod metrics;
pub(crate) mod preauth;
pub(crate) mod receipt;
pub(crate) mod session;
pub(crate) mod sweeper;

/// JSON error envelope returned by every handler that reports a
/// structured 4xx/5xx. The single field name keeps the on-wire shape
/// uniform across `/session`, `/session/:id`, and any future
/// JSON-returning handler that grows.
#[derive(Serialize)]
pub(crate) struct ApiError {
    error: String,
}

impl ApiError {
    pub(crate) fn new(s: impl Into<String>) -> Self {
        Self { error: s.into() }
    }
}
