// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Circle operation refusals and local execution failures remain separate.
use crate::execution::{Completion, Error, Rejection};
use octra_node_protocol::{circle_program::Refusal, circle_wasm::Error as WasmError};
pub(crate) enum Failure {
    Refused(Refusal),
    Unavailable(Error),
}
impl Failure {
    pub(crate) fn effect(self) -> WasmError {
        match self {
            Self::Refused(e) => WasmError::Rejected(e.reason),
            Self::Unavailable(e) => WasmError::Unavailable(e.0.into_bytes()),
        }
    }
}
impl From<Refusal> for Failure {
    fn from(error: Refusal) -> Self {
        Self::Refused(error)
    }
}
pub(crate) fn unavailable(reason: impl std::fmt::Display) -> Failure {
    Failure::Unavailable(Error(reason.to_string()))
}
pub(crate) fn refused(tag: &'static str, reason: impl Into<Vec<u8>>) -> Failure {
    Refusal::new(tag, reason).into()
}
pub(crate) fn completion(result: Result<(), Failure>) -> Result<Completion, Error> {
    match result {
        Ok(()) => Ok(Completion::Confirmed {
            created_account: None,
        }),
        Err(Failure::Unavailable(error)) => Err(error),
        Err(Failure::Refused(error)) => Ok(Completion::Rejected(Rejection {
            tag: error.tag.into(),
            reason: error.reason,
            notify_reason: None,
            consume_nonce: false,
            persist_state: false,
        })),
    }
}
