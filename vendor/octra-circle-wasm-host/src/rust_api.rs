// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Safe host entry point. The WASM interpreter and effect rules remain upstream.
use std::{cell::RefCell, fmt, sync::Arc};

use serde_json::Value;

use super::{native_bytes, HostFailure};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Rejected(String),
    Unavailable(String),
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(reason) | Self::Unavailable(reason) => output.write_str(reason),
        }
    }
}
impl std::error::Error for Error {}

impl From<HostFailure> for Error {
    fn from(failure: HostFailure) -> Self {
        match failure {
            HostFailure::Rejected(reason) => Self::Rejected(reason),
            HostFailure::Unavailable(reason) => Self::Unavailable(reason),
        }
    }
}

/// A trusted host capability. Rejections are deterministic; unavailable resources
/// must cause retry/abort rather than becoming an execution result.
pub trait HfheBackend: Send + Sync {
    fn call(&self, request: &Value) -> Result<Value, Error>;
}

/// Keeps the upstream memory lease alive until the caller releases the reply.
pub struct Reply(native_bytes::Value);

impl AsRef<[u8]> for Reply {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

thread_local! {
    static BACKEND: RefCell<Option<Arc<dyn HfheBackend>>> = const { RefCell::new(None) };
}

struct BackendScope(Option<Arc<dyn HfheBackend>>);
impl Drop for BackendScope {
    fn drop(&mut self) {
        BACKEND.with(|slot| slot.replace(self.0.take()));
    }
}

/// Executes synchronously; run it on the host's bounded execution pool.
/// Input and output use the existing native JSON schema. Caller/epoch/storage
/// must come from authenticated host state, never an untrusted RPC request.
pub fn run(input: &[u8], backend: Arc<dyn HfheBackend>) -> Result<Reply, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _scope = BackendScope(BACKEND.with(|slot| slot.replace(Some(backend))));
        super::run_reply_bytes(input).map(Reply).map_err(Error::from)
    }))
    .unwrap_or_else(|_| Err(Error::Unavailable("octra_circle_wasm_host: panic".into())))
}

/// A suspended upstream interpreter. Dropping this owner releases its WASM
/// memory and invocation, including when the host cannot answer a request.
pub struct CallSession {
    port: super::call_step::Port,
    backend: Arc<dyn HfheBackend>,
}

pub enum CallStep {
    Complete(Vec<u8>),
    Request(Vec<u8>),
}

impl CallSession {
    pub fn new(backend: Arc<dyn HfheBackend>) -> Self {
        Self { port: super::call_step::Port::new(), backend }
    }

    /// The first input is an authenticated execution payload. Further inputs
    /// answer the preceding request using the native call-session JSON schema.
    pub fn step(&mut self, input: &[u8]) -> Result<CallStep, Error> {
        if input.len() > 64 * 1024 * 1024 {
            return Err(Error::Unavailable("circle session input invalid".into()));
        }
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _scope = BackendScope(BACKEND.with(|slot| slot.replace(Some(self.backend.clone()))));
            match self.port.step(input) {
                Ok((0, body)) => Ok(CallStep::Complete(body.into_bytes())),
                Ok((3, body)) => Ok(CallStep::Request(body.into_bytes())),
                Err((1, reason)) => Err(Error::Rejected(reason)),
                Err((_, reason)) => Err(Error::Unavailable(reason)),
                Ok((_, _)) => Err(Error::Unavailable("invalid Circle session status".into())),
            }
        }))
        .unwrap_or_else(|_| Err(Error::Unavailable("circle session failed".into())))
    }
}

pub(super) fn invoke_backend(request: &Value) -> Result<Value, HostFailure> {
    let backend = BACKEND.with(|slot| slot.borrow().clone())
        .ok_or_else(|| HostFailure::Unavailable("Rust HFHE backend not installed".into()))?;
    backend.call(request).map_err(|error| match error {
        Error::Rejected(reason) => HostFailure::Rejected(reason),
        Error::Unavailable(reason) => HostFailure::Unavailable(reason),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Backend;
    impl HfheBackend for Backend {
        fn call(&self, _: &Value) -> Result<Value, Error> {
            Err(Error::Rejected("fixture rejection".into()))
        }
    }
    #[test]
    fn safe_api_classifies_errors_and_releases_backend_scope() {
        assert!(matches!(run(b"not-json", Arc::new(Backend)), Err(Error::Rejected(_))));
        assert!(BACKEND.with(|slot| slot.borrow().is_none()));
        assert!(matches!(invoke_backend(&Value::Null), Err(HostFailure::Unavailable(_))));
    }
}
