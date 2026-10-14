//! Runs the adopted native Circle engine without an OCaml runtime.
//! The supplied HFHE backend must implement the pinned crypto policy.
use octra_node_protocol::{
    circle_storage::StorageTable,
    circle_wasm::{self, receipt::Receipt},
};
use std::sync::Arc;

pub use octra_circle_wasm_host::rust_api::{Error, HfheBackend, Reply};
/// Native non-session input limit from Circle_wasm_native.run_json_classified.
pub const MAX_INPUT_BYTES: usize = 16_777_216;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WasmProfile {
    Standard,
    Compute,
    Manifest,
}
impl WasmProfile {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Compute => "compute",
            Self::Manifest => "manifest",
        }
    }
}

/// The node supplies rules selected for this committed epoch. This configuration
/// is intentionally not deserializable through the app bridge.
#[derive(Clone, Copy, Debug)]
pub struct WasmRules {
    pub wasm_float: bool,
    pub proof_exec: bool,
    pub math: bool,
}

#[derive(Clone)]
pub struct CircleRuntime {
    backend: Arc<dyn HfheBackend>,
}

impl CircleRuntime {
    pub fn new(backend: Arc<dyn HfheBackend>) -> Self {
        Self { backend }
    }

    /// Host-owned native input only. Execution is synchronous and returns
    /// effects; the host must check success/unavailable before applying them.
    pub fn execute(&self, input: &[u8]) -> Result<Reply, Error> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(Error::Rejected(format!(
                "input too large: bytes={} limit={MAX_INPUT_BYTES}",
                input.len()
            )));
        }
        octra_circle_wasm_host::rust_api::run(input, self.backend.clone())
    }

    /// Decode the complete native receipt, preserving operational unavailability.
    /// The authenticated host supplies the pre-call storage. A null storage
    /// reply retains that state, as native views do. Effects still require the
    /// native storage/policy checks before applying a successful update.
    pub fn execute_effects(
        &self,
        input: &[u8],
        before: &StorageTable,
    ) -> Result<Receipt, circle_wasm::Error> {
        let reply = self.execute(input).map_err(|error| match error {
            Error::Rejected(reason) => circle_wasm::Error::Rejected(reason.into_bytes()),
            Error::Unavailable(reason) => circle_wasm::Error::Unavailable(reason.into_bytes()),
        })?;
        circle_wasm::receipt::decode(reply.as_ref(), before)
    }

    /// Execute with the native resumable interpreter. A missing operation host
    /// aborts on its first request, before any effects can be published.
    pub fn execute_call_effects(
        &self,
        input: &[u8],
        before: &StorageTable,
        mut call: impl FnMut(&[u8]) -> Result<Vec<u8>, circle_wasm::Error>,
    ) -> Result<Receipt, circle_wasm::Error> {
        use octra_circle_wasm_host::rust_api::{CallSession, CallStep};
        let mut session = CallSession::new(self.backend.clone());
        let mut reply;
        let mut input = input;
        loop {
            match session.step(input).map_err(|error| match error {
                Error::Rejected(reason) => circle_wasm::Error::Rejected(reason.into_bytes()),
                Error::Unavailable(reason) => circle_wasm::Error::Unavailable(reason.into_bytes()),
            })? {
                CallStep::Complete(output) => return circle_wasm::receipt::decode(&output, before),
                CallStep::Request(request) => {
                    reply = call(&request)?;
                    input = &reply;
                }
            }
        }
    }
}
