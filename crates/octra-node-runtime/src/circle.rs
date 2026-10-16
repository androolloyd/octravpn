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
pub const MAX_CALL_INPUT_BYTES: usize = 67_108_864;

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
    program_keys: Arc<octra_node_protocol::program_trust::Keys>,
    public_keys: Option<Arc<dyn crate::pvac::Source>>,
}

impl CircleRuntime {
    pub fn new(backend: Arc<dyn HfheBackend>) -> Self {
        Self {
            backend,
            program_keys: Arc::new(octra_node_protocol::program_trust::Keys::default()),
            public_keys: None,
        }
    }
    pub fn with_program_keys(mut self, keys: octra_node_protocol::program_trust::Keys) -> Self {
        self.program_keys = Arc::new(keys);
        self
    }
    pub fn program_keys(&self) -> &octra_node_protocol::program_trust::Keys {
        &self.program_keys
    }
    pub fn with_public_keys(mut self, source: Arc<dyn crate::pvac::Source>) -> Self {
        self.public_keys = Some(source);
        self
    }
    pub(crate) fn public_keys(&self) -> Option<&Arc<dyn crate::pvac::Source>> {
        self.public_keys.as_ref()
    }
    pub(crate) fn public_key(
        &self,
        state: &crate::state_batch::Snapshot,
        address: &[u8],
    ) -> Result<Option<Arc<[u8]>>, crate::execution::Error> {
        crate::pvac::bound(self.public_keys.as_ref(), state, address)
    }
    pub fn admit_program(
        &self,
        raw: &[u8],
        point_ops: bool,
    ) -> Result<octra_node_protocol::octb::admission::Admitted, octra_node_protocol::octb::Error>
    {
        octra_node_protocol::octb::program::decode_deploy(raw, point_ops, &self.program_keys)
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

    pub(crate) fn execute_prepared(
        &self,
        input: &crate::circle_input::Encoded,
        before: &StorageTable,
    ) -> Result<Receipt, circle_wasm::Error> {
        if input.calls() {
            return Err(circle_wasm::Error::Unavailable(
                b"Circle call input requires a journal".to_vec(),
            ));
        }
        let reply = octra_circle_wasm_host::rust_api::run(input.bytes(), self.backend.clone())
            .map_err(|error| match error {
                Error::Rejected(reason) => circle_wasm::Error::Rejected(reason.into_bytes()),
                Error::Unavailable(reason) => circle_wasm::Error::Unavailable(reason.into_bytes()),
            })?;
        circle_wasm::receipt::decode(reply.as_ref(), before)
    }

    pub(crate) fn execute_prepared_call(
        &self,
        input: &crate::circle_input::Encoded,
        before: &StorageTable,
        call: impl FnMut(&[u8]) -> Result<Vec<u8>, circle_wasm::Error>,
    ) -> Result<Receipt, circle_wasm::Error> {
        if !input.calls() {
            return Err(circle_wasm::Error::Unavailable(
                b"Circle input is not admitted for calls".to_vec(),
            ));
        }
        self.call_effects(input.bytes(), before, call, true)
    }

    /// Execute with the native resumable interpreter. A missing operation host
    /// aborts on its first request, before any effects can be published.
    pub fn execute_call_effects(
        &self,
        input: &[u8],
        before: &StorageTable,
        call: impl FnMut(&[u8]) -> Result<Vec<u8>, circle_wasm::Error>,
    ) -> Result<Receipt, circle_wasm::Error> {
        self.call_effects(input, before, call, false)
    }
    fn call_effects(
        &self,
        input: &[u8],
        before: &StorageTable,
        mut call: impl FnMut(&[u8]) -> Result<Vec<u8>, circle_wasm::Error>,
        mut adapted: bool,
    ) -> Result<Receipt, circle_wasm::Error> {
        use octra_circle_wasm_host::rust_api::{CallSession, CallStep};
        let mut session = CallSession::new(self.backend.clone());
        let mut reply;
        let mut input = input;
        loop {
            let step = if adapted {
                session.step_byte_transport(input)
            } else {
                session.step(input)
            };
            adapted = false;
            match step.map_err(|error| match error {
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
