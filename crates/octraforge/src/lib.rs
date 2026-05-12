//! `octraforge` — Foundry-style test harness for Octra programs.
//!
//! See `DESIGN.md` for the API tour. The high-level idea: `ForgeCtx`
//! wraps the in-process `octravpn_mock_rpc::ChainState` and exposes
//! Foundry-equivalent cheatcodes plus domain helpers in
//! [`crate::octravpn`] for building canonical call envelopes for the
//! `OctraVPN` program.
//!
//! The cheatcode surface is intentionally Foundry-parallel so anyone
//! who has used `forge` can pattern-match.

pub mod aml_coverage;
pub mod aml_invariants;
pub mod cheatcodes;
pub mod ou_cost_model;
pub mod forge_std;
pub mod fork;
pub mod fs;
pub mod fuzz;
pub mod invariant;
pub mod macros;
pub mod mock;
pub mod octravpn;
pub mod ou;
pub mod wallet;

use std::sync::Arc;

use octravpn_mock_rpc::{AppState, ChainState};
use parking_lot::RwLock;
use serde_json::{json, Value};

pub use crate::cheatcodes::{Expectation, SnapshotId, SubmitError, SubmitResult};
pub use crate::fork::{ForkId, ForkTable};
pub use crate::mock::{MockEntry, MockKind, MockTable};
pub use crate::ou::OuRecorder;
pub use crate::wallet::{addr_from_keypair, addr_from_pubkey, sign, LabelTable, Wallet};

/// The default address used for the deployed `OctraVPN` program when a
/// test doesn't override it. Mirrors the e2e test convention.
pub const DEFAULT_PROGRAM_ADDR: &str = "octPROG";

/// Foundry-style test context. One per test (created by `octra_test!`).
pub struct ForgeCtx {
    /// Underlying mock chain state.
    pub app: AppState,
    /// Address of the deployed `OctraVPN` program.
    pub program_addr: String,
    /// Caller override consumed by the next call.
    pub(crate) pranked_caller: Option<String>,
    /// Caller override + origin used by the next call.
    pub(crate) pranked_origin: Option<String>,
    /// Persistent prank — survives across calls until `stop_prank`.
    pub(crate) sticky_prank: Option<String>,
    /// Persistent origin prank.
    pub(crate) sticky_origin: Option<String>,
    /// Queued expectations asserted at the next `submit`.
    pub(crate) expectations: Vec<Expectation>,
    /// Optional log recording buffer (Foundry `recordLogs`).
    pub(crate) recorded_logs: Option<Vec<Value>>,
    /// Snapshot stack.
    pub(crate) snapshots: Vec<ChainState>,
    /// Named snapshot label → snapshot index.
    pub(crate) named_snapshots: std::collections::HashMap<String, usize>,
    /// Mock-call table.
    pub mocks: MockTable,
    /// Fork registry.
    pub forks: ForkTable,
    /// Address label registry.
    pub labels: LabelTable,
    /// OU accounting.
    pub ou: OuRecorder,
    /// Optional name of the test currently running.
    pub test_name: Option<String>,
    pub(crate) tracing_paused: bool,
}

impl ForgeCtx {
    pub fn new() -> Self {
        Self::with_program(DEFAULT_PROGRAM_ADDR)
    }

    pub fn with_program(program_addr: impl Into<String>) -> Self {
        let app = AppState {
            state: Arc::new(RwLock::new(ChainState {
                epoch: 1,
                ..Default::default()
            })),
            program_addr: program_addr.into(),
        };
        Self {
            program_addr: app.program_addr.clone(),
            app,
            pranked_caller: None,
            pranked_origin: None,
            sticky_prank: None,
            sticky_origin: None,
            expectations: Vec::new(),
            recorded_logs: None,
            snapshots: Vec::new(),
            named_snapshots: std::collections::HashMap::new(),
            mocks: MockTable::default(),
            forks: ForkTable::default(),
            labels: LabelTable::default(),
            ou: OuRecorder::default(),
            test_name: None,
            tracing_paused: false,
        }
    }

    // ============== Time / epoch =================================

    pub fn warp_epoch(&mut self, n: u64) {
        self.app.state.write().epoch = n;
    }

    pub fn roll_epoch(&mut self, delta: u64) {
        let mut s = self.app.state.write();
        s.epoch = s.epoch.saturating_add(delta);
    }

    pub fn current_epoch(&self) -> u64 {
        self.app.state.read().epoch
    }

    /// `vm.skip(epochs)` — advance epoch by N. Alias of `roll_epoch`.
    pub fn skip(&mut self, epochs: u64) {
        self.roll_epoch(epochs);
    }

    // ============== Pranking ====================================

    pub fn prank(&mut self, addr: impl Into<String>) {
        self.pranked_caller = Some(addr.into());
    }

    pub fn prank_with_origin(
        &mut self,
        caller: impl Into<String>,
        origin: impl Into<String>,
    ) {
        self.pranked_caller = Some(caller.into());
        self.pranked_origin = Some(origin.into());
    }

    pub fn start_prank(&mut self, addr: impl Into<String>) {
        self.sticky_prank = Some(addr.into());
    }

    pub fn start_prank_with_origin(
        &mut self,
        caller: impl Into<String>,
        origin: impl Into<String>,
    ) {
        self.sticky_prank = Some(caller.into());
        self.sticky_origin = Some(origin.into());
    }

    pub fn stop_prank(&mut self) {
        self.sticky_prank = None;
        self.sticky_origin = None;
    }

    pub fn take_pranked_caller(&mut self) -> Option<String> {
        if let Some(c) = self.pranked_caller.take() {
            return Some(c);
        }
        self.sticky_prank.clone()
    }

    pub fn take_pranked_origin(&mut self) -> Option<String> {
        if let Some(c) = self.pranked_origin.take() {
            return Some(c);
        }
        self.sticky_origin.clone()
    }

    // ============== Balances ====================================

    pub fn deal(&mut self, addr: impl AsRef<str>, amount: u64) {
        self.app
            .state
            .write()
            .balances
            .insert(addr.as_ref().to_string(), amount);
    }

    pub fn balance(&self, addr: impl AsRef<str>) -> u64 {
        self.app
            .state
            .read()
            .balances
            .get(addr.as_ref())
            .copied()
            .unwrap_or(0)
    }

    pub fn get_nonce(&self, _addr: &str) -> u64 {
        0
    }

    pub fn set_nonce(&mut self, _addr: &str, _nonce: u64) {}

    // ============== Expectations =================================

    pub fn expect_emit(&mut self, event_name: impl Into<String>) {
        self.expectations.push(Expectation::Emit {
            name: event_name.into(),
        });
    }

    pub fn expect_emit_fields(
        &mut self,
        name: impl Into<String>,
        fields: Vec<(impl Into<String>, Value)>,
    ) {
        self.expectations.push(Expectation::EmitFields {
            name: name.into(),
            fields: fields
                .into_iter()
                .map(|(k, v)| (k.into(), v))
                .collect(),
        });
    }

    pub fn expect_no_emit(&mut self, name: impl Into<String>) {
        self.expectations
            .push(Expectation::NoEmit { name: name.into() });
    }

    pub fn expect_call(&mut self, method: impl Into<String>) {
        self.expectations.push(Expectation::Call {
            method: method.into(),
        });
    }

    pub fn expect_revert(&mut self, substring: impl Into<String>) {
        self.expectations.push(Expectation::Revert {
            substring: substring.into(),
        });
    }

    pub fn expect_revert_exact(&mut self, expected: impl Into<String>) {
        self.expectations.push(Expectation::RevertExact {
            expected: expected.into(),
        });
    }

    pub fn clear_expectations(&mut self) {
        self.expectations.clear();
    }

    // ============== Logs =========================================

    pub fn record_logs(&mut self) {
        self.recorded_logs = Some(Vec::new());
    }

    pub fn take_logs(&mut self) -> Vec<Value> {
        self.recorded_logs.take().unwrap_or_default()
    }

    pub fn pause_tracing(&mut self) {
        self.tracing_paused = true;
    }

    pub fn resume_tracing(&mut self) {
        self.tracing_paused = false;
    }

    // ============== Snapshot / revert ============================

    pub fn snapshot(&mut self) -> SnapshotId {
        let snap = self.app.state.read().clone();
        self.snapshots.push(snap);
        SnapshotId(self.snapshots.len() - 1)
    }

    pub fn snapshot_named(&mut self, label: impl Into<String>) -> SnapshotId {
        let id = self.snapshot();
        self.named_snapshots.insert(label.into(), id.0);
        id
    }

    pub fn revert_to(&mut self, id: SnapshotId) -> bool {
        if id.0 >= self.snapshots.len() {
            return false;
        }
        let snap = self.snapshots[id.0].clone();
        self.snapshots.truncate(id.0 + 1);
        *self.app.state.write() = snap;
        self.named_snapshots.retain(|_, &mut v| v <= id.0);
        true
    }

    pub fn revert_to_named(&mut self, label: &str) -> bool {
        if let Some(&idx) = self.named_snapshots.get(label) {
            self.revert_to(SnapshotId(idx))
        } else {
            false
        }
    }

    // ============== Mocks ========================================

    pub fn mock_submit_ok(
        &mut self,
        method: impl Into<String>,
        events: Vec<Value>,
        hash: impl Into<String>,
    ) {
        self.mocks.push(MockEntry {
            method: method.into(),
            kind: MockKind::SubmitOk {
                events,
                hash: hash.into(),
            },
        });
    }

    pub fn mock_submit_revert(
        &mut self,
        method: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.mocks.push(MockEntry {
            method: method.into(),
            kind: MockKind::SubmitRevert {
                message: message.into(),
            },
        });
    }

    pub fn mock_view(&mut self, method: impl Into<String>, value: Value) {
        self.mocks.push(MockEntry {
            method: method.into(),
            kind: MockKind::ViewOk { value },
        });
    }

    pub fn mock_view_revert(
        &mut self,
        method: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.mocks.push(MockEntry {
            method: method.into(),
            kind: MockKind::ViewRevert {
                message: message.into(),
            },
        });
    }

    pub fn clear_mocks(&mut self) {
        self.mocks.clear();
    }

    // ============== Forks ========================================

    pub fn create_fork(&mut self, label: impl Into<String>) -> ForkId {
        let snap = self.app.state.read().clone();
        self.forks.create(label, snap)
    }

    pub fn select_fork(&mut self, id: ForkId) -> bool {
        let Some(entry) = self.forks.get(id) else {
            return false;
        };
        let new_state = entry.state.clone();
        if !self.forks.select(id) {
            return false;
        }
        *self.app.state.write() = new_state;
        true
    }

    pub fn active_fork(&self) -> Option<ForkId> {
        self.forks.active
    }

    // ============== Labels =======================================

    pub fn label(&mut self, addr: impl Into<String>, name: impl Into<String>) {
        self.labels.label(addr, name);
    }

    pub fn get_label(&self, addr: &str) -> Option<&str> {
        self.labels.get(addr)
    }

    // ============== Submission ===================================

    pub fn submit(&mut self, mut call: Value) -> Result<SubmitResult, SubmitError> {
        if let Some(c) = self.take_pranked_caller() {
            if let Some(map) = call.as_object_mut() {
                map.insert("from".into(), json!(c));
            }
        }
        if let Some(o) = self.take_pranked_origin() {
            if let Some(map) = call.as_object_mut() {
                map.insert("origin".into(), json!(o));
            }
        }

        let method = call
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if let Some(kind) = self.mocks.match_submit(&method) {
            let expectations = std::mem::take(&mut self.expectations);
            match kind.clone() {
                MockKind::SubmitOk { events, hash } => {
                    if let Some(buf) = self.recorded_logs.as_mut() {
                        buf.extend(events.iter().cloned());
                    }
                    cheatcodes::check_success(&events, Some(&method), &expectations)?;
                    return Ok(SubmitResult { hash, events });
                }
                MockKind::SubmitRevert { message } => {
                    cheatcodes::check_failure(&message, &expectations)?;
                    return Ok(SubmitResult {
                        hash: String::new(),
                        events: Vec::new(),
                    });
                }
                _ => {}
            }
        }

        let result = octravpn_mock_rpc::submit_tx(&self.app, &call);
        let expectations = std::mem::take(&mut self.expectations);

        match result {
            Ok((hash, events)) => {
                if let Some(buf) = self.recorded_logs.as_mut() {
                    buf.extend(events.iter().cloned());
                }
                cheatcodes::check_success(&events, Some(&method), &expectations)?;
                Ok(SubmitResult { hash, events })
            }
            Err(msg) => {
                cheatcodes::check_failure(&msg, &expectations)?;
                Ok(SubmitResult {
                    hash: String::new(),
                    events: Vec::new(),
                })
            }
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn view(&self, method: &str, params: Vec<Value>) -> Result<Value, String> {
        if let Some(kind) = self.mocks.match_view(method) {
            return match kind.clone() {
                MockKind::ViewOk { value } => Ok(value),
                MockKind::ViewRevert { message } => Err(message),
                _ => unreachable!(),
            };
        }
        octravpn_mock_rpc::read_call(&self.app, method, &params)
    }
}

impl Default for ForgeCtx {
    fn default() -> Self {
        Self::new()
    }
}
