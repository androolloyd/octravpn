//! `mockCall` / `mockCallRevert` / `clearMockedCalls`.
//!
//! Foundry's `vm.mockCall(addr, calldata, returndata)` makes a chain
//! call return the canned value without executing the target. For us,
//! a "mocked call" can apply to:
//!
//!   - `submit` of a tx whose `method` matches: return pre-canned
//!     `(hash, events)` instead of running `apply_*`.
//!   - `view` of a method: return pre-canned `Value` instead of running
//!     the actual handler.
//!
//! Matching is by method name (the simple case). For more granularity
//! the test can supply a predicate via `mock_call_when`.

use serde_json::Value;

#[derive(Clone)]
pub struct MockEntry {
    pub method: String,
    pub kind: MockKind,
}

#[derive(Clone)]
pub enum MockKind {
    /// Return success with these events on `submit`.
    SubmitOk { events: Vec<Value>, hash: String },
    /// Return revert on `submit`.
    SubmitRevert { message: String },
    /// Return this value on `view`.
    ViewOk { value: Value },
    /// Return revert on `view`.
    ViewRevert { message: String },
}

#[derive(Clone, Default)]
pub struct MockTable {
    entries: Vec<MockEntry>,
}

impl MockTable {
    pub fn push(&mut self, e: MockEntry) {
        self.entries.push(e);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Find the first matching submit mock for `method`.
    pub fn match_submit(&self, method: &str) -> Option<&MockKind> {
        for e in &self.entries {
            if e.method != method {
                continue;
            }
            if matches!(e.kind, MockKind::SubmitOk { .. } | MockKind::SubmitRevert { .. }) {
                return Some(&e.kind);
            }
        }
        None
    }

    /// Find the first matching view mock for `method`.
    pub fn match_view(&self, method: &str) -> Option<&MockKind> {
        for e in &self.entries {
            if e.method != method {
                continue;
            }
            if matches!(e.kind, MockKind::ViewOk { .. } | MockKind::ViewRevert { .. }) {
                return Some(&e.kind);
            }
        }
        None
    }
}
