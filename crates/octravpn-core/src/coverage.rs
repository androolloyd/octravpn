//! Cross-crate branch-coverage hooks for the AML mock + program.
//!
//! The mock chain calls `record(method, branch)` on every control-flow
//! decision point so test runners can later compute coverage. The
//! recorder is a `Mutex<Option<...>>` global: `enable()` from a test to
//! start collecting, `finish()` to retrieve the recorded set.
//!
//! Default state is "no recorder installed" so production callers pay
//! at most a mutex lock + null-check per call.

use parking_lot::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

static RECORDER: OnceLock<Mutex<Option<Recorder>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<Recorder>> {
    RECORDER.get_or_init(|| Mutex::new(None))
}

/// Start collecting. Existing hits (if any) are dropped.
pub fn enable() {
    *slot().lock() = Some(Recorder::default());
}

/// Stop and return whatever was collected.
pub fn finish() -> Option<Recorder> {
    slot().lock().take()
}

/// Record a hit at `(method, branch)`. No-op if `enable()` hasn't been
/// called.
pub fn record(method: &str, branch: &str) {
    if let Some(r) = slot().lock().as_mut() {
        r.hit
            .entry(method.to_string())
            .or_default()
            .insert(branch.to_string());
    }
}

#[derive(Default, Debug, Clone)]
pub struct Recorder {
    /// method → branch labels hit during the recording window.
    pub hit: BTreeMap<String, BTreeSet<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // The recorder is a process-wide global, so concurrent `cargo test`
    // workers would race. We run both paths in one test serially.
    #[test]
    fn record_round_trip_and_noop_when_disabled() {
        // Start clean.
        let _ = finish();

        // Without enable, record() is a no-op.
        record("foo", "x");
        assert!(slot().lock().is_none());

        // Enable, record three hits, finish.
        enable();
        record("foo", "require[1]");
        record("foo", "if[2]");
        record("bar", "while[1]");
        let r = finish().unwrap();
        assert_eq!(r.hit.get("foo").unwrap().len(), 2);
        assert_eq!(r.hit.get("bar").unwrap().len(), 1);
    }
}
