//! Thread-local operation counts for scaling regressions, never production telemetry.
use std::cell::Cell;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Work {
    pub child_visits: usize,
    pub encoded_objects: usize,
}

thread_local! {
    static WORK: Cell<Work> = const { Cell::new(Work { child_visits: 0, encoded_objects: 0 }) };
}

pub(super) fn reset() {
    WORK.set(Work::default());
}

pub(super) fn snapshot() -> Work {
    WORK.get()
}

pub(super) fn visit_child() {
    WORK.with(|work| {
        let mut counts = work.get();
        counts.child_visits += 1;
        work.set(counts);
    });
}

pub(super) fn encode_object() {
    WORK.with(|work| {
        let mut counts = work.get();
        counts.encoded_objects += 1;
        work.set(counts);
    });
}
