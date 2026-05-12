//! `forge snapshot` — internal compare logic.
//!
//! We test the regression-detection function directly rather than
//! running `cargo test` (which would be slow and recursive).

use std::collections::BTreeMap;

#[test]
fn snapshot_regression_above_tolerance_is_flagged() {
    let mut prior: BTreeMap<String, u64> = BTreeMap::new();
    prior.insert("foo".into(), 100);
    prior.insert("bar".into(), 200);
    let mut now: BTreeMap<String, u64> = BTreeMap::new();
    now.insert("foo".into(), 120);
    now.insert("bar".into(), 201);
    let report = octra_cli::forge::snapshot::compare(&prior, &now, 5.0);
    assert_eq!(report.regressions.len(), 1);
    assert_eq!(report.regressions[0].name, "foo");
    assert!(report.regressions[0].delta_pct > 5.0);
}

#[test]
fn snapshot_within_tolerance_is_clean() {
    let mut prior: BTreeMap<String, u64> = BTreeMap::new();
    prior.insert("foo".into(), 100);
    let mut now: BTreeMap<String, u64> = BTreeMap::new();
    now.insert("foo".into(), 104);
    let report = octra_cli::forge::snapshot::compare(&prior, &now, 5.0);
    assert!(report.regressions.is_empty(), "got: {report:?}");
}
