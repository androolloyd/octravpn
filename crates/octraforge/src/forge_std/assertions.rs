//! Foundry-style assertion library.
//!
//! Rust already has `assert_eq!`, but Foundry's wider set is useful in
//! tests because: (a) approximate equality is non-trivial in tests
//! that exercise integer division; (b) the named macros produce more
//! readable failure messages.
//!
//! All assertions panic on failure (like Rust's `assert_eq!`), so they
//! integrate with `cargo test` directly — no special runner required.

// Assertion helpers are intentionally `if cond { panic!(...) }` patterns
// for readable panic messages; the lint flags this stylistically.
#![allow(clippy::manual_assert, clippy::neg_cmp_op_on_partial_ord)]

use std::fmt::Debug;

/// `assertEq(a, b)`.
#[track_caller]
pub fn assert_eq<T: PartialEq + Debug>(a: &T, b: &T) {
    if a != b {
        panic!("assertEq failed:\n  left:  {a:?}\n  right: {b:?}");
    }
}

/// `assertEq(a, b, "msg")`.
#[track_caller]
pub fn assert_eq_named<T: PartialEq + Debug>(name: &str, a: &T, b: &T) {
    if a != b {
        panic!("{name} assertEq failed:\n  left:  {a:?}\n  right: {b:?}");
    }
}

#[track_caller]
pub fn assert_ne<T: PartialEq + Debug>(a: &T, b: &T) {
    if a == b {
        panic!("assertNe failed: both = {a:?}");
    }
}

#[track_caller]
pub fn assert_gt<T: PartialOrd + Debug>(a: &T, b: &T) {
    if !(a > b) {
        panic!("assertGt failed: {a:?} not > {b:?}");
    }
}

#[track_caller]
pub fn assert_ge<T: PartialOrd + Debug>(a: &T, b: &T) {
    if !(a >= b) {
        panic!("assertGe failed: {a:?} not >= {b:?}");
    }
}

#[track_caller]
pub fn assert_lt<T: PartialOrd + Debug>(a: &T, b: &T) {
    if !(a < b) {
        panic!("assertLt failed: {a:?} not < {b:?}");
    }
}

#[track_caller]
pub fn assert_le<T: PartialOrd + Debug>(a: &T, b: &T) {
    if !(a <= b) {
        panic!("assertLe failed: {a:?} not <= {b:?}");
    }
}

#[track_caller]
pub fn assert_true(cond: bool) {
    if !cond {
        panic!("assertTrue failed");
    }
}

#[track_caller]
pub fn assert_false(cond: bool) {
    if cond {
        panic!("assertFalse failed");
    }
}

/// `assertApproxEqAbs(a, b, maxDelta)` — passes iff `|a - b| <= max_delta`.
#[track_caller]
pub fn assert_approx_eq_abs(a: u64, b: u64, max_delta: u64) {
    let diff = a.abs_diff(b);
    if diff > max_delta {
        panic!("assertApproxEqAbs failed: |{a} - {b}| = {diff} > {max_delta}");
    }
}

/// `assertApproxEqRel(a, b, max_rel_bps)` — passes iff the relative
/// difference is within `max_rel_bps` basis points (10000 = 100%).
#[track_caller]
pub fn assert_approx_eq_rel(a: u64, b: u64, max_rel_bps: u64) {
    if a == b {
        return;
    }
    let diff = a.abs_diff(b);
    let base = std::cmp::max(a, b).max(1);
    let rel = diff.saturating_mul(10_000) / base;
    if rel > max_rel_bps {
        panic!(
            "assertApproxEqRel failed: |{a} - {b}| / max(a,b) * 10000 = {rel} > {max_rel_bps}"
        );
    }
}

/// `assertEqDecimal(a, b, decimals)` — equality with a pretty-printed
/// failure message that shows the values in their decimal form.
#[track_caller]
pub fn assert_eq_decimal(a: u64, b: u64, decimals: u32) {
    if a == b {
        return;
    }
    let div = 10u64.pow(decimals);
    let af = (a / div, a % div);
    let bf = (b / div, b % div);
    panic!(
        "assertEqDecimal failed:\n  left:  {a} ({}.{:0wid$})\n  right: {b} ({}.{:0wid$})",
        af.0,
        af.1,
        bf.0,
        bf.1,
        wid = decimals as usize
    );
}

/// `assertContains(haystack, needle)` — string substring check.
#[track_caller]
pub fn assert_contains(haystack: &str, needle: &str) {
    if !haystack.contains(needle) {
        panic!("assertContains failed: `{needle}` not found in `{haystack}`");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approx_abs_ok() {
        assert_approx_eq_abs(100, 102, 5);
    }

    #[test]
    #[should_panic(expected = "assertApproxEqAbs failed")]
    fn approx_abs_too_far() {
        assert_approx_eq_abs(100, 200, 5);
    }

    #[test]
    fn approx_rel_ok() {
        // 1% diff at scale.
        assert_approx_eq_rel(1_000_000, 1_010_000, 200); // 2% tolerance
    }

    #[test]
    #[should_panic(expected = "assertApproxEqRel failed")]
    fn approx_rel_too_far() {
        assert_approx_eq_rel(1_000, 2_000, 100); // 1% tol, 100% diff
    }

    #[test]
    fn decimal_format_panic_message() {
        // Just exercise the path; ensure no infinite recursion.
        let r = std::panic::catch_unwind(|| assert_eq_decimal(123_456, 654_321, 3));
        assert!(r.is_err());
    }
}
