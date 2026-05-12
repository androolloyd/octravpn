//! Test-wrapping macros.
//!
//! `octra_test!` is the declarative analogue of Foundry's `function testFoo()`
//! base contract. It builds a fresh [`crate::ForgeCtx`], runs the user
//! body with `&mut forge` in scope, and tags the function with
//! `#[test]` so `cargo test` discovers it.
//!
//! A future `#[octra_test]` proc-macro is straightforward but kept out
//! of v0 to avoid pulling `syn`/`quote` into the dependency graph.

/// Define a test that receives a fresh `ForgeCtx` named `forge`.
///
/// ```ignore
/// use octraforge::octra_test;
/// octra_test!(my_first_test, |forge| {
///     forge.warp_epoch(5);
///     assert_eq!(forge.current_epoch(), 5);
/// });
/// ```
#[macro_export]
macro_rules! octra_test {
    ($name:ident, |$ctx:ident| $body:block) => {
        #[test]
        fn $name() {
            let mut $ctx = $crate::ForgeCtx::new();
            $body
        }
    };
}

/// Run `body` against fresh `forge` snapshots for each value yielded
/// by `strategy`. Snapshot/revert isolates iterations without paying
/// the cost of full ctx reconstruction.
///
/// ```ignore
/// use octraforge::forge_fuzz;
/// forge_fuzz!(0u64..1000, |bytes_used, forge| {
///     // ... call into the program with bytes_used as input
/// });
/// ```
///
/// The closure runs inside a `proptest!` block and may panic on
/// failure; `proptest` will shrink and report.
#[macro_export]
macro_rules! forge_fuzz {
    ($strategy:expr, |$input:ident, $ctx:ident| $body:block) => {{
        use ::proptest::prelude::*;
        let mut $ctx = $crate::ForgeCtx::new();
        // One snapshot is reused across iterations: take, run body, revert.
        let _root = $ctx.snapshot();
        ::proptest::proptest!(|($input in $strategy)| {
            let snap = $ctx.snapshot();
            $body
            $ctx.revert_to(snap);
        });
    }};
}
