//! Invariant testing.
//!
//! Foundry's invariant tests fuzz random sequences of calls and assert
//! the invariant holds throughout. Equivalent here: provide a runner
//! that calls a user-supplied `step` closure many times and a
//! user-supplied `check` closure after each step.

use crate::ForgeCtx;

/// Run `runs` rounds; each round executes `steps_per_run` random
/// transitions then asserts the invariant. Snapshots between runs so
/// state is reset to the starting point.
///
/// `step` may submit a tx, mutate state, or do nothing. `check`
/// receives the chain state and should return `Ok(())` if the
/// invariant holds, or `Err(reason)` otherwise.
pub fn run_invariant(
    ctx: &mut ForgeCtx,
    runs: usize,
    steps_per_run: usize,
    mut step: impl FnMut(&mut ForgeCtx, usize),
    mut check: impl FnMut(&ForgeCtx) -> Result<(), String>,
) {
    for run in 0..runs {
        let snap = ctx.snapshot();
        for step_idx in 0..steps_per_run {
            step(ctx, step_idx);
            if let Err(e) = check(ctx) {
                panic!(
                    "invariant violated on run {run}, step {step_idx}: {e}"
                );
            }
        }
        ctx.revert_to(snap);
    }
}
