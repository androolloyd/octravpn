//! `forge-std` equivalent — the assertion library + helpers Foundry's
//! standard tests build on top of the raw cheatcodes.
//!
//! Submodules:
//!   - [`assertions`]: `assertEq`, `assertGt`, `assertApproxEqAbs`, …
//!   - [`console`]: `log!`, `log_named_*!`
//!   - [`std_cheats`]: convenience composites (hoax, deal_and_prank, …)
//!   - [`std_storage`]: fluent state mutation
//!   - [`std_utils`]: bound, sha256, addr_from_label

pub mod assertions;
pub mod console;
pub mod std_cheats;
pub mod std_storage;
pub mod std_utils;
