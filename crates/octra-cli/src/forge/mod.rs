//! `octra forge` — build / deploy / test / snapshot / bind.
//!
//! These mirror Foundry's `forge` subcommands. The build pipeline goes
//! through `octra_compileAml` / `octra_compileAmlMulti` when an RPC URL
//! is provided; in offline mode (`--offline` or no URL set) we use the
//! same deterministic stub compiler used by the in-process mock so the
//! tool always produces *some* artifact for downstream commands.

pub mod bind;
pub mod build;
pub mod compile;
pub mod coverage;
pub mod create;
pub mod inspect;
pub mod snapshot;
pub mod test_cmd;
pub mod trace;

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum ForgeCmd {
    /// Walk `program/` for `*.aml` and emit `out/<Name>.{json,abi,bin,asm}`.
    Build(build::BuildArgs),
    /// Compile + sign + deploy + return address.
    Create(create::CreateArgs),
    /// Dump ABI / assembly / bytecode for an address or file.
    Inspect(inspect::InspectArgs),
    /// Generate typed Rust stubs from a compiled ABI.
    Bind(bind::BindArgs),
    /// Run `cargo test -p octraforge` with Foundry-style output.
    Test(test_cmd::TestArgs),
    /// Capture per-test OU costs to `.gas-snapshot` and diff on rerun.
    Snapshot(snapshot::SnapshotArgs),
    /// Print AML branch coverage from a recorder dump.
    Coverage(coverage::CoverageArgs),
}

pub fn dispatch(cmd: ForgeCmd) -> Result<()> {
    match cmd {
        ForgeCmd::Build(a) => build::run(&a),
        ForgeCmd::Create(a) => create::run(&a),
        ForgeCmd::Inspect(a) => inspect::run(&a),
        ForgeCmd::Bind(a) => bind::run(&a),
        ForgeCmd::Test(a) => test_cmd::run(&a),
        ForgeCmd::Snapshot(a) => snapshot::run(&a),
        ForgeCmd::Coverage(a) => coverage::run(&a),
    }
}
