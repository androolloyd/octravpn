//! Unified `octra` CLI entrypoint.
//!
//! Subcommands map to Foundry's tooling: `octra forge`, `octra cast`,
//! `octra anvil`, `octra chisel`. See [`octra_cli::run`] for the actual
//! dispatch logic — keeping `main` thin makes the CLI testable from
//! integration tests via `octra_cli::run_with_args`.

use std::process::ExitCode;

fn main() -> ExitCode {
    octravpn_core::util::init_tracing_stderr("warn");
    let args: Vec<String> = std::env::args().collect();
    match octra_cli::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
