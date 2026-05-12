//! `octra` CLI library — dispatch entry point and subcommand modules.
//!
//! `run(args)` parses the argv vector with `clap` and routes to one of
//! the subcommand modules. The library form lets integration tests
//! exercise commands by calling `octra_cli::run(&args)` directly without
//! spawning a subprocess, which is much faster and gives readable
//! backtraces.

pub mod anvil;
pub mod cast;
pub mod chisel;
pub mod forge;
pub mod io;
pub mod rpc_client;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

/// `octra` — Foundry-style toolchain for Octra programs.
#[derive(Parser, Debug)]
#[command(name = "octra", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Build / deploy / inspect / test Octra programs.
    #[command(subcommand)]
    Forge(forge::ForgeCmd),

    /// Read-only and signed JSON-RPC actions against an Octra node.
    #[command(subcommand)]
    Cast(cast::CastCmd),

    /// Run a local devnet (in-memory mock or fork of a remote endpoint).
    Anvil(anvil::AnvilArgs),

    /// Interactive REPL for ad-hoc AML / RPC exploration.
    Chisel(chisel::ChiselArgs),

    /// Generate shell completion scripts.
    Completions {
        /// Target shell (bash, zsh, fish, powershell, elvish).
        shell: Shell,
    },
}

/// Run the CLI with an argv-style vector.
pub fn run(args: &[String]) -> Result<()> {
    match Cli::try_parse_from(args) {
        Ok(cli) => run_parsed(cli),
        Err(e) => {
            // clap reports help/version through the same error channel
            // as parse failures; surface them via stdout (success) so
            // `--help` doesn't exit non-zero.
            use clap::error::ErrorKind;
            match e.kind() {
                ErrorKind::DisplayHelp
                | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                | ErrorKind::DisplayVersion => {
                    print!("{e}");
                    Ok(())
                }
                _ => Err(e.into()),
            }
        }
    }
}

/// Variant used by integration tests so they don't have to round-trip
/// through `Vec<String>` -> `clap`.
pub fn run_parsed(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Forge(cmd) => forge::dispatch(cmd),
        Command::Cast(cmd) => cast::dispatch(cmd),
        Command::Anvil(args) => anvil::run(&args),
        Command::Chisel(args) => chisel::run(&args),
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            let bin = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, bin, &mut std::io::stdout());
            Ok(())
        }
    }
}
