//! `forge test` — wrap `cargo test -p octraforge` with Foundry-style output.
//!
//! We parse libtest's text output (the default `--format pretty`),
//! buffer stdout/stderr, and re-emit a colored summary with pass/fail
//! icons. On failure the captured test output is preserved so a user
//! sees the call trace identical to `cargo test` semantics.

use std::process::Command;

use anyhow::{anyhow, Result};
use clap::Args;

use super::trace;

#[derive(Args, Debug)]
pub struct TestArgs {
    /// Test name filter.
    #[arg(long)]
    pub filter: Option<String>,
    /// Package to test (defaults to `octraforge`).
    #[arg(long, default_value = "octraforge")]
    pub package: String,
    /// Pass `--release` to cargo.
    #[arg(long)]
    pub release: bool,
    /// Skip the wrapper formatting and stream cargo's output verbatim.
    #[arg(long)]
    pub raw: bool,
}

pub fn run(args: &TestArgs) -> Result<()> {
    let mut cmd = Command::new(option_env!("CARGO").unwrap_or("cargo"));
    cmd.arg("test").arg("-p").arg(&args.package);
    if args.release {
        cmd.arg("--release");
    }
    cmd.arg("--").arg("--nocapture");
    if let Some(f) = &args.filter {
        cmd.arg(f);
    }
    if args.raw {
        let status = cmd.status()?;
        if !status.success() {
            return Err(anyhow!("cargo test failed: status {status}"));
        }
        return Ok(());
    }
    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    trace::render_test_output(&stdout, &stderr);
    if !output.status.success() {
        let s = output.status;
        return Err(anyhow!("cargo test failed: status {s}"));
    }
    Ok(())
}
