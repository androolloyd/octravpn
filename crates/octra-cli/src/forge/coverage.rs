//! `octra forge coverage` — enumerate AML branches and report which
//! ones an executed test session exercised.
//!
//! Foundry uses `forge coverage` to track Solidity branch coverage; we
//! do the equivalent for AML.
//!
//! Typical use: a test harness calls `octravpn_core::coverage::enable()`,
//! runs a sequence of mock-chain operations, calls `finish()`, then
//! formats the result with `octraforge::aml_coverage::report`. This
//! CLI subcommand is a thin standalone helper for the offline case:
//! given a recorder JSON dump and the AML source, print the textual
//! report.

use anyhow::{Context, Result};
use clap::Args;
use std::{fs, path::PathBuf};

#[derive(Args, Debug)]
pub struct CoverageArgs {
    /// Path to the AML source (defaults to `program/main.aml`).
    #[arg(long, default_value = "program/main.aml")]
    source: PathBuf,
    /// Path to a JSON-formatted recorder dump
    /// (see `octraforge::aml_coverage::Recorder`). Each test harness
    /// writes this file at the end of its run.
    #[arg(long)]
    hits: Option<PathBuf>,
    /// Write the human-readable report to this file (in addition to
    /// stdout).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Exit non-zero if total coverage falls below this percentage
    /// (0..=100). Default 0 — coverage is reported but not gated.
    #[arg(long, default_value_t = 0u8)]
    threshold: u8,
}

pub fn run(args: &CoverageArgs) -> Result<()> {
    let src = fs::read_to_string(&args.source)
        .with_context(|| format!("read AML source {}", args.source.display()))?;
    let rec: octraforge::aml_coverage::Recorder = match &args.hits {
        Some(p) => {
            let raw =
                fs::read_to_string(p).with_context(|| format!("read hits file {}", p.display()))?;
            let parsed: serde_json::Value =
                serde_json::from_str(&raw).context("parse hits JSON")?;
            recorder_from_json(&parsed)
        }
        None => octraforge::aml_coverage::Recorder::default(),
    };
    let report = octraforge::aml_coverage::report(&rec, &src);
    let pretty = report.pretty();
    println!("{pretty}");
    if let Some(p) = &args.out {
        fs::write(p, &pretty).with_context(|| format!("write report {}", p.display()))?;
    }
    let actual = report.percent() as u8;
    if actual < args.threshold {
        anyhow::bail!(
            "coverage {actual}% below required threshold {}%",
            args.threshold
        );
    }
    Ok(())
}

fn recorder_from_json(v: &serde_json::Value) -> octraforge::aml_coverage::Recorder {
    let mut r = octraforge::aml_coverage::Recorder::default();
    if let Some(obj) = v.as_object() {
        for (method, branches) in obj {
            let set = r.hit.entry(method.clone()).or_default();
            if let Some(arr) = branches.as_array() {
                for b in arr {
                    if let Some(s) = b.as_str() {
                        set.insert(s.to_string());
                    }
                }
            }
        }
    }
    r
}
