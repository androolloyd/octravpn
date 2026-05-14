//! `forge snapshot` — capture and diff per-test OU costs.
//!
//! Output file shape:
//!
//! ```text
//! test_name (octraforge::demo): 1234
//! ```
//!
//! Re-running diffs against the previous snapshot and reports
//! regressions over the threshold (default 5%). Today OU usage isn't
//! measured automatically; we read it from the same `OU=` token used by
//! `forge test`'s call-trace renderer. A future runtime hook will
//! populate it without test cooperation.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

#[derive(Args, Debug)]
pub struct SnapshotArgs {
    /// Output file (default `.gas-snapshot`).
    #[arg(long, default_value = ".gas-snapshot")]
    pub file: PathBuf,
    /// Package to test.
    #[arg(long, default_value = "octraforge")]
    pub package: String,
    /// Regression tolerance percent.
    #[arg(long, default_value_t = 5.0)]
    pub tolerance_pct: f64,
    /// Only check; do not write (errors out on regression).
    #[arg(long)]
    pub check: bool,
}

pub fn run(args: &SnapshotArgs) -> Result<()> {
    let stdout = run_tests(&args.package)?;
    let measurements = extract_measurements(&stdout);
    if args.check {
        let prior = load_snapshot(&args.file)?;
        let report = compare(&prior, &measurements, args.tolerance_pct);
        if !report.regressions.is_empty() {
            for r in &report.regressions {
                eprintln!(
                    "REGRESSION {}: {} -> {} (+{:.1}%)",
                    r.name, r.before, r.after, r.delta_pct
                );
            }
            return Err(anyhow::anyhow!(
                "{} regression(s) above {}%",
                report.regressions.len(),
                args.tolerance_pct
            ));
        }
        println!("OK: no regressions ({} measured)", measurements.len());
        return Ok(());
    }
    write_snapshot(&args.file, &measurements)?;
    println!(
        "wrote {} measurement(s) to {}",
        measurements.len(),
        args.file.display()
    );
    Ok(())
}

fn run_tests(pkg: &str) -> Result<String> {
    use std::process::Command;
    let out = Command::new(option_env!("CARGO").unwrap_or("cargo"))
        .arg("test")
        .arg("-p")
        .arg(pkg)
        .arg("--")
        .arg("--nocapture")
        .output()?;
    if !out.status.success() {
        return Err(anyhow::anyhow!("cargo test failed: {}", out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn extract_measurements(stdout: &str) -> BTreeMap<String, u64> {
    let mut by_test: BTreeMap<String, u64> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("test ") {
            if let Some((name, tail)) = rest.split_once(" ... ") {
                if tail.trim() == "ok" {
                    current = Some(name.trim().to_string());
                    continue;
                }
            }
            current = None;
        }
        if let Some(rest) = line.trim().strip_prefix("OU=") {
            if let (Some(test), Ok(n)) = (current.as_ref(), rest.parse::<u64>()) {
                by_test.insert(test.clone(), n);
            }
        }
    }
    by_test
}

fn load_snapshot(path: &std::path::Path) -> Result<BTreeMap<String, u64>> {
    let mut out = BTreeMap::new();
    if !path.exists() {
        return Ok(out);
    }
    let body = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    for line in body.lines() {
        if let Some((name, n)) = line.rsplit_once(": ") {
            if let Ok(n) = n.trim().parse::<u64>() {
                out.insert(name.trim().to_string(), n);
            }
        }
    }
    Ok(out)
}

fn write_snapshot(path: &std::path::Path, m: &BTreeMap<String, u64>) -> Result<()> {
    use std::fmt::Write;
    let mut body = String::new();
    for (k, v) in m {
        let _ = writeln!(body, "{k}: {v}");
    }
    crate::io::write_to(path, &body)
}

#[derive(Debug, Default)]
pub struct Report {
    pub regressions: Vec<Regression>,
}

#[derive(Debug)]
pub struct Regression {
    pub name: String,
    pub before: u64,
    pub after: u64,
    pub delta_pct: f64,
}

pub fn compare(prior: &BTreeMap<String, u64>, now: &BTreeMap<String, u64>, tol_pct: f64) -> Report {
    let mut r = Report::default();
    for (k, after) in now {
        if let Some(before) = prior.get(k) {
            if *before == 0 {
                continue;
            }
            #[allow(clippy::cast_precision_loss)]
            let delta = (*after as f64 - *before as f64) * 100.0 / *before as f64;
            if delta > tol_pct {
                r.regressions.push(Regression {
                    name: k.clone(),
                    before: *before,
                    after: *after,
                    delta_pct: delta,
                });
            }
        }
    }
    r
}
