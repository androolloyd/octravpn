//! Standalone `octravpn-analytics` binary.
//!
//! Reads an existing `--audit-dir` (the same path the node points
//! `[control].audit_dir` at), replays every `audit-*.jsonl` file
//! through the in-memory indexer, then serves the HTTP surface on
//! `--listen`. Useful for:
//!
//!   - Side-car deployments where ops want analytics out-of-process
//!     from the node (a panic in the indexer can't crash the data
//!     plane).
//!   - Offline analysis of an archived audit-log directory.
//!
//! There is no live tail mode in the standalone binary — it's a
//! batch replay only. The in-process variant (spawned by
//! `octravpn-node`) is the path that gets live updates.

use std::path::PathBuf;

use anyhow::{Context, Result};
use octravpn_analytics::{audit_reader, http::HttpState, Indexer};

#[derive(Debug)]
struct Args {
    audit_dir: PathBuf,
    listen: String,
    bearer_token: Option<String>,
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1);
    let mut audit_dir: Option<PathBuf> = None;
    let mut listen: Option<String> = None;
    let mut bearer_token: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--audit-dir" => audit_dir = args.next().map(PathBuf::from),
            "--listen" => listen = args.next(),
            "--bearer-token" => bearer_token = args.next(),
            "--help" | "-h" => {
                eprintln!(
                    "octravpn-analytics --audit-dir <dir> --listen <addr> [--bearer-token <tok>]\n\
                     \n\
                     Replays the audit log at <dir> through the in-memory analytics indexer\n\
                     and serves /metrics, /analytics/series, /analytics/health on <addr>."
                );
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown arg: {other}"),
        }
    }
    Ok(Args {
        audit_dir: audit_dir.context("--audit-dir is required")?,
        listen: listen.unwrap_or_else(|| "0.0.0.0:51822".into()),
        bearer_token,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = parse_args()?;
    let key = audit_reader::load_audit_key(&args.audit_dir)
        .with_context(|| format!("load audit key from {}", args.audit_dir.display()))?;
    let indexer = Indexer::new();
    let scans = indexer.ingest_audit_dir(&key, &args.audit_dir)?;
    tracing::info!(
        files = scans.len(),
        verified_lines = scans.iter().map(|s| s.verified_lines).sum::<u64>(),
        broken = scans.iter().filter(|s| !s.is_clean()).count(),
        "audit replay complete"
    );
    let state = HttpState::new(indexer.state.clone(), args.bearer_token);
    octravpn_analytics::http::serve(&args.listen, state, None).await
}
