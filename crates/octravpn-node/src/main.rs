//! `octravpn-node` — OctraVPN endpoint daemon.
//!
//! Responsibilities:
//!   1. Verify the configured wallet is an Octra protocol validator and
//!      register a paid endpoint (relay or exit) on the OctraVPN program.
//!   2. Run a userspace WireGuard endpoint (boringtun) for connecting
//!      tailnet clients.
//!   3. Track per-session bandwidth, accept signed receipts, retain the
//!      latest receipt per session for settlement / equivocation defense.
//!   4. Periodically re-verify Octra-validator membership; warn if lost.
//!   5. On request, claim accumulated encrypted earnings via stealth payout.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};

mod audit;
mod chain;
mod config;
mod control;
mod events;
mod hub;
mod onion;
mod rate_limit;
mod tunnel;

use config::NodeConfig;
use hub::Hub;

#[derive(Parser, Debug)]
#[command(name = "octravpn-node", version, about)]
struct Cli {
    /// Path to TOML config file.
    #[arg(long, env = "OCTRAVPN_NODE_CONFIG", default_value = "node.toml")]
    config: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Parser, Debug)]
enum Cmd {
    /// Run the daemon in long-lived mode.
    Run,
    /// Register endpoint on chain (idempotent: skips if already registered).
    /// Caller must have at least `MIN_ENDPOINT_STAKE` bonded — see
    /// `bond_endpoint` in the AML program.
    Register,
    /// Claim accumulated earnings via stealth payout.
    ClaimEarnings,
    /// Print derived addresses / pubkeys without changing on-chain state.
    Identity,
    /// Add (delta_amount, delta_blind) to the local earnings accumulator.
    /// Used by reconciliation tooling that watches `SessionSettled` events
    /// and tells the node which Pedersen contributions are theirs.
    AccumulatorAdd {
        #[arg(long)]
        delta_amount: u64,
        #[arg(long)]
        delta_blind_hex: String,
    },
    /// Verify the HMAC chain of an audit log file. Reads the audit key
    /// from the configured audit_dir (`.audit.key`) and walks the file
    /// line-by-line. Exits 0 on a clean chain; non-zero with the first
    /// broken line index otherwise.
    VerifyAuditLog {
        /// Path to the audit JSONL file to verify.
        path: std::path::PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    octravpn_core::util::init_tracing("info,octravpn_node=debug");

    let cli = Cli::parse();
    let cfg = NodeConfig::load(&cli.config)?;

    let hub = Arc::new(Hub::new(cfg).await?);

    match cli.cmd {
        Cmd::Identity => {
            hub.print_identity();
            Ok(())
        }
        Cmd::Register => hub.register_endpoint().await,
        Cmd::ClaimEarnings => hub.claim_earnings().await,
        Cmd::AccumulatorAdd {
            delta_amount,
            delta_blind_hex,
        } => hub.accumulator_add(delta_amount, &delta_blind_hex),
        Cmd::VerifyAuditLog { path } => verify_audit_log(&hub, &path),
        Cmd::Run => run(hub).await,
    }
}

fn verify_audit_log(hub: &Hub, path: &std::path::Path) -> Result<()> {
    let audit = hub
        .open_audit_log()
        .ok_or_else(|| anyhow::anyhow!("audit_dir not configured"))?;
    let key = audit.key();
    let n = crate::audit::AuditLog::verify_file(&key, path)?;
    info!(verified = n, "audit chain ok");
    println!("OK ({n} entries)");
    Ok(())
}

async fn run(hub: Arc<Hub>) -> Result<()> {
    if let Err(e) = hub.register_endpoint().await {
        warn!(error = %e, "endpoint registration skipped or failed; continuing if already registered");
    }

    let health_task = hub.clone().spawn_validator_health_loop();
    let tunnel_task = hub.clone().spawn_tunnel();
    let control_task = hub.clone().spawn_control_plane();

    info!("octravpn-node running");
    tokio::select! {
        r = health_task => r??,
        r = tunnel_task => r??,
        r = control_task => r??,
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown requested");
        }
    }
    Ok(())
}
