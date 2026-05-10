//! `octravpn-node` — OctraVPN validator-side daemon.
//!
//! Responsibilities:
//!   1. Register on chain as a VPN validator (bond + attestation).
//!   2. Run a userspace WireGuard endpoint (boringtun) for clients.
//!   3. Track per-session bandwidth, accept signed receipts, retain the
//!      latest receipt per session for settlement / equivocation defense.
//!   4. Periodically refresh attestation so we don't get jailed for offline.
//!   5. On request, claim accumulated encrypted earnings via stealth payout.
//!
//! The binary is structured as small async tasks fanning off `main`:
//!
//!     main -> {chain registrar, attestation refresher, wg server,
//!              onion forwarder, receipt collector, earnings claimer}
//!
//! Each task communicates through `mpsc` channels into a single `Hub`.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};

mod chain;
mod config;
mod control;
mod hub;
mod onion;
mod receipts;
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
    /// Register on chain (idempotent: skips if already registered).
    Register,
    /// One-shot attestation refresh.
    Attest,
    /// Claim accumulated encrypted earnings via stealth payout.
    ClaimEarnings,
    /// Print derived addresses / pubkeys without changing on-chain state.
    Identity,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,octravpn_node=debug".into()),
        )
        .init();

    let cli = Cli::parse();
    let cfg = NodeConfig::load(&cli.config)?;

    let hub = Arc::new(Hub::new(cfg).await?);

    match cli.cmd {
        Cmd::Identity => {
            hub.print_identity();
            Ok(())
        }
        Cmd::Register => hub.register_validator().await,
        Cmd::Attest => hub.refresh_attestation().await,
        Cmd::ClaimEarnings => hub.claim_earnings().await,
        Cmd::Run => run(hub).await,
    }
}

async fn run(hub: Arc<Hub>) -> Result<()> {
    // Make sure we're registered and attested before opening the tunnel.
    if let Err(e) = hub.register_validator().await {
        warn!(error = %e, "validator registration skipped or failed; continuing if already registered");
    }
    hub.refresh_attestation().await.ok();

    let attestation_task = hub.clone().spawn_attestation_loop();
    let tunnel_task = hub.clone().spawn_tunnel();
    let control_task = hub.clone().spawn_control_plane();

    info!("octravpn-node running");
    tokio::select! {
        r = attestation_task => r??,
        r = tunnel_task => r??,
        r = control_task => r??,
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown requested");
        }
    }
    Ok(())
}
