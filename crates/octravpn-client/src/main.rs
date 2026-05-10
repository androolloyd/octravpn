//! `octravpn` — the client CLI.
//!
//! Subcommands:
//!   - identity        Print derived addresses/pubkeys for the current wallet.
//!   - nodes           List active validator-VPN nodes from the on-chain registry.
//!   - connect         Open a 1..3 hop session, bring up the tunnel, hold it
//!                     until ctrl-c. Settle on close.
//!   - settle          Settle a session that was previously opened (e.g. if
//!                     `connect` was killed without a clean close).
//!   - reclaim         Trigger no-show refund for a session past grace.
//!
//! All subcommands take a config TOML for wallet/RPC details.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::info;

mod config;
mod discover;
mod runner;
mod settler;
mod wallet;

use config::ClientConfig;

#[derive(Parser, Debug)]
#[command(name = "octravpn", version, about = "OctraVPN client")]
struct Cli {
    #[arg(long, env = "OCTRAVPN_CONFIG", default_value = "client.toml")]
    config: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Parser, Debug)]
enum Cmd {
    Identity,
    Nodes {
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long, default_value_t = 50)]
        limit: u64,
    },
    Connect {
        /// Number of hops to use (1..=3).
        #[arg(long, default_value_t = 3)]
        hops: u8,
        /// Optional pinned exit region (e.g. "eu-west").
        #[arg(long)]
        region: Option<String>,
        /// Maximum OCT to escrow.
        #[arg(long)]
        deposit: u64,
    },
    Settle {
        session_id: String,
    },
    Reclaim {
        session_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,octravpn_client=debug".into()),
        )
        .init();

    let cli = Cli::parse();
    let cfg = Arc::new(ClientConfig::load(&cli.config)?);
    let client = Arc::new(runner::Client::new(cfg.clone()).await?);

    match cli.cmd {
        Cmd::Identity => {
            client.print_identity();
            Ok(())
        }
        Cmd::Nodes { offset, limit } => {
            let nodes = discover::list(&client, offset, limit).await?;
            for n in nodes {
                println!(
                    "{addr}  {endpoint:32}  {region:>12}  {price:>10} OU/MB  bond={bond}",
                    addr = n.addr.display,
                    endpoint = n.endpoint,
                    region = n.region,
                    price = n.price_per_mb,
                    bond = n.bond,
                );
            }
            Ok(())
        }
        Cmd::Connect {
            hops,
            region,
            deposit,
        } => {
            info!(hops, ?region, deposit, "connecting");
            client.connect(hops, region.as_deref(), deposit).await
        }
        Cmd::Settle { session_id } => {
            settler::settle(&client, &session_id).await
        }
        Cmd::Reclaim { session_id } => {
            settler::reclaim(&client, &session_id).await
        }
    }
}
