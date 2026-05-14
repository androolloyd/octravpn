//! `octravpn` — the client CLI.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::info;

mod commands;
mod config;
mod discover;
mod operator_backend;
mod runner;
mod settler;
mod tailnet;
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
    /// Print derived addresses/pubkeys for the current wallet.
    Identity,
    /// List active validator-VPN nodes from the on-chain registry.
    Nodes {
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long, default_value_t = 50)]
        limit: u64,
    },
    /// Open a 1..3 hop session and run the tunnel until ctrl-c.
    Connect {
        #[arg(long, default_value_t = 3)]
        hops: u8,
        #[arg(long)]
        region: Option<String>,
        #[arg(long)]
        deposit: u64,
    },
    /// Settle a session opened earlier.
    Settle { session_id: String },
    /// Trigger no-show refund for a session past grace.
    Reclaim { session_id: String },

    // ------- Deployment / provisioning subcommands -------
    /// Write a fresh client config + key files into a directory.
    Init {
        #[arg(long, default_value = ".")]
        dir: String,
        #[arg(long)]
        rpc_url: Option<String>,
        #[arg(long)]
        program_addr: Option<String>,
        #[arg(long)]
        force: bool,
    },
    /// Generate a new wallet keypair and write to disk.
    Keygen {
        #[arg(long)]
        out: String,
    },
    /// Run preflight checks: config readable, key valid, RPC reachable,
    /// TUN openable, system capabilities present.
    Doctor,
    /// Collect a redacted diagnostic bundle (tar.gz) for support reports.
    BugReport {
        /// Output path; defaults to `./octravpn-bugreport-<ts>.tar.gz`.
        #[arg(long)]
        out: Option<String>,
    },
    /// Tailnet operations (create / membership / mesh-up / discovery).
    Tailnet {
        #[command(subcommand)]
        op: tailnet::TailnetCmd,
    },
    /// Build or verify equivocation evidence against an endpoint.
    SlashEvidence {
        #[command(subcommand)]
        op: commands::SlashCmd,
    },
    /// Expose a local TCP service to tailnet members at
    /// `<host>.<tailnet>.octra:<port><path>`.
    Serve {
        #[command(subcommand)]
        cmd: ServeOp,
    },
    /// Same as `serve`, but additionally publish the service through a
    /// paid validator exit node to the public internet.
    Funnel {
        #[command(subcommand)]
        cmd: ServeOp,
    },
}

/// Operations supported by both `serve` and `funnel`. Identical surface
/// — the dispatcher decides whether the entry is recorded as a tailnet-only
/// serve or a public funnel.
#[derive(clap::Parser, Debug, Clone)]
pub(crate) enum ServeOp {
    /// Register a local port to advertise.
    Add {
        #[arg(long)]
        port: u16,
        #[arg(long)]
        path: String,
    },
    /// Remove a previously-registered port.
    Remove {
        #[arg(long)]
        port: u16,
    },
    /// List currently-registered entries.
    List,
}

impl ServeOp {
    fn into_inner(self) -> commands::ServeOp {
        match self {
            Self::Add { port, path } => commands::ServeOp::Add { port, path },
            Self::Remove { port } => commands::ServeOp::Remove { port },
            Self::List => commands::ServeOp::List,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    octravpn_core::util::init_tracing("info,octravpn_client=debug");

    let cli = Cli::parse();

    // Config-less subcommands handled first.
    match &cli.cmd {
        Cmd::Init {
            dir,
            rpc_url,
            program_addr,
            force,
        } => {
            return commands::init(dir, rpc_url.as_deref(), program_addr.as_deref(), *force);
        }
        Cmd::Keygen { out } => return commands::keygen(out),
        Cmd::Doctor => {
            return commands::doctor(&cli.config);
        }
        Cmd::BugReport { out } => {
            return commands::bugreport(&cli.config, out.as_deref());
        }
        Cmd::Serve { cmd } => {
            return commands::serve(cmd.clone().into_inner());
        }
        Cmd::Funnel { cmd } => {
            return commands::funnel(cmd.clone().into_inner());
        }
        Cmd::SlashEvidence { op } => {
            // Verify + Build don't touch the chain; dispatch early. Submit
            // needs the client + wallet, so it falls through to the
            // post-Client::new() arm below.
            if !matches!(op, commands::SlashCmd::Submit { .. }) {
                return commands::slash_evidence(op.clone());
            }
        }
        _ => {}
    }

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
                    "{addr}  {endpoint:32}  {region:>12}  {price:>10} OU/MB  rep={rep}",
                    addr = n.addr.display(),
                    endpoint = n.endpoint,
                    region = n.region,
                    price = n.price_per_mb,
                    rep = n.reputation,
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
        Cmd::Settle { session_id } => settler::settle(&client, &session_id).await,
        Cmd::Reclaim { session_id } => settler::reclaim(&client, &session_id).await,
        Cmd::Tailnet { op } => tailnet::dispatch(&client, &cfg, op).await,
        Cmd::SlashEvidence { op } => commands::slash_submit(&client, op.clone()).await,
        // Already handled above.
        Cmd::Init { .. }
        | Cmd::Keygen { .. }
        | Cmd::Doctor
        | Cmd::BugReport { .. }
        | Cmd::Serve { .. }
        | Cmd::Funnel { .. } => unreachable!(),
    }
}
