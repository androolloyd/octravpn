use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(about = "Rust Octra node")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    #[command(hide = true)]
    SingleRangeWorker {
        #[arg(long)]
        parent_pid: u32,
    },
    /// Manage the signed local validator duty pause; no network transaction.
    ValidatorControl(octra_node::validator_cli::Options),
    /// Prepare, authorize and serve native finalized state-sync snapshots.
    Snapshot {
        #[command(subcommand)]
        command: octra_node::bootstrap::export::Commands,
    },
    /// Create a private node identity at a new key path.
    InitIdentity {
        #[arg(long)]
        key: PathBuf,
    },
    /// Show the public native VPN keys used for operator registration.
    VpnIdentity {
        #[arg(long)]
        key: PathBuf,
    },
    /// Import an authenticated network snapshot into a new data directory.
    Bootstrap {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        directory: PathBuf,
    },
    /// Export a retained public-network ledger as a native ledger-image file.
    ExportLedger {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    InitDevnet {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long, default_value_t = 19870)]
        base_port: u16,
        /// Activate application VM rules in an explicit new isolated genesis.
        #[arg(long)]
        activated_applications: bool,
    },
    /// Run an explicitly private Single fixture, with no BFT voting or public join.
    RunSingle {
        #[arg(long)]
        config: PathBuf,
    },
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        compute_provider: bool,
    },
    /// Run a public-network observer (or explicitly configured validator).
    RunNetwork {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        compute_provider: bool,
        /// Use the configured native exporter identity without voting.
        #[arg(long)]
        publisher: bool,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::SingleRangeWorker { parent_pid } => {
            octra_node_runtime::single_private::worker::helper(parent_pid)
                .map_err(anyhow::Error::msg)?;
        }
        Command::ValidatorControl(options) => options.run()?,
        Command::Snapshot { command } => command.run(shutdown()).await?,
        Command::InitIdentity { key } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&octra_node::identity::create(&key)?)?
            );
        }
        Command::VpnIdentity { key } => {
            let node = octra_node::identity::read(&key)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&octra_node::vpn::Keys::derive(&node).public())?
            );
        }
        Command::Bootstrap { config, directory } => {
            let config = octra_node::bootstrap::read(&config)?;
            let report = tokio::select! {
                report=octra_node::bootstrap::install(config,&directory)=>report?,
                _=tokio::signal::ctrl_c()=>return Ok(()),
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::ExportLedger {
            config,
            directory,
            output,
        } => {
            let config = octra_node::bootstrap::read(&config)?;
            let limits = octra_node_runtime::ledger_image::Limits {
                bytes: config.max_bytes,
                records: config.max_records,
                string_bytes: config.max_string_bytes,
            };
            let authority = octra_node::bootstrap::Authority::new(config.network)?;
            let report =
                octra_node::bootstrap::export::ledger(&authority, &directory, &output, limits)
                    .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::InitDevnet {
            directory,
            base_port,
            activated_applications,
        } => {
            for config in octra_node::devnet::init_with_applications(
                &directory,
                base_port,
                activated_applications,
            )
            .await?
            {
                println!("{}", config.display());
            }
        }
        Command::RunSingle { config } => {
            octra_node::single::launch::run(octra_node::single::launch::read(&config)?, shutdown())
                .await?;
        }
        Command::Run {
            config,
            compute_provider,
        } => {
            let mut config = octra_node::devnet::read(&config)?;
            config.compute_provider |= compute_provider;
            octra_node::devnet::run(config, shutdown()).await?;
        }
        Command::RunNetwork {
            config,
            compute_provider,
            publisher,
        } => match octra_node::network::read_role(&config)? {
            octra_node::network::RoleConfig::Public(mut config) => {
                config.compute_provider |= compute_provider;
                config.publisher |= publisher;
                octra_node::network::run(*config, shutdown()).await?;
            }
            octra_node::network::RoleConfig::Single(config) => {
                anyhow::ensure!(
                    !compute_provider && !publisher,
                    "public-network flags cannot select private Single services"
                );
                octra_node::single::launch::run(*config, shutdown()).await?;
            }
        },
    }
    Ok(())
}
fn shutdown() -> tokio::sync::watch::Receiver<bool> {
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install SIGTERM handler");
            tokio::select! {_=tokio::signal::ctrl_c()=>(),_=terminate.recv()=>()}
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        stop.send_replace(true);
    });
    shutdown
}
