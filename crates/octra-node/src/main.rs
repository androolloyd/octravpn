use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(about = "Rust Octra node local devnet")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    InitDevnet {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long, default_value_t = 19870)]
        base_port: u16,
    },
    Run {
        #[arg(long)]
        config: PathBuf,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::InitDevnet {
            directory,
            base_port,
        } => {
            for config in octra_node::devnet::init(&directory, base_port).await? {
                println!("{}", config.display());
            }
        }
        Command::Run { config } => {
            let config = octra_node::devnet::read(&config)?;
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
            octra_node::devnet::run(config, shutdown).await?;
        }
    }
    Ok(())
}
