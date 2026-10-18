use super::{assemble, prepare, serve, Assemble, Prepare};
use anyhow::Result;
use clap::Subcommand;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Subcommand)]
pub enum Commands {
    /// Seal a verified portable snapshot or explicitly owned native store.
    Seal(super::offline::Options),
    /// Build a fresh native draft from a sealed snapshot.
    Build(super::offline::Options),
    /// Sign a checkpoint after local stable-head/history and role checks.
    SignCheckpoint(super::offline::Options),
    /// Sign the exact manifest only after complete source verification.
    SignManifest(super::offline::Options),
    /// Verify certificate authority/freshness and optionally all source bytes.
    Verify(super::offline::Options),
    /// Assemble the native legacy quorum interchange; never enables bootstrap.
    AssembleQuorum(super::offline::Options),
    /// Assemble native finalized authority with detached exporter signatures.
    AssembleFinalized(super::offline::Options),
    /// Create an unsigned immutable native package from one retained finalized head.
    Prepare {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// File containing the exact canonical-base64 native finalized anchor.
        #[arg(long)]
        finality: PathBuf,
        #[arg(long, default_value_t = 4_194_304)]
        chunk_size: u64,
        #[arg(long, default_value_t = 86_400)]
        valid_for: u64,
    },
    /// Verify a prepared package and publish its reference-finality certificate.
    Assemble {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        directory: PathBuf,
        /// Existing private raw Ed25519 key; never copied into the package.
        #[arg(long)]
        exporter_key: Option<PathBuf>,
        /// Native JSON signature-array file, repeatable.
        #[arg(long)]
        exporter_signatures: Vec<PathBuf>,
        /// Optional quorum signature-array file, repeatable and strictly verified.
        #[arg(long)]
        checkpoint_signatures: Vec<PathBuf>,
    },
    /// Serve only a completed, verified package over native state-sync HTTP.
    Serve {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        directory: PathBuf,
        #[arg(long, default_value = "127.0.0.1:19873")]
        bind: SocketAddr,
    },
}
impl Commands {
    pub async fn run(self, shutdown: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        match self {
            Self::Seal(options) => options.run(super::offline::Action::Seal).await?,
            Self::Build(options) => options.run(super::offline::Action::Build).await?,
            Self::SignCheckpoint(options) => {
                options.run(super::offline::Action::SignCheckpoint).await?;
            }
            Self::SignManifest(options) => {
                options.run(super::offline::Action::SignManifest).await?;
            }
            Self::Verify(options) => options.run(super::offline::Action::Verify).await?,
            Self::AssembleQuorum(options) => {
                options.run(super::offline::Action::AssembleQuorum).await?;
            }
            Self::AssembleFinalized(options) => {
                options
                    .run(super::offline::Action::AssembleFinalized)
                    .await?;
            }
            Self::Prepare {
                config,
                directory,
                output,
                finality,
                chunk_size,
                valid_for,
            } => {
                let (authority, limits) = context(&config)?;
                let report = prepare(
                    &authority,
                    &directory,
                    &output,
                    Prepare {
                        finality,
                        chunk_size,
                        valid_for,
                        limits,
                    },
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            Self::Assemble {
                config,
                directory,
                exporter_key,
                exporter_signatures,
                checkpoint_signatures,
            } => {
                let (authority, limits) = context(&config)?;
                let report = tokio::task::spawn_blocking(move || {
                    assemble(
                        &authority,
                        &directory,
                        Assemble {
                            exporter_key,
                            exporter_signatures,
                            checkpoint_signatures,
                            limits,
                        },
                    )
                })
                .await??;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            Self::Serve {
                config,
                directory,
                bind,
            } => {
                let (authority, limits) = context(&config)?;
                serve(&authority, &directory, limits, bind, shutdown).await?;
            }
        }
        Ok(())
    }
}
fn context(
    path: &std::path::Path,
) -> Result<(super::Authority, octra_node_runtime::ledger_image::Limits)> {
    let config = super::super::read(path)?;
    let limits = octra_node_runtime::ledger_image::Limits {
        bytes: config.max_bytes,
        records: config.max_records,
        string_bytes: config.max_string_bytes,
    };
    Ok((super::Authority::new(config.network)?, limits))
}
