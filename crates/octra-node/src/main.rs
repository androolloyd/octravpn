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
    /// Inspect a stopped store without repairing or importing it.
    #[command(alias = "check_store")]
    CheckStore(octra_node::offline_cli::CheckStore),
    /// Audit stored account cipher representation without exposing contents.
    #[command(alias = "fhe_audit")]
    FheAudit(octra_node::offline_cli::FheAudit),
    /// Check or durably prepare the stopped validator's anti-equivocation floor.
    #[command(alias = "vote_floor")]
    VoteFloor(octra_node::offline_cli::VoteFloor),
    /// Resume a locally staged repair in a stopped native-format store.
    LegacyRepair(octra_node::legacy_repair::Options),
    /// Stage an empty native-format fork only after authenticated peer proof.
    LegacyStage(octra_node::legacy_repair::StageOptions),
    /// Compile local AML to existing Legacy OCTB; does not grant typed Program authority.
    CompileLegacy {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        loops: bool,
        #[arg(long)]
        point_ops: bool,
    },
    /// Build immutable-term prepaid custody for the existing OCTB Circle host.
    CompileCirclePayments {
        /// Derive the receipt domain from the configured full chain origin.
        #[arg(long, conflicts_with = "domain", required_unless_present = "domain")]
        config: Option<PathBuf>,
        /// Explicit domain for offline fixtures; use --config for a network.
        #[arg(long, conflicts_with = "config", required_unless_present = "config")]
        domain: Option<String>,
        #[arg(long)]
        custody_cap: u64,
        #[arg(long)]
        minimum_stake: u64,
    },
    #[command(hide = true)]
    SingleRangeWorker {
        #[arg(long)]
        parent_pid: u32,
    },
    #[command(hide = true)]
    CryptoWorker {
        #[arg(long)]
        parent_pid: u32,
        #[arg(long)]
        session: bool,
    },
    /// Manage the signed local validator duty pause; no network transaction.
    ValidatorControl(octra_node::validator_cli::Options),
    /// Prepare, sign or submit native operator transactions, or wallet exit intents.
    #[command(name = "validator-tx", alias = "bft-control-tx")]
    ValidatorTransaction(octra_node::validator_cli::transaction::Options),
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
    /// Initialize a new encrypted operator wallet on supported devnet history.
    #[cfg(feature = "private-payments-experimental")]
    InitPrivateWallet {
        #[arg(long)]
        config: PathBuf,
    },
    /// Initialize empty encrypted payer/index books on a supported devnet pool.
    #[cfg(feature = "private-payments-experimental")]
    InitPrivatePayer {
        #[arg(long)]
        config: PathBuf,
    },
    /// Import finite deposit/purchase consent while the node is stopped.
    #[cfg(feature = "private-payments-experimental")]
    PrivatePayerConsent {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        requests: PathBuf,
    },
    /// Seal complete finite route consent offline, before any operator request.
    #[cfg(feature = "private-payments-experimental")]
    PrivateRouteConsent {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        requests: PathBuf,
        /// Finish an interrupted initialization with the exact original input.
        #[arg(long)]
        resume: bool,
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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|error| anyhow::anyhow!("initialize node diagnostics: {error}"))?;
    match Cli::parse().command {
        Command::CheckStore(options) => std::process::exit(options.run().await?),
        Command::FheAudit(options) => std::process::exit(options.run().await?),
        Command::VoteFloor(options) => std::process::exit(options.run().await?),
        Command::LegacyRepair(options) => options.run()?,
        Command::LegacyStage(options) => options.run().await?,
        Command::CompileLegacy {
            source,
            loops,
            point_ops,
        } => {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(source)?
                .take(1_048_577)
                .read_to_end(&mut bytes)?;
            let report = octra_node_runtime::program::build::legacy(&bytes, loops, point_ops)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::CompileCirclePayments {
            config,
            domain,
            custody_cap,
            minimum_stake,
        } => {
            let domain = match (config, domain) {
                (Some(path), None) => {
                    let config = octra_node::network::read(&path)?;
                    octra_node::vpn::payments::application_domain(
                        &config.network.identity,
                        octra_node::vpn::payments::Application::Circle,
                    )
                }
                (None, Some(domain)) => domain,
                _ => unreachable!("clap requires exactly one Circle domain source"),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&octra_node::vpn::payments::build::compile(
                    &domain,
                    custody_cap,
                    minimum_stake
                )?)?
            );
        }
        Command::SingleRangeWorker { parent_pid } => {
            octra_node_runtime::single_private::worker::helper(parent_pid)
                .map_err(anyhow::Error::msg)?;
        }
        Command::CryptoWorker {
            parent_pid,
            session,
        } => {
            if session {
                octra_node_runtime::crypto_worker::helper_session(parent_pid)
            } else {
                octra_node_runtime::crypto_worker::helper(parent_pid)
            }
            .map_err(anyhow::Error::msg)?;
        }
        Command::ValidatorControl(options) => options.run()?,
        Command::ValidatorTransaction(options) => options.run().await?,
        Command::Snapshot { command } => command.run(shutdown()).await?,
        Command::InitIdentity { key } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&octra_node::identity::create(&key)?)?
            );
        }
        #[cfg(feature = "private-payments-experimental")]
        Command::InitPrivateWallet { config } => {
            let wallet =
                octra_node::vpn::payments::shielded::startup::offline::run_with_runtime_factory(
                    &config,
                    private_crypto,
                    octra_node::vpn::payments::shielded::startup::Action::Operator,
                )
                .await?;
            println!("{}", serde_json::json!({"created":true,"wallet":wallet}));
        }
        #[cfg(feature = "private-payments-experimental")]
        Command::InitPrivatePayer { config } => {
            let wallet = Box::pin(
                octra_node::vpn::payments::shielded::startup::offline::run_with_runtime_factory(
                    &config,
                    private_crypto,
                    octra_node::vpn::payments::shielded::startup::Action::Payer,
                ),
            )
            .await?;
            println!("{}", serde_json::json!({"created":true,"wallet":wallet}));
        }
        #[cfg(feature = "private-payments-experimental")]
        Command::PrivatePayerConsent { config, requests } => {
            let requests =
                octra_node::vpn::payments::shielded::payer::startup::read_requests(&requests)?;
            let wallet = Box::pin(
                octra_node::vpn::payments::shielded::startup::offline::run_with_runtime_factory(
                    &config,
                    private_crypto,
                    octra_node::vpn::payments::shielded::startup::Action::Consent(requests),
                ),
            )
            .await?;
            println!("{}", serde_json::json!({"accepted":true,"wallet":wallet}));
        }
        #[cfg(feature = "private-payments-experimental")]
        Command::PrivateRouteConsent {
            config,
            requests,
            resume,
        } => {
            let hops = octra_node::vpn::payments::shielded::payer::startup::route::read_consent(
                &requests,
            )?;
            let wallet = Box::pin(
                octra_node::vpn::payments::shielded::startup::offline::run_with_runtime_factory(
                    &config,
                    private_crypto,
                    octra_node::vpn::payments::shielded::startup::Action::RouteConsent {
                        hops,
                        resume,
                    },
                ),
            )
            .await?;
            println!("{}", serde_json::json!({"accepted":true,"wallet":wallet}));
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
            octra_node::single::launch::run(
                octra_node::single::launch::read(&config)?,
                crypto()?,
                shutdown(),
            )
            .await?;
        }
        Command::Run {
            config,
            compute_provider,
        } => {
            let mut config = octra_node::devnet::read(&config)?;
            config.compute_provider |= compute_provider;
            octra_node::devnet::run(config, crypto()?, shutdown()).await?;
        }
        Command::RunNetwork {
            config,
            compute_provider,
            publisher,
        } => match octra_node::network::read_role(&config)? {
            octra_node::network::RoleConfig::Public(mut config) => {
                config.compute_provider |= compute_provider;
                config.publisher |= publisher;
                octra_node::network::run_with_runtime_factory(
                    *config,
                    crypto_from_settings,
                    shutdown(),
                )
                .await?;
            }
            octra_node::network::RoleConfig::Single(config) => {
                anyhow::ensure!(
                    !compute_provider && !publisher,
                    "public-network flags cannot select private Single services"
                );
                octra_node::single::launch::run(*config, crypto()?, shutdown()).await?;
            }
        },
    }
    Ok(())
}
/// Only this CLI assumes that its own executable implements the hidden helper.
/// Library launchers receive the runtime capability from their embedding host.
#[cfg(feature = "private-payments-experimental")]
fn private_crypto(
    settings: Option<&octra_node_protocol::consensus::profile::Settings>,
) -> Result<octra_node_runtime::circle::CircleRuntime> {
    settings.map_or_else(crypto, crypto_from_settings)
}
fn crypto() -> Result<octra_node_runtime::circle::CircleRuntime> {
    crypto_with_limits(octra_node_runtime::crypto_worker::Limits::capture())
}
fn crypto_from_settings(
    settings: &octra_node_protocol::consensus::profile::Settings,
) -> Result<octra_node_runtime::circle::CircleRuntime> {
    crypto_with_limits(octra_node_runtime::crypto_worker::Limits::from_values(
        |name| settings.get(name).map(<[u8]>::to_vec),
    ))
}
fn crypto_with_limits(
    limits: octra_node_runtime::crypto_worker::Limits,
) -> Result<octra_node_runtime::circle::CircleRuntime> {
    use octra_node_runtime::{circle::CircleRuntime, crypto_worker::Pool};
    let pool = Pool::open(&std::env::current_exe()?, limits).map_err(anyhow::Error::msg)?;
    Ok(CircleRuntime::isolated(pool))
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

#[cfg(test)]
mod startup_settings_tests {
    use super::*;
    #[test]
    fn private_wallet_initialization_command_is_feature_scoped() {
        let result = Cli::try_parse_from([
            "octra-node",
            "init-private-wallet",
            "--config",
            "private.json",
        ]);
        #[cfg(feature = "private-payments-experimental")]
        assert!(matches!(
            result.unwrap().command,
            Command::InitPrivateWallet { .. }
        ));
        #[cfg(not(feature = "private-payments-experimental"))]
        assert!(result.is_err());
    }

    #[test]
    fn private_payer_commands_are_feature_scoped() {
        for args in [
            vec![
                "octra-node",
                "init-private-payer",
                "--config",
                "private.json",
            ],
            vec![
                "octra-node",
                "private-payer-consent",
                "--config",
                "private.json",
                "--requests",
                "consent.json",
            ],
        ] {
            let result = Cli::try_parse_from(args);
            #[cfg(feature = "private-payments-experimental")]
            assert!(result.is_ok());
            #[cfg(not(feature = "private-payments-experimental"))]
            assert!(result.is_err());
        }
    }

    #[test]
    fn circle_build_requires_one_domain_source() {
        let base = ["octra-node", "compile-circle-payments"];
        let terms = ["--custody-cap", "200000000", "--minimum-stake", "100000000"];
        let parse = |source: &[&str]| {
            Cli::try_parse_from(base.into_iter().chain(source.iter().copied()).chain(terms))
        };
        assert!(matches!(
            parse(&["--config", "network.json"]).unwrap().command,
            Command::CompileCirclePayments {
                config: Some(_),
                domain: None,
                ..
            }
        ));
        assert!(matches!(
            parse(&["--domain", &"a".repeat(64)]).unwrap().command,
            Command::CompileCirclePayments {
                config: None,
                domain: Some(_),
                ..
            }
        ));
        assert!(parse(&[]).is_err());
        assert!(parse(&["--config", "network.json", "--domain", "a"]).is_err());
    }

    #[test]
    fn cli_worker_capability_uses_the_captured_file_values() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network.env");
        std::fs::write(&path, b"OCTRA_PVAC_VERIFY_WORKERS=2\nOCTRA_PVAC_VERIFY_TIMEOUT_SEC=1\nOCTRA_PVAC_VERIFY_MAX_RSS_MB=64\n").unwrap();
        let values = octra_node::network_profile::parse_env(&std::fs::read(path).unwrap()).unwrap();
        let settings =
            octra_node_protocol::consensus::profile::Settings::from_values(values).unwrap();
        let runtime = crypto_from_settings(&settings).unwrap();
        let limits = runtime.crypto_pool().unwrap().worker().limits();
        assert_eq!(limits.capacity, 2);
        assert_eq!(limits.timeout_seconds.to_bits(), 1_f64.to_bits());
        assert_eq!(limits.rss_mb, 64);
    }
}
