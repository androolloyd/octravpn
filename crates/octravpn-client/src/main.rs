//! `octravpn` — the client CLI.

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::info;

mod chain_v3;
mod commands;
mod config;
mod discover;
mod discover_v2;
mod operator_backend;
mod portal;
mod runner;
mod settler;
mod tailnet;
mod v2_cache;
mod v2_runner;
mod v3_runner;
mod wallet;

use config::{ClientConfig, ProtocolVersion};

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
    /// v2 substrate: list authorized circles for a tailnet and decrypt
    /// their sealed `/policy.json`. Members see endpoint/region/price;
    /// non-members see `[opaque]` and an explanatory message. Gated on
    /// `[chain].protocol_version = "v2"` in the config.
    Discover {
        #[command(subcommand)]
        op: DiscoverOp,
    },
    /// v3 substrate: open a session against the configured operator
    /// circle (`[v3].circle_id`) on the v3 chain-minimal program
    /// (`program/main-v3.aml`). Reads `[v3]` config + falls back to
    /// `[wallet].secret_path` when `[v3].wallet_key_path` is unset.
    /// Gated on `[chain].protocol_version = "v3"`.
    ConnectV3 {
        /// Override `[v3].tailnet_id`.
        #[arg(long)]
        tailnet_id: Option<u64>,
        /// Override `[v3].circle_id`.
        #[arg(long)]
        circle_id: Option<String>,
        /// Override `[v3].max_pay` (raw OU credit ceiling).
        #[arg(long)]
        max_pay: Option<u64>,
        /// Skip the normal `settle_confirm` and submit `claim_no_show`
        /// instead. Used by the integration tests + manual smoke tests
        /// when the operator deliberately stalls.
        #[arg(long, default_value_t = false)]
        no_show: bool,
        /// Plumb a deterministic `bytes_used` figure into the settle
        /// path. Only useful for tests; production clients leave this
        /// unset and read the value from session counters (deferred —
        /// real bring-up is the WG follow-up).
        #[arg(long)]
        bytes_used: Option<u64>,
    },
    /// v2 substrate: open a session against an authorized circle and
    /// print the WG handoff. The v1.1 `connect` path is preserved.
    ConnectV2 {
        /// Tailnet id (decimal). Looked up against the v2 program.
        #[arg(long)]
        tailnet_id: u64,
        /// Circle id (an `oct…` address) authorized for the tailnet.
        /// Leave unset to pick the first decryptable circle.
        #[arg(long)]
        circle_id: Option<String>,
        /// Session class: `shared` (default) or `internal`.
        #[arg(long, default_value = "shared")]
        class: String,
        /// Deposit in raw OU (must be >= chain `min_session_deposit`).
        #[arg(long)]
        deposit: u64,
        /// Sealed-policy passphrase override (env > this > config).
        #[arg(long)]
        secret: Option<String>,
        /// Force a refresh of cached policy even if the hash matches.
        #[arg(long, default_value_t = false)]
        refresh: bool,
    },

    /// Resolve an `oct://<circle>/<path>` URL — either render in the
    /// local browser portal (default), save to disk, or stream to
    /// stdout. The OS protocol handler (see `dist/`) dispatches here.
    OpenUrl(commands::OpenUrlArgs),

    /// `oct://` fetch surface for shell pipelines: raw bytes to stdout
    /// or `--output <path>`, optional interactive passphrase prompt
    /// for sealed assets. Bypasses the HTTP portal entirely. See
    /// `commands::fetch` for exit-code semantics.
    Fetch(commands::FetchArgs),

    /// Run the local `oct://` browser portal. Long-running. Serves
    /// HTML/JSON fetched over the active VPN session, sandboxes HTML
    /// inside an iframe, gates first-time circles on an explicit
    /// confirm. Defaults to `127.0.0.1:51823`; pass `--bind` to override.
    Portal {
        /// Loopback bind address. Defaults to 127.0.0.1:51823.
        #[arg(long)]
        bind: Option<std::net::SocketAddr>,
    },
}

/// `octravpn discover ...` — explore the v2 substrate (authorized
/// circles + sealed policies). v1.1 has `octravpn nodes` instead.
#[derive(clap::Parser, Debug)]
pub(crate) enum DiscoverOp {
    /// List authorized circles for a tailnet and decrypt their sealed
    /// `/policy.json`. Non-decryptable entries surface as `[opaque]`
    /// rather than being silently dropped.
    V2 {
        /// Tailnet id (decimal).
        tailnet_id: u64,
        /// Sealed-policy passphrase override. Precedence:
        /// env `OCTRAVPN_SEALED_PASSPHRASE` > this flag > `[v2].sealed_passphrase`.
        #[arg(long)]
        secret: Option<String>,
        /// Drop cached entries before fetching (forces full RPC + decrypt).
        #[arg(long, default_value_t = false)]
        refresh: bool,
        /// Output decrypted policies as JSON instead of a human-readable table.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Drop one circle's cached policy. Useful after the operator
    /// rotates policy out-of-band and you want the next discover to
    /// re-fetch immediately.
    Invalidate {
        /// Circle id whose cached policy to drop. Pass `--all` to
        /// clear every cached entry instead.
        #[arg(long)]
        circle_id: Option<String>,
        #[arg(long, default_value_t = false)]
        all: bool,
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
        // `open-url`, `fetch`, and `portal` are read-only over the
        // chain RPC — they don't need a session-runner, just a loaded
        // config.
        Cmd::OpenUrl(args) => {
            let cfg = ClientConfig::load(&cli.config)?;
            return commands::run_open_url(&cfg, args.clone()).await;
        }
        Cmd::Fetch(args) => {
            let cfg = ClientConfig::load(&cli.config)?;
            return commands::run_fetch(&cfg, args.clone()).await;
        }
        Cmd::Portal { bind } => {
            let cfg = ClientConfig::load(&cli.config)?;
            let chain = portal::chain::PortalChain::from_config(&cfg)?;
            let bind = bind.unwrap_or_else(|| {
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    portal::DEFAULT_PORTAL_PORT,
                )
            });
            return portal::run_portal(chain, bind).await;
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
        Cmd::Discover { op } => v2_runner::dispatch_discover(&client, &cfg, op).await,
        Cmd::ConnectV2 {
            tailnet_id,
            circle_id,
            class,
            deposit,
            secret,
            refresh,
        } => {
            v2_runner::connect_v2(
                &client,
                &cfg,
                tailnet_id,
                circle_id.as_deref(),
                &class,
                deposit,
                secret.as_deref(),
                refresh,
            )
            .await
        }
        Cmd::ConnectV3 {
            tailnet_id,
            circle_id,
            max_pay,
            no_show,
            bytes_used,
        } => {
            // Per-protocol dispatch — v3 is the only variant routed
            // through `protocol_version()` for now; v1.1 and v2 keep
            // their own connect subcommands untouched.
            match cfg.protocol_version()? {
                ProtocolVersion::V3 => {
                    let mut effective_cfg = (*cfg).clone();
                    if let Some(t) = tailnet_id {
                        effective_cfg.v3.tailnet_id = t;
                    }
                    if let Some(c) = circle_id {
                        effective_cfg.v3.circle_id = c;
                    }
                    if let Some(m) = max_pay {
                        effective_cfg.v3.max_pay = m;
                    }
                    let cfg_arc = Arc::new(effective_cfg);
                    v3_runner::connect_v3(&client, &cfg_arc, bytes_used, no_show).await
                }
                ProtocolVersion::V1_1 | ProtocolVersion::V2 => {
                    anyhow::bail!(
                        "`connect-v3` requires `[chain].protocol_version = \"v3\"` (currently `{}`)",
                        cfg.chain.protocol_version,
                    )
                }
            }
        }
        // Already handled above.
        Cmd::Init { .. }
        | Cmd::Keygen { .. }
        | Cmd::Doctor
        | Cmd::BugReport { .. }
        | Cmd::Serve { .. }
        | Cmd::Funnel { .. }
        | Cmd::OpenUrl(_)
        | Cmd::Fetch(_)
        | Cmd::Portal { .. } => unreachable!(),
    }
}
