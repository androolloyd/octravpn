//! Command-line adapter for the reusable client library.

use std::sync::Arc;

use crate::{
    commands, discover, migration, onboarding, portal, runner, settler, tailnet, v2_runner,
    v3_runner, wireguard,
};

use anyhow::Result;
use clap::Parser;
use tracing::info;

use crate::config::{ClientConfig, ProtocolVersion};

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
    /// Buy explicit prepaid class allowances, then run their raw IPv4 TUN.
    Payments {
        #[arg(long)]
        plan: std::path::PathBuf,
        #[arg(long)]
        journal: std::path::PathBuf,
        #[arg(long)]
        receipt_key: String,
        #[arg(long)]
        tun_name: String,
        #[arg(long)]
        resume: bool,
    },
    /// Run an explicitly accepted two/three-operator nested prepaid route (Linux).
    MultiPayments {
        #[arg(long)]
        route: std::path::PathBuf,
        #[arg(long)]
        resume: bool,
    },
    /// Buy fixed prepaid allowances for an already registered stock Tailscale node.
    StockPayments {
        #[arg(long)]
        plan: std::path::PathBuf,
        #[arg(long)]
        journal: std::path::PathBuf,
        #[arg(long)]
        receipt_key: String,
        #[arg(long)]
        node_key: String,
        #[arg(long)]
        resume: bool,
    },
    /// Print derived addresses/pubkeys for the current wallet.
    Identity,
    /// List active validator-VPN nodes from the on-chain registry.
    Nodes {
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long, default_value_t = 50)]
        limit: u64,
    },
    /// Run an authenticated single-exit session until ctrl-c.
    Connect {
        #[arg(long, default_value_t = 1)]
        hops: u8,
        #[arg(long)]
        region: Option<String>,
        #[arg(long)]
        deposit: u64,
        /// Public IPv4 UDP destination reached through the selected Circle.
        #[arg(
            long,
            required_unless_present = "tun_name",
            conflicts_with = "tun_name"
        )]
        udp_target: Option<std::net::SocketAddrV4>,
        #[arg(long, requires = "udp_target")]
        udp_bind: Option<std::net::SocketAddrV4>,
        /// Raw IPv4 through a TUN at its session-derived /32. Routes must be
        /// provisioned explicitly on the host; this command changes no routes.
        #[arg(long, conflicts_with_all = ["udp_target", "udp_bind"])]
        tun_name: Option<String>,
    },
    /// Durable settlement recovery operations.
    Settle {
        #[command(subcommand)]
        op: commands::SettleCmd,
    },
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
    /// Open a session against the configured operator Circle on the current
    /// receipt-key-pinned settlement app. Reads `[v3]` config + falls back to
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
        /// Run an explicit settlement fixture with this byte count. Cannot
        /// be combined with live UDP forwarding.
        #[arg(long)]
        bytes_used: Option<u64>,
        /// Forward one local UDP source through the authenticated operator.
        /// The target is a public IPv4 socket address, for example 1.1.1.1:53.
        #[arg(long)]
        udp_target: Option<std::net::SocketAddrV4>,
        /// Loopback listener for --udp-target. Port 0 selects an unused port.
        #[arg(long, requires = "udp_target")]
        udp_bind: Option<std::net::SocketAddrV4>,
        /// Raw IPv4 TUN; requires the operator's ip_tunnel_v1 capability.
        #[arg(long, conflicts_with_all = ["udp_target", "udp_bind", "bytes_used", "no_show"])]
        tun_name: Option<String>,
        /// Open a local, read-only funding/status page before a paid provider
        /// TUN session. Requires --tun-name; does not change host routes.
        #[arg(long, requires = "tun_name")]
        onboard: bool,
        /// Route this Linux host's public IPv4 traffic through the paid TUN.
        /// Requires an active personal Tailscale mesh and explicit disconnect.
        #[arg(long, requires = "tun_name")]
        paid_exit: bool,
    },
    /// Historical v2 connection ABI; rejected before funds are submitted.
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
    /// Open the local Octranet onboarding guide.
    Onboard {
        #[command(subcommand)]
        op: OnboardOp,
    },
}

#[derive(clap::Subcommand, Debug)]
enum OnboardOp {
    /// Guide a direct personal mesh join through stock Tailscale.
    Personal {
        /// HTTPS origin of your Octranet mesh control server.
        #[arg(long)]
        login_server: String,
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

pub async fn run() -> Result<()> {
    octravpn_core::util::init_tracing("info,octravpn_client=debug");

    let cli = Cli::parse();

    // Config-less subcommands handled first.
    match &cli.cmd {
        Cmd::Payments {
            plan,
            journal,
            receipt_key,
            tun_name,
            resume,
        } => {
            let client = Box::pin(crate::PaymentClient::open(crate::PaymentOptions {
                plan: crate::AcceptedPlan::load(plan)?,
                journal: journal.clone(),
                receipt_key: Arc::new(crate::wallet::load_keypair(receipt_key)?),
                interface_name: tun_name.clone(),
                mode: if *resume {
                    crate::JournalMode::Resume
                } else {
                    crate::JournalMode::Create
                },
            }))
            .await?;
            let interface = client.interface();
            eprintln!(
                "Octranet interface {} address {}; provision explicit routes to paid destinations",
                interface.name, interface.address
            );
            Box::pin(client.run(async {
                tokio::signal::ctrl_c().await?;
                Ok(())
            }))
            .await?;
            return Ok(());
        }
        Cmd::MultiPayments { route, resume } => {
            let mode = if *resume {
                crate::JournalMode::Resume
            } else {
                crate::JournalMode::Create
            };
            let client = Box::pin(crate::MultiPaymentClient::open(
                crate::MultiRoutePlan::load(route)?.options(mode)?,
            ))
            .await?;
            for (index, interface) in client.interfaces().iter().enumerate() {
                eprintln!(
                    "Octranet paid route hop {}: {} address {} MTU {}",
                    index + 1,
                    interface.name,
                    interface.address,
                    interface.mtu
                );
            }
            client
                .run(async {
                    tokio::signal::ctrl_c().await?;
                    Ok(())
                })
                .await?;
            return Ok(());
        }
        Cmd::StockPayments {
            plan,
            journal,
            receipt_key,
            node_key,
            resume,
        } => {
            let client =
                crate::payment_runner::StockClient::open(crate::payment_runner::StockOptions {
                    plan: crate::AcceptedPlan::load(plan)?,
                    journal: journal.clone(),
                    receipt_key: Arc::new(crate::wallet::load_keypair(receipt_key)?),
                    node_key: node_key.clone(),
                    mode: if *resume {
                        crate::JournalMode::Resume
                    } else {
                        crate::JournalMode::Create
                    },
                })
                .await?;
            eprintln!("Prepaid stock Tailscale allowances are canonical; select the configured Octranet exit in Tailscale");
            Box::pin(client.run(async {
                tokio::signal::ctrl_c().await?;
                Ok(())
            }))
            .await?;
            return Ok(());
        }
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
        Cmd::Settle {
            op: commands::SettleCmd::Migrate(args),
        } => {
            let cfg = ClientConfig::load(&cli.config)?;
            return migration::run(&cfg, args);
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
        Cmd::Onboard {
            op: OnboardOp::Personal { login_server },
        } => {
            let page = onboarding::Onboarding::personal(login_server).await?;
            return page.until_cancelled().await;
        }
        _ => {}
    }

    let mut effective = ClientConfig::load(&cli.config)?;
    if let Cmd::ConnectV3 {
        tailnet_id,
        circle_id,
        max_pay,
        ..
    } = &cli.cmd
    {
        if let Some(value) = tailnet_id {
            effective.v3.tailnet_id = *value;
        }
        if let Some(value) = circle_id {
            effective.v3.circle_id = value.clone();
        }
        if let Some(value) = max_pay {
            effective.v3.max_pay = *value;
        }
    }
    // Receipt context and durable recovery bind the command-line Circle
    // before the client and transaction queue are opened.
    let cfg = Arc::new(effective);
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
            udp_target,
            udp_bind,
            tun_name,
        } => {
            info!(hops, ?region, deposit, "connecting");
            let mode = forwarding_mode(udp_target, udp_bind, tun_name)
                .ok_or_else(|| anyhow::anyhow!("connect requires --udp-target or --tun-name"))?;
            Box::pin(client.connect(&cfg, hops, region.as_deref(), deposit, mode)).await
        }
        Cmd::Settle { op } => commands::run_settle(&client, op).await,
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
            tailnet_id: _,
            circle_id: _,
            max_pay: _,
            no_show,
            bytes_used,
            udp_target,
            udp_bind,
            tun_name,
            onboard,
            paid_exit,
        } => {
            // Per-protocol dispatch — v3 is the only variant routed
            // through `protocol_version()` for now; v1.1 and v2 keep
            // their own connect subcommands untouched.
            match cfg.protocol_version()? {
                ProtocolVersion::V3 => {
                    let mode = forwarding_mode(udp_target, udp_bind, tun_name);
                    Box::pin(v3_runner::connect_v3(
                        &client, &cfg, bytes_used, no_show, mode, onboard, paid_exit,
                    ))
                    .await
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
        | Cmd::Payments { .. }
        | Cmd::MultiPayments { .. }
        | Cmd::StockPayments { .. }
        | Cmd::Keygen { .. }
        | Cmd::Doctor
        | Cmd::BugReport { .. }
        | Cmd::Serve { .. }
        | Cmd::Funnel { .. }
        | Cmd::OpenUrl(_)
        | Cmd::Fetch(_)
        | Cmd::Portal { .. }
        | Cmd::Onboard { .. } => unreachable!(),
    }
}

fn forwarding_mode(
    target: Option<std::net::SocketAddrV4>,
    bind: Option<std::net::SocketAddrV4>,
    name: Option<String>,
) -> Option<wireguard::Mode> {
    if let Some(name) = name {
        return Some(wireguard::Mode::Ip { name });
    }
    target.map(|target| {
        wireguard::Mode::Udp(wireguard::Forward {
            bind: bind
                .unwrap_or_else(|| std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0)),
            target,
        })
    })
}
