//! `octravpn-node` — OctraVPN endpoint daemon (v1).
//!
//! Responsibilities:
//!   1. Bond OU into the OctraVPN program (`bond_endpoint`) — required
//!      before registering. The v1 AML no longer gates on Octra-validator
//!      status; it requires the operator's in-program stake to be
//!      >= MIN_ENDPOINT_STAKE.
//!   2. Register a paid endpoint (relay or exit) on the OctraVPN program.
//!   3. Run a userspace WireGuard endpoint (boringtun) for tailnet clients.
//!   4. Track per-session bandwidth, accept signed receipts, retain the
//!      latest receipt per session for settlement / equivocation defense.
//!   5. Periodically verify operator stake is above the AML's minimum.
//!   6. On request, claim accumulated encrypted earnings (two-step:
//!      AML `claim_earnings` with FHE zero-proof + native stealth payout
//!      by the operator's wallet).

use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Parser;
use tracing::{info, warn};

mod audit;
mod chain;
mod chain_v2;
mod chain_v3;
mod config;
mod control;
mod events;
mod hub;
mod onion;
mod rate_limit;
mod seal;
mod tunnel;
mod v3_boot;
mod v3_cli;

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
    /// Deposit OU as operator stake. Required before `register`.
    /// Use `--amount` in raw OU (1 OCT = 1_000_000 OU; default min
    /// stake is 1000 OCT = 10^9 OU).
    Bond {
        #[arg(long)]
        amount: u64,
    },
    /// Begin unbonding the operator stake. Starts the grace timer;
    /// the endpoint becomes inactive immediately.
    Unbond,
    /// After the unbond grace elapses, claim the stake back.
    FinalizeUnbond,
    /// Register endpoint on chain (idempotent: skips if already
    /// registered). Caller must have at least MIN_ENDPOINT_STAKE
    /// bonded — run `bond` first.
    Register,
    /// Claim accumulated earnings. Two-step: AML verifies an FHE
    /// zero-proof and transfers plaintext OU; the operator's wallet
    /// then wraps it in a native stealth tx for unlinkable payout.
    ClaimEarnings,
    /// Submit `settle_claim(session_id, bytes_used)` for a closed
    /// session. The operator MUST submit the same bytes_used per
    /// session for life — equivocation slashes the operator bond
    /// in-AML.
    SettleClaim {
        #[arg(long)]
        session_id: u64,
        #[arg(long)]
        bytes_used: u64,
    },
    /// Print derived addresses / pubkeys without changing on-chain state.
    Identity,
    /// Add (delta_amount, delta_blind) to the local earnings accumulator.
    /// Used by reconciliation tooling that watches `SessionSettled`
    /// events and tells the node which contributions are theirs.
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
    /// P1-6: wrap the operator's on-disk wallet + WG keys under the
    /// `octra_core::wallet_enc` passphrase envelope (ChaCha20-Poly1305
    /// over a PBKDF2-derived KEK). Reads the plaintext files the
    /// current config points at, writes `<path>.sealed` versions atomically
    /// (tempfile + rename + fsync), and optionally unlinks the plaintext
    /// source. Idempotent: re-running on already-sealed destinations
    /// is a no-op so an operator can safely include this in a
    /// post-deploy script. Passphrase resolution order:
    /// `--passphrase` > `--passphrase-file` > `--passphrase-stdin` >
    /// `OCTRAVPN_KEY_PASSPHRASE` env > TTY prompt (if stdin is a tty).
    /// See `docs/v2-operator-key-hygiene.md` for the recommended
    /// passphrase storage workflow per OS.
    SealKeys {
        /// Pass the passphrase inline. Warns about shell history.
        #[arg(long)]
        passphrase: Option<String>,
        /// Path to a file whose first line is the passphrase. Ideal
        /// for ops platforms that mount secrets via tmpfs.
        #[arg(long)]
        passphrase_file: Option<std::path::PathBuf>,
        /// Read the passphrase as one line from stdin (for `echo $PP
        /// | octravpn-node seal-keys --passphrase-stdin`).
        #[arg(long)]
        passphrase_stdin: bool,
        /// Delete the plaintext source files after a successful seal.
        /// Off by default — operators should verify the sealed file
        /// reads back before unlinking. Combine with `--rotate` once
        /// confident.
        #[arg(long)]
        remove_plaintext: bool,
    },
    /// P1-6: reverse `seal-keys` onto a tmpfs/ramfs path for emergency
    /// rotation or one-shot recovery. The destination MUST live on a
    /// memory-volatile filesystem (Linux: tmpfs/ramfs/devtmpfs;
    /// macOS: under `/private/tmp`); the command refuses to write
    /// elsewhere. Passphrase resolution mirrors `seal-keys`.
    UnsealKeys {
        /// Directory on a tmpfs/ramfs mount where the unsealed
        /// `wallet.key` and `wg.key` files will be written.
        #[arg(long)]
        tmpdir: std::path::PathBuf,
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        passphrase_file: Option<std::path::PathBuf>,
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// v3 chain-minimal entrypoints. Every non-boot v3 method exposed
    /// by `program/main-v3.aml` is reachable here as a subcommand:
    /// bond / unbond / finalize / slash / rotate / retire-circle,
    /// tailnet create / update / retire / deposit / withdraw, session
    /// open / settle-claim / settle-confirm / claim-no-show / sweep,
    /// and claim-earnings. The boot flow (`register_circle` /
    /// `update_circle_state`) still goes through `register` / `run`.
    V3 {
        #[command(subcommand)]
        cmd: v3_cli::V3Cmd,
    },
    /// Mesh / Tailscale-interop control surface. Subcommands here
    /// are exercised by `docker/devnet/tailscale-interop/run-interop.sh`
    /// and by operators provisioning new tailnet members. See
    /// `docs/tailscale-interop-blocker.md` for the gap between
    /// "we mint a preauth key" and "stock `tailscale up` completes a
    /// handshake against us."
    Mesh {
        #[command(subcommand)]
        sub: MeshCmd,
    },
}

#[derive(Parser, Debug)]
enum MeshCmd {
    /// Mint a fresh preauth key. Writes the key to stdout as a single
    /// line — easy to consume from a shell harness:
    ///
    ///   KEY=$(octravpn-node mesh mint-preauth --user alice)
    ///   tailscale up --login-server http://… --authkey "$KEY"
    ///
    /// The key is generated locally (no daemon contact) and is
    /// suitable for emitting to an operator. Cross-process binding
    /// (so a running daemon's coordination plane would accept the
    /// key) requires the persistent minter from
    /// `docs/tailscale-interop-blocker.md`; until that lands, this
    /// subcommand is fine for satisfying the interop test's "is the
    /// preauth surface reachable" probe but cannot, on its own,
    /// authorise a real tailscale join.
    MintPreauth {
        /// User label to bind the minted key to.
        #[arg(long, default_value = "default")]
        user: String,
        /// Mark the key as reusable (off by default — matches
        /// Tailscale's safer single-use default).
        #[arg(long)]
        reusable: bool,
        /// TTL in seconds. Defaults to `DEFAULT_PREAUTH_TTL` (1 h).
        #[arg(long)]
        ttl_secs: Option<u64>,
    },
    /// Run a minimal Tailscale-wire control plane (no chain / wallet
    /// dependencies). Used by the
    /// `docker/devnet/tailscale-interop/run-interop.sh` harness so a
    /// stock `tailscale up` can `GET /key`, `POST /machine/.../register`,
    /// `POST /machine/.../map` without bringing up the full Hub.
    ///
    /// Mounts in one process:
    ///   - `GET /key` + `POST /machine/.../register` + `POST /machine/.../map`
    ///     (the Tailscale-wire surface — `tailscale_wire_router`).
    ///   - `POST /admin/preauth` for minting keys over HTTP (bearer
    ///     token from `--admin-token` or `OCTRAVPN_ADMIN_TOKEN`).
    ///
    /// Both surfaces share one `PreauthMinter` so a key minted over
    /// HTTP is immediately redeemable through `register`.
    Serve {
        /// `host:port` to listen on. Defaults to `0.0.0.0:51821`.
        #[arg(long, default_value = "0.0.0.0:51821")]
        listen: String,
        /// Directory for the Noise long-term static key + future wire
        /// state. Defaults to `./state/tailscale-wire`.
        #[arg(long, default_value = "./state/tailscale-wire")]
        state_dir: String,
        /// Tailnet identifier (drives the IP allocator).
        #[arg(long, default_value = "octravpn-interop")]
        tailnet_id: String,
        /// Bearer token for `/admin/preauth`. Falls back to the
        /// `OCTRAVPN_ADMIN_TOKEN` env var when unset.
        #[arg(long)]
        admin_token: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    octravpn_core::util::init_tracing("info,octravpn_node=debug");

    let Cli { config, cmd } = Cli::parse();

    // Subcommands that do NOT need a Hub. Seal / unseal wrap the wallet
    // + wg keys (Hub::new would try to read them); v3 only needs a
    // ChainCtxV3 (RPC + program addr + wallet) that the v3_cli
    // dispatcher builds itself. Handle these first so we can short-
    // circuit before the Hub boot path.
    match cmd {
        Cmd::SealKeys {
            passphrase,
            passphrase_file,
            passphrase_stdin,
            remove_plaintext,
        } => {
            let cfg = NodeConfig::load(&config)?;
            return run_seal_keys(
                &cfg,
                passphrase.as_deref(),
                passphrase_file.as_deref(),
                passphrase_stdin,
                remove_plaintext,
            );
        }
        Cmd::UnsealKeys {
            tmpdir,
            passphrase,
            passphrase_file,
            passphrase_stdin,
        } => {
            let cfg = NodeConfig::load(&config)?;
            return run_unseal_keys(
                &cfg,
                &tmpdir,
                passphrase.as_deref(),
                passphrase_file.as_deref(),
                passphrase_stdin,
            );
        }
        Cmd::V3 { cmd: v3cmd } => {
            return v3_cli::dispatch(std::path::Path::new(&config), v3cmd).await;
        }
        // Mesh subcommands operate on the headscale-bridge surface and
        // do not need wallet/chain state. Dispatch before `Hub::new`
        // so the harness can mint a preauth key without a configured
        // RPC endpoint.
        Cmd::Mesh { sub } => {
            return run_mesh_cmd(sub).await;
        }
        // Everything else needs the Hub: dispatch below.
        rest => {
            let cfg = NodeConfig::load(&config)?;
            let hub = Arc::new(Hub::new(cfg).await?);
            return match rest {
                Cmd::Identity => {
                    hub.print_identity();
                    Ok(())
                }
                Cmd::Bond { amount } => hub.bond_endpoint(amount).await,
                Cmd::Unbond => hub.unbond_endpoint().await,
                Cmd::FinalizeUnbond => hub.finalize_unbond().await,
                Cmd::Register => hub.register_endpoint().await,
                Cmd::ClaimEarnings => hub.claim_earnings().await,
                Cmd::SettleClaim {
                    session_id,
                    bytes_used,
                } => hub.settle_claim(session_id, bytes_used).await,
                Cmd::AccumulatorAdd {
                    delta_amount,
                    delta_blind_hex,
                } => hub.accumulator_add(delta_amount, &delta_blind_hex),
                Cmd::VerifyAuditLog { path } => verify_audit_log(&hub, &path),
                Cmd::Run => run(hub).await,
                Cmd::SealKeys { .. }
                | Cmd::UnsealKeys { .. }
                | Cmd::V3 { .. }
                | Cmd::Mesh { .. } => {
                    // Handled above the Hub::new boundary.
                    unreachable!(
                        "seal-keys / unseal-keys / v3 / mesh dispatched pre-Hub::new"
                    )
                }
            };
        }
    }
}

/// Dispatch a `mesh …` subcommand. Lives outside `main` so future
/// subcommands (e.g. `mesh acl push`, `mesh peers list`) can drop in
/// next to `MintPreauth` without expanding the giant top-level match.
/// Returns `Result<()>` (rather than `()`) so future subcommands that
/// *do* fail (chain-touching ones) can `?`-propagate without a
/// signature change. The current single arm is infallible — clippy
/// allow is intentional.
#[allow(clippy::unnecessary_wraps)]
async fn run_mesh_cmd(sub: MeshCmd) -> Result<()> {
    match sub {
        MeshCmd::MintPreauth {
            user,
            reusable,
            ttl_secs,
        } => {
            use octravpn_mesh::{PreauthMinter, DEFAULT_PREAUTH_TTL};
            let ttl = ttl_secs
                .map(std::time::Duration::from_secs)
                .unwrap_or(DEFAULT_PREAUTH_TTL);
            let minter = PreauthMinter::new();
            let pk = minter.mint(&user, ttl, reusable);
            // Single-line stdout output so the harness can capture
            // with `KEY=$(octravpn-node mesh mint-preauth --user u)`.
            // Everything else (user, expiry) goes to stderr so it
            // doesn't pollute the captured value.
            eprintln!(
                "minted preauth: user={} reusable={} expires_at={}",
                pk.user, pk.reusable, pk.expires_at
            );
            println!("{}", pk.key);
            Ok(())
        }
        MeshCmd::Serve {
            listen,
            state_dir,
            tailnet_id,
            admin_token,
        } => run_mesh_serve(listen, state_dir, tailnet_id, admin_token).await,
    }
}

/// Hub-free wire surface entry point. See `MeshCmd::Serve` for the
/// rationale.
async fn run_mesh_serve(
    listen: String,
    state_dir: String,
    tailnet_id: String,
    admin_token: Option<String>,
) -> Result<()> {
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
        Json, Router,
    };
    use octravpn_mesh::{
        ip_alloc::TailnetIpAllocator, tailscale_wire::MachineRegistry, tailscale_wire_router,
        PreauthMinter, ServerNoiseKey, WireState, DEFAULT_PREAUTH_TTL,
    };
    use serde::{Deserialize, Serialize};
    use std::{net::SocketAddr, sync::Arc};

    // Admin token resolution: explicit > env > absent.
    let admin_token = admin_token.or_else(|| std::env::var("OCTRAVPN_ADMIN_TOKEN").ok());

    let server_noise_key = Arc::new(
        ServerNoiseKey::load_or_generate(&state_dir)
            .context("load tailscale_wire noise static key")?,
    );
    let minter = PreauthMinter::new();
    let ws = WireState {
        server_noise_key: server_noise_key.clone(),
        preauth: minter.clone(),
        ip_allocator: Arc::new(TailnetIpAllocator::new(tailnet_id)),
        machines: Arc::new(MachineRegistry::new()),
    };

    eprintln!(
        "mesh serve: noise pubkey mkey:{} listen={listen}",
        server_noise_key.public_hex()
    );

    // /admin/preauth shim for the harness. Kept identical to the
    // ControlState handler's behaviour (404 when no token, 404 on
    // wrong token, 200+JSON on success) so the run-interop.sh probe
    // succeeds.
    #[derive(Clone)]
    struct AdminCtx {
        minter: PreauthMinter,
        token: Option<Arc<str>>,
    }
    #[derive(Deserialize, Default)]
    #[serde(rename_all = "snake_case")]
    struct AdminReq {
        #[serde(default = "default_user")]
        user: String,
        #[serde(default)]
        reusable: bool,
    }
    fn default_user() -> String {
        "default".into()
    }
    #[derive(Serialize)]
    struct AdminResp {
        key: String,
        user: String,
        expires_at: u64,
        reusable: bool,
    }
    async fn mint_handler(
        State(ctx): State<AdminCtx>,
        headers: HeaderMap,
        body: Option<Json<AdminReq>>,
    ) -> impl IntoResponse {
        let Some(want) = ctx.token.as_deref() else {
            return (StatusCode::NOT_FOUND, "").into_response();
        };
        let got = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "));
        let authed = got.is_some_and(|t| t == want);
        if !authed {
            return (StatusCode::NOT_FOUND, "").into_response();
        }
        let req = body.map(|Json(b)| b).unwrap_or_default();
        let pk = ctx.minter.mint(req.user, DEFAULT_PREAUTH_TTL, req.reusable);
        Json(AdminResp {
            key: pk.key,
            user: pk.user,
            expires_at: pk.expires_at,
            reusable: pk.reusable,
        })
        .into_response()
    }
    let admin_ctx = AdminCtx {
        minter,
        token: admin_token.map(Arc::from),
    };
    let admin_router = Router::new()
        .route("/admin/preauth", post(mint_handler))
        .with_state(admin_ctx);

    let app = admin_router.merge(tailscale_wire_router(ws));
    let addr: SocketAddr = listen.parse().context("parse listen addr")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("mesh serve: listening on {addr}");
    axum::serve(listener, app)
        .await
        .context("mesh serve: axum::serve")?;
    Ok(())
}

fn run_seal_keys(
    cfg: &NodeConfig,
    explicit: Option<&str>,
    file: Option<&std::path::Path>,
    from_stdin: bool,
    remove_plaintext: bool,
) -> Result<()> {
    let mut pp = seal::resolve_passphrase(explicit, file, from_stdin)?;
    let targets = seal::targets_from_config(cfg);
    let mut n_sealed = 0_u32;
    for t in &targets {
        match seal::seal_one(t, &pp) {
            Ok(true) => {
                n_sealed += 1;
                println!("sealed {} → {}", t.src.display(), t.dst.display());
            }
            Ok(false) => {
                println!(
                    "skipped {} (already sealed at {})",
                    t.label,
                    t.dst.display()
                );
            }
            Err(e) => {
                // Best-effort wipe of the passphrase before bailing
                // out so we don't leave it sitting in the heap
                // alongside the error message.
                use zeroize::Zeroize;
                pp.zeroize();
                return Err(e);
            }
        }
    }
    if remove_plaintext {
        for t in &targets {
            if t.dst.exists() && t.src.exists() {
                std::fs::remove_file(&t.src)
                    .with_context(|| format!("remove plaintext {}", t.src.display()))?;
                println!("removed plaintext {}", t.src.display());
            }
        }
    }
    use zeroize::Zeroize;
    pp.zeroize();
    println!(
        "seal-keys: {n_sealed} newly sealed, {} total target(s); plaintext {}",
        targets.len(),
        if remove_plaintext { "removed" } else { "kept" }
    );
    Ok(())
}

fn run_unseal_keys(
    cfg: &NodeConfig,
    tmpdir: &std::path::Path,
    explicit: Option<&str>,
    file: Option<&std::path::Path>,
    from_stdin: bool,
) -> Result<()> {
    // Refuse to write plaintext anywhere that's not a memory-volatile
    // mount. This is best-effort but it catches the obvious mistake of
    // pointing the dir at $HOME.
    std::fs::create_dir_all(tmpdir)
        .with_context(|| format!("mkdir {}", tmpdir.display()))?;
    seal::check_tmpfs(tmpdir)?;
    let mut pp = seal::resolve_passphrase(explicit, file, from_stdin)?;
    let sealed_targets = seal::targets_from_config(cfg);
    for orig in &sealed_targets {
        // Source is the .sealed file; destination is in the tmpdir.
        let src = orig.dst.clone();
        let dst = tmpdir.join(
            orig.src
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new(orig.label)),
        );
        let t = seal::SealTarget {
            label: orig.label,
            src,
            dst: dst.clone(),
        };
        if let Err(e) = seal::unseal_one(&t, &pp) {
            use zeroize::Zeroize;
            pp.zeroize();
            return Err(e);
        }
        println!("unsealed {} → {}", t.src.display(), t.dst.display());
    }
    use zeroize::Zeroize;
    pp.zeroize();
    println!(
        "unseal-keys: wrote {} plaintext key(s) under {}",
        sealed_targets.len(),
        tmpdir.display()
    );
    Ok(())
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
