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
}

#[tokio::main]
async fn main() -> Result<()> {
    octravpn_core::util::init_tracing("info,octravpn_node=debug");

    let cli = Cli::parse();

    // Seal / unseal subcommands must NOT call `Hub::new`: Hub's
    // constructor reads the wallet + wg keys, which is precisely what
    // we're about to wrap. Dispatch them on the config (paths only)
    // without instantiating a hub.
    match cli.cmd {
        Cmd::SealKeys {
            ref passphrase,
            ref passphrase_file,
            passphrase_stdin,
            remove_plaintext,
        } => {
            let cfg = NodeConfig::load(&cli.config)?;
            return run_seal_keys(
                &cfg,
                passphrase.as_deref(),
                passphrase_file.as_deref(),
                passphrase_stdin,
                remove_plaintext,
            );
        }
        Cmd::UnsealKeys {
            ref tmpdir,
            ref passphrase,
            ref passphrase_file,
            passphrase_stdin,
        } => {
            let cfg = NodeConfig::load(&cli.config)?;
            return run_unseal_keys(
                &cfg,
                tmpdir,
                passphrase.as_deref(),
                passphrase_file.as_deref(),
                passphrase_stdin,
            );
        }
        _ => {}
    }

    let cfg = NodeConfig::load(&cli.config)?;
    let hub = Arc::new(Hub::new(cfg).await?);

    match cli.cmd {
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
        Cmd::SealKeys { .. } | Cmd::UnsealKeys { .. } => {
            // Handled above the Hub::new boundary; the early-return
            // matches ensure we never reach here.
            unreachable!("seal-keys / unseal-keys dispatched pre-Hub::new")
        }
    }
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
