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
mod audit_cli;
mod chain;
mod chain_v2;
mod chain_v3;
mod circle_update;
mod cli_ops;
mod config;
mod control;
mod events;
mod hub;
mod mesh_ops;
mod onion;
mod pvac;
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
    ///
    /// Deprecated alias for `audit verify --audit-path <path>`; kept
    /// so existing operator runbooks keep working.
    VerifyAuditLog {
        /// Path to the audit JSONL file to verify.
        path: std::path::PathBuf,
    },
    /// Operator-facing audit tooling: pretty-print the audit log +
    /// receipt journal as a timeline, or run a full crypto
    /// verification. The artifacts inspected here are the same files
    /// the daemon writes during normal operation.
    Audit {
        #[command(subcommand)]
        cmd: audit_cli::AuditCmd,
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
    /// Circle-asset CRUD: atomic update primitive for sealed circle
    /// assets. The `update` subcommand drives
    /// `circle_asset_put_encrypted` + `update_circle_state` in the
    /// correct order so a partial failure leaves chain state on the
    /// OLD anchor (old blobs still bound). See
    /// `docs/v2-operator-key-hygiene.md §5` for the operator-facing
    /// rotation runbook and `crates/octravpn-node/src/circle_update.rs`
    /// for the atomicity contract.
    Circle {
        #[command(subcommand)]
        cmd: CircleCmd,
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
    /// Embedded `headscale` admin CLI surface. Every subcommand the
    /// standalone `headscale` binary's admin surface supports is
    /// reachable here verbatim. `octravpn-node headscale users list`
    /// is byte-identical to `headscale users list` — same `--server`,
    /// `--token`, `--json` flags, same stdout, same stderr `error: …`
    /// envelope, same exit-code contract (0/3/4/5/6 — see
    /// `headscale_cli::admin::ExitCode`).
    ///
    /// Why: operators used to need two binaries (`octravpn-node` +
    /// `headscale`) plus juggle bearer tokens between them. With this
    /// surface folded in, the install footprint drops to one binary.
    /// The standalone `headscale` binary is still built/published by
    /// headscale-rs for shops that only need the admin surface (e.g.
    /// Tailscale-compat operators not running the OctraVPN node).
    ///
    /// Replaces the duplicated `mesh status` + `mesh policy {get,set,
    /// validate}` subcommands (those are now deprecated — see
    /// `docs/operators/cli-migration.md`).
    Headscale {
        /// Shared connection flags (`--server`, `--token`, `--json`)
        /// — flattened so the same CLI shape as the standalone binary
        /// works. `HEADSCALE_URL` / `HEADSCALE_ADMIN_TOKEN` env-var
        /// fallbacks are preserved.
        #[command(flatten)]
        connect: headscale_cli::ConnectArgs,
        #[command(subcommand)]
        cmd: headscale_cli::AdminCmd,
    },
    /// #232: schema-check + key + RPC + program reachability against a
    /// `node.toml`. Replaces the manual `octra cast rpc node_status`
    /// + `octra cast call $PROG get_params` smoke probe + ad-hoc TOML
    /// diffing dance from `docs/deployment-runbook.md` §1.
    Config {
        #[command(subcommand)]
        cmd: cli_ops::ConfigCmd,
    },
    /// #232: one-shot operator health probe. Reads on-chain stake /
    /// slashed / unbonding state, validates local audit log + receipt
    /// journal are openable, and (when `--remote` is set) hits the
    /// running daemon's `GET /health`. Replaces the manual `octra
    /// cast call` triple and `curl … | jq` step from the runbook §7.1
    /// + §2.
    Health(cli_ops::HealthArgs),
    /// #232: live-tail the audit log with per-line HMAC verification.
    /// `--follow` keeps reading appended lines (similar to `tail -F`);
    /// without `--follow` it prints existing lines and exits. A chain
    /// break interrupts output with a clear marker and a non-zero exit
    /// code so cron pipelines surface tampering immediately.
    AuditTail(cli_ops::AuditTailArgs),
    /// #232: report the receipt-journal floor for a session id plus
    /// every audit-log entry that names the same session. Cross-checks
    /// the P1-8/9 invariant (no signed seq above the journal floor).
    /// Useful as a quick forensic probe after an alert.
    ReceiptVerify(cli_ops::ReceiptVerifyArgs),
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
        /// `host:port` to listen on for plain HTTP. Defaults to
        /// `127.0.0.1:51821`; set an explicit public address for
        /// docker interop harnesses or remote clients.
        #[arg(long, default_value = "127.0.0.1:51821")]
        listen: String,
        /// `host:port` for the rustls-terminated HTTPS listener. Stock
        /// `tailscale up` v1.78+ forces a parallel HTTPS-on-443 dial
        /// after its initial /key probe; absent a TLS terminator the
        /// flow stalls before reaching `/machine/register`. Pass the
        /// empty string to disable (useful for hosts that can't bind
        /// :443).
        #[arg(long, default_value = "")]
        https_listen: String,
        /// SAN hostname embedded in the self-signed cert. Should match
        /// whatever the client resolves the login-server to (typically
        /// the docker service name, e.g. `tsi-mesh-control`).
        #[arg(long, default_value = "localhost")]
        cert_hostname: String,
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
    /// Wrap `GET /api/v1/machines` on the remote mesh-control admin
    /// surface — prints the current tailnet roster. Same auth posture
    /// as `mesh serve`'s `--admin-token` (bearer-gated).
    ///
    /// Equivalent to `headscale nodes list` from the sibling repo's
    /// CLI, but bound to octravpn-node so operators don't need the
    /// sibling repo installed.
    Status(mesh_ops::MeshStatusArgs),
    /// Wrap the `/api/v1/policy{,/validate}` admin CRUD surface.
    /// Subcommands:
    ///
    ///   * `get` — fetch the live hujson policy (optionally to file).
    ///   * `set --file <doc>` — PUT a new policy; takes effect within
    ///     ~1ms (the policy store's `Notify` wakes parked `/map`
    ///     long-pollers).
    ///   * `validate --file <doc>` — parse-only validation; never
    ///     mutates the live store.
    Policy {
        #[command(subcommand)]
        cmd: mesh_ops::MeshPolicyCmd,
    },
}

/// Circle-asset subcommands.
#[derive(clap::Subcommand, Debug)]
enum CircleCmd {
    /// Atomic update of one or more sealed circle assets + their
    /// state-root anchor. Blobs are written first; the anchor flip is
    /// the last tx. A failure between the two leaves chain state on
    /// the OLD anchor (old blobs still bound, new blobs are orphans
    /// recoverable via `retry-anchor`).
    Update(CircleUpdateArgs),
    /// Diagnostic: probe known sealed-asset paths and report any whose
    /// plaintext hash is not bound by the current on-chain anchor.
    ListOrphans(CircleListOrphansArgs),
    /// Re-submit only the `update_circle_state` tx with a pre-computed
    /// anchor. Used after an interrupted `update`.
    RetryAnchor(CircleRetryAnchorArgs),
}

#[derive(clap::Args, Debug)]
struct CircleUpdateArgs {
    /// Operator-circle id this update targets.
    #[arg(long)]
    circle: String,
    /// Sealed-asset passphrase. Falls back to
    /// `OCTRAVPN_SEALED_PASSPHRASE` env var when omitted.
    #[arg(long)]
    passphrase: Option<String>,
    /// Blob spec: `<asset_path>:<file>:<key_id>:<padding>`. Repeatable.
    /// `padding` is one of `none|4k|16k|32k|128k`.
    /// Example: `--blob /policy.json:./policy.json:default:4k`.
    #[arg(long = "blob")]
    blobs: Vec<String>,
    /// Override `state_root.region`.
    #[arg(long)]
    set_region: Option<String>,
    /// Override `state_root.member_count`.
    #[arg(long)]
    set_member_count: Option<u64>,
    /// Force `state_root.policy_hash` to a specific 64-char hex digest.
    #[arg(long)]
    set_policy_hash: Option<String>,
    /// Force `state_root.wg_pubkey_hash`.
    #[arg(long)]
    set_wg_pubkey_hash: Option<String>,
    /// Force `state_root.attestation_hash`. Empty string clears it.
    #[arg(long)]
    set_attestation_hash: Option<String>,
    /// Default ON: describe txs without broadcasting.
    #[arg(long, default_value_t = true)]
    dry_run: bool,
    /// Explicit opposite of `--dry-run`.
    #[arg(long, conflicts_with = "dry_run")]
    commit: bool,
}

#[derive(clap::Args, Debug)]
struct CircleListOrphansArgs {
    #[arg(long)]
    circle: String,
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(clap::Args, Debug)]
struct CircleRetryAnchorArgs {
    #[arg(long)]
    circle: String,
    /// 64-char hex anchor to commit.
    #[arg(long)]
    anchor: String,
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
        Cmd::Circle { cmd: circle_cmd } => {
            return run_circle_cmd(std::path::Path::new(&config), circle_cmd).await;
        }
        // Mesh subcommands operate on the headscale-bridge surface and
        // do not need wallet/chain state. Dispatch before `Hub::new`
        // so the harness can mint a preauth key without a configured
        // RPC endpoint.
        Cmd::Mesh { sub } => {
            return run_mesh_cmd(sub).await;
        }
        // Embedded `headscale` admin CLI: pure HTTP client surface, no
        // wallet / chain / Hub state. Dispatch pre-`Hub::new` so an
        // operator can drive a remote mesh-control against any
        // `node.toml` (even an offline one). `headscale_cli::dispatch`
        // returns a process exit code matching the standalone binary's
        // contract (0 / 3 / 4 / 5 / 6); exit directly so the contract
        // reaches the operator's shell.
        Cmd::Headscale { connect, cmd: hs_cmd } => {
            let code = headscale_cli::dispatch(connect, hs_cmd).await;
            std::process::exit(code);
        }
        // Audit is a pure local-file inspector — no wallet, no chain,
        // no Hub. Dispatch before `Hub::new` so an operator can run
        // it on a backup of state/ without a working `node.toml`.
        Cmd::Audit { cmd: audit_cmd } => {
            let code = audit_cli::dispatch(audit_cmd);
            // Exit directly so the structured exit codes (1/2/3) reach
            // the operator's shell. Returning `Ok(())` here would
            // collapse to 0 regardless of the verify result.
            std::process::exit(code);
        }
        // #232: new operator-facing surfaces. None of them need the
        // Hub — `config validate` and `health` build their own short-
        // lived `RpcClient`; `audit-tail` and `receipt-verify` are
        // pure local-file inspectors (same shape as `audit`). Dispatch
        // pre-Hub so an operator can run them against a `node.toml`
        // whose daemon is offline (incident response shape).
        Cmd::Config { cmd: cfg_cmd } => {
            let code = cli_ops::run_config(cfg_cmd)?;
            std::process::exit(code);
        }
        Cmd::Health(args) => {
            let code = cli_ops::run_health(args)?;
            std::process::exit(code);
        }
        Cmd::AuditTail(args) => {
            let code = cli_ops::run_audit_tail(args)?;
            std::process::exit(code);
        }
        Cmd::ReceiptVerify(args) => {
            let code = cli_ops::run_receipt_verify(args)?;
            std::process::exit(code);
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
                | Cmd::Circle { .. }
                | Cmd::Mesh { .. }
                | Cmd::Headscale { .. }
                | Cmd::Audit { .. }
                | Cmd::Config { .. }
                | Cmd::Health(_)
                | Cmd::AuditTail(_)
                | Cmd::ReceiptVerify(_) => {
                    // Handled above the Hub::new boundary.
                    unreachable!(
                        "seal-keys / unseal-keys / v3 / circle / mesh / headscale / audit / config / health / audit-tail / receipt-verify dispatched pre-Hub::new"
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
            let ttl = ttl_secs.map_or(DEFAULT_PREAUTH_TTL, std::time::Duration::from_secs);
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
            https_listen,
            cert_hostname,
            state_dir,
            tailnet_id,
            admin_token,
        } => {
            run_mesh_serve(
                listen,
                https_listen,
                cert_hostname,
                state_dir,
                tailnet_id,
                admin_token,
            )
            .await
        }
        // Remote control surface. Sync entry points (each builds its
        // own current-thread runtime) — exit codes propagate via
        // `std::process::exit` so a non-zero remote response surfaces
        // to the operator's shell.
        //
        // DEPRECATED: scheduled for removal 2026-Q3. Use
        // `octravpn-node headscale nodes list` /
        // `octravpn-node headscale policy {get,set,check}` — same
        // backend, byte-identical output. The warning is printed
        // unconditionally to stderr so cron / harness scripts surface
        // the migration TODO; stdout remains untouched for byte-diff
        // compatibility with the pre-deprecation contract. See
        // `docs/operators/cli-migration.md`.
        MeshCmd::Status(args) => {
            eprintln!(
                "WARN: 'octravpn-node mesh status' is deprecated; use \
                 'octravpn-node headscale nodes list' instead \
                 (removal scheduled 2026-Q3)"
            );
            let code = mesh_ops::run_status(args).await?;
            std::process::exit(code);
        }
        MeshCmd::Policy { cmd } => {
            eprintln!(
                "WARN: 'octravpn-node mesh policy' is deprecated; use \
                 'octravpn-node headscale policy {{get|set|check}}' instead \
                 (removal scheduled 2026-Q3)"
            );
            let code = mesh_ops::run_policy(cmd).await?;
            std::process::exit(code);
        }
    }
}

/// Dispatch a `circle …` subcommand. Builds a short-lived
/// `ChainCtxV3` (no Hub) the same way the v3 CLI does. On
/// `UpdateError::AnchorUpdateFailed` we surface the target anchor +
/// recovery hint so the operator can re-run
/// `circle retry-anchor --anchor <hex>`.
async fn run_circle_cmd(cfg_path: &std::path::Path, cmd: CircleCmd) -> Result<()> {
    use circle_update::{
        apply, list_orphaned_blobs, retry_anchor, AnchorOverrides, UpdateBundle, UpdateError,
    };

    let cfg = NodeConfig::load(cfg_path)?;
    let ctx = v3_cli::build_chain_ctx_for_circle(&cfg)?;

    match cmd {
        CircleCmd::Update(args) => {
            let dry_run = args.dry_run && !args.commit;
            let creds = resolve_sealed_passphrase(args.passphrase.as_deref())?;
            let blobs = parse_blob_specs(&args.blobs)?;
            let anchor_overrides = AnchorOverrides {
                policy_hash: args.set_policy_hash.clone(),
                members_hash: None,
                wg_pubkey_hash: args.set_wg_pubkey_hash.clone(),
                attestation_hash: args.set_attestation_hash.map(|s| {
                    if s.is_empty() {
                        None
                    } else {
                        Some(s)
                    }
                }),
                region: args.set_region.clone(),
                member_count: args.set_member_count,
            };
            let bundle = UpdateBundle {
                circle_id: args.circle.clone(),
                blobs,
                anchor_overrides,
            };

            if dry_run {
                println!("circle update dry-run for {}", &args.circle);
                println!("  blobs: {}", bundle.blobs.len());
                for b in &bundle.blobs {
                    println!(
                        "    - {} key_id={} padding={} plaintext_sha256={}",
                        b.asset_path,
                        b.key_id,
                        b.padding_class.as_str(),
                        b.plaintext_hash_hex()
                    );
                }
                let current = circle_update::fetch_current_state_root(&ctx, &args.circle)
                    .await
                    .with_context(|| {
                        format!("dry-run: fetch current state-root for {}", &args.circle)
                    })?;
                match current {
                    Some(c) => {
                        let target = circle_update::compute_target_state_root(&c, &bundle)
                            .map_err(|e| anyhow::anyhow!("compute target state-root: {e}"))?;
                        let anchor = target
                            .anchor_hex()
                            .map_err(|e| anyhow::anyhow!("compute target anchor: {e}"))?;
                        println!("  current_anchor: {}", c.anchor_hex().unwrap_or_default());
                        println!("  target_anchor:  {anchor}");
                    }
                    None => {
                        println!("  current_anchor: <none — circle not yet registered>");
                    }
                }
                println!(
                    "  would submit: {} blob put(s) + 1 update_circle_state + 1 state-root.json put",
                    bundle.blobs.len()
                );
                println!("(dry-run; pass --commit to broadcast)");
                return Ok(());
            }

            match apply(&ctx, &creds, bundle).await {
                Ok(res) => {
                    println!("circle update: new_anchor = {}", res.new_anchor_hex);
                    for h in &res.blob_tx_hashes {
                        println!("  blob_tx: {h}");
                    }
                    if let Some(h) = &res.anchor_tx_hash {
                        println!("  anchor_tx: {h}");
                    }
                    Ok(())
                }
                Err(UpdateError::AnchorUpdateFailed {
                    target_anchor_hex,
                    blob_tx_hashes,
                    source,
                }) => {
                    eprintln!(
                        "anchor flip failed; blobs are committed. \
                         Re-run with: octravpn-node circle retry-anchor \
                         --circle {} --anchor {}",
                        &args.circle, target_anchor_hex
                    );
                    for h in &blob_tx_hashes {
                        eprintln!("  blob_tx (committed): {h}");
                    }
                    Err(anyhow::anyhow!(source))
                }
                Err(e) => Err(anyhow::anyhow!(e)),
            }
        }
        CircleCmd::ListOrphans(args) => {
            let creds = resolve_sealed_passphrase(args.passphrase.as_deref())?;
            let current = circle_update::fetch_current_state_root(&ctx, &args.circle)
                .await?
                .ok_or_else(|| anyhow::anyhow!("circle {} has no on-chain anchor", &args.circle))?;
            let orphans = list_orphaned_blobs(&ctx, &args.circle, &current, &creds).await?;
            if orphans.is_empty() {
                println!("no orphaned blobs detected");
            } else {
                println!("orphaned blob paths (not bound by current anchor):");
                for p in &orphans {
                    println!("  {p}");
                }
            }
            Ok(())
        }
        CircleCmd::RetryAnchor(args) => {
            let hash = retry_anchor(&ctx, &args.circle, &args.anchor).await?;
            println!("anchor re-committed: tx_hash = {hash}");
            Ok(())
        }
    }
}

/// Parse the `--blob <asset_path>:<file>:<key_id>:<padding>` spec.
fn parse_blob_specs(raw: &[String]) -> Result<Vec<circle_update::BlobUpdate>> {
    use octravpn_core::circle::PaddingClass;

    let mut out = Vec::with_capacity(raw.len());
    for spec in raw {
        let parts: Vec<&str> = spec.splitn(4, ':').collect();
        if parts.len() != 4 {
            anyhow::bail!(
                "blob spec must be <asset_path>:<file>:<key_id>:<padding>; got {spec:?}"
            );
        }
        let plaintext = std::fs::read(parts[1])
            .with_context(|| format!("read blob plaintext {}", parts[1]))?;
        let padding = PaddingClass::from_str_opt(parts[3])
            .ok_or_else(|| anyhow::anyhow!("unknown padding class {:?}", parts[3]))?;
        out.push(circle_update::BlobUpdate {
            asset_path: parts[0].to_string(),
            plaintext,
            key_id: parts[2].to_string(),
            padding_class: padding,
        });
    }
    Ok(out)
}

/// Resolve the sealed-asset passphrase: CLI value, then
/// `OCTRAVPN_SEALED_PASSPHRASE` env var, then error.
fn resolve_sealed_passphrase(
    explicit: Option<&str>,
) -> Result<circle_update::SealedAssetCreds> {
    if let Some(p) = explicit {
        return Ok(circle_update::SealedAssetCreds::new(p));
    }
    if let Ok(p) = std::env::var("OCTRAVPN_SEALED_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(circle_update::SealedAssetCreds::new(p));
        }
    }
    anyhow::bail!(
        "no sealed-asset passphrase: pass --passphrase or set \
         OCTRAVPN_SEALED_PASSPHRASE"
    )
}

/// Hub-free wire surface entry point. See `MeshCmd::Serve` for the
/// rationale.
async fn run_mesh_serve(
    listen: String,
    https_listen: String,
    cert_hostname: String,
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
        ip_alloc::TailnetIpAllocator,
        tailscale_wire::{
            derp_config::{empty_derp_map, load_derp_map},
            serve::{serve as wire_serve, ServeConfig},
            tls::SanConfig,
            MachineRegistry,
        },
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
    // Wall 6: optional DERP-map fixture for the interop harness. The
    // env var points at a JSON file in the same shape as the on-wire
    // `DerpMap`. Unset (the production default) ⇒ empty map ⇒ same
    // behaviour as pre-Wall-6. See
    // `docs/tailscale-interop-blocker.md` 2026-05-19 §"Wall 6 closed".
    let derp_map = match std::env::var("OCTRAVPN_DERP_MAP_PATH") {
        Ok(path) if !path.is_empty() => {
            let map = load_derp_map(std::path::Path::new(&path))
                .with_context(|| format!("load DERP map from {path}"))?;
            eprintln!(
                "mesh serve: loaded DERP map from {path} ({} region(s))",
                map.regions.len()
            );
            map
        }
        _ => empty_derp_map(),
    };
    let ws = WireState {
        server_noise_key: server_noise_key.clone(),
        preauth: Arc::new(minter.clone()),
        ip_allocator: Arc::new(TailnetIpAllocator::new(tailnet_id)),
        machines: Arc::new(MachineRegistry::new()),
        derp_map: Arc::new(derp_map),
        // P1-policy: empty store ⇒ wire layer falls back to
        // `allow_all_packet_filter`. The admin surface (when
        // mounted) holds an `Arc` clone of this store and uses
        // PUT to push hujson docs; the store's `Notify` wakes
        // parked `/map` long-pollers within ~1 ms.
        policy: Arc::new(octravpn_mesh::policy::PolicyStore::new()),
        // PSK-gated handshake (layer 3 of the active-probe shield).
        // Default-disabled — operators opt in via
        // `[control.knock] enabled = true` in node.toml, with the PSK
        // distributed out-of-band alongside the preauth key. See
        // `docs/operators/tls-rotation.md` §"PSK-gated control plane".
        knock: load_knock_cfg_from_env(),
        dns: Arc::new(octravpn_mesh::headscale_api::dns::DnsStore::new()),
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

    // Dual-bind: plain HTTP on `listen` for /admin/preauth + curl
    // probes; rustls-terminated HTTPS on `https_listen` for the
    // forced-443 dial stock Tailscale clients make. Pass an empty
    // string to https_listen to skip TLS (useful on hosts that can't
    // bind 443).
    let http_addr: SocketAddr = listen.parse().context("parse http listen addr")?;
    let https_addr: Option<SocketAddr> = if https_listen.is_empty() {
        None
    } else {
        Some(https_listen.parse().context("parse https listen addr")?)
    };

    let cfg = ServeConfig {
        http_addr,
        https_addr,
        state_dir: std::path::PathBuf::from(&state_dir),
        sans: SanConfig::with_hostname(&cert_hostname),
    };
    let handle = wire_serve(ws, cfg, admin_router)
        .await
        .context("mesh serve: bind wire surface")?;
    if let Some(tls) = handle.tls.as_ref() {
        eprintln!(
            "mesh serve: HTTPS listening on {} (cert={}, key={})",
            https_addr.unwrap(),
            tls.cert_path.display(),
            tls.key_path.display()
        );
        eprintln!("mesh serve: trust the cert in peer containers with `update-ca-certificates`");
    }
    eprintln!("mesh serve: HTTP listening on {http_addr}");

    // Wait for whichever listener exits first. Either bubbling up an
    // error is fine — the harness teardown handles container restart.
    let http_fut = handle.http;
    let https_fut = handle.https;
    match https_fut {
        Some(https_fut) => {
            tokio::select! {
                r = http_fut => r.context("mesh serve: http listener")?
                    .context("mesh serve: http accept")?,
                r = https_fut => r.context("mesh serve: https listener")?
                    .context("mesh serve: https accept")?,
            };
        }
        None => {
            http_fut
                .await
                .context("mesh serve: http listener")?
                .context("mesh serve: http accept")?;
        }
    }
    Ok(())
}

/// Load the PSK-gated handshake config from the operator environment.
///
/// Source of truth:
///   1. `OCTRAVPN_KNOCK_ENABLED` (any non-empty value enables)
///   2. `OCTRAVPN_KNOCK_PSK` (base64-encoded 32-byte secret)
///   3. `OCTRAVPN_KNOCK_WINDOW_SECS` (optional, defaults to 60)
///
/// Defaults to disabled when the env vars are absent — keeps existing
/// deployments backward-compatible. See `docs/operators/tls-rotation.md`
/// §"PSK-gated control plane" for the operator playbook.
fn load_knock_cfg_from_env() -> octravpn_mesh::tailscale_wire::KnockConfig {
    let enabled = std::env::var("OCTRAVPN_KNOCK_ENABLED")
        .map(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(false);
    if !enabled {
        return octravpn_mesh::tailscale_wire::KnockConfig::disabled();
    }
    let Ok(raw) = std::env::var("OCTRAVPN_KNOCK_PSK") else {
        eprintln!(
            "mesh serve: OCTRAVPN_KNOCK_ENABLED set but OCTRAVPN_KNOCK_PSK missing; \
             knock layer DISABLED (would otherwise reject every connection)"
        );
        return octravpn_mesh::tailscale_wire::KnockConfig::disabled();
    };
    let psk = match octravpn_mesh::knock::decode_psk(raw.trim()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("mesh serve: OCTRAVPN_KNOCK_PSK decode failed ({e}); knock layer DISABLED");
            return octravpn_mesh::tailscale_wire::KnockConfig::disabled();
        }
    };
    let window_secs = std::env::var("OCTRAVPN_KNOCK_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(octravpn_mesh::tailscale_wire::knock::DEFAULT_WINDOW_SECS);
    eprintln!("mesh serve: PSK-gated handshake ENABLED (window={window_secs}s)");
    let mut cfg = octravpn_mesh::tailscale_wire::KnockConfig::enabled(psk);
    cfg.window_secs = window_secs;
    cfg
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
    std::fs::create_dir_all(tmpdir).with_context(|| format!("mkdir {}", tmpdir.display()))?;
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
    // #240: `verify_file` returns a rich `FileVerifyReport` (the
    // shared verifier the new `audit_cli` also calls). Surface any
    // chain error here so the legacy `verify-audit-log` command stays
    // usable as a yes/no check.
    let report = crate::audit::AuditLog::verify_file(&key, path)?;
    if let Some(err) = report.first_error {
        anyhow::bail!("{err}");
    }
    let n = report.entries;
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
// ============================================================================
// Tests — Cmd::SealKeys / Cmd::UnsealKeys / Cmd::VerifyAuditLog dispatch
// surface coverage. These exercise the helper fns directly because
// driving full `Cli::parse` would require a binary harness (assert_cmd).
// ============================================================================

#[cfg(test)]
mod main_tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn write_minimal_node_toml(
        path: &std::path::Path,
        wallet_key: &std::path::Path,
        wg_key: &std::path::Path,
    ) {
        let toml = format!(
            r#"
[chain]
rpc_url = "http://127.0.0.1:0/unused"
program_addr = "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3"
validator_addr = "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun"
wallet_secret_path = "{wallet}"

[tunnel]
public_endpoint = "1.2.3.4:51820"
listen = "0.0.0.0:51820"
wg_secret_path = "{wg}"

[pricing]
price_per_mb = 100
region = "test"

[control]
listen = "0.0.0.0:51821"
"#,
            wallet = wallet_key.display(),
            wg = wg_key.display(),
        );
        std::fs::write(path, toml).unwrap();
    }

    fn write_hex_key(path: &std::path::Path, raw: [u8; 32]) {
        std::fs::write(path, hex::encode(raw) + "\n").unwrap();
    }

    #[test]
    fn seal_keys_round_trip_via_run_seal_keys() {
        // Plaintext wallet + wg keys → seal → check `.sealed` files
        // exist and original plaintext still readable (no
        // --remove-plaintext).
        let dir = tempdir().unwrap();
        let wallet = dir.path().join("wallet.key");
        let wg = dir.path().join("wg.key");
        let toml_path = dir.path().join("node.toml");
        write_hex_key(&wallet, [0x42; 32]);
        write_hex_key(&wg, [0x43; 32]);
        write_minimal_node_toml(&toml_path, &wallet, &wg);
        let cfg = NodeConfig::load(&toml_path).unwrap();

        // Run with explicit passphrase, no --remove-plaintext.
        run_seal_keys(&cfg, Some("pw1234"), None, false, false).unwrap();
        assert!(wallet.with_extension("key.sealed").exists());
        assert!(wg.with_extension("key.sealed").exists());
        // Plaintext preserved.
        assert!(wallet.exists());
        assert!(wg.exists());
    }

    #[test]
    fn seal_keys_rotate_mode_removes_plaintext() {
        let dir = tempdir().unwrap();
        let wallet = dir.path().join("wallet.key");
        let wg = dir.path().join("wg.key");
        let toml_path = dir.path().join("node.toml");
        write_hex_key(&wallet, [0xAA; 32]);
        write_hex_key(&wg, [0xBB; 32]);
        write_minimal_node_toml(&toml_path, &wallet, &wg);
        let cfg = NodeConfig::load(&toml_path).unwrap();

        run_seal_keys(&cfg, Some("rotate-pw"), None, false, true).unwrap();
        // .sealed must exist; plaintext must be gone.
        assert!(wallet.with_extension("key.sealed").exists());
        assert!(wg.with_extension("key.sealed").exists());
        assert!(!wallet.exists(), "plaintext wallet must be removed");
        assert!(!wg.exists(), "plaintext wg must be removed");
    }

    #[test]
    fn seal_keys_idempotent_on_already_sealed() {
        // Sealing twice with the same passphrase must NOT corrupt; the
        // second call is a no-op.
        let dir = tempdir().unwrap();
        let wallet = dir.path().join("wallet.key");
        let wg = dir.path().join("wg.key");
        let toml_path = dir.path().join("node.toml");
        write_hex_key(&wallet, [0xCC; 32]);
        write_hex_key(&wg, [0xDD; 32]);
        write_minimal_node_toml(&toml_path, &wallet, &wg);
        let cfg = NodeConfig::load(&toml_path).unwrap();

        run_seal_keys(&cfg, Some("pw"), None, false, false).unwrap();
        let first = std::fs::read(wallet.with_extension("key.sealed")).unwrap();
        // Re-run (passphrase can differ → still idempotent).
        run_seal_keys(&cfg, Some("different-pw"), None, false, false).unwrap();
        let second = std::fs::read(wallet.with_extension("key.sealed")).unwrap();
        assert_eq!(first, second, "second seal must be a no-op");
    }

    #[test]
    fn unseal_keys_recovers_plaintext_into_tmpdir() {
        let dir = tempdir().unwrap();
        let wallet = dir.path().join("wallet.key");
        let wg = dir.path().join("wg.key");
        let toml_path = dir.path().join("node.toml");
        write_hex_key(&wallet, [0xEE; 32]);
        write_hex_key(&wg, [0xFF; 32]);
        write_minimal_node_toml(&toml_path, &wallet, &wg);
        let cfg = NodeConfig::load(&toml_path).unwrap();

        // Seal then unseal into a /tmp subdir (macOS accepts /tmp under
        // its check_tmpfs path; Linux test runners typically run tests
        // under /tmp/cargo-target or a tmpfs).
        run_seal_keys(&cfg, Some("pw"), None, false, false).unwrap();
        // Use the system tmpdir which is /tmp on macOS (check_tmpfs ok)
        // and tmpfs on most Linux CI containers.
        let recovery_dir = PathBuf::from(std::env::temp_dir())
            .join(format!("octravpn-test-{}", std::process::id()));
        let r = run_unseal_keys(&cfg, &recovery_dir, Some("pw"), None, false);
        if r.is_err() {
            // The check_tmpfs gate may refuse the path on this host;
            // that's an environmental skip, not a test failure.
            eprintln!("unseal skipped (tmpfs gate): {:?}", r.err());
            return;
        }
        let recovered_wallet = recovery_dir.join("wallet.key");
        let recovered_wg = recovery_dir.join("wg.key");
        assert!(recovered_wallet.exists());
        assert!(recovered_wg.exists());
        // Confirm round-trip equality.
        let wallet_hex = std::fs::read_to_string(&recovered_wallet).unwrap();
        let wg_hex = std::fs::read_to_string(&recovered_wg).unwrap();
        assert_eq!(wallet_hex.trim(), hex::encode([0xEE; 32]));
        assert_eq!(wg_hex.trim(), hex::encode([0xFF; 32]));
        // Cleanup.
        let _ = std::fs::remove_dir_all(&recovery_dir);
    }

    #[test]
    fn unseal_keys_wrong_passphrase_fails() {
        let dir = tempdir().unwrap();
        let wallet = dir.path().join("wallet.key");
        let wg = dir.path().join("wg.key");
        let toml_path = dir.path().join("node.toml");
        write_hex_key(&wallet, [0x11; 32]);
        write_hex_key(&wg, [0x22; 32]);
        write_minimal_node_toml(&toml_path, &wallet, &wg);
        let cfg = NodeConfig::load(&toml_path).unwrap();
        run_seal_keys(&cfg, Some("right"), None, false, false).unwrap();

        let recovery = PathBuf::from(std::env::temp_dir())
            .join(format!("octravpn-unseal-bad-{}", std::process::id()));
        let r = run_unseal_keys(&cfg, &recovery, Some("wrong"), None, false);
        assert!(r.is_err(), "wrong passphrase must fail unseal");
        let _ = std::fs::remove_dir_all(&recovery);
    }

    #[test]
    fn seal_keys_fails_when_plaintext_missing() {
        let dir = tempdir().unwrap();
        let wallet = dir.path().join("wallet.key");
        let wg = dir.path().join("wg.key");
        let toml_path = dir.path().join("node.toml");
        // Only write one of the two key files.
        write_hex_key(&wallet, [0x55; 32]);
        // wg.key intentionally missing.
        write_minimal_node_toml(&toml_path, &wallet, &wg);
        let cfg = NodeConfig::load(&toml_path).unwrap();
        let r = run_seal_keys(&cfg, Some("pw"), None, false, false);
        assert!(r.is_err());
    }

    #[test]
    fn verify_audit_log_helper_passes_on_clean_chain() {
        // Build a Hub-less invocation of the deprecated `verify_audit_log`
        // alias by routing through the underlying `AuditLog::verify_file`
        // directly. We can't construct a Hub here (would require a
        // working RPC), so we exercise the path the alias delegates to.
        use crate::audit::{AuditLog, AuditRecord};
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..3u64 {
            log.write(&AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "announce",
                source: None,
                session_id: Some(hex::encode([1u8; 32])),
                extra: serde_json::json!({"i": i}),
            })
            .unwrap();
        }
        let audit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let key = log.key();
        let report = AuditLog::verify_file(&key, &audit_file).unwrap();
        assert_eq!(report.entries, 3);
        assert!(report.first_error.is_none());
    }

    #[test]
    fn verify_audit_log_helper_reports_chain_break() {
        use crate::audit::{AuditLog, AuditRecord};
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..3u64 {
            log.write(&AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "announce",
                source: None,
                session_id: Some(hex::encode([1u8; 32])),
                extra: serde_json::json!({"i": i}),
            })
            .unwrap();
        }
        let audit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        // Tamper line 2 (1-indexed) so the chain breaks.
        let body = std::fs::read_to_string(&audit_file).unwrap();
        let mut lines: Vec<String> = body.lines().map(String::from).collect();
        lines[1] = lines[1].replacen("\\\"i\\\":1", "\\\"i\\\":999", 1);
        std::fs::write(&audit_file, lines.join("\n") + "\n").unwrap();
        let key = log.key();
        let report = AuditLog::verify_file(&key, &audit_file).unwrap();
        assert!(report.first_error.is_some());
    }

    #[test]
    fn cli_parses_run_subcommand() {
        // Smoke-test that `Cli::parse_from` accepts a minimal `run`
        // invocation and routes to Cmd::Run.
        let cli = Cli::try_parse_from(["octravpn-node", "--config", "/tmp/x.toml", "run"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Run));
        assert_eq!(cli.config, "/tmp/x.toml");
    }

    #[test]
    fn cli_parses_bond_subcommand_with_amount() {
        let cli = Cli::try_parse_from(["octravpn-node", "bond", "--amount", "12345"]).unwrap();
        match cli.cmd {
            Cmd::Bond { amount } => assert_eq!(amount, 12345),
            other => panic!("expected Bond, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_v3_open_session_subcommand() {
        let cli = Cli::try_parse_from([
            "octravpn-node",
            "v3",
            "open-session",
            "--tailnet-id",
            "1",
            "--circle",
            "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun",
            "--max-pay",
            "1000",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::V3 {
                cmd: v3_cli::V3Cmd::OpenSession(args),
            } => {
                assert_eq!(args.tailnet_id, 1);
                assert_eq!(args.max_pay, 1000);
            }
            other => panic!("expected V3::OpenSession, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_audit_verify_subcommand() {
        let cli = Cli::try_parse_from([
            "octravpn-node",
            "audit",
            "verify",
            "--audit-path",
            "/tmp/a",
            "--journal-path",
            "/tmp/j",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::Audit {
                cmd: audit_cli::AuditCmd::Verify(_),
            } => {}
            other => panic!("expected Audit::Verify, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_config_validate_with_offline() {
        let cli = Cli::try_parse_from([
            "octravpn-node",
            "config",
            "validate",
            "--offline",
            "/tmp/node.toml",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::Config {
                cmd: cli_ops::ConfigCmd::Validate(args),
            } => {
                assert!(args.offline);
                assert_eq!(args.path, PathBuf::from("/tmp/node.toml"));
            }
            other => panic!("expected Config::Validate, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_audit_tail_with_follow_flag() {
        let cli = Cli::try_parse_from([
            "octravpn-node",
            "audit-tail",
            "--audit-path",
            "/tmp/log",
            "--follow",
            "--poll-ms",
            "500",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::AuditTail(args) => {
                assert!(args.follow);
                assert_eq!(args.poll_ms, 500);
            }
            other => panic!("expected AuditTail, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_receipt_verify_with_session_id() {
        let cli =
            Cli::try_parse_from(["octravpn-node", "receipt-verify", &"a".repeat(64)]).unwrap();
        match cli.cmd {
            Cmd::ReceiptVerify(args) => {
                assert_eq!(args.session_id, "a".repeat(64));
            }
            other => panic!("expected ReceiptVerify, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_seal_keys_with_passphrase_file() {
        let cli = Cli::try_parse_from([
            "octravpn-node",
            "seal-keys",
            "--passphrase-file",
            "/run/secret",
            "--remove-plaintext",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::SealKeys {
                passphrase,
                passphrase_file,
                passphrase_stdin,
                remove_plaintext,
            } => {
                assert!(passphrase.is_none());
                assert_eq!(passphrase_file, Some(PathBuf::from("/run/secret")));
                assert!(!passphrase_stdin);
                assert!(remove_plaintext);
            }
            other => panic!("expected SealKeys, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_unseal_keys_with_tmpdir() {
        let cli = Cli::try_parse_from([
            "octravpn-node",
            "unseal-keys",
            "--tmpdir",
            "/private/tmp/octra",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::UnsealKeys { tmpdir, .. } => {
                assert_eq!(tmpdir, PathBuf::from("/private/tmp/octra"));
            }
            other => panic!("expected UnsealKeys, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_mesh_mint_preauth() {
        let cli = Cli::try_parse_from([
            "octravpn-node",
            "mesh",
            "mint-preauth",
            "--user",
            "alice",
            "--reusable",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::Mesh {
                sub:
                    MeshCmd::MintPreauth {
                        user,
                        reusable,
                        ttl_secs,
                    },
            } => {
                assert_eq!(user, "alice");
                assert!(reusable);
                assert!(ttl_secs.is_none());
            }
            other => panic!("expected Mesh::MintPreauth, got {other:?}"),
        }
    }
}
