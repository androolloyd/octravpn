//! CLI surface for `octravpn-node`.
//!
//! # Layout
//!
//! Each operator-facing subcommand owns one file under `cli/`:
//!
//! ```text
//! cli/bond.rs       — bond / unbond / finalize-unbond / register / claim-earnings
//!                     / settle-claim — the v1.1-style subcommands
//! cli/identity.rs   — identity / accumulator-add
//! cli/audit.rs      — audit (subcommand tree) + verify-audit-log (deprecated alias)
//! cli/seal.rs       — seal-keys / unseal-keys
//! cli/v3.rs         — v3 (subcommand tree) — delegates to `crate::v3_cli`
//! cli/mesh.rs       — mesh (subcommand tree) — delegates to `crate::mesh_ops`
//!                     plus the deprecated `mesh status` / `mesh policy` arms
//! cli/circle.rs     — circle (subcommand tree) — delegates to `crate::circle_update`
//! cli/headscale.rs  — headscale (embedded admin CLI passthrough)
//! cli/ops.rs        — config / health / audit-tail / receipt-verify — the #232
//!                     operator surfaces
//! cli/runtime.rs    — run — the long-lived daemon boot
//! ```
//!
//! # Adding a new subcommand
//!
//! 1. Create a new file under `cli/` with an `#[derive(clap::Args)]` (or
//!    `clap::Subcommand`) struct/enum that owns the doc-comment, args, and
//!    handler body.
//! 2. `impl Subcommand for FooCmd` — declare `needs_hub()` (returns `bool`)
//!    and `dispatch(self, ctx: CliContext<'_>) -> Result<i32>`. The trait's
//!    blanket exit-code semantics: `Ok(0)` for success, non-zero for a
//!    handled failure that should still report through the structured exit
//!    contract, `Err(e)` for anything that should bubble up an
//!    `anyhow::Error`.
//! 3. Add the variant to [`Cmd`] in this file (one line). `main.rs` does
//!    not need to change — the dispatch loop here resolves the variant via
//!    a match that delegates to `Subcommand::dispatch` for every arm.
//!
//! See [`Subcommand`] for the trait contract and [`CliContext`] for the
//! per-call carrier struct.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;

use crate::config::NodeConfig;
use crate::hub::Hub;

pub(crate) mod audit;
pub(crate) mod bond;
pub(crate) mod circle;
pub(crate) mod headscale;
pub(crate) mod identity;
pub(crate) mod journal;
pub(crate) mod mesh;
pub(crate) mod ops;
pub(crate) mod runtime;
pub(crate) mod seal;
pub(crate) mod v3;

#[cfg(test)]
mod tests;

/// Top-level CLI.
#[derive(Parser, Debug)]
#[command(name = "octravpn-node", version, about)]
pub(crate) struct Cli {
    /// Path to TOML config file.
    #[arg(long, env = "OCTRAVPN_NODE_CONFIG", default_value = "node.toml")]
    pub(crate) config: String,

    #[command(subcommand)]
    pub(crate) cmd: Cmd,
}

/// Top-level subcommand variants. Each variant is a thin newtype around a
/// `clap::Args` struct that lives in its own module under `cli/`. To add a
/// new subcommand: add one variant here (and `impl Subcommand` for the
/// args struct in its own file). Nothing in `main.rs` needs to change.
#[derive(Parser, Debug)]
pub(crate) enum Cmd {
    /// Run the daemon in long-lived mode.
    Run(runtime::RunArgs),
    /// Deposit OU as operator stake. Required before `register`.
    /// Use `--amount` in raw OU (1 OCT = 1_000_000 OU; default min
    /// stake is 1000 OCT = 10^9 OU).
    Bond(bond::BondArgs),
    /// Begin unbonding the operator stake. Starts the grace timer;
    /// the endpoint becomes inactive immediately.
    Unbond(bond::UnbondArgs),
    /// After the unbond grace elapses, claim the stake back.
    FinalizeUnbond(bond::FinalizeUnbondArgs),
    /// Register endpoint on chain (idempotent: skips if already
    /// registered). Caller must have at least MIN_ENDPOINT_STAKE
    /// bonded — run `bond` first.
    Register(bond::RegisterArgs),
    /// Claim accumulated earnings. Two-step: AML verifies an FHE
    /// zero-proof and transfers plaintext OU; the operator's wallet
    /// then wraps it in a native stealth tx for unlinkable payout.
    ClaimEarnings(bond::ClaimEarningsArgs),
    /// Submit `settle_claim(session_id, bytes_used)` for a closed
    /// session. The operator MUST submit the same bytes_used per
    /// session for life — equivocation slashes the operator bond
    /// in-AML.
    SettleClaim(bond::SettleClaimArgs),
    /// Print derived addresses / pubkeys without changing on-chain state.
    Identity(identity::IdentityArgs),
    /// Add (delta_amount, delta_blind) to the local earnings accumulator.
    /// Used by reconciliation tooling that watches `SessionSettled`
    /// events and tells the node which contributions are theirs.
    AccumulatorAdd(identity::AccumulatorAddArgs),
    /// Verify the HMAC chain of an audit log file. Reads the audit key
    /// from the configured audit_dir (`.audit.key`) and walks the file
    /// line-by-line. Exits 0 on a clean chain; non-zero with the first
    /// broken line index otherwise.
    ///
    /// Deprecated alias for `audit verify --audit-path <path>`; kept
    /// so existing operator runbooks keep working.
    VerifyAuditLog(audit::VerifyAuditLogArgs),
    /// Operator-facing audit tooling: pretty-print the audit log +
    /// receipt journal as a timeline, or run a full crypto
    /// verification. The artifacts inspected here are the same files
    /// the daemon writes during normal operation.
    Audit(audit::AuditArgs),
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
    SealKeys(seal::SealKeysArgs),
    /// P1-6: reverse `seal-keys` onto a tmpfs/ramfs path for emergency
    /// rotation or one-shot recovery. The destination MUST live on a
    /// memory-volatile filesystem (Linux: tmpfs/ramfs/devtmpfs;
    /// macOS: under `/private/tmp`); the command refuses to write
    /// elsewhere. Passphrase resolution mirrors `seal-keys`.
    UnsealKeys(seal::UnsealKeysArgs),
    /// v3 chain-minimal entrypoints. Every non-boot v3 method exposed
    /// by `program/main-v3.aml` is reachable here as a subcommand:
    /// bond / unbond / finalize / slash / rotate / retire-circle,
    /// tailnet create / update / retire / deposit / withdraw, session
    /// open / settle-claim / settle-confirm / claim-no-show / sweep,
    /// and claim-earnings. The boot flow (`register_circle` /
    /// `update_circle_state`) still goes through `register` / `run`.
    V3(v3::V3Args),
    /// Circle-asset CRUD: atomic update primitive for sealed circle
    /// assets. The `update` subcommand drives
    /// `circle_asset_put_encrypted` + `update_circle_state` in the
    /// correct order so a partial failure leaves chain state on the
    /// OLD anchor (old blobs still bound). See
    /// `docs/v2-operator-key-hygiene.md §5` for the operator-facing
    /// rotation runbook and `crates/octravpn-node/src/circle_update.rs`
    /// for the atomicity contract.
    Circle(circle::CircleArgs),
    /// Mesh / Tailscale-interop control surface. Subcommands here
    /// are exercised by `docker/devnet/tailscale-interop/run-interop.sh`
    /// and by operators provisioning new tailnet members. See
    /// `docs/tailscale-interop-blocker.md` for the gap between
    /// "we mint a preauth key" and "stock `tailscale up` completes a
    /// handshake against us."
    Mesh(mesh::MeshArgs),
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
    Headscale(headscale::HeadscaleArgs),
    /// #232: schema-check + key + RPC + program reachability against a
    /// `node.toml`. Replaces the manual `octra cast rpc node_status`
    /// + `octra cast call $PROG get_params` smoke probe + ad-hoc TOML
    /// diffing dance from `docs/deployment-runbook.md` §1.
    Config(ops::ConfigArgs),
    /// #232: one-shot operator health probe. Reads on-chain stake /
    /// slashed / unbonding state, validates local audit log + receipt
    /// journal are openable, and (when `--remote` is set) hits the
    /// running daemon's `GET /health`. Replaces the manual `octra
    /// cast call` triple and `curl … | jq` step from the runbook §7.1
    /// + §2.
    Health(ops::HealthArgs),
    /// #232: live-tail the audit log with per-line HMAC verification.
    /// `--follow` keeps reading appended lines (similar to `tail -F`);
    /// without `--follow` it prints existing lines and exits. A chain
    /// break interrupts output with a clear marker and a non-zero exit
    /// code so cron pipelines surface tampering immediately.
    AuditTail(ops::AuditTailArgs),
    /// #232: report the receipt-journal floor for a session id plus
    /// every audit-log entry that names the same session. Cross-checks
    /// the P1-8/9 invariant (no signed seq above the journal floor).
    /// Useful as a quick forensic probe after an alert.
    ReceiptVerify(ops::ReceiptVerifyArgs),
    /// audit-9 H-RTO: receipt-journal disaster-recovery tooling.
    /// `journal rebuild --from-audit <dir> --output <path>`
    /// reconstructs a v1 journal from the HMAC-chained audit log when
    /// the live journal is corrupted (CRC mismatch on a v1 record).
    /// Closes the recovery gap operators previously had to fill by
    /// hand-rebuilding 44-byte records — target RTO drops from
    /// ≥30 min to under 2 min.
    Journal(journal::JournalArgs),
}

/// Per-call dispatch context. `hub` is `Some` iff the dispatching
/// subcommand returned `true` from [`Subcommand::needs_hub`]; otherwise
/// it is `None` and the handler runs pre-`Hub::new`.
pub(crate) struct CliContext<'a> {
    pub(crate) cfg_path: &'a str,
    pub(crate) hub: Option<Arc<Hub>>,
}

impl CliContext<'_> {
    /// Load the config from `cfg_path` on demand. Used by pre-Hub
    /// handlers that need a `NodeConfig` (e.g. seal/unseal) but not a
    /// live Hub.
    pub(crate) fn load_config(&self) -> Result<NodeConfig> {
        NodeConfig::load(self.cfg_path)
    }

    /// Hub accessor for post-Hub handlers. Panics with a clear message
    /// if `needs_hub()` returned `false` but the handler tried to read
    /// the hub anyway — that's a wiring bug in the trait impl, not
    /// reachable in production code paths.
    pub(crate) fn hub(&self) -> &Arc<Hub> {
        self.hub
            .as_ref()
            .expect("CliContext::hub called from a pre-Hub subcommand; check needs_hub()")
    }
}

/// Self-registering subcommand contract. Each handler in `cli/` impls
/// this once; the top-level dispatcher in `dispatch()` calls into it
/// uniformly. The only place the variant name appears outside its
/// module is the `Cmd` enum + this match.
#[async_trait]
pub(crate) trait Subcommand {
    /// Whether this subcommand needs a Hub. If `false`, it dispatches
    /// pre-`Hub::new` and `CliContext::hub` will be `None`.
    fn needs_hub(&self) -> bool;
    /// Run the subcommand. Returns the desired process exit code; the
    /// dispatcher calls `std::process::exit` with this value.
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32>;
}

/// Top-level entrypoint called from `main`. Parses the CLI, decides pre-
/// vs post-Hub, builds the Hub if needed, and dispatches.
pub(crate) async fn run() -> Result<i32> {
    let Cli { config, cmd } = Cli::parse();
    let needs_hub = cmd_needs_hub(&cmd);
    let hub = if needs_hub {
        let cfg = NodeConfig::load(&config)?;
        Some(Arc::new(Hub::new(cfg).await?))
    } else {
        None
    };
    let ctx = CliContext {
        cfg_path: &config,
        hub,
    };
    dispatch(cmd, ctx).await
}

fn cmd_needs_hub(cmd: &Cmd) -> bool {
    match cmd {
        Cmd::Run(a) => a.needs_hub(),
        Cmd::Bond(a) => a.needs_hub(),
        Cmd::Unbond(a) => a.needs_hub(),
        Cmd::FinalizeUnbond(a) => a.needs_hub(),
        Cmd::Register(a) => a.needs_hub(),
        Cmd::ClaimEarnings(a) => a.needs_hub(),
        Cmd::SettleClaim(a) => a.needs_hub(),
        Cmd::Identity(a) => a.needs_hub(),
        Cmd::AccumulatorAdd(a) => a.needs_hub(),
        Cmd::VerifyAuditLog(a) => a.needs_hub(),
        Cmd::Audit(a) => a.needs_hub(),
        Cmd::SealKeys(a) => a.needs_hub(),
        Cmd::UnsealKeys(a) => a.needs_hub(),
        Cmd::V3(a) => a.needs_hub(),
        Cmd::Circle(a) => a.needs_hub(),
        Cmd::Mesh(a) => a.needs_hub(),
        Cmd::Headscale(a) => a.needs_hub(),
        Cmd::Config(a) => a.needs_hub(),
        Cmd::Health(a) => a.needs_hub(),
        Cmd::AuditTail(a) => a.needs_hub(),
        Cmd::ReceiptVerify(a) => a.needs_hub(),
        Cmd::Journal(a) => a.needs_hub(),
    }
}

async fn dispatch(cmd: Cmd, ctx: CliContext<'_>) -> Result<i32> {
    match cmd {
        Cmd::Run(a) => a.dispatch(ctx).await,
        Cmd::Bond(a) => a.dispatch(ctx).await,
        Cmd::Unbond(a) => a.dispatch(ctx).await,
        Cmd::FinalizeUnbond(a) => a.dispatch(ctx).await,
        Cmd::Register(a) => a.dispatch(ctx).await,
        Cmd::ClaimEarnings(a) => a.dispatch(ctx).await,
        Cmd::SettleClaim(a) => a.dispatch(ctx).await,
        Cmd::Identity(a) => a.dispatch(ctx).await,
        Cmd::AccumulatorAdd(a) => a.dispatch(ctx).await,
        Cmd::VerifyAuditLog(a) => a.dispatch(ctx).await,
        Cmd::Audit(a) => a.dispatch(ctx).await,
        Cmd::SealKeys(a) => a.dispatch(ctx).await,
        Cmd::UnsealKeys(a) => a.dispatch(ctx).await,
        Cmd::V3(a) => a.dispatch(ctx).await,
        Cmd::Circle(a) => a.dispatch(ctx).await,
        Cmd::Mesh(a) => a.dispatch(ctx).await,
        Cmd::Headscale(a) => a.dispatch(ctx).await,
        Cmd::Config(a) => a.dispatch(ctx).await,
        Cmd::Health(a) => a.dispatch(ctx).await,
        Cmd::AuditTail(a) => a.dispatch(ctx).await,
        Cmd::ReceiptVerify(a) => a.dispatch(ctx).await,
        Cmd::Journal(a) => a.dispatch(ctx).await,
    }
}
