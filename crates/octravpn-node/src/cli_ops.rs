//! Operator-facing one-shot CLI commands (#232).
//!
//! Surfaces in this module:
//!
//!   * `octravpn-node config validate <path>` — schema check + key
//!     files readable + RPC reachable + program responsive. Replaces
//!     the manual `octra cast rpc node_status` + `octra cast call $PROG
//!     get_params` + ad-hoc TOML diffing dance in
//!     `docs/deployment-runbook.md` §1.
//!   * `octravpn-node health` — runs the §7.1 chain reads
//!     (`get_endpoint_stake`, `is_endpoint_slashed`,
//!     `get_endpoint_unbonding`) PLUS local-file probes (audit log
//!     openable, receipt journal openable) PLUS, when `--remote` is
//!     passed, a curl-free `GET /health` against the running daemon.
//!     Replaces the manual `octra cast call` triple + `curl … | jq`
//!     incantations in the runbook.
//!   * `octravpn-node audit tail [--follow]` — live-tail the audit log
//!     with per-line HMAC verification. The verify path reuses
//!     `audit::chain_step` so the implementation cannot drift from
//!     `AuditLog::verify_file`.
//!   * `octravpn-node receipt verify --session-id <hex>` — read the
//!     receipt-journal floor for a session and report whether the
//!     local audit log corroborates it.
//!
//! Each subcommand is dispatched pre-Hub so an operator can run them
//! against a `node.toml` whose underlying daemon is offline (a typical
//! incident-response shape: "the daemon won't boot — is my config or my
//! key sane?").

use std::{
    fmt::Write as FmtWrite,
    fs,
    io::{BufRead, BufReader, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::{json, Value};

use octravpn_core::{
    address::Address, receipt_journal::ReceiptJournal, session::SessionId,
};

use crate::audit::{chain_step, resolve_hmac_key, AuditLog, HmacKeyError};
use crate::config::NodeConfig;

// ============================================================================
// Top-level subcommand types — surfaced from `main.rs`.
// ============================================================================

#[derive(Subcommand, Debug)]
pub(crate) enum ConfigCmd {
    /// Schema-check a `node.toml`, prove the configured wallet + WG key
    /// files load, prove the RPC endpoint is reachable, and prove the
    /// program responds to a no-side-effects view call. Exits 0 on a
    /// clean validation; exits 1 with the first failure surfaced.
    Validate(ConfigValidateArgs),
}

#[derive(Args, Debug)]
pub(crate) struct ConfigValidateArgs {
    /// Path to the `node.toml` to validate. Defaults to the value of
    /// `OCTRAVPN_NODE_CONFIG` or `./node.toml`.
    #[arg(default_value = "node.toml")]
    pub path: PathBuf,
    /// Skip the chain reachability probe (RPC + `get_params`). Useful
    /// in air-gapped CI where the RPC endpoint isn't accessible.
    #[arg(long, default_value_t = false)]
    pub offline: bool,
    /// Output a JSON report instead of human-friendly text.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub(crate) struct HealthArgs {
    /// Path to the `node.toml` whose configured wallet + RPC + audit
    /// dir to probe.
    #[arg(long, env = "OCTRAVPN_NODE_CONFIG", default_value = "node.toml")]
    pub config: PathBuf,
    /// If passed, additionally hit the running daemon's `GET /health`
    /// at this URL (e.g. `http://localhost:51821`). Replaces the manual
    /// `curl -sS http://localhost:51821/health | jq` step in the
    /// runbook.
    #[arg(long)]
    pub remote: Option<String>,
    /// Output a JSON report instead of human-friendly text.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub(crate) struct AuditTailArgs {
    /// Path to the audit log file OR directory. The directory form
    /// (one file per UTC day) is auto-detected; the latest file is
    /// tailed.
    #[arg(long, default_value = "./state/audit.log")]
    pub audit_path: PathBuf,
    /// HMAC key file. Defaults to the same `--audit-path` discovery the
    /// `audit verify` subcommand uses.
    #[arg(long)]
    pub hmac_key: Option<PathBuf>,
    /// Keep reading appended lines until interrupted (Ctrl-C). When
    /// unset, the command prints existing lines then exits.
    #[arg(long, default_value_t = false)]
    pub follow: bool,
    /// Poll interval in milliseconds when `--follow` is set. Default
    /// 250 ms — matches `tail -F` behaviour on most platforms.
    #[arg(long, default_value_t = 250)]
    pub poll_ms: u64,
}

#[derive(Args, Debug)]
pub(crate) struct ReceiptVerifyArgs {
    /// Session id to look up. Accepts the 64-char hex form or the
    /// legacy v1 u64 decimal form.
    pub session_id: String,
    /// Path to the receipt journal. Defaults to `./state/receipts.bin`.
    #[arg(long, default_value = "./state/receipts.bin")]
    pub journal_path: PathBuf,
    /// Optional audit log to cross-check against. When set, the
    /// command also reports every audit entry whose `session_id`
    /// matches the requested session.
    #[arg(long)]
    pub audit_path: Option<PathBuf>,
    /// Output a JSON report instead of human-friendly text.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

// ============================================================================
// `config validate` — reports
// ============================================================================

#[derive(Debug, Serialize)]
struct ConfigValidateReport {
    schema_parsed: CheckOutcome,
    wallet_key_loadable: CheckOutcome,
    wg_key_loadable: CheckOutcome,
    audit_dir_writable: CheckOutcome,
    journal_path_writable: CheckOutcome,
    rpc_reachable: CheckOutcome,
    program_responsive: CheckOutcome,
    overall_pass: bool,
}

#[derive(Debug, Serialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
enum CheckOutcome {
    Ok { detail: String },
    Fail { detail: String },
    Skipped { detail: String },
}

impl CheckOutcome {
    fn is_fail(&self) -> bool {
        matches!(self, Self::Fail { .. })
    }
    fn label(&self) -> &'static str {
        match self {
            Self::Ok { .. } => "OK",
            Self::Fail { .. } => "FAIL",
            Self::Skipped { .. } => "SKIP",
        }
    }
    fn detail(&self) -> &str {
        match self {
            Self::Ok { detail } | Self::Fail { detail } | Self::Skipped { detail } => detail,
        }
    }
}

/// Synchronous entry point. Dispatches to async-needing work via a
/// short-lived single-thread runtime; lets `main.rs` keep its current
/// sync top-level for these subcommands.
pub(crate) fn run_config(cmd: ConfigCmd) -> Result<i32> {
    match cmd {
        ConfigCmd::Validate(args) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build current-thread runtime")?;
            let report = rt.block_on(run_config_validate(&args));
            render_config_validate(&report, args.json);
            Ok(i32::from(!report.overall_pass))
        }
    }
}

async fn run_config_validate(args: &ConfigValidateArgs) -> ConfigValidateReport {
    // 1. Schema.
    let cfg_result: Result<NodeConfig> = NodeConfig::load(&args.path);
    let (schema_parsed, cfg_opt): (CheckOutcome, Option<NodeConfig>) = match cfg_result {
        Ok(cfg) => (
            CheckOutcome::Ok {
                detail: format!("parsed {}", args.path.display()),
            },
            Some(cfg),
        ),
        Err(e) => (
            CheckOutcome::Fail {
                detail: format!("{e:#}"),
            },
            None,
        ),
    };

    // Without a parsed config every downstream check is meaningless.
    let Some(cfg) = cfg_opt else {
        return ConfigValidateReport {
            schema_parsed,
            wallet_key_loadable: CheckOutcome::Skipped {
                detail: "schema failed".into(),
            },
            wg_key_loadable: CheckOutcome::Skipped {
                detail: "schema failed".into(),
            },
            audit_dir_writable: CheckOutcome::Skipped {
                detail: "schema failed".into(),
            },
            journal_path_writable: CheckOutcome::Skipped {
                detail: "schema failed".into(),
            },
            rpc_reachable: CheckOutcome::Skipped {
                detail: "schema failed".into(),
            },
            program_responsive: CheckOutcome::Skipped {
                detail: "schema failed".into(),
            },
            overall_pass: false,
        };
    };

    // 2. Wallet key loadable. Accept either plaintext or sealed —
    // `require_sealed_keys` is enforced at boot; here we only verify
    // the file's reachable + the bytes parse.
    let wallet_key_loadable = probe_secret_file(&cfg.chain.wallet_secret_path);

    // 3. WG master key loadable.
    let wg_key_loadable = probe_secret_file(&cfg.tunnel.wg_secret_path);

    // 4. Audit dir writable (the daemon will try to create files
    // here on boot — surfacing perms problems pre-boot saves a 30s
    // debug loop).
    let audit_dir_writable = probe_audit_dir(cfg.control.audit_dir.as_deref());

    // 5. Receipt-journal path writable.
    let journal_path_writable = probe_journal_path(cfg.control.receipt_journal_path.as_deref());

    // 6 + 7: chain reachability.
    let (rpc_reachable, program_responsive) = if args.offline {
        (
            CheckOutcome::Skipped {
                detail: "--offline".into(),
            },
            CheckOutcome::Skipped {
                detail: "--offline".into(),
            },
        )
    } else {
        probe_chain(&cfg).await
    };

    let overall_pass = !schema_parsed.is_fail()
        && !wallet_key_loadable.is_fail()
        && !wg_key_loadable.is_fail()
        && !audit_dir_writable.is_fail()
        && !journal_path_writable.is_fail()
        && !rpc_reachable.is_fail()
        && !program_responsive.is_fail();

    ConfigValidateReport {
        schema_parsed,
        wallet_key_loadable,
        wg_key_loadable,
        audit_dir_writable,
        journal_path_writable,
        rpc_reachable,
        program_responsive,
        overall_pass,
    }
}

fn probe_secret_file(path: &str) -> CheckOutcome {
    // Accept either plaintext 32-byte (raw or hex) or a sealed
    // envelope. We don't decrypt the envelope here — that needs the
    // passphrase, which the validator shouldn't ask for. Existence +
    // readability is enough.
    let p = Path::new(path);
    if !p.exists() {
        return CheckOutcome::Fail {
            detail: format!("{path}: file does not exist"),
        };
    }
    match fs::metadata(p) {
        Ok(_) => match fs::read(p) {
            Ok(bytes) if !bytes.is_empty() => CheckOutcome::Ok {
                detail: format!("{path}: {} bytes readable", bytes.len()),
            },
            Ok(_) => CheckOutcome::Fail {
                detail: format!("{path}: empty file"),
            },
            Err(e) => CheckOutcome::Fail {
                detail: format!("{path}: read error: {e}"),
            },
        },
        Err(e) => CheckOutcome::Fail {
            detail: format!("{path}: stat error: {e}"),
        },
    }
}

fn probe_audit_dir(dir: Option<&str>) -> CheckOutcome {
    let dir = dir.unwrap_or("./audit");
    let p = Path::new(dir);
    // Try to create the dir; the daemon does this on boot.
    if let Err(e) = fs::create_dir_all(p) {
        return CheckOutcome::Fail {
            detail: format!("{dir}: cannot create: {e}"),
        };
    }
    // Try to write a probe file.
    let probe = p.join(".octravpn-validate-probe");
    match fs::write(&probe, b"probe") {
        Ok(()) => {
            let _ = fs::remove_file(&probe);
            CheckOutcome::Ok {
                detail: format!("{dir}: writable"),
            }
        }
        Err(e) => CheckOutcome::Fail {
            detail: format!("{dir}: write error: {e}"),
        },
    }
}

fn probe_journal_path(journal_path: Option<&str>) -> CheckOutcome {
    let p = journal_path.unwrap_or("./state/receipts.bin");
    let path = Path::new(p);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = fs::create_dir_all(parent) {
                return CheckOutcome::Fail {
                    detail: format!("{p}: cannot create parent dir: {e}"),
                };
            }
        }
    }
    // Open the journal — covers both the "does not exist yet" and
    // "exists, parses" paths. We immediately drop it.
    match ReceiptJournal::open(path) {
        Ok(_) => CheckOutcome::Ok {
            detail: format!("{p}: openable"),
        },
        Err(e) => CheckOutcome::Fail {
            detail: format!("{p}: open error: {e}"),
        },
    }
}

async fn probe_chain(cfg: &NodeConfig) -> (CheckOutcome, CheckOutcome) {
    let rpc = match cfg.chain.build_rpc_client() {
        Ok(r) => r,
        Err(e) => {
            return (
                CheckOutcome::Fail {
                    detail: format!("build rpc client: {e:#}"),
                },
                CheckOutcome::Skipped {
                    detail: "rpc unreachable".into(),
                },
            );
        }
    };
    let rpc_outcome = match rpc.node_status().await {
        Ok(s) => CheckOutcome::Ok {
            detail: format!("{} reachable (epoch {})", cfg.chain.rpc_url, s.epoch),
        },
        Err(e) => {
            return (
                CheckOutcome::Fail {
                    detail: format!("{}: {e}", cfg.chain.rpc_url),
                },
                CheckOutcome::Skipped {
                    detail: "rpc unreachable".into(),
                },
            );
        }
    };
    // Program responsive: a view call with no params that every
    // OctraVPN program version supports. `get_params` is the canonical
    // pre-flight from the runbook.
    let program_addr = Address::from_display(&cfg.chain.program_addr);
    let prog_outcome = match rpc
        .contract_call(&program_addr, "get_params", &[], None)
        .await
    {
        Ok(v) => CheckOutcome::Ok {
            detail: format!(
                "{}: get_params returned {}",
                cfg.chain.program_addr,
                trim_for_display(&v.to_string(), 64)
            ),
        },
        Err(e) => CheckOutcome::Fail {
            detail: format!("{}: get_params failed: {e}", cfg.chain.program_addr),
        },
    };
    (rpc_outcome, prog_outcome)
}

fn trim_for_display(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

fn render_config_validate(report: &ConfigValidateReport, json: bool) {
    if json {
        // Stable JSON shape so downstream tooling can consume it.
        match serde_json::to_string_pretty(report) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("config validate: serialize report: {e}"),
        }
        return;
    }
    let rows: [(&str, &CheckOutcome); 7] = [
        ("schema", &report.schema_parsed),
        ("wallet key", &report.wallet_key_loadable),
        ("wg key", &report.wg_key_loadable),
        ("audit dir", &report.audit_dir_writable),
        ("journal", &report.journal_path_writable),
        ("rpc", &report.rpc_reachable),
        ("program", &report.program_responsive),
    ];
    for (label, outcome) in rows {
        println!("{:<22} {:<6} {}", label, outcome.label(), outcome.detail());
    }
    println!();
    if report.overall_pass {
        println!("config OK");
    } else {
        println!("config FAILED");
    }
}

// ============================================================================
// `health` — reports
// ============================================================================

#[derive(Debug, Serialize)]
struct HealthReport {
    schema_parsed: CheckOutcome,
    endpoint_stake: CheckOutcome,
    endpoint_slashed: CheckOutcome,
    endpoint_unbonding: CheckOutcome,
    audit_log: CheckOutcome,
    receipt_journal: CheckOutcome,
    remote_health: CheckOutcome,
    overall_pass: bool,
}

pub(crate) fn run_health(args: &HealthArgs) -> Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build current-thread runtime")?;
    let report = rt.block_on(run_health_async(args));
    render_health(&report, args.json);
    Ok(i32::from(!report.overall_pass))
}

async fn run_health_async(args: &HealthArgs) -> HealthReport {
    let cfg_result = NodeConfig::load(&args.config);
    let (schema_parsed, cfg_opt) = match cfg_result {
        Ok(c) => (
            CheckOutcome::Ok {
                detail: format!("loaded {}", args.config.display()),
            },
            Some(c),
        ),
        Err(e) => (
            CheckOutcome::Fail {
                detail: format!("{e:#}"),
            },
            None,
        ),
    };
    let Some(cfg) = cfg_opt else {
        return HealthReport {
            schema_parsed,
            endpoint_stake: CheckOutcome::Skipped {
                detail: "no config".into(),
            },
            endpoint_slashed: CheckOutcome::Skipped {
                detail: "no config".into(),
            },
            endpoint_unbonding: CheckOutcome::Skipped {
                detail: "no config".into(),
            },
            audit_log: CheckOutcome::Skipped {
                detail: "no config".into(),
            },
            receipt_journal: CheckOutcome::Skipped {
                detail: "no config".into(),
            },
            remote_health: CheckOutcome::Skipped {
                detail: "no config".into(),
            },
            overall_pass: false,
        };
    };

    let (endpoint_stake, endpoint_slashed, endpoint_unbonding) = probe_endpoint_state(&cfg).await;
    let audit_log = probe_audit_log_file(cfg.control.audit_dir.as_deref());
    let receipt_journal = probe_journal_file(cfg.control.receipt_journal_path.as_deref());
    let remote_health = match args.remote.as_deref() {
        Some(url) => probe_remote_health(url).await,
        None => CheckOutcome::Skipped {
            detail: "no --remote passed".into(),
        },
    };

    let overall_pass = !schema_parsed.is_fail()
        && !endpoint_stake.is_fail()
        && !endpoint_slashed.is_fail()
        && !endpoint_unbonding.is_fail()
        && !audit_log.is_fail()
        && !receipt_journal.is_fail()
        && !remote_health.is_fail();

    HealthReport {
        schema_parsed,
        endpoint_stake,
        endpoint_slashed,
        endpoint_unbonding,
        audit_log,
        receipt_journal,
        remote_health,
        overall_pass,
    }
}

async fn probe_endpoint_state(cfg: &NodeConfig) -> (CheckOutcome, CheckOutcome, CheckOutcome) {
    let rpc = match cfg.chain.build_rpc_client() {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("build rpc: {e:#}");
            return (
                CheckOutcome::Fail { detail: msg },
                CheckOutcome::Skipped {
                    detail: "rpc unavailable".into(),
                },
                CheckOutcome::Skipped {
                    detail: "rpc unavailable".into(),
                },
            );
        }
    };
    let program = Address::from_display(&cfg.chain.program_addr);
    let validator = Address::from_display(&cfg.chain.validator_addr);
    let stake_outcome = match rpc
        .contract_call(
            &program,
            "get_endpoint_stake",
            &[json!(validator.display())],
            Some(&validator),
        )
        .await
    {
        Ok(v) => {
            let n = v.as_u64().unwrap_or(0);
            CheckOutcome::Ok {
                detail: format!("stake = {n} OU"),
            }
        }
        Err(e) => CheckOutcome::Fail {
            detail: format!("get_endpoint_stake: {e}"),
        },
    };
    let slashed_outcome = match rpc
        .contract_call(
            &program,
            "is_endpoint_slashed",
            &[json!(validator.display())],
            Some(&validator),
        )
        .await
    {
        Ok(v) => {
            let slashed = v.as_bool().unwrap_or_else(|| v.as_u64() == Some(1));
            if slashed {
                CheckOutcome::Fail {
                    detail: "endpoint is governance-slashed (permanent)".into(),
                }
            } else {
                CheckOutcome::Ok {
                    detail: "not slashed".into(),
                }
            }
        }
        Err(e) => CheckOutcome::Fail {
            detail: format!("is_endpoint_slashed: {e}"),
        },
    };
    let unbonding_outcome = match rpc
        .contract_call(
            &program,
            "get_endpoint_unbonding",
            &[json!(validator.display())],
            Some(&validator),
        )
        .await
    {
        Ok(v) => {
            let n = v.as_u64().unwrap_or(0);
            if n > 0 {
                CheckOutcome::Ok {
                    detail: format!(
                        "unbonding = {n} OU (call `octravpn-node finalize-unbond` after grace)"
                    ),
                }
            } else {
                CheckOutcome::Ok {
                    detail: "no unbonding in flight".into(),
                }
            }
        }
        // get_endpoint_unbonding is v1.1; v2/v3 don't have it. Treat
        // "method not found" as a soft skip rather than a hard fail.
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("unknown method")
                || msg.contains("not found")
                || msg.contains("invalid method")
            {
                CheckOutcome::Skipped {
                    detail: "get_endpoint_unbonding unsupported on this program shape".into(),
                }
            } else {
                CheckOutcome::Fail {
                    detail: format!("get_endpoint_unbonding: {e}"),
                }
            }
        }
    };
    (stake_outcome, slashed_outcome, unbonding_outcome)
}

fn probe_audit_log_file(dir: Option<&str>) -> CheckOutcome {
    let dir = dir.unwrap_or("./audit");
    let p = Path::new(dir);
    if !p.exists() {
        return CheckOutcome::Skipped {
            detail: format!("{dir}: not created yet (daemon hasn't booted)"),
        };
    }
    // Try to open the writer side. This both validates the HMAC key
    // is present + readable and that today's file path is openable.
    match AuditLog::open(p) {
        Ok(_) => CheckOutcome::Ok {
            detail: format!("{dir}: openable"),
        },
        Err(e) => CheckOutcome::Fail {
            detail: format!("{dir}: {e:#}"),
        },
    }
}

fn probe_journal_file(path: Option<&str>) -> CheckOutcome {
    let p = path.unwrap_or("./state/receipts.bin");
    let path = Path::new(p);
    if !path.exists() {
        return CheckOutcome::Skipped {
            detail: format!("{p}: not created yet"),
        };
    }
    match ReceiptJournal::open(path) {
        Ok(j) => CheckOutcome::Ok {
            detail: format!("{p}: {} session floor(s)", j.entries().len()),
        },
        Err(e) => CheckOutcome::Fail {
            detail: format!("{p}: {e}"),
        },
    }
}

async fn probe_remote_health(url: &str) -> CheckOutcome {
    // Use a quick raw HTTP probe via `RpcClient`-less reqwest. We pin
    // no roots; this is a localhost-or-LAN convenience. Production
    // operators with a TLS reverse proxy should pass the public URL.
    let target = if url.ends_with("/health") {
        url.to_string()
    } else {
        format!("{}/health", url.trim_end_matches('/'))
    };
    // Build a one-shot client. `reqwest` is already in the workspace
    // via other crates' transitive deps.
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return CheckOutcome::Fail {
                detail: format!("build client: {e}"),
            };
        }
    };
    match client.get(&target).send().await {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status.is_success() {
                CheckOutcome::Ok {
                    detail: format!("{target}: {status} {}", trim_for_display(&body, 80)),
                }
            } else {
                CheckOutcome::Fail {
                    detail: format!("{target}: {status} {}", trim_for_display(&body, 120)),
                }
            }
        }
        Err(e) => CheckOutcome::Fail {
            detail: format!("{target}: {e}"),
        },
    }
}

fn render_health(report: &HealthReport, json: bool) {
    if json {
        match serde_json::to_string_pretty(report) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("health: serialize: {e}"),
        }
        return;
    }
    let rows: [(&str, &CheckOutcome); 7] = [
        ("config", &report.schema_parsed),
        ("endpoint stake", &report.endpoint_stake),
        ("endpoint slashed", &report.endpoint_slashed),
        ("endpoint unbonding", &report.endpoint_unbonding),
        ("audit log", &report.audit_log),
        ("receipt journal", &report.receipt_journal),
        ("remote /health", &report.remote_health),
    ];
    for (label, outcome) in rows {
        println!("{:<22} {:<6} {}", label, outcome.label(), outcome.detail());
    }
    println!();
    if report.overall_pass {
        println!("health OK");
    } else {
        println!("health FAILED");
    }
}

// ============================================================================
// `audit tail` — live-follow + verify
// ============================================================================

pub(crate) fn run_audit_tail(args: &AuditTailArgs) -> Result<i32> {
    // Pick the file to tail. If a directory is passed, take the
    // lexically-latest `audit-*.jsonl` (which is also chronologically
    // latest because of the UTC-date prefix).
    let file = if args.audit_path.is_dir() {
        let mut best: Option<PathBuf> = None;
        for entry in fs::read_dir(&args.audit_path)
            .with_context(|| format!("readdir {}", args.audit_path.display()))?
        {
            let entry = entry?;
            let name = entry.file_name();
            let lossy = name.to_string_lossy();
            if lossy.starts_with("audit-") && lossy.ends_with(".jsonl") {
                let p = entry.path();
                if best.as_ref().map_or(true, |b| p > *b) {
                    best = Some(p);
                }
            }
        }
        let Some(p) = best else {
            eprintln!(
                "audit tail: no audit-*.jsonl files in {}",
                args.audit_path.display()
            );
            return Ok(3);
        };
        p
    } else if args.audit_path.exists() {
        args.audit_path.clone()
    } else {
        eprintln!("audit tail: {} does not exist", args.audit_path.display());
        return Ok(3);
    };

    // Locate the HMAC key, identical resolution to `audit verify`.
    let key = match locate_hmac_key(&args.audit_path, args.hmac_key.as_deref()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("audit tail: {e}");
            return Ok(3);
        }
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    // Replay the whole file once to recover the running `prev_mac`,
    // verifying as we go. Print every existing line that passes.
    let mut prev_mac = [0u8; 32];
    let f = fs::File::open(&file).with_context(|| format!("open {}", file.display()))?;
    let mut reader = BufReader::new(f);
    let mut line_no: u64 = 0;
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        line_no += 1;
        if buf.trim().is_empty() {
            continue;
        }
        match verify_one_line(&key, &prev_mac, buf.trim_end()) {
            Ok(next_mac) => {
                prev_mac = next_mac;
                writeln!(out, "{}", format_tail_line(line_no, buf.trim_end()))?;
            }
            Err(e) => {
                writeln!(
                    out,
                    "audit tail: CHAIN BREAK at line {line_no}: {e}\n  raw: {}",
                    buf.trim_end()
                )?;
                if !args.follow {
                    return Ok(1);
                }
            }
        }
    }

    if !args.follow {
        return Ok(0);
    }

    // Follow mode: poll the file for new appends. We snapshot the
    // current position and re-read whatever lands. Rotation across
    // midnight is intentionally NOT auto-followed — the tail target is
    // pinned at startup (mirrors `tail -F` against a single named
    // file).
    let mut pos = reader.stream_position()?;
    loop {
        // Sleep first so a tight Ctrl-C is responsive.
        std::thread::sleep(Duration::from_millis(args.poll_ms.max(50)));
        let f = fs::File::open(&file).with_context(|| format!("re-open {}", file.display()))?;
        let len = f.metadata()?.len();
        if len < pos {
            writeln!(out, "audit tail: file shrank ({pos} -> {len}) — pinned target was rotated/truncated; stopping")?;
            return Ok(2);
        }
        if len == pos {
            continue;
        }
        let mut reader = BufReader::new(f);
        reader.seek(SeekFrom::Start(pos))?;
        loop {
            buf.clear();
            let n = reader.read_line(&mut buf)?;
            if n == 0 {
                break;
            }
            // Only count fully-terminated lines so a partial append
            // doesn't get treated as a complete record.
            if !buf.ends_with('\n') {
                // Reset position to before this partial line so the
                // next poll picks up the complete line.
                break;
            }
            line_no += 1;
            pos += n as u64;
            if buf.trim().is_empty() {
                continue;
            }
            match verify_one_line(&key, &prev_mac, buf.trim_end()) {
                Ok(next_mac) => {
                    prev_mac = next_mac;
                    writeln!(out, "{}", format_tail_line(line_no, buf.trim_end()))?;
                }
                Err(e) => {
                    writeln!(
                        out,
                        "audit tail: CHAIN BREAK at line {line_no}: {e}\n  raw: {}",
                        buf.trim_end()
                    )?;
                }
            }
        }
    }
}

fn verify_one_line(key: &[u8; 32], prev_mac: &[u8; 32], line: &str) -> Result<[u8; 32]> {
    let v: Value = serde_json::from_str(line).context("parse chained line")?;
    let claimed_prev = v
        .get("prev_mac")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing prev_mac"))?;
    let claimed_mac = v
        .get("mac")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing mac"))?;
    let canonical = v
        .get("record_json")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing record_json"))?;
    let expected_prev = hex::encode(prev_mac);
    if claimed_prev != expected_prev {
        anyhow::bail!("chain break: expected prev_mac={expected_prev}, claimed={claimed_prev}");
    }
    let expect = chain_step(key, prev_mac, canonical.as_bytes());
    if hex::encode(expect) != claimed_mac {
        anyhow::bail!("mac mismatch");
    }
    Ok(expect)
}

fn locate_hmac_key(audit_path: &Path, explicit: Option<&Path>) -> Result<[u8; 32]> {
    resolve_hmac_key(audit_path, explicit).map_err(|e| match e {
        HmacKeyError::NotFound(p) => {
            anyhow::anyhow!("HMAC key not found at {} (pass --hmac-key)", p.display())
        }
        HmacKeyError::Invalid(e) => e,
    })
}

fn format_tail_line(line_no: u64, raw: &str) -> String {
    // Strip the chain envelope for display — operators want to see
    // the inner record, not the prev_mac/mac dance. Falls back to the
    // raw line if the envelope shape is unexpected.
    if let Ok(v) = serde_json::from_str::<Value>(raw) {
        if let Some(inner) = v.get("record_json").and_then(Value::as_str) {
            return format!("[#{line_no:>6}] {inner}");
        }
    }
    format!("[#{line_no:>6}] {raw}")
}

// ============================================================================
// `receipt verify` — single-session view
// ============================================================================

#[derive(Debug, Serialize)]
struct ReceiptVerifyReport {
    session_id_hex: String,
    journal_floor: Option<u64>,
    audit_seqs: Vec<u64>,
    cross_check_pass: bool,
    detail: String,
}

pub(crate) fn run_receipt_verify(args: &ReceiptVerifyArgs) -> Result<i32> {
    let sid = parse_session(&args.session_id)?;
    let report = build_receipt_report(&sid, &args.journal_path, args.audit_path.as_deref())?;
    render_receipt_verify(&report, args.json);
    Ok(i32::from(!report.cross_check_pass))
}

fn parse_session(raw: &str) -> Result<SessionId> {
    if let Some(sid) = SessionId::from_hex(raw) {
        return Ok(sid);
    }
    if let Ok(n) = raw.parse::<u64>() {
        return Ok(SessionId::from_u64(n));
    }
    anyhow::bail!("session id `{raw}`: must be 64-char hex or a u64 (legacy v1 form)")
}

fn build_receipt_report(
    sid: &SessionId,
    journal_path: &Path,
    audit_path: Option<&Path>,
) -> Result<ReceiptVerifyReport> {
    let mut report = ReceiptVerifyReport {
        session_id_hex: sid.to_hex(),
        journal_floor: None,
        audit_seqs: Vec::new(),
        cross_check_pass: true,
        detail: String::new(),
    };

    if journal_path.exists() {
        let j = ReceiptJournal::open(journal_path)
            .with_context(|| format!("open journal {}", journal_path.display()))?;
        let floor = j.floor(sid);
        if floor > 0 {
            report.journal_floor = Some(floor);
        }
    } else {
        let _ = write!(
            report.detail,
            "journal {} does not exist; ",
            journal_path.display()
        );
    }

    if let Some(audit_path) = audit_path {
        report.audit_seqs = harvest_audit_seqs(audit_path, sid)?;
    }

    // Cross-check: every audit-emitted seq must be <= journal floor
    // (the journal floor monotonically tracks the highest signed seq;
    // a seq above the floor means we signed something the journal
    // didn't record — a P1-8/9 invariant break).
    if let (Some(floor), false) = (report.journal_floor, report.audit_seqs.is_empty()) {
        let max_audit = report.audit_seqs.iter().copied().max().unwrap_or(0);
        if max_audit > floor {
            report.cross_check_pass = false;
            let _ = write!(
                report.detail,
                "audit max seq {max_audit} > journal floor {floor} (P1-8/9 invariant violation); ",
            );
        } else {
            let _ = write!(
                report.detail,
                "max audit seq {max_audit} <= journal floor {floor} (OK); ",
            );
        }
    } else if report.journal_floor.is_none() && !report.audit_seqs.is_empty() {
        report.cross_check_pass = false;
        report.detail.push_str(
            "audit log carries entries for this session but journal has no floor (lost-state); ",
        );
    } else if report.journal_floor.is_none() && report.audit_seqs.is_empty() {
        report
            .detail
            .push_str("no journal floor and no audit entries — session unknown locally; ");
        report.cross_check_pass = false;
    } else {
        report
            .detail
            .push_str("journal floor present, no audit entries cross-referenced; ");
    }

    Ok(report)
}

fn harvest_audit_seqs(path: &Path, sid: &SessionId) -> Result<Vec<u64>> {
    let wanted = sid.to_hex();
    let mut out = Vec::new();
    let files = if path.is_dir() {
        let mut entries = Vec::new();
        for e in fs::read_dir(path).with_context(|| format!("readdir {}", path.display()))? {
            let e = e?;
            let name = e.file_name();
            let lossy = name.to_string_lossy();
            if lossy.starts_with("audit-") && lossy.ends_with(".jsonl") {
                entries.push(e.path());
            }
        }
        entries.sort();
        entries
    } else if path.exists() {
        vec![path.to_path_buf()]
    } else {
        return Ok(out);
    };
    for f in files {
        let file = fs::File::open(&f).with_context(|| format!("open {}", f.display()))?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = match line {
                Ok(l) if l.trim().is_empty() => continue,
                Ok(l) => l,
                Err(_) => continue,
            };
            let v: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some(canonical) = v.get("record_json").and_then(Value::as_str) else {
                continue;
            };
            let Ok(rec) = serde_json::from_str::<Value>(canonical) else {
                continue;
            };
            let Some(rec_sid) = rec.get("session_id").and_then(Value::as_str) else {
                continue;
            };
            if rec_sid != wanted {
                continue;
            }
            let seq = rec.get("seq").and_then(Value::as_u64).or_else(|| {
                rec.get("extra")
                    .and_then(|e| e.get("seq"))
                    .and_then(Value::as_u64)
            });
            if let Some(s) = seq {
                out.push(s);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn render_receipt_verify(report: &ReceiptVerifyReport, json: bool) {
    if json {
        match serde_json::to_string_pretty(report) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("receipt verify: serialize: {e}"),
        }
        return;
    }
    println!("session_id      {}", report.session_id_hex);
    match report.journal_floor {
        Some(n) => println!("journal_floor   {n}"),
        None => println!("journal_floor   <none>"),
    }
    if report.audit_seqs.is_empty() {
        println!("audit_seqs      <none>");
    } else {
        println!("audit_seqs      {:?}", report.audit_seqs);
    }
    println!("detail          {}", report.detail.trim_end_matches("; "));
    println!();
    if report.cross_check_pass {
        println!("receipt verify OK");
    } else {
        println!("receipt verify FAILED");
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditLog, AuditRecord};
    use serde_json::json;
    use tempfile::tempdir;

    fn sid_hex(b: u8) -> String {
        hex::encode([b; 32])
    }

    fn write_basic_node_toml(path: &Path, audit_dir: &str, journal: &str) {
        let toml = format!(
            r#"
[chain]
rpc_url = "http://127.0.0.1:1"
program_addr = "oct1111111111111111111111111111111111111111111"
validator_addr = "oct2222222222222222222222222222222222222222222"
wallet_secret_path = "{wallet}"

[tunnel]
public_endpoint = "1.2.3.4:51820"
listen = "0.0.0.0:51820"
wg_secret_path = "{wg}"

[pricing]
price_per_mb = 100
region = "eu-west"

[control]
listen = "0.0.0.0:51821"
audit_dir = "{audit_dir}"
receipt_journal_path = "{journal}"
"#,
            wallet = path.parent().unwrap().join("wallet.key").display(),
            wg = path.parent().unwrap().join("wg.key").display(),
            audit_dir = audit_dir,
            journal = journal,
        );
        fs::write(path, toml).unwrap();
        // Write throwaway key files referenced above so the secret
        // probes have something to read.
        fs::write(path.parent().unwrap().join("wallet.key"), [0xAA; 32]).unwrap();
        fs::write(path.parent().unwrap().join("wg.key"), [0xBB; 32]).unwrap();
    }

    #[test]
    fn config_validate_offline_passes_on_well_formed_config() {
        let dir = tempdir().unwrap();
        let toml = dir.path().join("node.toml");
        let audit_dir = dir.path().join("audit").to_string_lossy().to_string();
        let journal = dir
            .path()
            .join("receipts.bin")
            .to_string_lossy()
            .to_string();
        write_basic_node_toml(&toml, &audit_dir, &journal);
        let args = ConfigValidateArgs {
            path: toml,
            offline: true,
            json: false,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let report = rt.block_on(run_config_validate(&args));
        assert!(
            report.overall_pass,
            "offline config validate should pass: {report:#?}"
        );
        assert!(matches!(report.rpc_reachable, CheckOutcome::Skipped { .. }));
        assert!(matches!(
            report.program_responsive,
            CheckOutcome::Skipped { .. }
        ));
    }

    #[test]
    fn config_validate_fails_on_missing_wallet() {
        let dir = tempdir().unwrap();
        let toml = dir.path().join("node.toml");
        let audit_dir = dir.path().join("audit").to_string_lossy().to_string();
        let journal = dir
            .path()
            .join("receipts.bin")
            .to_string_lossy()
            .to_string();
        write_basic_node_toml(&toml, &audit_dir, &journal);
        fs::remove_file(dir.path().join("wallet.key")).unwrap();
        let args = ConfigValidateArgs {
            path: toml,
            offline: true,
            json: false,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let report = rt.block_on(run_config_validate(&args));
        assert!(!report.overall_pass);
        assert!(matches!(
            report.wallet_key_loadable,
            CheckOutcome::Fail { .. }
        ));
    }

    #[test]
    fn config_validate_fails_on_broken_schema() {
        let dir = tempdir().unwrap();
        let toml = dir.path().join("node.toml");
        fs::write(&toml, "this is not toml").unwrap();
        let args = ConfigValidateArgs {
            path: toml,
            offline: true,
            json: false,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let report = rt.block_on(run_config_validate(&args));
        assert!(!report.overall_pass);
        assert!(matches!(report.schema_parsed, CheckOutcome::Fail { .. }));
    }

    #[test]
    fn audit_tail_prints_existing_lines_and_verifies_chain() {
        let dir = tempdir().unwrap();
        // Build a small audit log.
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..3u64 {
            log.write(&AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "announce",
                source: None,
                session_id: Some(sid_hex(1)),
                extra: json!({"i": i}),
            })
            .unwrap();
        }
        // Find the rotated audit file.
        let audit_file = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let args = AuditTailArgs {
            audit_path: audit_file,
            hmac_key: Some(dir.path().join(".audit.key")),
            follow: false,
            poll_ms: 250,
        };
        // Smoke test — no panics, exit 0 on a clean chain.
        let code = run_audit_tail(&args).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn audit_tail_reports_chain_break_and_exits_nonzero() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        for i in 0..3u64 {
            log.write(&AuditRecord {
                ts_unix: 1_700_000_000 + i,
                kind: "announce",
                source: None,
                session_id: Some(sid_hex(1)),
                extra: json!({"i": i}),
            })
            .unwrap();
        }
        // Tamper line 2 (1-indexed).
        let audit_file = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let body = fs::read_to_string(&audit_file).unwrap();
        let mut lines: Vec<String> = body.lines().map(String::from).collect();
        lines[1] = lines[1].replacen("\\\"i\\\":1", "\\\"i\\\":99", 1);
        fs::write(&audit_file, lines.join("\n") + "\n").unwrap();

        let args = AuditTailArgs {
            audit_path: audit_file,
            hmac_key: Some(dir.path().join(".audit.key")),
            follow: false,
            poll_ms: 250,
        };
        let code = run_audit_tail(&args).unwrap();
        assert_ne!(code, 0, "tampered chain must surface non-zero exit");
    }

    #[test]
    fn receipt_verify_reports_journal_floor_and_audit_seqs() {
        let dir = tempdir().unwrap();
        // Journal.
        let journal_path = dir.path().join("receipts.bin");
        let j = ReceiptJournal::open(&journal_path).unwrap();
        j.bump(&SessionId::new([0xAA; 32]), 7).unwrap();
        // Audit.
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "receipt_signed",
            source: None,
            session_id: Some(sid_hex(0xAA)),
            extra: json!({"seq": 5}),
        })
        .unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_001,
            kind: "receipt_signed",
            source: None,
            session_id: Some(sid_hex(0xAA)),
            extra: json!({"seq": 7}),
        })
        .unwrap();

        let report =
            build_receipt_report(&SessionId::new([0xAA; 32]), &journal_path, Some(dir.path()))
                .unwrap();
        assert_eq!(report.journal_floor, Some(7));
        assert_eq!(report.audit_seqs, vec![5, 7]);
        assert!(report.cross_check_pass, "{:?}", report.detail);
    }

    #[test]
    fn receipt_verify_flags_audit_above_floor_as_invariant_break() {
        let dir = tempdir().unwrap();
        let journal_path = dir.path().join("receipts.bin");
        let j = ReceiptJournal::open(&journal_path).unwrap();
        j.bump(&SessionId::new([0xAA; 32]), 3).unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "receipt_signed",
            source: None,
            session_id: Some(sid_hex(0xAA)),
            extra: json!({"seq": 9}),
        })
        .unwrap();
        let report =
            build_receipt_report(&SessionId::new([0xAA; 32]), &journal_path, Some(dir.path()))
                .unwrap();
        assert!(!report.cross_check_pass);
        assert!(report.detail.contains("P1-8/9"));
    }

    #[test]
    fn receipt_verify_parses_decimal_session_id() {
        let dir = tempdir().unwrap();
        let journal_path = dir.path().join("receipts.bin");
        // Build a u64 session id from `42` — same conversion the
        // legacy v1 surface uses.
        let sid = SessionId::from_u64(42);
        let j = ReceiptJournal::open(&journal_path).unwrap();
        j.bump(&sid, 1).unwrap();
        // Decimal parse should resolve to the same sid.
        let parsed = parse_session("42").unwrap();
        assert_eq!(parsed.to_hex(), sid.to_hex());
        // And the report finds the floor.
        let report = build_receipt_report(&parsed, &journal_path, None).unwrap();
        assert_eq!(report.journal_floor, Some(1));
    }

    // ----------------------------------------------------------------
    // Additional coverage — config validate
    // ----------------------------------------------------------------

    fn build_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn config_validate_skips_everything_when_schema_missing_file() {
        let dir = tempdir().unwrap();
        let args = ConfigValidateArgs {
            path: dir.path().join("does-not-exist.toml"),
            offline: true,
            json: false,
        };
        let rt = build_runtime();
        let report = rt.block_on(run_config_validate(&args));
        assert!(!report.overall_pass);
        assert!(matches!(report.schema_parsed, CheckOutcome::Fail { .. }));
        assert!(matches!(
            report.wallet_key_loadable,
            CheckOutcome::Skipped { .. }
        ));
        assert!(matches!(
            report.wg_key_loadable,
            CheckOutcome::Skipped { .. }
        ));
        assert!(matches!(report.rpc_reachable, CheckOutcome::Skipped { .. }));
    }

    #[test]
    fn config_validate_fails_on_missing_wg_key() {
        let dir = tempdir().unwrap();
        let toml = dir.path().join("node.toml");
        let audit_dir = dir.path().join("audit").to_string_lossy().to_string();
        let journal = dir
            .path()
            .join("receipts.bin")
            .to_string_lossy()
            .to_string();
        write_basic_node_toml(&toml, &audit_dir, &journal);
        fs::remove_file(dir.path().join("wg.key")).unwrap();
        let args = ConfigValidateArgs {
            path: toml,
            offline: true,
            json: false,
        };
        let rt = build_runtime();
        let report = rt.block_on(run_config_validate(&args));
        assert!(!report.overall_pass);
        assert!(matches!(report.wg_key_loadable, CheckOutcome::Fail { .. }));
    }

    #[test]
    fn config_validate_fails_on_empty_wallet_file() {
        let dir = tempdir().unwrap();
        let toml = dir.path().join("node.toml");
        let audit_dir = dir.path().join("audit").to_string_lossy().to_string();
        let journal = dir
            .path()
            .join("receipts.bin")
            .to_string_lossy()
            .to_string();
        write_basic_node_toml(&toml, &audit_dir, &journal);
        // Truncate wallet key to 0 bytes.
        fs::write(dir.path().join("wallet.key"), b"").unwrap();
        let args = ConfigValidateArgs {
            path: toml,
            offline: true,
            json: false,
        };
        let rt = build_runtime();
        let report = rt.block_on(run_config_validate(&args));
        assert!(!report.overall_pass);
        let detail = match report.wallet_key_loadable {
            CheckOutcome::Fail { detail } => detail,
            other => panic!("expected Fail, got {other:?}"),
        };
        assert!(detail.contains("empty"), "got: {detail}");
    }

    #[test]
    fn config_validate_offline_short_circuits_chain_probes() {
        let dir = tempdir().unwrap();
        let toml = dir.path().join("node.toml");
        let audit_dir = dir.path().join("audit").to_string_lossy().to_string();
        let journal = dir
            .path()
            .join("receipts.bin")
            .to_string_lossy()
            .to_string();
        write_basic_node_toml(&toml, &audit_dir, &journal);
        let args = ConfigValidateArgs {
            path: toml,
            offline: true,
            json: false,
        };
        let rt = build_runtime();
        let report = rt.block_on(run_config_validate(&args));
        match report.rpc_reachable {
            CheckOutcome::Skipped { detail } => assert!(detail.contains("offline")),
            other => panic!("expected Skipped with offline marker, got {other:?}"),
        }
    }

    #[test]
    fn config_validate_chain_probe_fails_on_unreachable_rpc() {
        // Without `--offline` the probe MUST attempt the dial; an
        // unreachable :1 port surfaces as `Fail` for rpc_reachable.
        let dir = tempdir().unwrap();
        let toml = dir.path().join("node.toml");
        let audit_dir = dir.path().join("audit").to_string_lossy().to_string();
        let journal = dir
            .path()
            .join("receipts.bin")
            .to_string_lossy()
            .to_string();
        write_basic_node_toml(&toml, &audit_dir, &journal);
        let args = ConfigValidateArgs {
            path: toml,
            offline: false,
            json: false,
        };
        let rt = build_runtime();
        let report = rt.block_on(run_config_validate(&args));
        assert!(!report.overall_pass);
        assert!(matches!(report.rpc_reachable, CheckOutcome::Fail { .. }));
    }

    #[test]
    fn config_validate_run_config_returns_exit_code_one_on_fail() {
        let dir = tempdir().unwrap();
        let toml = dir.path().join("node.toml");
        fs::write(&toml, "garbage").unwrap();
        let args = ConfigValidateArgs {
            path: toml,
            offline: true,
            json: false,
        };
        let code = run_config(ConfigCmd::Validate(args)).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn config_validate_run_config_returns_exit_code_zero_on_pass() {
        let dir = tempdir().unwrap();
        let toml = dir.path().join("node.toml");
        let audit_dir = dir.path().join("audit").to_string_lossy().to_string();
        let journal = dir
            .path()
            .join("receipts.bin")
            .to_string_lossy()
            .to_string();
        write_basic_node_toml(&toml, &audit_dir, &journal);
        let args = ConfigValidateArgs {
            path: toml,
            offline: true,
            json: true, // JSON output path is also exercised here.
        };
        let code = run_config(ConfigCmd::Validate(args)).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn probe_secret_file_reports_missing() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.key");
        let outcome = probe_secret_file(missing.to_str().unwrap());
        assert!(matches!(outcome, CheckOutcome::Fail { .. }));
        assert!(outcome.detail().contains("does not exist"));
    }

    #[test]
    fn probe_secret_file_accepts_nonempty() {
        let dir = tempdir().unwrap();
        let key = dir.path().join("k");
        fs::write(&key, [0u8; 16]).unwrap();
        let outcome = probe_secret_file(key.to_str().unwrap());
        assert!(matches!(outcome, CheckOutcome::Ok { .. }));
    }

    #[test]
    fn probe_audit_dir_creates_when_missing() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("does/not/exist/yet");
        let outcome = probe_audit_dir(Some(nested.to_str().unwrap()));
        assert!(matches!(outcome, CheckOutcome::Ok { .. }));
        assert!(nested.exists());
    }

    #[test]
    fn probe_journal_path_opens_existing_file() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("receipts.bin");
        let j = ReceiptJournal::open(&p).unwrap();
        j.bump(&SessionId::new([1u8; 32]), 3).unwrap();
        drop(j);
        let outcome = probe_journal_path(Some(p.to_str().unwrap()));
        assert!(matches!(outcome, CheckOutcome::Ok { .. }));
    }

    #[test]
    fn check_outcome_helpers_are_consistent() {
        let ok = CheckOutcome::Ok { detail: "x".into() };
        let f = CheckOutcome::Fail { detail: "y".into() };
        let s = CheckOutcome::Skipped { detail: "z".into() };
        assert!(!ok.is_fail());
        assert!(f.is_fail());
        assert!(!s.is_fail());
        assert_eq!(ok.label(), "OK");
        assert_eq!(f.label(), "FAIL");
        assert_eq!(s.label(), "SKIP");
        assert_eq!(ok.detail(), "x");
        assert_eq!(f.detail(), "y");
        assert_eq!(s.detail(), "z");
    }

    #[test]
    fn trim_for_display_truncates_with_ellipsis() {
        assert_eq!(trim_for_display("abcdef", 10), "abcdef");
        let long = "x".repeat(100);
        let out = trim_for_display(&long, 16);
        assert!(out.ends_with('…'));
        assert!(out.starts_with(&"x".repeat(16)));
    }

    #[test]
    fn format_tail_line_strips_envelope_when_record_json_present() {
        let envelope = json!({
            "prev_mac": "00",
            "mac": "11",
            "record_json": "{\"kind\":\"announce\"}",
        });
        let s = format_tail_line(7, &envelope.to_string());
        assert!(s.contains("[#     7]"));
        assert!(s.contains("kind"));
        // Should be the inner record, not the envelope.
        assert!(!s.contains("prev_mac"));
    }

    #[test]
    fn format_tail_line_falls_back_to_raw_on_bad_envelope() {
        let s = format_tail_line(2, "not json at all");
        assert!(s.contains("not json at all"));
        assert!(s.contains("[#     2]"));
    }

    // ----------------------------------------------------------------
    // Additional coverage — health
    // ----------------------------------------------------------------

    #[test]
    fn probe_audit_log_file_skips_when_missing() {
        let dir = tempdir().unwrap();
        let outcome = probe_audit_log_file(Some(dir.path().join("missing").to_str().unwrap()));
        assert!(matches!(outcome, CheckOutcome::Skipped { .. }));
    }

    #[test]
    fn probe_audit_log_file_ok_when_dir_present() {
        let dir = tempdir().unwrap();
        // Open and drop a log so the dir + key are seeded.
        let _ = AuditLog::open(dir.path()).unwrap();
        let outcome = probe_audit_log_file(Some(dir.path().to_str().unwrap()));
        assert!(matches!(outcome, CheckOutcome::Ok { .. }));
    }

    #[test]
    fn probe_journal_file_skips_when_missing() {
        let dir = tempdir().unwrap();
        let outcome = probe_journal_file(Some(dir.path().join("nope.bin").to_str().unwrap()));
        assert!(matches!(outcome, CheckOutcome::Skipped { .. }));
    }

    #[test]
    fn probe_journal_file_reports_session_count() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("receipts.bin");
        let j = ReceiptJournal::open(&p).unwrap();
        j.bump(&SessionId::new([1u8; 32]), 4).unwrap();
        j.bump(&SessionId::new([2u8; 32]), 8).unwrap();
        drop(j);
        let outcome = probe_journal_file(Some(p.to_str().unwrap()));
        match outcome {
            CheckOutcome::Ok { detail } => assert!(detail.contains("2 session"), "got: {detail}"),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn probe_remote_health_ok_against_mock_server() {
        use axum::{routing::get, Router};
        let app = Router::new().route("/health", get(|| async { "OK" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _join = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        // Yield so the server is ready.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let outcome = probe_remote_health(&format!("http://{addr}")).await;
        assert!(matches!(outcome, CheckOutcome::Ok { .. }), "{outcome:?}");
    }

    #[tokio::test]
    async fn probe_remote_health_reports_non_2xx_as_fail() {
        use axum::{http::StatusCode, routing::get, Router};
        let app = Router::new().route(
            "/health",
            get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _join = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let outcome = probe_remote_health(&format!("http://{addr}")).await;
        assert!(matches!(outcome, CheckOutcome::Fail { .. }), "{outcome:?}");
    }

    #[tokio::test]
    async fn probe_remote_health_dial_failure_is_fail() {
        // Unroutable port → connect error.
        let outcome = probe_remote_health("http://127.0.0.1:1/health").await;
        assert!(matches!(outcome, CheckOutcome::Fail { .. }));
    }

    #[tokio::test]
    async fn probe_remote_health_appends_health_when_missing() {
        use axum::{routing::get, Router};
        let app = Router::new().route("/health", get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _join = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let bare = format!("http://{addr}/"); // trailing slash
        let outcome = probe_remote_health(&bare).await;
        assert!(matches!(outcome, CheckOutcome::Ok { .. }), "{outcome:?}");
    }

    // ----------------------------------------------------------------
    // Additional coverage — audit tail
    // ----------------------------------------------------------------

    #[test]
    fn audit_tail_returns_3_when_path_missing() {
        let dir = tempdir().unwrap();
        let args = AuditTailArgs {
            audit_path: dir.path().join("missing.jsonl"),
            hmac_key: None,
            follow: false,
            poll_ms: 250,
        };
        let code = run_audit_tail(&args).unwrap();
        assert_eq!(code, 3);
    }

    #[test]
    fn audit_tail_returns_3_when_directory_has_no_audit_files() {
        let dir = tempdir().unwrap();
        let args = AuditTailArgs {
            audit_path: dir.path().to_path_buf(),
            hmac_key: None,
            follow: false,
            poll_ms: 250,
        };
        let code = run_audit_tail(&args).unwrap();
        assert_eq!(code, 3);
    }

    #[test]
    fn audit_tail_picks_latest_file_from_directory() {
        let dir = tempdir().unwrap();
        // Seed two audit files; the lexically-latest one is opened.
        fs::write(dir.path().join("audit-2030-01-01.jsonl"), b"").unwrap();
        // Build a real (chained) audit log with one entry so the
        // verifier doesn't bail on a malformed line.
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "announce",
            source: None,
            session_id: Some(sid_hex(1)),
            extra: json!({}),
        })
        .unwrap();
        let args = AuditTailArgs {
            audit_path: dir.path().to_path_buf(),
            hmac_key: None,
            follow: false,
            poll_ms: 250,
        };
        let code = run_audit_tail(&args).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn audit_tail_returns_3_when_hmac_key_missing() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "announce",
            source: None,
            session_id: Some(sid_hex(1)),
            extra: json!({}),
        })
        .unwrap();
        let audit_file = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        // Remove the auto-written .audit.key so the resolver can't find
        // an HMAC key.
        fs::remove_file(dir.path().join(".audit.key")).unwrap();
        let args = AuditTailArgs {
            audit_path: audit_file,
            hmac_key: None,
            follow: false,
            poll_ms: 250,
        };
        let code = run_audit_tail(&args).unwrap();
        assert_eq!(code, 3);
    }

    #[test]
    fn audit_tail_explicit_hmac_key_wrong_size_returns_3() {
        let dir = tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "announce",
            source: None,
            session_id: Some(sid_hex(1)),
            extra: json!({}),
        })
        .unwrap();
        let audit_file = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
            .unwrap()
            .path();
        let bad_key = dir.path().join("short.key");
        fs::write(&bad_key, b"too-short").unwrap();
        let args = AuditTailArgs {
            audit_path: audit_file,
            hmac_key: Some(bad_key),
            follow: false,
            poll_ms: 250,
        };
        let code = run_audit_tail(&args).unwrap();
        assert_eq!(code, 3);
    }

    #[test]
    fn verify_one_line_detects_mac_mismatch() {
        let key = [7u8; 32];
        let prev = [0u8; 32];
        // Build a syntactically valid envelope with a bogus mac.
        let v = json!({
            "prev_mac": hex::encode(prev),
            "mac": hex::encode([0xFFu8; 32]),
            "record_json": "{\"k\":\"v\"}",
        });
        let err = verify_one_line(&key, &prev, &v.to_string()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("mac mismatch"), "{msg}");
    }

    #[test]
    fn verify_one_line_detects_prev_mac_break() {
        let key = [7u8; 32];
        let prev = [1u8; 32]; // verifier carries 0x01..; envelope claims 0x00..
        let v = json!({
            "prev_mac": hex::encode([0u8; 32]),
            "mac": hex::encode([0u8; 32]),
            "record_json": "{}",
        });
        let err = verify_one_line(&key, &prev, &v.to_string()).unwrap_err();
        assert!(format!("{err:#}").contains("chain break"));
    }

    // ----------------------------------------------------------------
    // Additional coverage — receipt verify
    // ----------------------------------------------------------------

    #[test]
    fn parse_session_rejects_garbage() {
        let r = parse_session("not-a-session-id");
        assert!(r.is_err());
    }

    #[test]
    fn parse_session_accepts_full_hex() {
        let hex = "a".repeat(64);
        let sid = parse_session(&hex).unwrap();
        assert_eq!(sid.to_hex(), hex);
    }

    #[test]
    fn receipt_verify_flags_audit_without_floor_as_lost_state() {
        let dir = tempdir().unwrap();
        // Don't create a journal at all; only audit entries.
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000,
            kind: "receipt_signed",
            source: None,
            session_id: Some(sid_hex(0xAA)),
            extra: json!({"seq": 3}),
        })
        .unwrap();
        let report = build_receipt_report(
            &SessionId::new([0xAA; 32]),
            &dir.path().join("missing.bin"),
            Some(dir.path()),
        )
        .unwrap();
        assert!(report.journal_floor.is_none());
        assert!(!report.cross_check_pass);
        assert!(report.detail.contains("lost-state"));
    }

    #[test]
    fn receipt_verify_unknown_session_when_no_floor_and_no_audit_entries() {
        let dir = tempdir().unwrap();
        let journal_path = dir.path().join("receipts.bin");
        // Empty journal (only magic) — open then drop without bump.
        let _ = ReceiptJournal::open(&journal_path).unwrap();
        let report =
            build_receipt_report(&SessionId::new([0xBB; 32]), &journal_path, Some(dir.path()))
                .unwrap();
        assert!(report.journal_floor.is_none());
        assert!(report.audit_seqs.is_empty());
        assert!(!report.cross_check_pass);
        assert!(report.detail.contains("session unknown locally"));
    }

    #[test]
    fn receipt_verify_journal_floor_only_passes() {
        let dir = tempdir().unwrap();
        let journal_path = dir.path().join("receipts.bin");
        let j = ReceiptJournal::open(&journal_path).unwrap();
        j.bump(&SessionId::new([0xAA; 32]), 4).unwrap();
        let report =
            build_receipt_report(&SessionId::new([0xAA; 32]), &journal_path, None).unwrap();
        assert_eq!(report.journal_floor, Some(4));
        assert!(report.audit_seqs.is_empty());
        assert!(report.cross_check_pass);
    }

    #[test]
    fn run_receipt_verify_returns_zero_on_pass() {
        let dir = tempdir().unwrap();
        let journal_path = dir.path().join("receipts.bin");
        let j = ReceiptJournal::open(&journal_path).unwrap();
        j.bump(&SessionId::new([0xAA; 32]), 4).unwrap();
        drop(j);
        let args = ReceiptVerifyArgs {
            session_id: sid_hex(0xAA),
            journal_path,
            audit_path: None,
            json: false,
        };
        let code = run_receipt_verify(&args).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn run_receipt_verify_returns_one_when_unknown_session() {
        let dir = tempdir().unwrap();
        let journal_path = dir.path().join("receipts.bin");
        // Empty journal.
        let _ = ReceiptJournal::open(&journal_path).unwrap();
        let args = ReceiptVerifyArgs {
            session_id: sid_hex(0xCD),
            journal_path,
            audit_path: Some(dir.path().to_path_buf()),
            json: true,
        };
        let code = run_receipt_verify(&args).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn harvest_audit_seqs_dedupes_and_sorts() {
        let dir = tempdir().unwrap();
        let sid = SessionId::new([0xAA; 32]);
        let log = AuditLog::open(dir.path()).unwrap();
        for s in [3u64, 1, 3, 2, 2] {
            log.write(&AuditRecord {
                ts_unix: 1_700_000_000 + s,
                kind: "receipt_signed",
                source: None,
                session_id: Some(sid.to_hex()),
                extra: json!({"seq": s}),
            })
            .unwrap();
        }
        let seqs = harvest_audit_seqs(dir.path(), &sid).unwrap();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[test]
    fn harvest_audit_seqs_ignores_other_sessions() {
        let dir = tempdir().unwrap();
        let target = SessionId::new([0xAA; 32]);
        let other = SessionId::new([0xBB; 32]);
        let log = AuditLog::open(dir.path()).unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_001,
            kind: "receipt_signed",
            source: None,
            session_id: Some(target.to_hex()),
            extra: json!({"seq": 9}),
        })
        .unwrap();
        log.write(&AuditRecord {
            ts_unix: 1_700_000_002,
            kind: "receipt_signed",
            source: None,
            session_id: Some(other.to_hex()),
            extra: json!({"seq": 4}),
        })
        .unwrap();
        let seqs = harvest_audit_seqs(dir.path(), &target).unwrap();
        assert_eq!(seqs, vec![9]);
    }

    #[test]
    fn harvest_audit_seqs_returns_empty_on_missing_path() {
        let dir = tempdir().unwrap();
        let sid = SessionId::new([0xAA; 32]);
        let seqs = harvest_audit_seqs(&dir.path().join("missing"), &sid).unwrap();
        assert!(seqs.is_empty());
    }
}
