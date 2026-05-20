//! `audit` (subcommand tree) + `verify-audit-log` (deprecated alias).
//!
//! Both surfaces are pure local-file inspectors — no Hub, no chain.
//! `verify-audit-log` still opens an `AuditLog` to recover the HMAC key
//! from the configured `audit_dir`, which means it needs a Hub-equivalent
//! file-system view; we satisfy that by routing through the Hub (kept
//! `needs_hub == true` for the deprecated alias so the existing
//! `Hub::open_audit_log` path still drives the key load).

use anyhow::Result;
use async_trait::async_trait;
use tracing::info;

use crate::audit_cli;

use super::{CliContext, Subcommand};

/// `octravpn-node audit <subcmd>` — pure file-tree surface; the dispatcher
/// uses `process::exit` to surface the structured exit codes (1/2/3) from
/// `audit_cli::dispatch`. We keep that contract: `dispatch()` calls
/// `std::process::exit` rather than returning, so callers (cron, harness)
/// see the precise exit code instead of a flattened `Ok(0)`.
#[derive(clap::Args, Debug)]
pub(crate) struct AuditArgs {
    #[command(subcommand)]
    pub(crate) cmd: audit_cli::AuditCmd,
}

#[async_trait]
impl Subcommand for AuditArgs {
    fn needs_hub(&self) -> bool {
        false
    }
    async fn dispatch(self, _ctx: CliContext<'_>) -> Result<i32> {
        let code = audit_cli::dispatch(self.cmd);
        std::process::exit(code);
    }
}

/// `octravpn-node verify-audit-log <path>` — deprecated alias for
/// `audit verify --audit-path <path>`. Kept so existing operator runbooks
/// keep working. Hub-bound because it reads the audit key out of the
/// configured `audit_dir` via `Hub::open_audit_log`.
#[derive(clap::Args, Debug)]
pub(crate) struct VerifyAuditLogArgs {
    /// Path to the audit JSONL file to verify.
    pub(crate) path: std::path::PathBuf,
}

#[async_trait]
impl Subcommand for VerifyAuditLogArgs {
    fn needs_hub(&self) -> bool {
        true
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        let hub = ctx.hub();
        let audit = hub
            .open_audit_log()
            .ok_or_else(|| anyhow::anyhow!("audit_dir not configured"))?;
        let key = audit.key();
        // `verify_file` returns a rich `FileVerifyReport` (the shared
        // verifier the new `audit_cli` also calls). Surface any chain
        // error here so the legacy `verify-audit-log` command stays
        // usable as a yes/no check.
        let report = crate::audit::AuditLog::verify_file(&key, &self.path)?;
        if let Some(err) = report.first_error {
            anyhow::bail!("{err}");
        }
        let n = report.entries;
        info!(verified = n, "audit chain ok");
        println!("OK ({n} entries)");
        Ok(0)
    }
}
