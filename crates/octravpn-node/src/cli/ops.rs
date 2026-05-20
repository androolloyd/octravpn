//! `config` / `health` / `audit-tail` / `receipt-verify` — the #232
//! operator-facing surfaces. All Hub-free; each builds its own short-
//! lived RPC client or opens local files directly. The structured exit
//! codes from `cli_ops::run_*` propagate via `std::process::exit` so
//! cron pipelines see the precise code instead of a flattened `Ok(0)`.

use anyhow::Result;
use async_trait::async_trait;

use crate::cli_ops;

use super::{CliContext, Subcommand};

/// `octravpn-node config <subcmd>`
#[derive(clap::Args, Debug)]
pub(crate) struct ConfigArgs {
    #[command(subcommand)]
    pub(crate) cmd: cli_ops::ConfigCmd,
}

#[async_trait]
impl Subcommand for ConfigArgs {
    fn needs_hub(&self) -> bool {
        false
    }
    async fn dispatch(self, _ctx: CliContext<'_>) -> Result<i32> {
        let code = cli_ops::run_config(self.cmd)?;
        std::process::exit(code);
    }
}

/// `octravpn-node health …`
pub(crate) type HealthArgs = cli_ops::HealthArgs;

#[async_trait]
impl Subcommand for HealthArgs {
    fn needs_hub(&self) -> bool {
        false
    }
    async fn dispatch(self, _ctx: CliContext<'_>) -> Result<i32> {
        let code = cli_ops::run_health(self)?;
        std::process::exit(code);
    }
}

/// `octravpn-node audit-tail …`
pub(crate) type AuditTailArgs = cli_ops::AuditTailArgs;

#[async_trait]
impl Subcommand for AuditTailArgs {
    fn needs_hub(&self) -> bool {
        false
    }
    async fn dispatch(self, _ctx: CliContext<'_>) -> Result<i32> {
        let code = cli_ops::run_audit_tail(self)?;
        std::process::exit(code);
    }
}

/// `octravpn-node receipt-verify …`
pub(crate) type ReceiptVerifyArgs = cli_ops::ReceiptVerifyArgs;

#[async_trait]
impl Subcommand for ReceiptVerifyArgs {
    fn needs_hub(&self) -> bool {
        false
    }
    async fn dispatch(self, _ctx: CliContext<'_>) -> Result<i32> {
        let code = cli_ops::run_receipt_verify(self)?;
        std::process::exit(code);
    }
}
