//! Embedded `headscale` admin CLI passthrough. Pure HTTP client surface —
//! no Hub. `headscale_cli::dispatch` returns a process exit code matching
//! the standalone binary's contract (0/3/4/5/6); we forward that via
//! `std::process::exit` so the contract reaches the operator's shell.

use anyhow::Result;
use async_trait::async_trait;

use super::{CliContext, Subcommand};

/// `octravpn-node headscale <subcmd>`
#[derive(clap::Args, Debug)]
pub(crate) struct HeadscaleArgs {
    /// Shared connection flags (`--server`, `--token`, `--json`)
    /// — flattened so the same CLI shape as the standalone binary
    /// works. `HEADSCALE_URL` / `HEADSCALE_ADMIN_TOKEN` env-var
    /// fallbacks are preserved.
    #[command(flatten)]
    pub(crate) connect: headscale_cli::ConnectArgs,
    #[command(subcommand)]
    pub(crate) cmd: headscale_cli::AdminCmd,
}

#[async_trait]
impl Subcommand for HeadscaleArgs {
    fn needs_hub(&self) -> bool {
        false
    }
    async fn dispatch(self, _ctx: CliContext<'_>) -> Result<i32> {
        let code = headscale_cli::dispatch(self.connect, self.cmd).await;
        std::process::exit(code);
    }
}
