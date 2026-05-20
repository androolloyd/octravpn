//! `v3` subcommand tree — delegates to `crate::v3_cli`. No Hub required;
//! `v3_cli::dispatch` builds its own short-lived `ChainCtxV3`.

use anyhow::Result;
use async_trait::async_trait;

use crate::v3_cli;

use super::{CliContext, Subcommand};

/// `octravpn-node v3 <subcmd>`
#[derive(clap::Args, Debug)]
pub(crate) struct V3Args {
    #[command(subcommand)]
    pub(crate) cmd: v3_cli::V3Cmd,
}

#[async_trait]
impl Subcommand for V3Args {
    fn needs_hub(&self) -> bool {
        false
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        v3_cli::dispatch(std::path::Path::new(ctx.cfg_path), self.cmd).await?;
        Ok(0)
    }
}
