//! `identity` (Hub print) + `accumulator-add` (post-hoc earnings
//! reconciliation). Both are Hub-bound.

use anyhow::Result;
use async_trait::async_trait;

use super::{CliContext, Subcommand};

/// `octravpn-node identity`
#[derive(clap::Args, Debug)]
pub(crate) struct IdentityArgs {}

#[async_trait]
impl Subcommand for IdentityArgs {
    fn needs_hub(&self) -> bool {
        true
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        ctx.hub().print_identity();
        Ok(0)
    }
}

/// `octravpn-node accumulator-add --delta-amount <ou> --delta-blind-hex <hex>`
#[derive(clap::Args, Debug)]
pub(crate) struct AccumulatorAddArgs {
    #[arg(long)]
    pub(crate) delta_amount: u64,
    #[arg(long)]
    pub(crate) delta_blind_hex: String,
}

#[async_trait]
impl Subcommand for AccumulatorAddArgs {
    fn needs_hub(&self) -> bool {
        true
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        ctx.hub()
            .accumulator_add(self.delta_amount, &self.delta_blind_hex)?;
        Ok(0)
    }
}
