//! Bond / unbond / register / settle subcommands — the v1.1-style
//! operator surfaces. All of these dispatch through a live [`Hub`] so
//! they declare `needs_hub() == true`.
//!
//! Each variant is a thin [`clap::Args`] struct so the outer `Cmd` enum
//! in `cli/mod.rs` only needs to mention the type. The doc-comments on
//! the variants in `cli/mod.rs` drive `--help` output; struct-level docs
//! here are implementation notes (clap ignores them).

use anyhow::Result;
use async_trait::async_trait;

use super::{CliContext, Subcommand};

/// `octravpn-node bond --amount <ou>`
#[derive(clap::Args, Debug)]
pub(crate) struct BondArgs {
    #[arg(long)]
    pub(crate) amount: u64,
}

#[async_trait]
impl Subcommand for BondArgs {
    fn needs_hub(&self) -> bool {
        true
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        ctx.hub().bond_endpoint(self.amount).await?;
        Ok(0)
    }
}

/// `octravpn-node unbond`
#[derive(clap::Args, Debug)]
pub(crate) struct UnbondArgs {}

#[async_trait]
impl Subcommand for UnbondArgs {
    fn needs_hub(&self) -> bool {
        true
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        ctx.hub().unbond_endpoint().await?;
        Ok(0)
    }
}

/// `octravpn-node finalize-unbond`
#[derive(clap::Args, Debug)]
pub(crate) struct FinalizeUnbondArgs {}

#[async_trait]
impl Subcommand for FinalizeUnbondArgs {
    fn needs_hub(&self) -> bool {
        true
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        ctx.hub().finalize_unbond().await?;
        Ok(0)
    }
}

/// `octravpn-node register`
#[derive(clap::Args, Debug)]
pub(crate) struct RegisterArgs {}

#[async_trait]
impl Subcommand for RegisterArgs {
    fn needs_hub(&self) -> bool {
        true
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        ctx.hub().register_endpoint().await?;
        Ok(0)
    }
}

/// `octravpn-node claim-earnings`
#[derive(clap::Args, Debug)]
pub(crate) struct ClaimEarningsArgs {}

#[async_trait]
impl Subcommand for ClaimEarningsArgs {
    fn needs_hub(&self) -> bool {
        true
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        ctx.hub().claim_earnings().await?;
        Ok(0)
    }
}

/// `octravpn-node settle-claim --session-id <id> --bytes-used <n>`
#[derive(clap::Args, Debug)]
pub(crate) struct SettleClaimArgs {
    #[arg(long)]
    pub(crate) session_id: u64,
    #[arg(long)]
    pub(crate) bytes_used: u64,
}

#[async_trait]
impl Subcommand for SettleClaimArgs {
    fn needs_hub(&self) -> bool {
        true
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        ctx.hub()
            .settle_claim(self.session_id, self.bytes_used)
            .await?;
        Ok(0)
    }
}
