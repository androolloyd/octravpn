//! `octravpn-node run` — the long-lived daemon boot. Hub-bound.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tracing::{info, warn};

use crate::hub::Hub;

use super::{CliContext, Subcommand};

/// `octravpn-node run` — start the daemon.
#[derive(clap::Args, Debug)]
pub(crate) struct RunArgs {}

#[async_trait]
impl Subcommand for RunArgs {
    fn needs_hub(&self) -> bool {
        true
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        run(ctx.hub().clone()).await?;
        Ok(0)
    }
}

async fn run(hub: Arc<Hub>) -> Result<()> {
    if let Err(e) = hub.register_endpoint().await {
        warn!(error = %e, "endpoint registration skipped or failed; continuing if already registered");
    }

    let health_task = hub.clone().spawn_validator_health_loop();
    let tunnel_task = hub.clone().spawn_tunnel();
    let control_task = hub.clone().spawn_control_plane();
    // Step 6: in-daemon autonomous relay-claimer. Parks unless
    // `[control.relay].auto_claim = true`.
    let claimer_task = hub.clone().spawn_relay_claimer();
    // Step 8b: permissionless keeper sweeper. Parks unless
    // `[control.relay].auto_sweep = true`.
    let sweeper_task = hub.clone().spawn_relay_sweeper();

    info!("octravpn-node running");
    tokio::select! {
        r = health_task => r??,
        r = tunnel_task => r??,
        r = control_task => r??,
        r = claimer_task => r??,
        r = sweeper_task => r??,
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown requested");
        }
    }
    Ok(())
}
