//! Embeddable Octra VPN services and the standalone daemon CLI.

pub mod admission;
mod audit;
mod audit_cli;
mod chain;
mod chain_v2;
mod chain_v3;
mod circle_update;
mod cli;
mod cli_ops;
mod cli_report;
mod config;
mod control;
pub mod embedded;
mod events;
mod hub;
mod members_policy;
pub mod mesh_control;
mod mesh_ops;
pub mod mesh_store;
mod native_derp;
mod onion;
pub mod payment_meter;
mod pvac;
mod rate_limit;
mod relay_claimer;
mod relay_settlement;
mod relay_sweeper;
mod seal;
mod tunnel;
mod v3_boot;
mod v3_cli;

/// Run the standalone operator command line.
pub async fn run_cli() -> anyhow::Result<i32> {
    cli::run().await
}
