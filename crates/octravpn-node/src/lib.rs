//! Embeddable Octra VPN services, and — behind the `standalone` feature —
//! the standalone operator daemon and its command line.
//!
//! The split is enforced, not conventional. Everything `octra-node` embeds
//! lives in the unconditional modules below; the Hub, the CLI, the v1.1/v2
//! chain layers and the relay keepers are compiled only with `standalone`.
//! A library module that reaches into one of those fails the
//! `--no-default-features` build in CI.
//!
//! The boundary is at module granularity. Several unconditional modules
//! still carry items only the operator calls — most of `config`,
//! `circle_update` and `v3_boot` — which are dead code when the feature is
//! off. Delete the attribute below to list them: that list is the remaining
//! work of moving the operator out of this crate.
#![cfg_attr(not(feature = "standalone"), allow(dead_code, unused_imports))]

pub mod admission;
mod audit;
mod chain_v3;
mod circle_update;
mod config;
mod control;
pub mod embedded;
mod events;
mod members_policy;
pub mod mesh_control;
pub mod mesh_store;
mod native_derp;
mod onion;
pub mod payment_meter;
pub mod payments;
mod pvac;
mod rate_limit;
mod relay_settlement;
pub mod stock;
mod tunnel;
mod v3_boot;

#[cfg(feature = "standalone")]
mod audit_cli;
#[cfg(feature = "standalone")]
mod chain;
#[cfg(feature = "standalone")]
mod chain_v2;
#[cfg(feature = "standalone")]
mod cli;
#[cfg(feature = "standalone")]
mod cli_ops;
#[cfg(feature = "standalone")]
mod cli_report;
#[cfg(feature = "standalone")]
mod hub;
#[cfg(feature = "standalone")]
mod mesh_ops;
#[cfg(feature = "standalone")]
mod relay_claimer;
#[cfg(feature = "standalone")]
mod relay_sweeper;
#[cfg(feature = "standalone")]
mod seal;
#[cfg(feature = "standalone")]
mod v3_cli;

/// Run the standalone operator command line.
#[cfg(feature = "standalone")]
pub async fn run_cli() -> anyhow::Result<i32> {
    cli::run().await
}
