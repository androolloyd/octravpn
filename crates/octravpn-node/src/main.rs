//! `octravpn-node` — OctraVPN endpoint daemon (v1).
//!
//! Responsibilities:
//!   1. Bond OU into the OctraVPN program (`bond_endpoint`) — required
//!      before registering. The v1 AML no longer gates on Octra-validator
//!      status; it requires the operator's in-program stake to be
//!      >= MIN_ENDPOINT_STAKE.
//!   2. Register a paid endpoint (relay or exit) on the OctraVPN program.
//!   3. Run a userspace WireGuard endpoint (boringtun) for tailnet clients.
//!   4. Track per-session bandwidth, accept signed receipts, retain the
//!      latest receipt per session for settlement / equivocation defense.
//!   5. Periodically verify operator stake is above the AML's minimum.
//!   6. On request, claim accumulated encrypted earnings (two-step:
//!      AML `claim_earnings` with FHE zero-proof + native stealth payout
//!      by the operator's wallet).
//!
//! The CLI surface lives entirely under [`cli`]. `main` is a thin
//! wrapper: init tracing, hand off to `cli::run`, exit with the returned
//! code. Adding a new subcommand never requires touching this file —
//! see `cli/mod.rs` for the contract.

use anyhow::Result;

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
mod events;
mod hub;
mod mesh_ops;
mod onion;
mod pvac;
mod rate_limit;
mod seal;
mod tunnel;
mod v3_boot;
mod v3_cli;

#[tokio::main]
async fn main() -> Result<()> {
    octravpn_core::util::init_tracing("info,octravpn_node=debug");
    let code = cli::run().await?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
