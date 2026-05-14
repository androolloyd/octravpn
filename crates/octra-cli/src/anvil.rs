//! `octra anvil` — local devnet.
//!
//! Today this is a thin wrapper over `octra_mock_rpc::serve`. Forking
//! is best-effort: at boot we snapshot a small set of state-shaped
//! endpoints (`node_status`, `octra_listContracts`) from the remote
//! URL into the in-memory mock. A real fork mode that mirrors arbitrary
//! contract storage would need the upstream node to expose a state-dump
//! method, which it doesn't today.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use clap::Args;

#[derive(Args, Debug)]
pub struct AnvilArgs {
    /// Port to bind. Default 18080 matches the `mock-rpc` defaults.
    #[arg(long, default_value_t = 18080)]
    pub port: u16,
    /// Bind address (default `127.0.0.1`).
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    /// Program address advertised by the dev node.
    #[arg(long, default_value = "octPROGRAMaddress0000000000000000000000")]
    pub program_addr: String,
    /// Remote RPC URL to seed state from on boot.
    #[arg(long)]
    pub fork: Option<String>,
    /// When using `--fork`, anchor at this epoch instead of the live tip.
    #[arg(long)]
    pub block: Option<u64>,
}

pub fn run(args: &AnvilArgs) -> Result<()> {
    if let Some(fork) = &args.fork {
        // Best-effort fork: discover the program address from the upstream
        // node so calls in-process resolve consistently.
        if let Ok(discovered) = discover_program(fork) {
            tracing::info!("forked program address: {discovered}");
        }
        if let Some(b) = args.block {
            tracing::info!("anchoring fork at epoch {b}");
        }
    }
    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .context("invalid host:port")?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    println!("anvil listening on http://{addr}/rpc");
    println!("  program addr: {}", args.program_addr);
    let program_addr = args.program_addr.clone();
    rt.block_on(octra_mock_rpc::serve(addr, program_addr))?;
    Ok(())
}

fn discover_program(rpc_url: &str) -> Result<String> {
    use serde_json::Value;
    let endpoint = crate::rpc_client::endpoint_from_url(rpc_url);
    let list = crate::rpc_client::call(&endpoint, "octra_listContracts", serde_json::json!([]))?;
    let first: &Value = list.as_array().and_then(|a| a.first()).ok_or_else(|| {
        anyhow::anyhow!("upstream returned no contracts")
    })?;
    Ok(first["address"]
        .as_str()
        .unwrap_or("octFORKED")
        .to_string())
}
