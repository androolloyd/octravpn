//! `cast tx` / `cast block` — fetch + pretty-print.

use anyhow::Result;
use serde_json::json;

use crate::{io::dump_json, rpc_client};

pub fn print_tx(hash: &str, rpc_url: &str) -> Result<()> {
    let endpoint = rpc_client::endpoint_from_url(rpc_url);
    let v = rpc_client::call(&endpoint, "octra_transaction", json!([hash]))?;
    dump_json(&v);
    Ok(())
}

pub fn print_block(epoch_id: u64, rpc_url: &str) -> Result<()> {
    let endpoint = rpc_client::endpoint_from_url(rpc_url);
    let v = rpc_client::call(&endpoint, "epoch_get", json!([epoch_id]))?;
    dump_json(&v);
    Ok(())
}
