//! `octra cast` — JSON-RPC and wallet operations.
//!
//! Modelled after `cast` (Foundry). All subcommands route through
//! [`crate::rpc_client`] so they work identically against a real Octra
//! node, a locally-spawned `anvil`, or an in-process mock spawned by
//! integration tests.

pub mod abi;
pub mod hash;
pub mod tx;
pub mod wallet;

use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use serde_json::{json, Value};

use crate::{io as cio, rpc_client};

/// Default RPC endpoint used when `--rpc-url` is not supplied.
pub const DEFAULT_RPC_URL: &str = "https://octra.network/rpc";

#[derive(Subcommand, Debug)]
pub enum CastCmd {
    /// Read-only program call. Output is JSON.
    Call {
        /// Program (contract) address.
        addr: String,
        /// Method name.
        method: String,
        /// Positional method args (JSON literal or plain string).
        args: Vec<String>,
        #[arg(long, env = "OCTRA_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
        #[arg(long)]
        caller: Option<String>,
    },
    /// Build, sign, and submit a state-changing tx.
    Send {
        addr: String,
        method: String,
        args: Vec<String>,
        #[arg(long, default_value_t = 0u64)]
        value: u64,
        #[arg(long, default_value_t = 10u64)]
        fee: u64,
        #[arg(long, default_value_t = 0u64)]
        nonce: u64,
        #[arg(long)]
        from: Option<String>,
        #[arg(long, env = "OCTRA_KEY_FILE")]
        key: Option<std::path::PathBuf>,
        #[arg(long, env = "OCTRA_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
    },
    /// Fetch a tx by hash.
    Tx {
        hash: String,
        #[arg(long, env = "OCTRA_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
    },
    /// Fetch an epoch by id (== block).
    Block {
        epoch: u64,
        #[arg(long, env = "OCTRA_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
    },
    /// Wallet operations.
    #[command(subcommand)]
    Wallet(wallet::WalletCmd),
    /// sha256 helper. Octra uses sha256 for hashes; `keccak` is an alias
    /// so `cast keccak <hex>` keeps muscle memory from Ethereum tooling.
    Sha256 {
        hex: String,
    },
    /// Alias of `sha256`. Octra uses sha256 for hashing; this name only
    /// exists for muscle memory with Foundry's `cast keccak`.
    Keccak {
        hex: String,
    },
    /// Decode a hex-encoded params blob against a compiled ABI.
    #[command(name = "abi-decode")]
    AbiDecode {
        abi_file: std::path::PathBuf,
        method: String,
        hex: String,
    },
    /// Raw JSON-RPC pass-through.
    Rpc {
        method: String,
        args: Vec<String>,
        #[arg(long, env = "OCTRA_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
    },
}

pub fn dispatch(cmd: CastCmd) -> Result<()> {
    match cmd {
        CastCmd::Call {
            addr,
            method,
            args,
            rpc_url,
            caller,
        } => cast_call(&addr, &method, &args, &rpc_url, caller.as_deref()),
        CastCmd::Send {
            addr,
            method,
            args,
            value,
            fee,
            nonce,
            from,
            key,
            rpc_url,
        } => cast_send(
            &addr,
            &method,
            &args,
            value,
            fee,
            nonce,
            from.as_deref(),
            key.as_deref(),
            &rpc_url,
        ),
        CastCmd::Tx { hash, rpc_url } => tx::print_tx(&hash, &rpc_url),
        CastCmd::Block { epoch, rpc_url } => tx::print_block(epoch, &rpc_url),
        CastCmd::Wallet(c) => wallet::dispatch(c),
        CastCmd::Sha256 { hex } | CastCmd::Keccak { hex } => hash::sha256_cmd(&hex),
        CastCmd::AbiDecode {
            abi_file,
            method,
            hex,
        } => abi::abi_decode_cmd(&abi_file, &method, &hex),
        CastCmd::Rpc {
            method,
            args,
            rpc_url,
        } => cast_rpc(&method, &args, &rpc_url),
    }
}

fn cast_call(
    addr: &str,
    method: &str,
    args: &[String],
    rpc_url: &str,
    caller: Option<&str>,
) -> Result<()> {
    let endpoint = rpc_client::endpoint_from_url(rpc_url);
    let parsed: Vec<Value> = args.iter().map(|a| cio::parse_arg_token(a)).collect();
    let mut params = vec![json!(addr), json!(method), json!(parsed)];
    if let Some(c) = caller {
        params.push(json!(c));
    }
    let result = rpc_client::call(&endpoint, "contract_call", json!(params))?;
    cio::dump_json(&result);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cast_send(
    addr: &str,
    method: &str,
    args: &[String],
    value: u64,
    fee: u64,
    nonce: u64,
    from: Option<&str>,
    key: Option<&std::path::Path>,
    rpc_url: &str,
) -> Result<()> {
    let parsed: Vec<Value> = args.iter().map(|a| cio::parse_arg_token(a)).collect();
    // Decide `from` and signing key. Three modes:
    //   - `--from` only      → unsigned (mock-friendly).
    //   - `--key`            → derive `from` from the key.
    //   - both               → use given `from`, sign with the key.
    let (from_str, signed) = build_envelope(
        addr,
        method,
        &parsed,
        value,
        fee,
        nonce,
        from,
        key,
    )?;
    let endpoint = rpc_client::endpoint_from_url(rpc_url);
    let result = rpc_client::call(&endpoint, "octra_submit", json!([signed]))?;
    println!("submitted from: {from_str}");
    cio::dump_json(&result);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_envelope(
    addr: &str,
    method: &str,
    params: &[Value],
    value: u64,
    fee: u64,
    nonce: u64,
    from: Option<&str>,
    key: Option<&std::path::Path>,
) -> Result<(String, Value)> {
    let mut call = json!({
        "kind": "contract_call",
        "from": from.unwrap_or(""),
        "to": addr,
        "method": method,
        "params": params,
        "value": value,
        "fee": fee,
        "nonce": nonce,
        "timestamp": cio::current_timestamp(),
    });
    if let Some(p) = key {
        let bytes = cio::read_secret_hex(p)?;
        let kp = octravpn_core::sig::KeyPair::from_secret_bytes(&bytes);
        let derived_addr = octravpn_core::address::Address::from_pubkey(&kp.public.0)
            .display()
            .to_string();
        // If --from was also supplied, prefer it, but warn via stderr.
        let from_value = from.map_or_else(|| derived_addr, str::to_string);
        if let Some(obj) = call.as_object_mut() {
            obj.insert("from".into(), json!(from_value));
        }
        let signed = octravpn_core::tx::sign_call(&kp, call)
            .map_err(|e| anyhow!("sign_call: {e}"))?;
        Ok((from_value, signed))
    } else {
        let from_value = from
            .ok_or_else(|| anyhow!("either --from or --key is required"))?
            .to_string();
        Ok((from_value, call))
    }
}

fn cast_rpc(method: &str, args: &[String], rpc_url: &str) -> Result<()> {
    let endpoint = rpc_client::endpoint_from_url(rpc_url);
    let parsed: Vec<Value> = args.iter().map(|a| cio::parse_arg_token(a)).collect();
    let v = rpc_client::call(&endpoint, method, json!(parsed))
        .with_context(|| format!("rpc {method}"))?;
    cio::dump_json(&v);
    Ok(())
}
