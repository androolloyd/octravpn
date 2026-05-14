//! `forge create` — compile + sign + deploy + return address.
//!
//! Octra exposes deploy as a regular tx with `op_type="deploy"` and a
//! payload containing the compiled bytecode + constructor args. The
//! resulting program address is computed from the deploying account
//! and a nonce by Octra; we surface what the RPC returns. Against the
//! in-process mock we synthesize a `octPROG`-prefixed address so the
//! rest of the toolchain can chain off this command.

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::Args;
use octravpn_core::{address::Address, sig::KeyPair};
use serde_json::{json, Value};

use crate::{
    forge::compile,
    io::{current_timestamp, dump_json, parse_arg_token, read_secret_hex},
    rpc_client,
};

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Source `.aml` file.
    pub file: PathBuf,
    /// Constructor args (parsed as JSON if possible).
    #[arg(long = "constructor-args", num_args = 0.., allow_hyphen_values = true)]
    pub constructor_args: Vec<String>,
    /// Key file (32-byte hex) to sign the deploy tx.
    #[arg(long, env = "OCTRA_KEY_FILE")]
    pub key: PathBuf,
    /// RPC URL (HTTP or `inprocess://...`).
    #[arg(long, env = "OCTRA_RPC_URL")]
    pub rpc_url: String,
}

pub fn run(args: &CreateArgs) -> Result<()> {
    let source = std::fs::read_to_string(&args.file)?;
    let name = compile::infer_program_name(
        args.file
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("Program"),
        &source,
    );
    let endpoint = rpc_client::endpoint_from_url(&args.rpc_url);
    let artifact = rpc_client::call(&endpoint, "octra_compileAml", json!([source, &name]))
        .unwrap_or_else(|_| compile::synthesize_artifact(&name, &source));
    let bytecode = artifact["bytecode"]
        .as_str()
        .ok_or_else(|| anyhow!("missing bytecode in compile result"))?;

    let secret = read_secret_hex(&args.key)?;
    let kp = KeyPair::from_secret_bytes(&secret);
    let from_addr = Address::from_pubkey(&kp.public.0).display().to_string();
    let args_values: Vec<Value> = args
        .constructor_args
        .iter()
        .map(|s| parse_arg_token(s))
        .collect();

    // Synthetic deploy address used by the in-process backend; real
    // Octra returns the address in the submit response. We compute the
    // hash here so the local mock path produces a stable, deterministic
    // address users can copy-paste into follow-up commands.
    let deploy_addr = derive_deploy_addr(&from_addr, &name);

    let call = json!({
        "kind": "contract_call",
        "from": from_addr,
        "to": deploy_addr,
        "method": "__deploy__",
        "params": [bytecode, name, args_values],
        "value": 0u64,
        "fee": 1000u64,
        "nonce": 0u64,
        "timestamp": current_timestamp(),
    });
    let signed = octravpn_core::tx::sign_call(&kp, call).map_err(|e| anyhow!("sign_call: {e}"))?;
    let res = rpc_client::call(&endpoint, "octra_submit", json!([signed]))?;
    dump_json(&json!({
        "address": res
            .get("address")
            .and_then(|v| v.as_str())
            .unwrap_or(&deploy_addr),
        "tx_hash": res.get("hash").and_then(|v| v.as_str()).unwrap_or(""),
        "name": name,
        "compiler": artifact.get("compiler").cloned().unwrap_or(Value::Null),
    }));
    Ok(())
}

fn derive_deploy_addr(from: &str, name: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(from.as_bytes());
    h.update(b"::");
    h.update(name.as_bytes());
    let digest = h.finalize();
    let body = bs58::encode(digest).into_string();
    let padded = if body.len() >= 44 {
        body[..44].to_string()
    } else {
        let mut s = String::with_capacity(44);
        for _ in body.len()..44 {
            s.push('1');
        }
        s.push_str(&body);
        s
    };
    format!("oct{padded}")
}
