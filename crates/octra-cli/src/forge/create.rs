//! `octra forge create` — compile + sign + deploy + return address.
//!
//! Real Octra exposes deploy as a regular `Transaction` with
//! `op_type="deploy"` and `encrypted_data` carrying the compiled
//! bytecode (base64). The deployed contract address is computed by the
//! chain from `(bytecode, deployer, nonce)` — see
//! `octra_computeContractAddress`. We:
//!
//!   1. compile the AML source (`octra_compileAml`),
//!   2. fetch the deployer's nonce (`octra_balance`),
//!   3. compute the would-be deploy address (`octra_computeContractAddress`)
//!      so callers learn it before broadcast,
//!   4. assemble the OctraTx (`op_type=deploy`, `encrypted_data=bytecode`)
//!      and sign it (`octravpn_core::tx::sign_call`),
//!   5. broadcast via `octra_submit`,
//!   6. emit `{ address, tx_hash, name, compiler }` as JSON.
//!
//! The in-process mock at `inprocess://<prog>` doesn't expose
//! `octra_computeContractAddress`; in that path we fall back to a
//! deterministic hash-derived address and let the mock's
//! `op_type=deploy` synthesizer return the same one.

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::Args;
use octravpn_core::{
    address::Address,
    sig::KeyPair,
    tx::{OctraTx, OP_DEPLOY},
};
use serde_json::{json, Value};

use crate::{
    forge::compile,
    io::{current_timestamp, dump_json, parse_arg_token, read_secret_hex},
    rpc_client,
};

/// Default deploy fee in OU per the reference web client
/// (`octra-labs/webcli`). The user can override with `--ou`.
const DEFAULT_DEPLOY_OU: u64 = 50_000_000;

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Source `.aml` file.
    pub file: PathBuf,
    /// Constructor args (parsed as JSON if possible). When supplied,
    /// rendered as a JSON-encoded `message` on the tx envelope.
    #[arg(long = "constructor-args", num_args = 0.., allow_hyphen_values = true)]
    pub constructor_args: Vec<String>,
    /// Key file (32-byte hex) to sign the deploy tx.
    #[arg(long, env = "OCTRA_KEY_FILE")]
    pub key: PathBuf,
    /// RPC URL (HTTP or `inprocess://...`).
    #[arg(long, env = "OCTRA_RPC_URL")]
    pub rpc_url: String,
    /// Fee in OU (defaults to 50_000_000, the webcli default).
    #[arg(long)]
    pub ou: Option<u64>,
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
    let is_mock = matches!(endpoint, rpc_client::Endpoint::InProcess(_));

    // (1) Compile the AML source. Real Octra accepts the RPC; the
    //     in-process mock provides the same shape via a stub.
    let artifact = rpc_client::call(&endpoint, "octra_compileAml", json!([source, &name]))
        .unwrap_or_else(|_| compile::synthesize_artifact(&name, &source));
    let bytecode = artifact["bytecode"]
        .as_str()
        .ok_or_else(|| anyhow!("missing bytecode in compile result"))?;

    // (2) Sender + key. The signer derives the from-address.
    let secret = read_secret_hex(&args.key)?;
    let kp = KeyPair::from_secret_bytes(&secret);
    let from_addr = Address::from_pubkey(&kp.public.0).display().to_string();

    // (3) Fetch nonce. Real Octra: `octra_balance` returns
    //     `pending_nonce` + `nonce`. The next available nonce is
    //     `max(pending_nonce, nonce) + 1`. The mock always returns 0;
    //     we still treat that as a starting point.
    let bal = rpc_client::call(&endpoint, "octra_balance", json!([from_addr]))
        .unwrap_or_else(|_| json!({"nonce": 0u64, "pending_nonce": 0u64}));
    let cur_nonce = bal
        .get("nonce")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let pending = bal
        .get("pending_nonce")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let nonce = cur_nonce.max(pending) + 1;

    // (4) Predict the deploy address. Real Octra exposes
    //     `octra_computeContractAddress(bytecode_b64, deployer, nonce)`;
    //     against the mock we deterministically derive an `oct…`
    //     address from `(deployer, bytecode, nonce)` — the same scheme
    //     the mock's `op_type=deploy` handler synthesizes, so the
    //     submitted tx's returned `address` matches.
    let address = if is_mock {
        synth_deploy_addr(&from_addr, bytecode, nonce)
    } else {
        let resp = rpc_client::call(
            &endpoint,
            "octra_computeContractAddress",
            json!([bytecode, from_addr, nonce]),
        )?;
        resp.get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("octra_computeContractAddress missing `address`: {resp}"))?
            .to_string()
    };

    // (5) Build the OctraTx envelope. Optional constructor-args go
    //     into `message` as a JSON-encoded array — that matches webcli
    //     which puts a plain string there.
    let message = if args.constructor_args.is_empty() {
        None
    } else {
        let args_values: Vec<Value> = args
            .constructor_args
            .iter()
            .map(|s| parse_arg_token(s))
            .collect();
        Some(Value::Array(args_values).to_string())
    };

    let tx = OctraTx {
        from: from_addr,
        to: address.clone(),
        amount: 0,
        nonce,
        ou: args.ou.unwrap_or(DEFAULT_DEPLOY_OU),
        timestamp: current_timestamp(),
        op_type: OP_DEPLOY.to_string(),
        encrypted_data: Some(bytecode.to_string()),
        message,
    };

    // (6) Sign and submit.
    let envelope = serde_json::to_value(&tx).map_err(|e| anyhow!("serialize tx: {e}"))?;
    let signed =
        octravpn_core::tx::sign_call(&kp, envelope).map_err(|e| anyhow!("sign_call: {e}"))?;
    let res = rpc_client::call(&endpoint, "octra_submit", json!([signed]))?;

    dump_json(&json!({
        "address": res
            .get("address")
            .and_then(|v| v.as_str())
            .unwrap_or(&address),
        "tx_hash": res.get("hash").and_then(|v| v.as_str()).unwrap_or(""),
        "name": name,
        "compiler": artifact.get("compiler").cloned().unwrap_or(Value::Null),
    }));
    Ok(())
}

/// Mock-path deploy-address synthesis. Mirrors the mock's
/// `synthesize_deploy_address` in `octra-mock-rpc` so the address
/// predicted client-side matches the one the mock returns. Real Octra
/// uses `octra_computeContractAddress` instead.
fn synth_deploy_addr(from: &str, bytecode: &str, nonce: u64) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(from.as_bytes());
    h.update(b"::deploy::");
    h.update(bytecode.as_bytes());
    h.update(nonce.to_le_bytes());
    let digest = h.finalize();
    let body = hex::encode(digest);
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
