//! `forge inspect` — show the ABI / bytecode / assembly for a program.
//!
//! Two operating modes:
//!
//!   - `<file.aml>` → compile and dump fresh.
//!   - `<oct...addr>` → load `out/<best-match>.json` from disk if it
//!     was produced by `forge build`. If nothing matches, fall back to
//!     `octra_listContracts` for a name resolution.

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::Args;
use serde_json::{json, Value};

use crate::{
    forge::compile,
    io::dump_json,
    rpc_client,
};

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Path to `.aml` source OR a program address.
    pub target: String,
    /// What to print (`abi` | `bytecode` | `assembly` | `all`).
    #[arg(long, default_value = "all")]
    pub field: String,
    /// Directory containing compiled artifacts (used when `target` is
    /// an address that resolves to a name).
    #[arg(long, default_value = "out")]
    pub out: PathBuf,
    /// RPC URL for address-mode resolution.
    #[arg(long, env = "OCTRA_RPC_URL")]
    pub rpc_url: Option<String>,
}

pub fn run(args: &InspectArgs) -> Result<()> {
    let artifact = if std::path::Path::new(&args.target).exists() {
        let src = std::fs::read_to_string(&args.target)?;
        let name = compile::infer_program_name(&args.target, &src);
        compile::synthesize_artifact(&name, &src)
    } else if args.target.starts_with("oct") {
        load_for_address(&args.target, &args.out, args.rpc_url.as_deref())?
    } else {
        return Err(anyhow!(
            "target must be either an existing file or an `oct...` address"
        ));
    };
    match args.field.as_str() {
        "abi" => dump_json(artifact.get("abi").unwrap_or(&Value::Null)),
        "bytecode" | "bin" => {
            println!("{}", artifact.get("bytecode").and_then(|v| v.as_str()).unwrap_or("0x"));
        }
        "assembly" | "asm" => {
            println!("{}", artifact.get("assembly").and_then(|v| v.as_str()).unwrap_or(""));
        }
        "storage" => dump_json(artifact.get("storage").unwrap_or(&Value::Null)),
        _ => dump_json(&artifact),
    }
    Ok(())
}

fn load_for_address(addr: &str, out: &std::path::Path, rpc_url: Option<&str>) -> Result<Value> {
    let mut name_hint: Option<String> = None;
    if let Some(url) = rpc_url {
        let endpoint = rpc_client::endpoint_from_url(url);
        if let Ok(list) = rpc_client::call(&endpoint, "octra_listContracts", json!([])) {
            if let Some(arr) = list.as_array() {
                for item in arr {
                    if item["address"].as_str() == Some(addr) {
                        name_hint = item["name"].as_str().map(str::to_string);
                        break;
                    }
                }
            }
        }
    }
    if let Some(name) = name_hint {
        let path = out.join(format!("{name}.json"));
        if path.exists() {
            let s = std::fs::read_to_string(&path)?;
            return Ok(serde_json::from_str(&s)?);
        }
    }
    // Last resort: walk `out/` for any matching artifact JSON.
    if let Ok(rd) = std::fs::read_dir(out) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let body = std::fs::read_to_string(&path).unwrap_or_default();
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    return Ok(v);
                }
            }
        }
    }
    Err(anyhow!("no artifact found for {addr}"))
}
