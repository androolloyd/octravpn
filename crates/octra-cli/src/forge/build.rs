//! `forge build` — walk `program/` for `*.aml`, compile, emit artifacts.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};

use crate::{io::write_to, rpc_client};

use super::compile;

#[derive(Args, Debug)]
pub struct BuildArgs {
    /// Source root (defaults to `program/`).
    #[arg(long, default_value = "program")]
    pub root: PathBuf,
    /// Output dir (defaults to `out/`).
    #[arg(long, default_value = "out")]
    pub out: PathBuf,
    /// Skip the RPC compile and use the deterministic offline stub
    /// compiler. Always implied when `--rpc-url` is unset.
    #[arg(long)]
    pub offline: bool,
    /// RPC URL to use for `octra_compileAmlMulti`.
    #[arg(long, env = "OCTRA_RPC_URL")]
    pub rpc_url: Option<String>,
}

pub fn run(args: &BuildArgs) -> Result<()> {
    let files = discover_aml(&args.root)?;
    if files.is_empty() {
        return Err(anyhow::anyhow!(
            "no .aml files found under {}",
            args.root.display()
        ));
    }
    let multi_in = files
        .iter()
        .map(|(rel, src)| (rel.clone(), Value::String(src.clone())))
        .collect::<serde_json::Map<_, _>>();
    let compiled = if args.offline || args.rpc_url.is_none() {
        compile_offline(&multi_in)
    } else {
        let endpoint = rpc_client::endpoint_from_url(args.rpc_url.as_deref().unwrap_or(""));
        rpc_client::call(
            &endpoint,
            "octra_compileAmlMulti",
            json!([Value::Object(multi_in.clone())]),
        )
        .or_else(|e| {
            tracing::warn!("rpc compile failed ({e}); falling back to offline stub");
            Ok::<Value, anyhow::Error>(compile_offline(&multi_in))
        })?
    };
    let map = compiled
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("compile result not an object"))?;
    let mut produced = Vec::new();
    for (path, artifact) in map {
        let name = artifact["name"]
            .as_str()
            .map_or_else(|| path.clone(), str::to_string);
        write_artifact(&args.out, &name, artifact)?;
        produced.push(name);
    }
    println!(
        "compiled {} program(s) → {}/{{{}}}.json",
        produced.len(),
        args.out.display(),
        produced.join(",")
    );
    Ok(())
}

fn compile_offline(files: &serde_json::Map<String, Value>) -> Value {
    let mut out = serde_json::Map::new();
    for (path, src) in files {
        let source = src.as_str().unwrap_or_default();
        let name = compile::infer_program_name(path, source);
        out.insert(path.clone(), compile::synthesize_artifact(&name, source));
    }
    Value::Object(out)
}

fn discover_aml(root: &Path) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    walk_dir(root, root, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk_dir(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) -> Result<()> {
    let rd = std::fs::read_dir(dir)
        .with_context(|| format!("read_dir {}", dir.display()))?;
    for entry in rd {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir(root, &path, out)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("aml") {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            let body = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            out.push((rel, body));
        }
    }
    Ok(())
}

pub fn write_artifact(out_dir: &Path, name: &str, artifact: &Value) -> Result<()> {
    let json_path = out_dir.join(format!("{name}.json"));
    write_to(
        &json_path,
        &serde_json::to_string_pretty(artifact).unwrap_or_default(),
    )?;
    let abi = artifact.get("abi").cloned().unwrap_or(Value::Array(vec![]));
    let abi_path = out_dir.join(format!("{name}.abi"));
    write_to(&abi_path, &serde_json::to_string_pretty(&abi).unwrap_or_default())?;
    let bin = artifact
        .get("bytecode")
        .and_then(|v| v.as_str())
        .unwrap_or("0x");
    write_to(&out_dir.join(format!("{name}.bin")), bin)?;
    let asm = artifact
        .get("assembly")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    write_to(&out_dir.join(format!("{name}.asm")), asm)?;
    Ok(())
}
