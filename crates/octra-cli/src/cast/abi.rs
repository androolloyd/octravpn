//! `cast abi-decode` — reverse a hex params blob against a compiled ABI.
//!
//! Today this is a best-effort decoder against the mock compiler's ABI
//! shape (`{name, kind, inputs:[{name,type}]}`). It accepts:
//!
//!   - hex-encoded JSON (i.e. `hex` of `{"method":"x","params":[...]}`)
//!   - raw JSON params arrays
//!
//! Real Octra's ABI format isn't published; this gives users a useful
//! decoder for tooling-produced blobs and an extension hook for future
//! ABI revisions.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

use crate::io::dump_json;

pub fn abi_decode_cmd(abi_file: &Path, method: &str, hex_input: &str) -> Result<()> {
    let abi_bytes =
        std::fs::read(abi_file).with_context(|| format!("read abi: {}", abi_file.display()))?;
    let abi: Value = serde_json::from_slice(&abi_bytes).context("abi file is not valid JSON")?;
    let method_def =
        find_method(&abi, method).ok_or_else(|| anyhow!("method `{method}` not found in ABI"))?;
    let stripped = hex_input.trim().trim_start_matches("0x");
    let bytes = hex::decode(stripped).context("input is not hex")?;
    let payload: Value = serde_json::from_slice(&bytes)
        .with_context(|| "hex bytes are not JSON; only encoded-JSON blobs are decoded today")?;
    let decoded = align_to_method(method_def, &payload);
    dump_json(&decoded);
    Ok(())
}

fn find_method<'a>(abi: &'a Value, method: &str) -> Option<&'a Value> {
    let arr = abi
        .as_array()
        .or_else(|| abi.get("abi").and_then(|v| v.as_array()))?;
    arr.iter()
        .find(|item| item["name"].as_str() == Some(method))
}

fn align_to_method(method_def: &Value, payload: &Value) -> Value {
    let inputs = method_def["inputs"].as_array().cloned().unwrap_or_default();
    let params = payload
        .get("params")
        .cloned()
        .unwrap_or_else(|| payload.clone());
    let p_arr = params.as_array().cloned().unwrap_or_default();
    let mut out = serde_json::Map::new();
    for (i, def) in inputs.iter().enumerate() {
        let name = def["name"].as_str().unwrap_or("arg").to_string();
        let val = p_arr.get(i).cloned().unwrap_or(Value::Null);
        out.insert(name, val);
    }
    Value::Object(out)
}
