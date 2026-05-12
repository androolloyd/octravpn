//! Compile-pipeline plumbing.
//!
//! The real Octra RPC implements `octra_compileAml` / `octra_compileAmlMulti`,
//! which we use when an RPC URL is supplied. When the user runs offline
//! (or against an in-process mock), we synthesize a deterministic
//! artifact in-process so downstream commands (`bind`, `inspect`,
//! `create`) still have something to chew on.
//!
//! The synthesizer here is a near-clone of the mock-side helper. Keeping
//! them in lockstep is asserted by `tests/forge_build_offline.rs`.

use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Build a compiled artifact JSON for a single source. This is the
/// offline-mode equivalent of an `octra_compileAml` response.
pub fn synthesize_artifact(name: &str, source: &str) -> Value {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"::");
    h.update(source.as_bytes());
    let digest = hex::encode(h.finalize());
    let abi = synth_abi(source);
    json!({
        "name": name,
        "abi": abi,
        "bytecode": format!("0x{digest}"),
        "assembly": format!("; mock AML bytecode for {name}\n; sha256(source) = {digest}\n"),
        "source_hash": digest,
        "compiler": "octra-cli-offline-0.1",
    })
}

/// Infer the program name from a file path or `program X {` declaration.
///
/// We strip line and block comments before scanning so a doc-comment
/// like `// great program for Octra` doesn't capture the word `for`
/// as the program name.
pub fn infer_program_name(path: &str, source: &str) -> String {
    let stripped = strip_comments(source);
    let bytes = stripped.as_bytes();
    let mut i = 0;
    while i + 8 <= bytes.len() {
        // word boundary + `program ` literal.
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if before_ok && &bytes[i..i + 8] == b"program " {
            // Skip whitespace, then read identifier.
            let mut j = i + 8;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let name_start = j;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if j > name_start {
                let name = &stripped[name_start..j];
                // Sanity check: AML program names are PascalCase but the
                // parser only insists on a valid Rust identifier.
                if !name.is_empty() {
                    return name.to_string();
                }
            }
        }
        i += 1;
    }
    Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Program")
        .to_string()
}

/// Strip `// line` and `/* block */` comments. We don't try to parse
/// strings exactly — AML source is small enough that a heuristic that
/// errs on the side of removing more is fine.
fn strip_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && &bytes[i..i + 2] == b"//" {
            // line comment
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < bytes.len() && &bytes[i..i + 2] == b"/*" {
            i += 2;
            while i + 1 < bytes.len() && &bytes[i..i + 2] != b"*/" {
                i += 1;
            }
            i = i.saturating_add(2);
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn synth_abi(source: &str) -> Vec<Value> {
    let methods = extract_methods(source);
    let events = extract_events(source);
    let mut abi: Vec<Value> = methods
        .into_iter()
        .map(|m| {
            json!({
                "name": m.name,
                "kind": if m.is_view { "view" } else { "call" },
                "inputs": m.inputs.iter().map(|(n, t)| json!({"name": n, "type": t})).collect::<Vec<_>>(),
            })
        })
        .collect();
    for e in events {
        abi.push(json!({"name": e, "kind": "event"}));
    }
    abi
}

struct MethodSig {
    name: String,
    is_view: bool,
    inputs: Vec<(String, String)>,
}

fn extract_methods(source: &str) -> Vec<MethodSig> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"fn ")
            && (i == 0 || !bytes[i.saturating_sub(1)].is_ascii_alphanumeric())
        {
            let prefix_end = i;
            let is_view = back_word_is(source, prefix_end, "view");
            let private = back_word_is(source, prefix_end, "private")
                || back_word_is(source, prefix_end, "view private");
            let mut j = i + 3;
            let name_start = j;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            let name = source[name_start..j].to_string();
            while j < bytes.len() && bytes[j] != b'(' {
                j += 1;
            }
            if j >= bytes.len() {
                break;
            }
            let params_start = j + 1;
            let mut depth = 1;
            j += 1;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            let params_str = &source[params_start..j - 1];
            let inputs = parse_params(params_str);
            if !name.is_empty() && !private {
                out.push(MethodSig {
                    name,
                    is_view,
                    inputs,
                });
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn back_word_is(source: &str, end: usize, word: &str) -> bool {
    let s = source[..end].trim_end();
    s.ends_with(word) && {
        let before = s.len() - word.len();
        before == 0 || !source.as_bytes()[before - 1].is_ascii_alphanumeric()
    }
}

fn parse_params(s: &str) -> Vec<(String, String)> {
    s.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                return None;
            }
            let (n, t) = chunk.split_once(':')?;
            Some((n.trim().to_string(), t.trim().to_string()))
        })
        .collect()
}

fn extract_events(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in source.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("event ") {
            if let Some((name, _)) = rest.split_once('(') {
                out.push(name.trim().to_string());
            }
        }
    }
    out
}
