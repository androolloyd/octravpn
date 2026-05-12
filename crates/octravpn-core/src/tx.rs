//! Octra transaction signing — canonical form per
//! `octra-labs/webcli/lib/tx_builder.hpp:78-92` (cross-confirmed by the
//! Rust `ocs01-test` and Python `octra_pre_client` references).
//!
//! The signed bytes are the **UTF-8-encoded JSON string** with fixed,
//! insertion-order field layout:
//!
//! ```text
//! {"from":"<from>","to_":"<to>","amount":"<amt>","nonce":<int>,
//!  "ou":"<ou>","timestamp":<float>,"op_type":"<op_or_standard>"
//!  [,"encrypted_data":"..."][,"message":"..."]}
//! ```
//!
//! Notes captured from the research dossier:
//!   - Recipient field is `"to_"` (trailing underscore), not `"to"`.
//!   - `amount` and `ou` are quoted *integer* strings (in OU).
//!   - `nonce` is an unquoted integer.
//!   - `timestamp` is an unquoted float (Python `time.time()`).
//!   - `op_type` defaults to `"standard"` when missing.
//!   - Optional fields appear only when set, in the order shown.
//!   - The signature is over the JSON bytes; `signature` and
//!     `public_key` (base64) are appended *after* signing.
//!
//! We also bind a `chain_id` prefix to defeat cross-chain replay
//! between mainnet / testnet / forks. Real Octra doesn't include a
//! chain_id today (single mainnet); we add it as a hidden prefix that
//! the mock RPC cooperates with. When the SDK adds a real chain
//! identifier this is a one-line change.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::sig::KeyPair;

pub const TX_DOMAIN: &[u8] = b"octravpn-tx-v1";
pub const CHAIN_ID_MAINNET: u32 = 0x_0C_72_A0_01;

/// Operation types per `webcli/main.cpp:1054`.
pub const OP_STANDARD: &str = "standard";
pub const OP_CALL: &str = "call";
pub const OP_DEPLOY: &str = "deploy";
pub const OP_STEALTH: &str = "stealth";
pub const OP_CLAIM: &str = "claim";
pub const OP_ENCRYPT: &str = "encrypt";
pub const OP_DECRYPT: &str = "decrypt";

/// Logical Octra transaction. Use `to_canonical_json` to get the
/// signed bytes; use `sign_call` to produce a fully-signed envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OctraTx {
    pub from: String,
    /// Recipient address. Serialized as `"to_"` per Octra convention.
    pub to: String,
    /// Amount in OU (1 OCT = 1_000_000 OU; 6 decimals). Integer.
    pub amount: u64,
    pub nonce: u64,
    /// Fee in OU.
    pub ou: u64,
    pub timestamp: f64,
    pub op_type: String,
    pub encrypted_data: Option<String>,
    pub message: Option<String>,
}

impl OctraTx {
    /// Produce the exact UTF-8 bytes the wallet signs.
    pub fn to_canonical_json(&self) -> String {
        let mut s = String::with_capacity(256);
        s.push('{');
        write_kv_str(&mut s, "from", &self.from, true);
        write_kv_str(&mut s, "to_", &self.to, false);
        write_kv_str(&mut s, "amount", &self.amount.to_string(), false);
        write_kv_int(&mut s, "nonce", self.nonce, false);
        write_kv_str(&mut s, "ou", &self.ou.to_string(), false);
        write_kv_float(&mut s, "timestamp", self.timestamp, false);
        let op = if self.op_type.is_empty() {
            OP_STANDARD
        } else {
            &self.op_type
        };
        write_kv_str(&mut s, "op_type", op, false);
        if let Some(ed) = &self.encrypted_data {
            write_kv_str(&mut s, "encrypted_data", ed, false);
        }
        if let Some(m) = &self.message {
            write_kv_str(&mut s, "message", m, false);
        }
        s.push('}');
        s
    }
}

fn write_kv_str(out: &mut String, k: &str, v: &str, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(k);
    out.push_str("\":\"");
    push_json_str(out, v);
    out.push('"');
}

fn write_kv_int(out: &mut String, k: &str, v: u64, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(k);
    out.push_str("\":");
    out.push_str(&v.to_string());
}

fn write_kv_float(out: &mut String, k: &str, v: f64, first: bool) {
    use std::fmt::Write;
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(k);
    out.push_str("\":");
    // Python repr-style float for compatibility with `time.time()` repr.
    let _ = write!(out, "{v}");
}

fn push_json_str(out: &mut String, s: &str) {
    use std::fmt::Write;
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Backwards-compatible wrapper used by the rest of the workspace.
///
/// Accepts either a JSON object with the OctraTx shape, or our older
/// "kind: contract_call" envelope (which we translate to a `call`
/// op_type call-data payload). This keeps the workspace building
/// while we migrate every site to `OctraTx` directly.
pub fn canonical_bytes(call: &Value) -> Result<Vec<u8>> {
    canonical_bytes_with_chain(call, CHAIN_ID_MAINNET)
}

pub fn canonical_bytes_with_chain(call: &Value, chain_id: u32) -> Result<Vec<u8>> {
    let json = canonical_json(call)?;
    let mut out = Vec::with_capacity(TX_DOMAIN.len() + 4 + json.len());
    out.extend_from_slice(TX_DOMAIN);
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(json.as_bytes());
    Ok(out)
}

fn canonical_json(call: &Value) -> Result<String> {
    let map = call
        .as_object()
        .ok_or_else(|| anyhow!("tx must be a JSON object"))?;
    // Recognize either the legacy contract_call shape (kind, method,
    // params, value, fee, nonce, from, to) or the OctraTx shape.
    if map.contains_key("kind") {
        let from = map.get("from").and_then(|v| v.as_str()).unwrap_or("");
        let to = map.get("to").and_then(|v| v.as_str()).unwrap_or("");
        let amount = map
            .get("value")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let nonce = map
            .get("nonce")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let ou = map
            .get("fee")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let timestamp = map
            .get("timestamp")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0);
        let op_type = OP_CALL.to_string();
        // Encode method+params as the encrypted_data slot per Octra
        // contract-call convention. Method = first param of the
        // `call` data; params are JSON-encoded after.
        let method = map.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let params = map
            .get("params")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![]));
        let payload = json!({"method": method, "params": params}).to_string();
        let encrypted = Some(payload);
        let tx = OctraTx {
            from: from.to_string(),
            to: to.to_string(),
            amount,
            nonce,
            ou,
            timestamp,
            op_type,
            encrypted_data: encrypted,
            message: None,
        };
        return Ok(tx.to_canonical_json());
    }
    // Direct OctraTx shape.
    let tx: OctraTx = serde_json::from_value(call.clone())
        .map_err(|e| anyhow!("not an OctraTx envelope: {e}"))?;
    Ok(tx.to_canonical_json())
}

/// Sign a tx envelope and append `signature` + `public_key` (base64).
pub fn sign_call(kp: &KeyPair, mut call: Value) -> Result<Value> {
    let bytes = canonical_bytes(&call)?;
    let sig = kp.sign(&bytes);
    let map = call
        .as_object_mut()
        .ok_or_else(|| anyhow!("tx must be a JSON object"))?;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    map.insert("signature".into(), json!(STANDARD.encode(sig.0)));
    map.insert("public_key".into(), json!(STANDARD.encode(kp.public.0)));
    Ok(call)
}

/// Verify a signed tx envelope **using only the envelope itself** — no
/// chain RPC required. The envelope must carry `public_key`,
/// `signature`, and `from`; this helper checks that:
///
///   1. `Address::from_pubkey(public_key)` matches the `from` field.
///   2. The Ed25519 signature verifies over the canonical bytes (with
///      `signature` and `public_key` stripped before canonicalisation).
///
/// This removes the need for the chain to expose an `octra_publicKey`
/// lookup: every signed tx carries the pubkey, and the address-from-pubkey
/// derivation is part of the well-known Octra address scheme.
pub fn verify_envelope_signature(call: &Value) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let obj = call
        .as_object()
        .ok_or_else(|| anyhow!("tx must be a JSON object"))?;
    let from = obj
        .get("from")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("tx missing `from`"))?;
    let sig_b64 = obj
        .get("signature")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("tx missing `signature`"))?;
    let pk_b64 = obj
        .get("public_key")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("tx missing `public_key`"))?;
    let sig_bytes = STANDARD
        .decode(sig_b64)
        .map_err(|e| anyhow!("signature base64: {e}"))?;
    let pk_bytes = STANDARD
        .decode(pk_b64)
        .map_err(|e| anyhow!("public_key base64: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err(anyhow!("signature wrong length: {}", sig_bytes.len()));
    }
    if pk_bytes.len() != 32 {
        return Err(anyhow!("public_key wrong length: {}", pk_bytes.len()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    // (1) Address-from-pubkey check.
    let derived_addr = crate::address::Address::from_pubkey(&pk_arr);
    let derived = derived_addr.display();
    if derived != from {
        return Err(anyhow!(
            "from={from} does not match Address::from_pubkey={derived}"
        ));
    }

    // (2) Canonical bytes are computed with signature + public_key
    //     stripped (those weren't part of the message the wallet signed).
    let mut stripped = call.clone();
    if let Some(m) = stripped.as_object_mut() {
        m.remove("signature");
        m.remove("public_key");
    }
    let bytes = canonical_bytes(&stripped)?;
    crate::sig::verify(
        &crate::sig::PublicKey(pk_arr),
        &bytes,
        &crate::sig::Signature(sig_arr),
    )
    .map_err(|e| anyhow!("sig verify: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::KeyPair;

    fn sample_call() -> Value {
        json!({
            "kind": "contract_call",
            "from": "",            // filled in below from the kp pubkey
            "to": "octPROG",
            "method": "create_tailnet",
            "params": ["ab".repeat(32)],
            "value": 100u64,
            "fee": 10u64,
            "nonce": 0u64,
        })
    }

    #[test]
    fn sign_then_verify_envelope_round_trip() {
        let kp = KeyPair::generate();
        let mut call = sample_call();
        call["from"] = json!(crate::address::Address::from_pubkey(&kp.public.0).display());
        let signed = sign_call(&kp, call).unwrap();
        verify_envelope_signature(&signed).unwrap();
    }

    #[test]
    fn verify_envelope_rejects_address_mismatch() {
        let kp = KeyPair::generate();
        let mut call = sample_call();
        // `from` is intentionally NOT the kp's derived address.
        call["from"] = json!("octIMPOSTER0000000000000000000000000000001");
        let signed = sign_call(&kp, call).unwrap();
        let r = verify_envelope_signature(&signed);
        assert!(r.is_err(), "address mismatch must fail; got {r:?}");
    }

    #[test]
    fn verify_envelope_rejects_tampered_canonical_bytes() {
        let kp = KeyPair::generate();
        let mut call = sample_call();
        call["from"] = json!(crate::address::Address::from_pubkey(&kp.public.0).display());
        let mut signed = sign_call(&kp, call).unwrap();
        // Mutate a field after signing — signature was over the old bytes.
        signed["value"] = json!(999u64);
        assert!(verify_envelope_signature(&signed).is_err());
    }

    #[test]
    fn canonical_json_roundtrip_octratx() {
        let tx = OctraTx {
            from: "octFROM".into(),
            to: "octTO".into(),
            amount: 100,
            nonce: 7,
            ou: 1000,
            timestamp: 1.23,
            op_type: OP_STANDARD.into(),
            encrypted_data: None,
            message: None,
        };
        let s = tx.to_canonical_json();
        assert!(s.starts_with("{\"from\":\"octFROM\""));
        assert!(s.contains("\"to_\":\"octTO\""));
        assert!(s.contains("\"op_type\":\"standard\""));
        assert!(s.ends_with('}'));
    }

    #[test]
    fn legacy_contract_call_canonicalizes() {
        let v = json!({
            "kind": "contract_call",
            "from": "octF",
            "to": "octT",
            "method": "register",
            "params": [],
            "value": 100u64,
            "fee": 1000u64,
            "nonce": 1u64,
            "timestamp": 0.0
        });
        let bytes = canonical_bytes(&v).unwrap();
        // Domain prefix + chain id are first 18 bytes.
        assert!(bytes.starts_with(TX_DOMAIN));
    }

    #[test]
    fn signing_roundtrip() {
        let kp = KeyPair::generate();
        let v = json!({
            "kind": "contract_call",
            "from": "octF",
            "to": "octT",
            "method": "x",
            "params": [],
            "value": 0u64,
            "fee": 1000u64,
            "nonce": 0u64,
            "timestamp": 0.0
        });
        let signed = sign_call(&kp, v).unwrap();
        let bytes = canonical_bytes(&signed).unwrap();
        let sig_b64 = signed["signature"].as_str().unwrap();
        let pk_b64 = signed["public_key"].as_str().unwrap();
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let sig_bytes = STANDARD.decode(sig_b64).unwrap();
        let pk_bytes = STANDARD.decode(pk_b64).unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        crate::sig::verify(
            &crate::sig::PublicKey(pk_arr),
            &bytes,
            &crate::sig::Signature(sig_arr),
        )
        .unwrap();
    }
}
