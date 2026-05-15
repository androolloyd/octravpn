//! Octra transaction signing — canonical form per
//! `octra-labs/webcli/lib/tx_builder.hpp:78-92` (cross-confirmed by the
//! Rust `ocs01-test` and Python `octra_pre_client` references).
//!
//! The signed bytes are the **UTF-8-encoded JSON string** with fixed,
//! insertion-order field layout — and **nothing else**. No domain
//! prefix, no chain id. Real Octra wallets sign the bare canonical
//! JSON, and the node verifies over the same bytes:
//!
//! ```text
//! {"from":"<from>","to_":"<to>","amount":"<amt>","nonce":<int>,
//!  "ou":"<ou>","timestamp":<float>,"op_type":"<op_or_standard>"
//!  [,"encrypted_data":"..."][,"message":"..."]}
//! ```
//!
//! Notes captured from the reference dossier:
//!   - Recipient field is `"to_"` (trailing underscore), not `"to"`.
//!   - `amount` and `ou` are quoted *integer* strings (in OU).
//!   - `nonce` is an unquoted integer.
//!   - `timestamp` is an unquoted float (Python `time.time()`).
//!   - `op_type` defaults to `"standard"` when missing.
//!   - Optional fields appear only when set, in the order shown.
//!   - The signature is over the JSON bytes; `signature` and
//!     `public_key` (base64) are appended *after* signing.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::sig::KeyPair;

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

    /// Serialize as a JSON `Value` with the same field shape as
    /// `to_canonical_json` (i.e. `to_` not `to`, string `amount`/`ou`,
    /// optional `encrypted_data`/`message` only when present).
    pub fn to_envelope_value(&self) -> Value {
        let mut obj = serde_json::Map::with_capacity(10);
        obj.insert("from".into(), Value::String(self.from.clone()));
        obj.insert("to_".into(), Value::String(self.to.clone()));
        obj.insert("amount".into(), Value::String(self.amount.to_string()));
        obj.insert("nonce".into(), json!(self.nonce));
        obj.insert("ou".into(), Value::String(self.ou.to_string()));
        obj.insert("timestamp".into(), json!(self.timestamp));
        let op = if self.op_type.is_empty() {
            OP_STANDARD.to_string()
        } else {
            self.op_type.clone()
        };
        obj.insert("op_type".into(), Value::String(op));
        if let Some(ed) = &self.encrypted_data {
            obj.insert("encrypted_data".into(), Value::String(ed.clone()));
        }
        if let Some(m) = &self.message {
            obj.insert("message".into(), Value::String(m.clone()));
        }
        Value::Object(obj)
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

/// Canonical bytes the wallet signs. Real Octra signs the bare
/// canonical JSON with no envelope prefix; this matches webcli's
/// `sign_transaction(canonical_json(tx).as_bytes())`.
///
/// Accepts either an OctraTx-shaped object (the on-the-wire envelope,
/// optionally with `signature`/`public_key` already appended — they're
/// stripped before computing canonical bytes) or the legacy
/// `{"kind":"contract_call","method":...,"params":...,"value":...,"fee":...}`
/// shape used by callers inside this workspace. Either way the output
/// is the same bytes a real Octra wallet would sign.
pub fn canonical_bytes(call: &Value) -> Result<Vec<u8>> {
    Ok(canonical_json(call)?.into_bytes())
}

fn canonical_json(call: &Value) -> Result<String> {
    let tx = to_octra_tx(call)?;
    Ok(tx.to_canonical_json())
}

/// Translate either input shape to an `OctraTx`. The legacy
/// `kind:contract_call` shape becomes an `op_type=call` tx with
/// `encrypted_data` carrying `{method, params}`.
fn to_octra_tx(call: &Value) -> Result<OctraTx> {
    let map = call
        .as_object()
        .ok_or_else(|| anyhow!("tx must be a JSON object"))?;

    // Legacy `{kind: "contract_call", ...}` shape — translate.
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
        let method = map.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let params = map
            .get("params")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![]));
        let payload = json!({"method": method, "params": params}).to_string();
        let op_type = OP_CALL.to_string();
        return Ok(OctraTx {
            from: from.to_string(),
            to: to.to_string(),
            amount,
            nonce,
            ou,
            timestamp,
            op_type,
            encrypted_data: Some(payload),
            message: None,
        });
    }

    // OctraTx-shaped: support either `to_` (canonical) or `to` (alias).
    // Strip any pre-existing `signature` / `public_key` before parsing,
    // because they don't appear in the OctraTx struct.
    let mut obj = map.clone();
    obj.remove("signature");
    obj.remove("public_key");
    // serde_json's default field name for `to` is `to`. Map `to_` back.
    if let Some(v) = obj.remove("to_") {
        obj.insert("to".into(), v);
    }
    // `amount` and `ou` may arrive as quoted strings (per the wire
    // format); accept both that and an unquoted integer.
    if let Some(v) = obj.get_mut("amount") {
        if let Some(s) = v.as_str() {
            let n: u64 = s.parse().map_err(|e| anyhow!("amount parse: {e}"))?;
            *v = json!(n);
        }
    }
    if let Some(v) = obj.get_mut("ou") {
        if let Some(s) = v.as_str() {
            let n: u64 = s.parse().map_err(|e| anyhow!("ou parse: {e}"))?;
            *v = json!(n);
        }
    }
    let tx: OctraTx = serde_json::from_value(Value::Object(obj))
        .map_err(|e| anyhow!("not an OctraTx envelope: {e}"))?;
    Ok(tx)
}

/// Sign a tx envelope and append `signature` + `public_key` (base64).
///
/// Always emits the OctraTx wire shape regardless of input. Legacy
/// `{"kind":"contract_call",...}` callers get auto-translated; the
/// returned envelope uses `to_`, string-encoded `amount`/`ou`, and
/// `encrypted_data` carrying `{method, params}` for `op_type="call"`.
///
/// `call` is taken by value so existing call sites can pass an
/// owned `serde_json::json!(...)` literal without an extra `.clone()`.
#[allow(clippy::needless_pass_by_value)]
pub fn sign_call(kp: &KeyPair, call: Value) -> Result<Value> {
    let tx = to_octra_tx(&call)?;
    let canonical = tx.to_canonical_json();
    let sig = kp.sign(canonical.as_bytes());
    let mut envelope = tx.to_envelope_value();
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    if let Some(map) = envelope.as_object_mut() {
        map.insert("signature".into(), json!(STANDARD.encode(sig.0)));
        map.insert("public_key".into(), json!(STANDARD.encode(kp.public.0)));
    }
    Ok(envelope)
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
        // Mutate the *canonical* `amount` field (which is what the
        // signed envelope carries) — signature was over the old bytes.
        signed["amount"] = json!("999");
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

    /// `canonical_bytes` must equal `canonical_json(tx).as_bytes()`
    /// verbatim — no prefix, no envelope, just the JSON. This is what
    /// real Octra wallets sign and what real Octra nodes verify.
    #[test]
    fn canonical_bytes_equals_canonical_json_bytes() {
        let v = json!({
            "kind": "contract_call",
            "from": "octF", "to": "octT",
            "method": "x", "params": [],
            "value": 0u64, "fee": 1000u64, "nonce": 0u64, "timestamp": 0.0
        });
        let bytes = canonical_bytes(&v).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
        // No octravpn-tx-v1 prefix — that was incorrect for real Octra.
        assert!(!s.contains("octravpn-tx-v1"));
    }

    /// Legacy `kind:contract_call` input must translate to an `op_type=call`
    /// envelope with `encrypted_data={method,params}` on the wire.
    #[test]
    fn legacy_contract_call_translates_to_call_envelope() {
        let kp = KeyPair::generate();
        let v = json!({
            "kind": "contract_call",
            "from": crate::address::Address::from_pubkey(&kp.public.0).display(),
            "to": "octT",
            "method": "register",
            "params": [1u64, "hello"],
            "value": 100u64,
            "fee": 1000u64,
            "nonce": 1u64,
            "timestamp": 0.0,
        });
        let signed = sign_call(&kp, v).unwrap();
        let obj = signed.as_object().unwrap();
        // OctraTx shape.
        for k in [
            "from",
            "to_",
            "amount",
            "nonce",
            "ou",
            "timestamp",
            "op_type",
            "signature",
            "public_key",
        ] {
            assert!(obj.contains_key(k), "missing key {k}: {signed}");
        }
        // No legacy field names.
        for k in ["to", "value", "fee", "method", "params", "kind"] {
            assert!(!obj.contains_key(k), "unexpected legacy key {k}: {signed}");
        }
        assert_eq!(obj.get("op_type").and_then(|v| v.as_str()), Some("call"));
        assert_eq!(obj.get("amount").and_then(|v| v.as_str()), Some("100"));
        assert_eq!(obj.get("ou").and_then(|v| v.as_str()), Some("1000"));
        let ed = obj.get("encrypted_data").and_then(|v| v.as_str()).unwrap();
        let payload: Value = serde_json::from_str(ed).unwrap();
        assert_eq!(payload["method"], json!("register"));
        assert_eq!(payload["params"], json!([1u64, "hello"]));
    }

    /// An OctraTx fed in directly survives `sign_call` unchanged in shape.
    #[test]
    fn octratx_input_round_trips_envelope() {
        let kp = KeyPair::generate();
        let tx = OctraTx {
            from: crate::address::Address::from_pubkey(&kp.public.0)
                .display()
                .to_string(),
            to: "octRECIPIENT".into(),
            amount: 7,
            nonce: 42,
            ou: 50_000_000,
            timestamp: 1.0,
            op_type: OP_STANDARD.into(),
            encrypted_data: None,
            message: Some("note".into()),
        };
        let v = serde_json::to_value(&tx).unwrap();
        let signed = sign_call(&kp, v).unwrap();
        let obj = signed.as_object().unwrap();
        assert_eq!(
            obj.get("op_type").and_then(|v| v.as_str()),
            Some("standard")
        );
        assert_eq!(
            obj.get("to_").and_then(|v| v.as_str()),
            Some("octRECIPIENT")
        );
        assert_eq!(obj.get("amount").and_then(|v| v.as_str()), Some("7"));
        assert_eq!(obj.get("message").and_then(|v| v.as_str()), Some("note"));
        // No `encrypted_data` because we didn't set one.
        assert!(!obj.contains_key("encrypted_data"));
        // Verify roundtrips.
        verify_envelope_signature(&signed).unwrap();
    }

    /// The signed bytes must equal exactly `canonical_json(tx).as_bytes()`.
    /// This is the property real Octra nodes check against — webcli signs
    /// with no prefix at all.
    #[test]
    fn signed_bytes_match_webcli_algorithm() {
        let kp = KeyPair::generate();
        let from: String = crate::address::Address::from_pubkey(&kp.public.0)
            .display()
            .to_string();
        let tx = OctraTx {
            from,
            to: "octRECIPIENT".into(),
            amount: 1_000_000,
            nonce: 3,
            ou: 50_000_000,
            timestamp: 1_700_000_000.123,
            op_type: OP_STANDARD.into(),
            encrypted_data: None,
            message: None,
        };
        let canonical = tx.to_canonical_json();
        let v = serde_json::to_value(&tx).unwrap();
        let signed = sign_call(&kp, v).unwrap();
        let obj = signed.as_object().unwrap();
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let sig = STANDARD.decode(obj["signature"].as_str().unwrap()).unwrap();
        let pk = STANDARD
            .decode(obj["public_key"].as_str().unwrap())
            .unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk);
        // Verify against the bare canonical JSON bytes (no prefix).
        crate::sig::verify(
            &crate::sig::PublicKey(pk_arr),
            canonical.as_bytes(),
            &crate::sig::Signature(sig_arr),
        )
        .expect("signed bytes must equal canonical_json bytes");
    }

    #[test]
    fn signing_roundtrip() {
        let kp = KeyPair::generate();
        let v = json!({
            "kind": "contract_call",
            "from": crate::address::Address::from_pubkey(&kp.public.0).display(),
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
