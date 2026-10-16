// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native payload admission and lifetime of the host's temporary key material.
use crate::circle::{MAX_CALL_INPUT_BYTES, MAX_INPUT_BYTES};
use octra_node_protocol::circle_wasm::{transcript, Error};
use serde_json::Value;
use std::sync::OnceLock;
use zeroize::{Zeroize, Zeroizing};

struct Input(Value);
impl Drop for Input {
    fn drop(&mut self) {
        if let Some(Value::String(secret)) = self
            .0
            .get_mut("hfhe_active_key")
            .and_then(|key| key.get_mut("seckey_b64"))
        {
            secret.zeroize();
        }
    }
}

/// Only this module can admit an adapted wire payload. The engine receives the
/// longer metadata encoding without reinterpreting it as a protocol byte count.
pub(crate) struct Encoded {
    bytes: Zeroizing<Vec<u8>>,
    calls: bool,
}
impl Encoded {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn calls(&self) -> bool {
        self.calls
    }
}

/// Size the full native payload before any local cache omission. The byte key
/// ID substitutes for the adapter's optional base64 metadata transport only.
// Preserve the native bounds expression and intermediate arithmetic.
#[allow(clippy::manual_div_ceil)]
pub(crate) fn encode(
    value: Value,
    proof: bool,
    calls: bool,
    key_id: Option<&[u8]>,
) -> Result<Encoded, Error> {
    let mut input = Input(value);
    let limit = if calls {
        MAX_CALL_INPUT_BYTES
    } else {
        MAX_INPUT_BYTES
    };
    if proof {
        let reserved = receipt_bytes();
        if input
            .0
            .get("hfhe_receipt_entries")
            .and_then(|v| measure(v, reserved, None))
            .is_none()
        {
            return Err(Error::Rejected(b"input too large".to_vec()));
        }
        let mode = std::mem::replace(
            &mut input.0["hfhe_receipt_mode"],
            Value::String("capture".into()),
        );
        let entries = std::mem::replace(&mut input.0["hfhe_receipt_entries"], Value::Array(vec![]));
        let fits = measure(&input.0, limit - reserved + 2, key_id).is_some();
        input.0["hfhe_receipt_mode"] = mode;
        input.0["hfhe_receipt_entries"] = entries;
        if !fits {
            return Err(Error::Rejected(b"input too large".to_vec()));
        }
    }
    // A missing cache transport is an operational limit, never a new consensus
    // rejection. The logical check above always includes code and full storage.
    if measure(&input.0, limit, key_id).is_none() {
        return Err(Error::Unavailable(
            b"Circle input requires native cache transport".to_vec(),
        ));
    }
    let bytes = Zeroizing::new(
        serde_json::to_vec(&input.0)
            .map_err(|error| Error::Unavailable(error.to_string().into_bytes()))?,
    );
    // Only one byte-string key ID is adapted. Even an all-high-byte ID expands
    // by at most its base64 ratio and the alternate metadata field name.
    if bytes.len() > ((limit + 2) / 3) * 4 + 16 {
        return Err(Error::Unavailable(
            b"Circle input requires native byte-preserving transport".to_vec(),
        ));
    }
    Ok(Encoded { bytes, calls })
}

fn receipt_bytes() -> usize {
    static SIZE: OnceLock<usize> = OnceLock::new();
    *SIZE.get_or_init(|| {
        transcript::entries_json(&vec![
            transcript::Entry {
                method: vec![0; 64],
                request_hash: vec![b'0'; 64],
                response_hash: vec![b'0'; 64],
                result: None,
            };
            transcript::MAX_ENTRIES
        ])
        .len()
    })
}

/// Json_tree.measure, using a stack so payload nesting cannot consume the host
/// call stack. String sizes count native bytes, including DEL escaping.
fn measure(value: &Value, limit: usize, key_id: Option<&[u8]>) -> Option<usize> {
    enum Part<'a> {
        Value(&'a Value, bool),
        String(&'a [u8]),
    }
    let mut pending = vec![Part::Value(value, false)];
    let mut left = limit;
    while let Some(part) = pending.pop() {
        let size = match part {
            Part::String(raw) => {
                left = left.checked_sub(2)?;
                for byte in raw {
                    left = left.checked_sub(match byte {
                        b'"' | b'\\' | 8 | 12 | b'\n' | b'\r' | b'\t' => 2,
                        0..=31 | 127 => 6,
                        _ => 1,
                    })?;
                }
                0
            }
            Part::Value(Value::String(raw), _) => {
                pending.push(Part::String(raw.as_bytes()));
                0
            }
            Part::Value(Value::Array(items), _) => {
                pending.extend(items.iter().map(|item| Part::Value(item, false)));
                2 + items.len().saturating_sub(1)
            }
            Part::Value(Value::Object(fields), active) => {
                for (name, value) in fields {
                    if active && name == "key_id_b64" && key_id.is_some() {
                        pending.push(Part::String(b"key_id"));
                        pending.push(Part::String(key_id?));
                    } else {
                        pending.push(Part::String(name.as_bytes()));
                        pending.push(Part::Value(value, name == "hfhe_active_key"));
                    }
                }
                2 + fields.len().saturating_sub(1) + fields.len()
            }
            Part::Value(atom, _) => atom.to_string().len(),
        };
        left = left.checked_sub(size)?;
    }
    Some(limit - left)
}
