// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native encrypted-account read authorization and strict stealth pagination.
use crate::{
    light_rpc::json::{self, boolean, number, object, optional, string},
    native_base64,
    native_integer::{parse_int63, parse_int64, parse_integer},
    native_json::{Document, Value},
    registration_rpc::verify_address_signature,
    rpc::{self, Fault},
};
use num_bigint::{BigInt, BigUint};

#[derive(Clone, Copy)]
pub struct Page {
    pub from_epoch: i64,
    pub before_id: Option<i64>,
    pub limit: usize,
}
fn epoch_string(raw: &[u8]) -> Option<i64> {
    let epoch = parse_int63(raw).filter(|value| *value >= 0)?;
    let sign = usize::from(matches!(raw.first(), Some(b'+' | b'-')));
    let exact = if raw.len() > sign + 2 && raw[sign] == b'0' && matches!(raw[sign + 1], b'u' | b'U')
    {
        [&raw[..sign], &raw[sign + 2..]].concat()
    } else {
        raw.to_vec()
    };
    (parse_integer(&exact)? == BigInt::from(epoch)).then_some(epoch)
}
pub fn from_epoch(doc: &Document, params: &Value) -> Result<i64, Fault> {
    let value = match params {
        Value::List(values) if values.is_empty() => Some(0),
        Value::List(values) => match values.first().and_then(|id| doc.get(*id)) {
            Some(Value::Int(value)) if value.get() >= 0 => Some(value.get()),
            Some(Value::String(raw)) => epoch_string(raw),
            _ => None,
        },
        _ => None,
    };
    value.ok_or_else(|| Fault::invalid(b"from_epoch must be a nonnegative integer"))
}
pub fn page(doc: &Document, params: &Value, legacy: bool) -> Result<Page, Fault> {
    let from_epoch = from_epoch(doc, params)?;
    if legacy {
        return Ok(Page {
            from_epoch,
            before_id: None,
            limit: 256,
        });
    }
    let before_id = match rpc::param(doc, params, 1) {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            match value {
                Value::Int(value) => Some(value.get()),
                Value::IntLiteral(raw) | Value::String(raw) => parse_int64(raw),
                _ => None,
            }
            .filter(|value| *value >= 0)
            .ok_or_else(|| Fault::invalid(b"before_id must be a nonnegative integer or null"))?,
        ),
    };
    let limit = match rpc::param(doc, params, 2) {
        None => 256,
        Some(Value::Int(value)) if (1..=256).contains(&value.get()) => value.get() as usize,
        _ => return Err(Fault::invalid(b"limit must be between 1 and 256")),
    };
    Ok(Page {
        from_epoch,
        before_id,
        limit,
    })
}
pub fn ids(doc: &Document, params: &Value) -> Result<Vec<i64>, Fault> {
    let Some(Value::List(values)) = rpc::param(doc, params, 0) else {
        return Err(Fault::invalid(b"ids must be an array"));
    };
    if values.is_empty() {
        return Err(Fault::invalid(b"ids must not be empty"));
    }
    if values.len() > 64 {
        return Err(Fault::invalid(b"ids exceeds limit 64"));
    }
    values
        .iter()
        .map(|id| {
            match doc.get(*id) {
                Some(Value::Int(value)) => Some(value.get()),
                Some(Value::IntLiteral(raw) | Value::String(raw)) => parse_int63(raw),
                _ => None,
            }
            .filter(|value| *value >= 0)
            .ok_or_else(|| Fault::invalid(b"ids must contain only nonnegative integers"))
        })
        .collect()
}
pub fn encrypted_auth(doc: &Document, params: &Value, address: &[u8]) -> Result<(), Fault> {
    let (Some(Value::String(signature)), Some(Value::String(public))) =
        (rpc::param(doc, params, 1), rpc::param(doc, params, 2))
    else {
        return Err(Fault::new(105, b"malformed transaction")
            .string_data(b"encryptedBalance requires [address, signature, pubkey]"));
    };
    verify_address_signature(
        address,
        public,
        signature,
        &[b"octra_encryptedBalance|".as_slice(), address].concat(),
        b"pubkey does not match address",
    )
}
pub fn view_pubkey(address: &[u8], public: Option<&[u8]>) -> Result<Vec<u8>, Fault> {
    let (key, reason) = match public {
        None => (None, Some(b"no public key registered".as_slice())),
        Some(encoded) => {
            let raw = native_base64::decode(encoded)
                .map_err(|_| Fault::new(110, b"service unavailable"))?;
            if raw.len() == 32 {
                // Native uses the birational y-coordinate formula directly,
                // including noncanonical y and denominator-zero inputs.
                let mut raw = raw;
                raw[31] &= 0x7f;
                let prime: BigUint = (BigUint::from(1_u8) << 255_usize) - BigUint::from(19_u8);
                let y = BigUint::from_bytes_le(&raw) % &prime;
                let numerator = (&y + BigUint::from(1_u8)) % &prime;
                let denominator = (&prime + BigUint::from(1_u8) - y) % &prime;
                let inverse = denominator.modpow(&(&prime - BigUint::from(2_u8)), &prime);
                let mut view = (numerator * inverse % &prime).to_bytes_le();
                view.resize(32, 0);
                (Some(json::base64(&view)), None)
            } else {
                (None, Some(b"conversion failed".as_slice()))
            }
        }
    };
    let mut fields = vec![
        ("address", string(address)),
        (
            "view_pubkey",
            optional(key.as_ref().map(std::string::String::as_bytes)),
        ),
    ];
    if let Some(reason) = reason {
        fields.push(("reason", string(reason)));
    }
    Ok(object(&fields))
}
pub fn page_response(
    page: Page,
    outputs: Vec<Vec<u8>>,
    next: Option<i64>,
    has_more: bool,
    scanned: usize,
) -> Vec<u8> {
    object(&[
        ("from_epoch", number(page.from_epoch)),
        ("before_id", page.before_id.map_or_else(json::null, number)),
        ("count", number(outputs.len())),
        ("scanned", number(scanned)),
        ("has_more", boolean(has_more)),
        ("next_before_id", next.map_or_else(json::null, number)),
        ("outputs", json::array(outputs)),
    ])
}
pub fn ids_response(requested: usize, outputs: Vec<Vec<u8>>) -> Vec<u8> {
    object(&[
        ("requested", number(requested)),
        ("count", number(outputs.len())),
        ("complete", boolean(outputs.len() == requested)),
        ("outputs", json::array(outputs)),
    ])
}
