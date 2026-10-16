//! Native full and bounded-prefix transaction summary projections.
use super::{
    boolean, display_from, display_to, float, number, object, string, unavailable, Document, Fault,
    Head, NativeTransaction, Transaction,
};
pub(super) fn summary(
    head: &Head,
    record: &NativeTransaction,
) -> std::result::Result<Vec<u8>, Fault> {
    let tx =
        Transaction::from_document(&Document::parse(&record.transaction).map_err(unavailable)?)
            .map_err(unavailable)?;
    let mut values = vec![
        ("hash", string(&record.hash)),
        ("epoch", number(head.cursor.epoch.0)),
        ("from", string(display_from(&tx))),
        ("to", string(display_to(&tx))),
        ("amount", string(tx.amount.to_string())),
        ("ou", string(tx.ou.to_string())),
        ("timestamp", float(tx.timestamp)?),
        ("op_type", string(tx.op_type.as_str())),
    ];
    if let Some(value) = tx.encrypted_data.filter(|value| !value.is_empty()) {
        values.push(("has_encrypted_data", boolean(true)));
        values.push(("encrypted_data_len", number(value.len())));
    }
    if let Some(value) = tx.message.filter(|value| !value.is_empty()) {
        values.push(("has_message", boolean(true)));
        values.push(("message_len", number(value.len())));
    }
    Ok(object(&values))
}
fn find(raw: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    raw.get(start..)?
        .windows(needle.len())
        .position(|value| value == needle)
        .map(|offset| start + offset)
}
fn start(raw: &[u8], key: &[u8]) -> Option<usize> {
    let quoted = [b"\"".as_slice(), key, b"\""].concat();
    let at = find(raw, &quoted, 0)?;
    let colon = find(raw, b":", at + quoted.len())?;
    let mut start = colon + 1;
    while raw
        .get(start)
        .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
    {
        start += 1;
    }
    Some(start)
}
fn text(raw: &[u8], key: &[u8]) -> Vec<u8> {
    let Some(start) = start(raw, key).filter(|start| raw.get(*start) == Some(&b'"')) else {
        return Vec::new();
    };
    let mut escaped = false;
    let mut result = Vec::new();
    for &byte in &raw[start + 1..] {
        if escaped {
            result.push(byte);
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return result;
        } else {
            result.push(byte);
        }
    }
    Vec::new()
}
fn numeric<'a>(raw: &'a [u8], key: &[u8]) -> &'a [u8] {
    let Some(start) = start(raw, key) else {
        return b"";
    };
    let tail = &raw[start..];
    let end = tail
        .iter()
        .position(|byte| matches!(byte, b',' | b'}' | b' ' | b'\n' | b'\r' | b'\t'))
        .unwrap_or(tail.len());
    &tail[..end]
}
pub(super) fn prefix(
    head: &Head,
    record: &NativeTransaction,
) -> std::result::Result<Vec<u8>, Fault> {
    let tx =
        Transaction::from_document(&Document::parse(&record.transaction).map_err(unavailable)?)
            .map_err(unavailable)?;
    // The retained exact identity includes explicit null optionals; native
    // txlog stores Transaction.to_yojson with absent optionals omitted.
    let raw = tx.to_json_bytes().map_err(unavailable)?;
    let raw = &raw[..raw.len().min(16_384)];
    let timestamp = std::str::from_utf8(numeric(raw, b"timestamp"))
        .ok()
        .and_then(|raw| raw.parse::<f64>().ok())
        .unwrap_or(0.);
    let from = text(raw, b"from");
    let to = text(raw, b"to_");
    let amount = text(raw, b"amount");
    let ou = text(raw, b"ou");
    let operation = text(raw, b"op_type");
    let from = if matches!(operation.as_slice(), b"stealth" | b"claim") {
        b"-".as_slice()
    } else {
        &from
    };
    let to = if operation == b"claim" {
        b"-".as_slice()
    } else {
        &to
    };
    Ok(object(&[
        ("hash", string(&record.hash)),
        ("epoch", number(head.cursor.epoch.0)),
        ("from", string(from)),
        ("to", string(to)),
        (
            "amount",
            string(if amount.is_empty() {
                b"0".as_slice()
            } else {
                &amount
            }),
        ),
        (
            "ou",
            string(if ou.is_empty() { b"0".as_slice() } else { &ou }),
        ),
        ("timestamp", float(timestamp)?),
        (
            "op_type",
            string(if operation.is_empty() {
                b"standard".as_slice()
            } else {
                &operation
            }),
        ),
        ("summary_truncated", boolean(true)),
    ]))
}
