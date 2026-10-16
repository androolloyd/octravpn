// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native epoch outcome encoding and confirmed/rejected transaction partitioning.
//! JSON syntax exceptions retain an operational error until native diagnostic
//! text is qualified; they must not be turned into an invented consensus refusal.
use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::{
    native_json::{Document, Value},
    transaction::{json_string, Transaction},
    transaction_payload,
};

pub const SCHEMA: &[u8] = b"octra_epoch_rejection";
pub const MAX_REJECTIONS: usize = 2048;

#[derive(Clone, Debug, PartialEq)]
pub struct Rejection {
    pub position: i64,
    pub tx: Transaction,
    pub error_type: Vec<u8>,
    pub reason: Vec<u8>,
    pub charged: bool,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Partition {
    pub preverify: Vec<Vec<u8>>,
    pub rejections: Vec<Rejection>,
}
#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Preverify(Vec<u8>),
    Rejection(Box<Rejection>),
}
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Rejected(String),
    #[error("outcome parsing unavailable: {0}")]
    Unavailable(String),
}
type Result<T> = std::result::Result<T, Error>;
fn reject(message: &str) -> Error {
    Error::Rejected(message.into())
}
fn unavailable(error: impl std::fmt::Display) -> Error {
    Error::Unavailable(error.to_string())
}
fn tx_hash(tx: &Transaction) -> Result<[u8; 32]> {
    tx.hash().map_err(unavailable)
}

fn normalize(default: &[u8], max: usize, value: &[u8]) -> Vec<u8> {
    let printable = value.iter().all(|b| (0x20..=0x7e).contains(b));
    if !value.is_empty() && printable && value.len() <= max {
        return value.to_vec();
    }
    let suffix = format!(" [sha256={}]", hex::encode(Sha256::digest(value)));
    let source = if value.is_empty() { default } else { value };
    let mut result: Vec<_> = source
        .iter()
        .take(max.saturating_sub(suffix.len()))
        .map(|b| if (0x20..=0x7e).contains(b) { *b } else { b'?' })
        .collect();
    result.extend_from_slice(suffix.as_bytes());
    result
}
pub fn normalize_error_type(value: &[u8]) -> Vec<u8> {
    normalize(b"execution_failed", 128, value)
}
pub fn normalize_reason(error_type: &[u8], value: &[u8]) -> Vec<u8> {
    if error_type.ends_with(b"_exception") {
        b"execution exception".to_vec()
    } else {
        normalize(b"execution rejected", 512, value)
    }
}
pub fn encode_rejection(value: &Rejection) -> Result<Vec<u8>> {
    let mut out = b"{\"schema\":\"octra_epoch_rejection\",\"position\":".to_vec();
    out.extend_from_slice(value.position.to_string().as_bytes());
    out.extend_from_slice(b",\"hash\":");
    json_string(&mut out, hex::encode(tx_hash(&value.tx)?).as_bytes());
    out.extend_from_slice(b",\"tx\":");
    out.extend_from_slice(&value.tx.to_json_bytes().map_err(unavailable)?);
    out.extend_from_slice(b",\"error_type\":");
    json_string(&mut out, &value.error_type);
    out.extend_from_slice(b",\"reason\":");
    json_string(&mut out, &value.reason);
    if value.charged {
        out.extend_from_slice(b",\"charged\":true");
    }
    out.push(b'}');
    Ok(out)
}
fn text_ok(max: usize, value: &[u8]) -> bool {
    !value.is_empty() && value.len() <= max && value.iter().all(|b| (0x20..=0x7e).contains(b))
}
/// `admit` adds native payload size/control-message admission for rejected
/// transactions. Finalized history uses `false`, as native decode_final does.
pub fn parse(raw: &[u8], admit: bool) -> Result<Item> {
    let doc = Document::parse(raw).map_err(unavailable)?;
    let field = |key| doc.field(doc.root(), key);
    if !matches!(field(b"schema"), Some(Value::String(s)) if s == SCHEMA) {
        return Ok(Item::Preverify(raw.to_vec()));
    }
    let (
        Some(Value::Int(position)),
        Some(Value::String(hash)),
        Some(tx),
        Some(Value::String(error_type)),
        Some(Value::String(reason)),
    ) = (
        field(b"position"),
        field(b"hash"),
        field(b"tx"),
        field(b"error_type"),
        field(b"reason"),
    )
    else {
        return Err(reject("rejection_fields_invalid"));
    };
    let tx = Transaction::from_value(&doc, tx)
        .and_then(|tx| {
            if admit {
                transaction_payload::admit(transaction_payload::Limits::default(), &tx)?;
            }
            Ok(tx)
        })
        .map_err(|e| reject(&format!("rejection_tx_invalid:{e}")))?;
    let value = Rejection {
        position: position.get(),
        tx,
        error_type: error_type.clone(),
        reason: reason.clone(),
        charged: matches!(field(b"charged"), Some(Value::Bool(true))),
    };
    if !(0..MAX_REJECTIONS as i64).contains(&value.position) {
        return Err(reject("rejection_position_invalid"));
    }
    if hex::encode(tx_hash(&value.tx)?).as_bytes() != hash {
        return Err(reject("rejection_hash_mismatch"));
    }
    if !text_ok(128, error_type) {
        return Err(reject("rejection_error_type_invalid"));
    }
    if !text_ok(512, reason) {
        return Err(reject("rejection_reason_invalid"));
    }
    if encode_rejection(&value)? != raw {
        return Err(reject("rejection_encoding_mismatch"));
    }
    Ok(Item::Rejection(Box::new(value)))
}
fn strictly_ordered(values: &[Rejection]) -> bool {
    values.first().is_none_or(|r| r.position > -1)
        && values.windows(2).all(|v| v[0].position < v[1].position)
}
fn distinct<'a>(transactions: impl Iterator<Item = &'a Transaction>) -> Result<bool> {
    let mut hashes = BTreeSet::new();
    for tx in transactions {
        if !hashes.insert(tx_hash(tx)?) {
            return Ok(false);
        }
    }
    Ok(true)
}
pub fn split(raws: &[Vec<u8>], admit: bool) -> Result<Partition> {
    let mut out = Partition {
        preverify: Vec::new(),
        rejections: Vec::new(),
    };
    for raw in raws {
        match parse(raw, admit)? {
            Item::Preverify(value) if out.rejections.is_empty() => out.preverify.push(value),
            Item::Preverify(_) => return Err(reject("preverify_after_rejection")),
            Item::Rejection(value) => out.rejections.push(*value),
        }
    }
    if out.rejections.len() > MAX_REJECTIONS {
        return Err(reject("rejection_count_exceeded"));
    }
    if !strictly_ordered(&out.rejections) {
        return Err(reject("rejection_positions_not_ordered"));
    }
    if !distinct(out.rejections.iter().map(|r| &r.tx))? {
        return Err(reject("rejection_hash_duplicate"));
    }
    Ok(out)
}
fn consensus_order(transactions: &[Transaction]) -> Result<Vec<Transaction>> {
    let mut keyed = transactions
        .iter()
        .map(|tx| Ok((tx.from.as_slice(), tx.nonce, tx_hash(tx)?, tx)))
        .collect::<Result<Vec<_>>>()?;
    keyed.sort_by(|a, b| (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)));
    Ok(keyed.into_iter().map(|(_, _, _, tx)| tx.clone()).collect())
}
pub fn build(
    inputs: &[Transaction],
    rejected: &[(Transaction, Vec<u8>, Vec<u8>)],
    charged: &[Transaction],
) -> Result<Vec<Rejection>> {
    let inputs = consensus_order(inputs)?;
    if !distinct(inputs.iter())? {
        return Err(reject("candidate_hash_duplicate"));
    }
    let hashes = inputs.iter().map(tx_hash).collect::<Result<Vec<_>>>()?;
    let charged = charged
        .iter()
        .map(tx_hash)
        .collect::<Result<BTreeSet<_>>>()?;
    let mut out = Vec::new();
    for (tx, error_type, reason) in rejected {
        let hash = tx_hash(tx)?;
        let position = hashes
            .iter()
            .position(|h| *h == hash)
            .ok_or_else(|| reject("rejection_not_in_candidates"))?;
        out.push(Rejection {
            position: position as i64,
            tx: tx.clone(),
            error_type: normalize_error_type(error_type),
            reason: normalize_reason(error_type, reason),
            charged: charged.contains(&hash),
        });
    }
    out.sort_by_key(|r| r.position);
    if !distinct(out.iter().map(|r| &r.tx))? {
        return Err(reject("rejection_hash_duplicate"));
    }
    Ok(out)
}
pub fn merge(confirmed: &[Transaction], rejections: &[Rejection]) -> Result<Vec<Transaction>> {
    let total = confirmed
        .len()
        .checked_add(rejections.len())
        .filter(|n| *n <= MAX_REJECTIONS)
        .ok_or_else(|| reject("outcome_count_exceeded"))?;
    if !strictly_ordered(rejections) {
        return Err(reject("rejection_positions_not_ordered"));
    }
    let (mut next_confirmed, mut next_rejected) = (0, 0);
    let mut out = Vec::with_capacity(total);
    for position in 0..total {
        match rejections.get(next_rejected) {
            Some(r) if r.position == position as i64 => {
                out.push(r.tx.clone());
                next_rejected += 1;
            }
            Some(r) if r.position < position as i64 => {
                return Err(reject("rejection_position_duplicate"))
            }
            _ => {
                out.push(
                    confirmed
                        .get(next_confirmed)
                        .ok_or_else(|| reject("rejection_position_missing"))?
                        .clone(),
                );
                next_confirmed += 1;
            }
        }
    }
    if next_confirmed != confirmed.len() || next_rejected != rejections.len() {
        return Err(reject("outcome_partition_incomplete"));
    }
    if consensus_order(&out)? != out {
        return Err(reject("outcome_order_invalid"));
    }
    if !distinct(out.iter())? {
        return Err(reject("outcome_hash_duplicate"));
    }
    Ok(out)
}
pub fn executed(confirmed: &[Transaction], rejections: &[Rejection]) -> Result<Vec<Transaction>> {
    let transactions: Vec<_> = confirmed
        .iter()
        .chain(rejections.iter().filter(|r| r.charged).map(|r| &r.tx))
        .cloned()
        .collect();
    consensus_order(&transactions)
}
pub fn decode(confirmed: &[Transaction], raws: &[Vec<u8>], admit: bool) -> Result<Partition> {
    let partition = split(raws, admit)?;
    merge(confirmed, &partition.rejections)?;
    Ok(partition)
}
pub fn encode(preverify: &[Vec<u8>], rejections: &[Rejection]) -> Result<Vec<Vec<u8>>> {
    let mut out = preverify.to_vec();
    for rejection in rejections {
        out.push(encode_rejection(rejection)?);
    }
    Ok(out)
}

/// Rules come from the host's authenticated rule fold, not peer receipts.
#[derive(Clone, Copy)]
pub struct Rules {
    pub envelope: crate::transaction::RuleMode,
    pub compute: crate::transaction::RuleMode,
    pub settle: crate::transaction::RuleMode,
}
pub fn check_charged(mode: crate::transaction::RuleMode, rejections: &[Rejection]) -> Result<()> {
    use crate::transaction::{OpType, RuleMode};
    if rejections.iter().all(|r| {
        !r.charged
            || mode == RuleMode::Active
                && matches!(
                    r.tx.op_type,
                    OpType::ComputeFund | OpType::ComputeReturn | OpType::ComputeSettle
                )
    }) {
        Ok(())
    } else {
        Err(reject("charged outcome not active"))
    }
}
pub fn check_envelopes(
    rules: Rules,
    confirmed: &[Transaction],
    receipts: &[Vec<u8>],
) -> Result<()> {
    use crate::transaction::{self, RuleMode};
    if rules.envelope == RuleMode::Prior {
        return Ok(());
    }
    let partition = decode(confirmed, receipts, false)?;
    check_charged(rules.compute, &partition.rejections)?;
    let inputs = merge(confirmed, &partition.rejections)?;
    transaction::check_compute(rules.compute, rules.settle, &inputs).map_err(|e| reject(&e.0))?;
    transaction::check_envelopes(rules.envelope, &inputs).map_err(|e| reject(&e.0))
}
