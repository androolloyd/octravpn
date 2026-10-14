// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native bundle admission. These checks authenticate commitments and receipt
//! bindings; executing the bundle against the parent ledger is a separate gate.
use num_bigint::BigInt;
use octra_node_protocol::{
    consensus::{engine::tx_list_hash_for_header, hash, Bytes, EpochHeader, Error},
    native_json::Document,
    preverify_commit,
    transaction::{self, Transaction},
    transaction_outcome::{self, Rejection},
    transaction_payload::{self, Limits},
};

/// Resolve from trusted historical configuration at the bundle's epoch.
pub struct Rules {
    pub payload: Limits,
    pub crypto_active: bool,
    pub stealth_minimum: BigInt,
    pub envelope: transaction_outcome::Rules,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawBundle {
    pub tx_hashes: Vec<Bytes>,
    pub txs_json: Vec<Bytes>,
    pub receipts_json: Vec<Bytes>,
}
pub struct Accepted {
    pub tx_hashes: Vec<Bytes>,
    pub txs: Vec<Transaction>,
    pub receipts_json: Vec<Bytes>,
    pub rejections: Vec<Rejection>,
}
/// A finalized bundle with native execution inputs already selected. Historical
/// rejection receipts remain in the bundle; only this partition enters replay.
pub struct Replay {
    bundle: Accepted,
    partition: crate::epoch_partition::Partition,
}
impl Replay {
    pub fn bundle(&self) -> &Accepted {
        &self.bundle
    }
    pub fn partition(&self) -> &crate::epoch_partition::Partition {
        &self.partition
    }
}
impl Accepted {
    pub fn replay(self, rules: transaction_outcome::Rules) -> Result<Replay, Error> {
        let partition =
            crate::epoch_partition::Partition::finalized(&self.txs, &self.rejections, rules)
                .map_err(error)?;
        Ok(Replay {
            bundle: self,
            partition,
        })
    }
    /// Native cache/journal representation: hexadecimal hashes and normalized
    /// transaction JSON, after the network response has passed admission.
    pub fn to_raw(&self) -> Result<RawBundle, Error> {
        Ok(RawBundle {
            tx_hashes: self.tx_hashes.clone(),
            txs_json: self
                .txs
                .iter()
                .map(|tx| tx.to_json_bytes().map_err(error))
                .collect::<Result<_, _>>()?,
            receipts_json: self.receipts_json.clone(),
        })
    }
}
fn error(e: impl std::fmt::Display) -> Error {
    e.to_string().into()
}
fn parse(raw: &RawBundle, rules: &Rules) -> Result<Vec<Transaction>, Error> {
    raw.txs_json
        .iter()
        .map(|bytes| {
            let doc = Document::parse(bytes).map_err(error)?;
            let tx =
                Transaction::from_document(&doc).map_err(|e| error(format!("of_yojson: {e}")))?;
            transaction_payload::admit(rules.payload, &tx)
                .map_err(|e| error(format!("of_yojson: {e}")))?;
            Ok(tx)
        })
        .collect()
}
fn hashes(txs: &[Transaction]) -> Result<Vec<Bytes>, Error> {
    txs.iter()
        .map(|tx| {
            tx.hash()
                .map(|h| hex::encode(h).into_bytes())
                .map_err(error)
        })
        .collect()
}
fn artifacts(
    raw: &RawBundle,
    rules: &Rules,
    txs: &[Transaction],
    check_epoch: bool,
) -> Result<Vec<Rejection>, Error> {
    let items = transaction_outcome::split(&raw.receipts_json, true)
        .map_err(|e| error(format!("bundle outcome: {e}")))?;
    preverify_commit::check_strings(
        &items.preverify,
        txs,
        rules.crypto_active,
        &rules.stealth_minimum,
    )
    .map_err(|e| error(format!("bundle preverify: {e}")))?;
    let inputs = transaction_outcome::merge(txs, &items.rejections)
        .map_err(|e| error(format!("bundle outcome: {e}")))?;
    if check_epoch {
        transaction::check_compute(rules.envelope.compute, rules.envelope.settle, &inputs)
            .map_err(error)?;
        transaction::check_envelopes(rules.envelope.envelope, &inputs).map_err(error)?;
    }
    Ok(items.rejections)
}
fn accepted(raw: &RawBundle, txs: Vec<Transaction>, rejections: Vec<Rejection>) -> Accepted {
    Accepted {
        tx_hashes: raw.tx_hashes.clone(),
        txs,
        receipts_json: raw.receipts_json.clone(),
        rejections,
    }
}
/// Cached proposal bundles carry hexadecimal transaction hashes.
pub fn decode(raw: &RawBundle, rules: &Rules) -> Result<Accepted, Error> {
    if raw.tx_hashes.len() != raw.txs_json.len() {
        return Err("bundle length mismatch".into());
    }
    let txs = parse(raw, rules)?;
    if hashes(&txs)? != raw.tx_hashes {
        return Err("bundle tx hash mismatch".into());
    }
    let rejections = artifacts(raw, rules, &txs, false)?;
    Ok(accepted(raw, txs, rejections))
}
/// Network responses accept raw 32-byte hashes or their hexadecimal form.
pub fn finalized(header: &EpochHeader, raw: &RawBundle, rules: &Rules) -> Result<Accepted, Error> {
    if raw.tx_hashes.len() != raw.txs_json.len() {
        return Err("bundle length mismatch".into());
    }
    let txs = parse(raw, rules)?;
    let normalized = RawBundle {
        tx_hashes: raw.tx_hashes.iter().map(|h| hash_hex(h)).collect(),
        ..raw.clone()
    };
    if hashes(&txs)? != normalized.tx_hashes {
        return Err("bundle tx hash mismatch".into());
    }
    if tx_list_hash_for_header(&normalized.tx_hashes).as_slice() != header.tx_list_hash {
        return Err("bundle tx_list_hash mismatch".into());
    }
    if hash::receipt_root(&raw.receipts_json)?.as_slice() != header.receipt_root {
        return Err("bundle receipt_root mismatch".into());
    }
    let rejections = artifacts(raw, rules, &txs, true)?;
    Ok(accepted(&normalized, txs, rejections))
}
/// Bind a fetched proposal bundle to the hashes from the authenticated proposal.
/// Native admission only uses response hashes for the length check; accepted
/// hashes come from the proposal. The engine checks its header commitment.
pub fn proposal(
    header: &EpochHeader,
    expected_hashes: &[Bytes],
    raw: &RawBundle,
    rules: &Rules,
) -> Result<Accepted, Error> {
    if raw.tx_hashes.len() != raw.txs_json.len() {
        return Err("bundle length mismatch".into());
    }
    if raw.tx_hashes.len() != expected_hashes.len() {
        return Err("bundle expected length mismatch".into());
    }
    if hash::receipt_root(&raw.receipts_json)?.as_slice() != header.receipt_root {
        return Err("bundle receipt_root mismatch".into());
    }
    let txs = parse(raw, rules)?;
    if hashes(&txs)? != expected_hashes {
        return Err("bundle tx hash mismatch".into());
    }
    let rejections = artifacts(raw, rules, &txs, true)?;
    Ok(Accepted {
        tx_hashes: expected_hashes.to_vec(),
        txs,
        receipts_json: raw.receipts_json.clone(),
        rejections,
    })
}
pub(crate) fn hash_hex(bytes: &[u8]) -> Bytes {
    if bytes.len() == 32 {
        hex::encode(bytes).into_bytes()
    } else {
        bytes.to_vec()
    }
}
