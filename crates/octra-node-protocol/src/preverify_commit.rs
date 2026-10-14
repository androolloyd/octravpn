// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native admission of preverification receipts into an epoch. Cryptographic
//! verification and binding to the live ledger remain execution responsibilities.
use crate::{
    native_integer,
    preverify_receipt::{Binding, Receipt},
    resource_lanes::{self, Budget, Lane, Usage},
    transaction::{Nonce, OpType, Transaction},
};
use num_bigint::BigInt;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Invalid(Vec<u8>),
    Unavailable(String),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(bytes) => write!(f, "{}", String::from_utf8_lossy(bytes)),
            Self::Unavailable(reason) => write!(f, "preverification gate unavailable: {reason}"),
        }
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn invalid(e: impl Into<Vec<u8>>) -> Error {
    Error::Invalid(e.into())
}
fn hash(tx: &Transaction) -> Result<Vec<u8>> {
    tx.hash()
        .map(|h| hex::encode(h).into_bytes())
        .map_err(|e| Error::Unavailable(e.to_string()))
}
fn suffix(reason: &str, hash: &[u8]) -> Error {
    let mut bytes = reason.as_bytes().to_vec();
    bytes.push(b':');
    bytes.extend_from_slice(hash);
    invalid(bytes)
}
pub fn managed(tx: &Transaction) -> bool {
    matches!(
        Lane::of(tx.op_type),
        Lane::CircleCompute | Lane::Pvac | Lane::Fhe
    )
}
pub fn activation(raw: Option<&[u8]>) -> i64 {
    raw.and_then(native_integer::parse_int63)
        .filter(|n| *n >= 0)
        .unwrap_or(Nonce::MAX.get())
}
pub fn should_check(epoch: i64, activation: i64, receipts: &[Vec<u8>]) -> bool {
    !receipts.is_empty() || epoch >= activation
}
pub struct Gate {
    pub receipts: Vec<Receipt>,
}
impl Gate {
    pub fn parse(raws: &[Vec<u8>]) -> std::result::Result<Self, String> {
        raws.iter()
            .map(|raw| Receipt::parse(raw))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map(|receipts| Self { receipts })
    }
    pub fn receipt(&self, tx: &Transaction) -> Result<&Receipt> {
        let hash = hash(tx)?;
        let mut found = self.receipts.iter().filter(|r| r.tx_hash == hash);
        let receipt = found
            .next()
            .ok_or_else(|| suffix("missing_receipt", &hash))?;
        if found.next().is_some() {
            return Err(suffix("duplicate_receipt", &hash));
        }
        Ok(receipt)
    }
    pub fn check_receipt(
        tx: &Transaction,
        receipt: &Receipt,
        crypto_active: bool,
        minimum: &BigInt,
    ) -> Result<()> {
        receipt
            .validate()
            .map_err(|e| invalid(format!("invalid_receipt:{e}")))?;
        let hash = hash(tx)?;
        let lane = Lane::of(tx.op_type);
        let cost =
            resource_lanes::cost(tx, minimum).map_err(|e| Error::Unavailable(e.to_string()))?;
        let input = receipt.binding.input_hash(tx).map_err(Error::Unavailable)?;
        let output = receipt
            .binding
            .output_hash(tx, b"ok")
            .map_err(Error::Unavailable)?;
        let crypto = matches!(
            tx.op_type,
            OpType::Encrypt | OpType::Decrypt | OpType::Stealth | OpType::Claim | OpType::KeySwitch
        );
        let reason = if receipt.tx_hash != hash {
            return Err(invalid("receipt_tx_mismatch"));
        } else if receipt.lane != lane {
            Some("receipt_lane_mismatch")
        } else if !receipt.ok {
            Some("receipt_failed")
        } else if crypto_active && crypto && !matches!(receipt.binding, Binding::Private(_)) {
            Some("receipt_state_binding_missing")
        } else if receipt.input_hash != input {
            Some("receipt_input_mismatch")
        } else if receipt.output_hash != output {
            Some("receipt_output_mismatch")
        } else if receipt.cost != cost {
            Some("receipt_cost_mismatch")
        } else {
            None
        };
        reason.map_or(Ok(()), |reason| Err(suffix(reason, &hash)))
    }
    pub fn check(&self, txs: &[Transaction], crypto_active: bool, minimum: &BigInt) -> Result<()> {
        self.check_with(txs, crypto_active, minimum, Lane::budget)
    }
    pub fn check_with(
        &self,
        txs: &[Transaction],
        crypto_active: bool,
        minimum: &BigInt,
        budget: impl Fn(Lane) -> Budget,
    ) -> Result<()> {
        let hashes = txs.iter().map(hash).collect::<Result<Vec<_>>>()?;
        let mut seen = BTreeSet::new();
        for hash in &hashes {
            if !seen.insert(hash) {
                return Err(suffix("duplicate_tx", hash));
            }
        }
        let mut seen = BTreeSet::new();
        for receipt in &self.receipts {
            if !seen.insert(&receipt.tx_hash) {
                return Err(suffix("duplicate_receipt", &receipt.tx_hash));
            }
        }
        for receipt in &self.receipts {
            receipt
                .validate()
                .map_err(|e| invalid(format!("invalid_receipt:{e}")))?;
            let index = hashes
                .iter()
                .position(|h| h == &receipt.tx_hash)
                .ok_or_else(|| suffix("orphan_receipt", &receipt.tx_hash))?;
            if !managed(&txs[index]) {
                return Err(suffix("receipt_for_light_tx", &receipt.tx_hash));
            }
        }
        let mut used = BTreeMap::new();
        for tx in txs.iter().filter(|tx| managed(tx)) {
            Self::check_receipt(tx, self.receipt(tx)?, crypto_active, minimum)?;
            let lane = Lane::of(tx.op_type);
            let cost =
                resource_lanes::cost(tx, minimum).map_err(|e| Error::Unavailable(e.to_string()))?;
            Self::reserve(&mut used, lane, &cost, &budget(lane))?;
        }
        Ok(())
    }
    pub fn reserve(
        used: &mut BTreeMap<Lane, Usage>,
        lane: Lane,
        cost: &Usage,
        budget: &Budget,
    ) -> Result<()> {
        let next = used.get(&lane).cloned().unwrap_or_default().add(cost);
        if let Some(reason) = budget.over(&next) {
            return Err(invalid(format!("lane_budget:{}:{reason}", lane.as_str())));
        }
        used.insert(lane, next);
        Ok(())
    }
}
pub fn check_strings(
    raws: &[Vec<u8>],
    txs: &[Transaction],
    crypto_active: bool,
    minimum: &BigInt,
) -> Result<()> {
    Gate::parse(raws)
        .map_err(|e| invalid(format!("receipt_parse:{e}")))?
        .check(txs, crypto_active, minimum)
}
