// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native proposal caps, private slots and Circle turns. Preserve staging order;
//! execution supplies consensus order after these selection decisions.
use crate::{execution::Error, preverify_batch::snapshot_transition};
use num_bigint::BigInt;
use octra_node_protocol::{
    consensus::{engine::tx_list_hash_for_header, hash, ParentCommit},
    control_payload::BondedReady,
    transaction::{Nonce, OpType, Transaction},
    transaction_policy,
    validator::ready,
};
use std::collections::{BTreeMap, BTreeSet};

fn error(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
#[derive(Clone)]
pub struct Limits {
    transactions: usize,
    bytes: usize,
    ou: BigInt,
}
impl Limits {
    pub fn new(transactions: usize, bytes: usize, ou: BigInt) -> Self {
        Self {
            transactions: transactions.max(1),
            bytes: bytes.max(1024),
            ou,
        }
    }
    pub fn within(&self, inputs: &[Transaction], minimum: &BigInt) -> Result<bool, Error> {
        let mut bytes = 0usize;
        let mut ou = BigInt::from(0);
        for tx in inputs {
            bytes = bytes
                .checked_add(tx.to_json_bytes().map_err(error)?.len())
                .ok_or_else(|| error("bundle size overflow"))?;
            ou += transaction_policy::ou_cost(tx, minimum);
        }
        Ok(inputs.len() <= self.transactions && bytes <= self.bytes && ou <= self.ou)
    }
    /// Native cap stops the entire suffix at the first exceeded limit.
    pub fn cap(&self, inputs: &[Transaction], minimum: &BigInt) -> Result<Vec<Transaction>, Error> {
        let mut bytes = 0usize;
        let mut ou = BigInt::from(0);
        let mut selected = Vec::new();
        for tx in inputs {
            bytes = bytes
                .checked_add(tx.to_json_bytes().map_err(error)?.len())
                .ok_or_else(|| error("bundle size overflow"))?;
            ou += transaction_policy::ou_cost(tx, minimum);
            if selected.len() >= self.transactions || bytes > self.bytes || ou > self.ou {
                break;
            }
            selected.push(tx.clone());
        }
        Ok(selected)
    }
}

#[derive(Clone, Copy)]
pub struct Slots {
    fhe: usize,
    stealth: usize,
}
impl Slots {
    pub fn new(fhe: usize, stealth: usize) -> Self {
        Self { fhe, stealth }
    }
    /// Missing proofs and exhausted slots block every later input from that
    /// sender. Private debits reserve at most one slot per sender.
    pub fn select(
        self,
        inputs: &[Transaction],
        verified: &[Transaction],
    ) -> Result<Vec<Transaction>, Error> {
        let ready = verified
            .iter()
            .map(|tx| tx.hash().map_err(error))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut left = self;
        let mut debits = BTreeSet::new();
        let mut blocked = BTreeSet::new();
        let mut selected = Vec::new();
        for tx in inputs {
            if blocked.contains(&tx.from) {
                continue;
            }
            let (fhe, stealth, debit) = match tx.op_type {
                OpType::Encrypt | OpType::Claim | OpType::KeySwitch => (true, false, false),
                OpType::Decrypt => (true, false, true),
                OpType::Stealth => (true, true, true),
                _ => (false, false, false),
            };
            if !ready.contains(&tx.hash().map_err(error)?)
                || (fhe && left.fhe == 0)
                || (stealth && left.stealth == 0)
                || (debit && debits.contains(&tx.from))
            {
                blocked.insert(tx.from.clone());
                continue;
            }
            left.fhe -= usize::from(fhe);
            left.stealth -= usize::from(stealth);
            if debit {
                debits.insert(tx.from.clone());
            }
            selected.push(tx.clone());
        }
        Ok(selected)
    }
}

/// Circle_refill.without also removes the sender's dependent suffix.
pub fn without(inputs: &[Transaction]) -> Vec<Transaction> {
    let mut cutoffs = BTreeMap::new();
    for tx in inputs.iter().filter(|tx| snapshot_transition(tx.op_type)) {
        cutoffs
            .entry(&tx.from)
            .and_modify(|n: &mut Nonce| *n = (*n).min(tx.nonce))
            .or_insert(tx.nonce);
    }
    inputs
        .iter()
        .filter(|tx| cutoffs.get(&tx.from).is_none_or(|n| tx.nonce < *n))
        .cloned()
        .collect()
}
fn root(inputs: &[Transaction]) -> Result<Vec<u8>, Error> {
    let hashes = inputs
        .iter()
        .map(|tx| {
            tx.hash()
                .map(|h| hex::encode(h).into_bytes())
                .map_err(error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(tx_list_hash_for_header(&hashes).to_vec())
}
/// A missing/mismatched parent bundle cannot claim that the prior epoch was
/// free of snapshot transitions. Parent authentication is the caller's gate.
pub fn previous(
    chain: &[u8],
    epoch: i64,
    parent: Option<&ParentCommit>,
    transactions: Option<&[Transaction]>,
) -> Result<Option<bool>, Error> {
    let Some(parent) = parent else {
        return Ok((epoch == 0).then_some(false));
    };
    let cert = &parent.certificate;
    let header = &cert.header;
    if epoch <= 0
        || cert.epoch_id != epoch - 1
        || header.epoch_id != cert.epoch_id
        || cert.chain_id != chain
        || header.chain_id != chain
        || hash::proposal_id(header).map_err(error)?.as_slice() != cert.proposal_id
    {
        return Ok(None);
    }
    if header.tx_list_hash == root(&[])? {
        return Ok(Some(false));
    }
    match transactions {
        Some(txs) if root(txs)? == header.tx_list_hash => {
            Ok(Some(txs.iter().any(|tx| snapshot_transition(tx.op_type))))
        }
        _ => Ok(None),
    }
}
pub fn urgent(epoch: i64, tx: &Transaction) -> bool {
    tx.op_type == OpType::ValidatorReady
        && BondedReady::parse(tx.message.as_deref()).is_ok_and(|r| {
            ready::delivery(epoch, r.head_epoch) && epoch - 1 - r.head_epoch == ready::WINDOW
        })
}
pub fn turn(
    ordered: bool,
    epoch: i64,
    previous: Option<bool>,
    ordinary: &[Transaction],
    inputs: &[Transaction],
) -> Vec<Transaction> {
    let isolated = inputs.iter().any(|tx| {
        snapshot_transition(tx.op_type) && (!ordered || tx.op_type != OpType::CircleCall)
    });
    let urgent = ordinary.iter().any(|tx| urgent(epoch, tx));
    if (ordered && !isolated && !urgent) || (previous == Some(false) && !urgent) {
        inputs.to_vec()
    } else {
        ordinary.to_vec()
    }
}
