// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native preverification dependency isolation and ordered proposal preparation.
//! Callbacks perform actual proof work; a ready entry alone is not a vote.
use crate::execution::Error;
use num_bigint::BigInt;
use octra_node_protocol::{
    preverify_commit::Gate,
    preverify_receipt::Receipt,
    resource_lanes::{self, Lane},
    transaction::{Nonce, OpType, Transaction},
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Deferred,
    Unavailable,
    Invalid,
}
#[derive(Clone)]
pub struct Skip {
    pub index: usize,
    pub reason: Vec<u8>,
    pub kind: Kind,
}
#[derive(Clone)]
pub struct Ready {
    pub index: usize,
    pub receipt: Option<Receipt>,
}
pub enum Checked {
    Ready(Option<Box<Receipt>>),
    Skip { reason: Vec<u8>, kind: Kind },
}
#[derive(Default)]
pub struct Batch {
    pub ready: Vec<Ready>,
    pub skipped: Vec<Skip>,
}
impl Batch {
    /// Native retry requires every skip to be unavailable and exact input
    /// coverage, including duplicates. Dependency deferrals are not retryable.
    pub fn may_retry(&self, txs: &[Transaction]) -> Result<bool, Error> {
        if self.skipped.is_empty() || self.skipped.iter().any(|s| s.kind != Kind::Unavailable) {
            return Ok(false);
        }
        let all = hashes(txs)?;
        let mut inputs = all.clone();
        let mut covered = self
            .ready
            .iter()
            .map(|r| r.index)
            .chain(self.skipped.iter().map(|s| s.index))
            .map(|i| {
                all.get(i)
                    .copied()
                    .ok_or_else(|| Error("preverify batch index invalid".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        inputs.sort_unstable();
        covered.sort_unstable();
        Ok(inputs == covered)
    }
}
fn hashes(txs: &[Transaction]) -> Result<Vec<[u8; 32]>, Error> {
    txs.iter()
        .map(|t| t.hash().map_err(|e| Error(e.to_string())))
        .collect()
}
pub fn snapshot_transition(op: OpType) -> bool {
    matches!(
        op,
        OpType::CircleCall | OpType::CircleBalanceCellPut | OpType::CircleRegisterCellPut
    )
}
fn private_transition(op: OpType) -> bool {
    matches!(
        op,
        OpType::Encrypt | OpType::Decrypt | OpType::Stealth | OpType::Claim | OpType::KeySwitch
    )
}
fn skipped(index: usize, reason: &str) -> Skip {
    Skip {
        index,
        reason: reason.as_bytes().to_vec(),
        kind: Kind::Deferred,
    }
}
fn checked(batch: &mut Batch, index: usize, result: Checked) {
    match result {
        Checked::Ready(receipt) => batch.ready.push(Ready {
            index,
            receipt: receipt.map(|r| *r),
        }),
        Checked::Skip { reason, kind } => batch.skipped.push(Skip {
            index,
            reason,
            kind,
        }),
    }
}

fn run(
    txs: &[Transaction],
    hashes: &[[u8; 32]],
    indices: &[usize],
    verify: &mut impl FnMut(&Transaction) -> Result<Checked, Error>,
) -> Result<Batch, Error> {
    let mut positions: BTreeMap<&[u8], Vec<(Nonce, [u8; 32])>> = BTreeMap::new();
    for &i in indices
        .iter()
        .filter(|i| private_transition(txs[**i].op_type))
    {
        positions
            .entry(&txs[i].from)
            .or_default()
            .push((txs[i].nonce, hashes[i]));
    }
    let cutoffs = positions
        .into_iter()
        .filter_map(|(sender, mut positions)| {
            positions.sort();
            positions.get(1).copied().map(|cutoff| (sender, cutoff))
        })
        .collect::<BTreeMap<_, _>>();
    let (mut selected, mut isolated) = (Vec::new(), Vec::new());
    for &i in indices {
        if cutoffs
            .get(txs[i].from.as_slice())
            .is_some_and(|cutoff| (txs[i].nonce, hashes[i]) >= *cutoff)
        {
            isolated.push(skipped(i, "private_transition_dependency_deferred"));
        } else {
            selected.push(i);
        }
    }
    let mut batch = Batch::default();
    if let Some(position) = selected
        .iter()
        .position(|i| snapshot_transition(txs[*i].op_type))
    {
        let first = selected[position];
        let reason = if txs[first].op_type == OpType::CircleCall {
            "circle_receipt_snapshot_isolation"
        } else {
            "circle_cell_receipt_snapshot_isolation"
        };
        if position > 0 {
            isolated.extend(selected[position..].iter().map(|&i| skipped(i, reason)));
            selected.truncate(position);
        } else {
            let verdict = verify(&txs[first])?;
            if matches!(verdict, Checked::Ready(_)) {
                checked(&mut batch, first, verdict);
                isolated.extend(
                    selected
                        .iter()
                        .filter(|&&i| hashes[i] != hashes[first])
                        .map(|&i| skipped(i, reason)),
                );
                batch.skipped = isolated;
                return Ok(batch);
            }
            let Checked::Skip { reason, kind } = verdict else {
                unreachable!()
            };
            for &i in selected
                .iter()
                .filter(|&&i| snapshot_transition(txs[i].op_type))
            {
                isolated.push(if hashes[i] == hashes[first] {
                    Skip {
                        index: first,
                        reason: reason.clone(),
                        kind,
                    }
                } else {
                    skipped(i, "circle_preverify_deferred")
                });
            }
            selected.retain(|&i| !snapshot_transition(txs[i].op_type));
        }
    }
    for i in selected {
        checked(&mut batch, i, verify(&txs[i])?);
    }
    batch.skipped.extend(isolated);
    Ok(batch)
}

/// Mirrors Preverify_worker.run_checked, then Consensus_proposal.precheck when
/// ordered capture is enabled. Callback failures are operational errors; proof
/// rejection and temporary unavailability belong in Checked::Skip.
pub fn prepare(
    txs: &[Transaction],
    ordered: bool,
    minimum: &BigInt,
    mut verify: impl FnMut(&Transaction) -> Result<Checked, Error>,
) -> Result<Batch, Error> {
    let hashes = hashes(txs)?;
    let indices = (0..txs.len())
        .filter(|&i| !ordered || txs[i].op_type != OpType::CircleCall)
        .collect::<Vec<_>>();
    let batch = run(txs, &hashes, &indices, &mut verify)?;
    if !ordered {
        return Ok(batch);
    }
    let isolated = batch
        .ready
        .iter()
        .any(|r| snapshot_transition(txs[r.index].op_type));
    let mut result = Batch {
        ready: vec![],
        skipped: batch.skipped,
    };
    let mut used = BTreeMap::new();
    for (index, tx) in txs.iter().enumerate() {
        let item = if tx.op_type == OpType::CircleCall {
            Some(Ready {
                index,
                receipt: None,
            })
        } else {
            batch
                .ready
                .iter()
                .find(|r| hashes[r.index] == hashes[index])
                .cloned()
        };
        let Some(item) = item else {
            continue;
        };
        let checked = if tx.op_type == OpType::CircleCall && isolated {
            Err(octra_node_protocol::preverify_commit::Error::Invalid(
                b"circle cell isolation".to_vec(),
            ))
        } else {
            let lane = Lane::of(tx.op_type);
            let work = resource_lanes::work(tx, minimum).map_err(|e| Error(e.to_string()))?;
            Gate::reserve(&mut used, lane, &work, &lane.budget())
        };
        match checked {
            Ok(()) => result.ready.push(item),
            Err(reason) => result.skipped.push(skipped(index, &reason.to_string())),
        }
    }
    let mut cutoffs = BTreeMap::new();
    for skip in &result.skipped {
        let tx = &txs[skip.index];
        let cutoff = cutoffs.entry(tx.from.as_slice()).or_insert(tx.nonce);
        *cutoff = (*cutoff).min(tx.nonce);
    }
    let included = result
        .ready
        .iter()
        .filter(|r| {
            let tx = &txs[r.index];
            cutoffs
                .get(tx.from.as_slice())
                .is_none_or(|nonce| tx.nonce < *nonce)
        })
        .map(|r| hashes[r.index])
        .collect::<BTreeSet<_>>();
    let (ready, dependent): (Vec<_>, Vec<_>) = result
        .ready
        .into_iter()
        .partition(|r| included.contains(&hashes[r.index]));
    result.ready = ready;
    let dependent = dependent
        .into_iter()
        .map(|r| {
            let tx = &txs[r.index];
            let unavailable = result.skipped.iter().any(|s| {
                s.kind == Kind::Unavailable
                    && txs[s.index].from == tx.from
                    && txs[s.index].nonce <= tx.nonce
            });
            Skip {
                index: r.index,
                reason: b"predecessor deferred".to_vec(),
                kind: if unavailable {
                    Kind::Unavailable
                } else {
                    Kind::Deferred
                },
            }
        })
        .collect::<Vec<_>>();
    result.skipped.extend(dependent);
    Ok(result)
}
