// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native full-range and common-prefix source agreement. Responses must already
//! have passed window, membership, signature and per-responder deduplication.
use super::{driver_policy, hash, Bytes, CatchupResponse, Error, ValidatorSet};
use crate::native_table::Table;
use num_bigint::BigInt;
use std::collections::BTreeSet;

struct Group<'a> {
    weight: BigInt,
    count: i64,
    epoch: i64,
    response: &'a CatchupResponse,
    prefix: Option<usize>,
}
fn add<'a>(
    groups: &mut Table<Group<'a>>,
    key: Bytes,
    response: &'a CatchupResponse,
    prefix: Option<usize>,
    epoch: i64,
    weight: BigInt,
) {
    let group = match groups.get(&key) {
        Some(prior) => Group {
            weight: &prior.weight + weight,
            count: prior.count + 1,
            epoch: prior.epoch,
            response: prior.response,
            prefix: prior.prefix,
        },
        None => Group {
            weight,
            count: 1,
            epoch,
            response,
            prefix,
        },
    };
    groups.replace(key, group);
}

#[derive(Default)]
pub struct Agreement {
    rejected: BTreeSet<Bytes>,
}
impl Agreement {
    /// Pass responses newest first, as retained by the native handler. Rejected
    /// responders stay excluded for the lifetime of this query. The caller
    /// supplies the historical, already weight-capped validator set per epoch.
    /// Prefix selections need a fresh response signature before re-encoding.
    pub fn select<'a>(
        &mut self,
        chain: &[u8],
        from_epoch: i64,
        responses: impl IntoIterator<Item = &'a CatchupResponse>,
        mut validators: impl FnMut(i64) -> Result<ValidatorSet, Error>,
        mut validate: impl FnMut(&CatchupResponse) -> Result<bool, Error>,
    ) -> Result<Option<CatchupResponse>, Error> {
        let mut full = Table::new(8);
        let mut prefixes = Table::new(16);
        for response in responses {
            if self.rejected.contains(&response.responder_addr) {
                continue;
            }
            let key = if validate(response)? {
                driver_policy::catchup_response_key(response)?
            } else {
                None
            };
            let Some(key) = key else {
                self.rejected.insert(response.responder_addr.clone());
                continue;
            };
            let epoch = driver_policy::catchup_agreement_epoch(from_epoch, &response.records);
            let weight = validators(epoch)?
                .weight(&response.responder_addr)
                .cloned()
                .unwrap_or_default();
            add(&mut full, key, response, None, epoch, weight);
            if response.status != b"ok" {
                continue;
            }
            for length in 1..=response.records.len() {
                let records = &response.records[..length];
                let epoch = driver_policy::catchup_agreement_epoch(from_epoch, records);
                let weight = validators(epoch)?
                    .weight(&response.responder_addr)
                    .cloned()
                    .unwrap_or_default();
                let mut key = format!("ok|prefix:{length}|").into_bytes();
                key.extend_from_slice(&hash::catchup_records_root(records)?);
                add(&mut prefixes, key, response, Some(length), epoch, weight);
            }
        }
        // Native fold keeps the first hash-table entry on ties. Select before
        // checking quorum, including the native longest-prefix preference.
        let best_full = full.iter().map(|(_, group)| group).reduce(|best, group| {
            if group.weight > best.weight {
                group
            } else {
                best
            }
        });
        let best_prefix = prefixes
            .iter()
            .map(|(_, group)| group)
            .reduce(|best, group| {
                if (group.prefix, &group.weight) > (best.prefix, &best.weight) {
                    group
                } else {
                    best
                }
            });
        for group in [best_full, best_prefix].into_iter().flatten() {
            if driver_policy::catchup_source_agreement_reached(
                &validators(group.epoch)?,
                super::policy::quorum_active(chain, group.epoch),
                group.count,
                &group.weight,
            ) {
                // Groups borrow records; only the selected representative is
                // copied, instead of cloning every payload for every prefix.
                let mut response = group.response.clone();
                if let Some(length) = group.prefix {
                    response.records.truncate(length);
                    response.next_epoch = Some(group.epoch.wrapping_add(1));
                }
                return Ok(Some(response));
            }
        }
        Ok(None)
    }
}

/// Prevent one request spanning a scheduled validator-set change.
pub fn limit(from_epoch: i64, max_epochs: i64, activation: Option<i64>) -> i64 {
    match activation {
        Some(epoch) if from_epoch < epoch && max_epochs > 0 => {
            max_epochs.min(epoch.wrapping_sub(from_epoch))
        }
        _ => max_epochs,
    }
}
pub fn waves<T>(set: &ValidatorSet, mut peers: Vec<T>) -> Vec<Vec<T>> {
    let width = (set.f + 2).max(1) as usize;
    let mut second = peers.split_off(peers.len().min(width));
    let third = second.split_off(second.len().min(width));
    [peers, second, third]
        .into_iter()
        .filter(|wave| !wave.is_empty())
        .collect()
}
#[allow(clippy::cast_precision_loss)] // Native float_of_int; actual plans have at most three waves.
pub fn wave_delay(budget: f64, count: usize) -> f64 {
    if count <= 1 {
        budget
    } else {
        (budget / count as f64).min(0.5)
    }
}
