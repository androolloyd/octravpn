// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native round-sync history and weighted witnesses. Callers authenticate syncs
//! before admission; this cache does not verify signatures or peer identities.
use super::{engine::MAX_SYNC_AHEAD, Bytes, RoundSync, ValidatorSet};
use num_bigint::BigInt;
use std::{cmp::Ordering, collections::BTreeMap};

fn int63(value: i64) -> i64 {
    value.wrapping_shl(1) >> 1
}
fn later(left: &RoundSync, right: &RoundSync) -> bool {
    left.epoch_id > right.epoch_id
        || left.epoch_id == right.epoch_id
            && (left.round > right.round
                || left.round == right.round
                    && (left.request && !right.request
                        || left.request == right.request && (left.step as u8) > (right.step as u8)))
}
fn key(sync: &RoundSync) -> Bytes {
    [sync.round.to_string().as_bytes(), b"\0", &sync.validator].concat()
}

#[derive(Default)]
pub struct RoundPool {
    epoch: Option<i64>,
    by_address: BTreeMap<Bytes, RoundSync>,
    by_round: BTreeMap<Bytes, RoundSync>,
    replies: BTreeMap<Bytes, (RoundSync, f64)>,
    sent: BTreeMap<i64, RoundSync>,
    sent_top: Option<i64>,
}
impl RoundPool {
    /// Native clear retains the epoch discriminator.
    pub fn clear(&mut self) {
        self.by_address.clear();
        self.by_round.clear();
        self.replies.clear();
        self.sent.clear();
        self.sent_top = None;
    }
    pub fn add_at(&mut self, current: i64, sync: RoundSync, now: f64) {
        match self.epoch {
            Some(epoch) if sync.epoch_id < epoch => return,
            Some(epoch) if sync.epoch_id > epoch => {
                self.clear();
                self.epoch = Some(sync.epoch_id);
            }
            None => self.epoch = Some(sync.epoch_id),
            _ => (),
        }
        if self
            .by_address
            .get(&sync.validator)
            .map_or(true, |prior| later(&sync, prior))
        {
            self.by_address.insert(sync.validator.clone(), sync.clone());
        }
        if !sync.request
            && self
                .replies
                .get(&sync.validator)
                .map_or(true, |(prior, _)| !later(prior, &sync))
        {
            // Equal replies refresh their wall-clock timestamp, unlike history.
            self.replies
                .insert(sync.validator.clone(), (sync.clone(), now));
        }
        let floor = int63(current.wrapping_sub(MAX_SYNC_AHEAD)).max(0);
        let ceiling = int63(current.wrapping_add(MAX_SYNC_AHEAD));
        if sync.round >= floor && sync.round <= ceiling {
            let key = key(&sync);
            if self
                .by_round
                .get(&key)
                .map_or(true, |prior| later(&sync, prior))
            {
                self.by_round.insert(key, sync);
            }
            self.by_round
                .retain(|_, sync| sync.round >= floor && sync.round <= ceiling);
        }
    }
    pub fn add(&mut self, sync: RoundSync, now: f64) {
        self.add_at(sync.round, sync, now);
    }
    pub fn add_local(&mut self, sync: RoundSync, now: f64) {
        self.add(sync.clone(), now);
        if self.epoch != Some(sync.epoch_id) || sync.request {
            return;
        }
        let top = self.sent_top.map_or(sync.round, |v| v.max(sync.round));
        self.sent_top = Some(top);
        let floor = int63(top.wrapping_sub(MAX_SYNC_AHEAD));
        if sync.round >= floor
            && self
                .sent
                .get(&sync.round)
                .map_or(true, |prior| later(&sync, prior))
        {
            self.sent.insert(sync.round, sync);
        }
        self.sent.retain(|round, _| *round >= floor);
    }
    pub fn reply(&self, epoch: i64, validator: &[u8]) -> Option<&(RoundSync, f64)> {
        if self.epoch == Some(epoch) {
            self.replies.get(validator)
        } else {
            None
        }
    }
    pub fn sent_reply(&self, epoch: i64, after: i64, through: i64) -> Option<&RoundSync> {
        if self.epoch != Some(epoch) {
            return None;
        }
        self.sent
            .iter()
            .filter(|(round, _)| **round > after && **round <= through)
            .map(|(_, sync)| sync)
            .max_by(|a, b| {
                if later(a, b) {
                    Ordering::Greater
                } else if later(b, a) {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            })
    }
    pub fn sent_range(&self, epoch: i64, after: i64, through: i64) -> Vec<RoundSync> {
        if self.epoch != Some(epoch) {
            return vec![];
        }
        self.sent
            .iter()
            .filter(|(round, _)| **round > after && **round <= through)
            .map(|(_, sync)| sync.clone())
            .collect()
    }
    pub fn witness(
        &self,
        chain: &[u8],
        epoch: i64,
        after: i64,
        through: i64,
        validators: &ValidatorSet,
    ) -> Vec<RoundSync> {
        if self.epoch != Some(epoch) {
            return vec![];
        }
        let mut rounds = BTreeMap::<i64, Vec<&RoundSync>>::new();
        for sync in self.by_round.values() {
            if sync.round > after
                && sync.round <= through
                && validators.weight(&sync.validator).is_some()
            {
                rounds.entry(sync.round).or_default().push(sync);
            }
        }
        for (_, mut syncs) in rounds.into_iter().rev() {
            syncs.sort_by(|a, b| {
                validators
                    .weight(&b.validator)
                    .cmp(&validators.weight(&a.validator))
                    .then_with(|| a.validator.cmp(&b.validator))
            });
            let mut weight = BigInt::from(0);
            let mut selected = Vec::new();
            for sync in syncs {
                if validators.round_skip_reached_at(chain, epoch, selected.len() as i64, &weight) {
                    return selected;
                }
                weight += validators.weight(&sync.validator).expect("known validator");
                selected.push(sync.clone());
            }
            if validators.round_skip_reached_at(chain, epoch, selected.len() as i64, &weight) {
                return selected;
            }
        }
        vec![]
    }
}
