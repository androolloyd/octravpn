// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Epoch-root query leases keep concurrent readers isolated from cancellation.
use super::Error;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    epoch: i64,
    reader: i64,
}
struct Slot<T> {
    readers: BTreeSet<i64>,
    replies: Vec<T>,
}
pub struct RootQueries<T> {
    next: i64,
    slots: BTreeMap<i64, Slot<T>>,
}
impl<T> Default for RootQueries<T> {
    fn default() -> Self {
        Self {
            next: 0,
            slots: BTreeMap::new(),
        }
    }
}
impl<T> RootQueries<T> {
    pub fn join(&mut self, epoch: i64) -> Result<Lease, Error> {
        if self.next == (1i64 << 62) - 1 {
            return Err("root query reader limit reached".into());
        }
        let lease = Lease {
            epoch,
            reader: self.next,
        };
        self.next += 1;
        self.slots
            .entry(epoch)
            .or_insert_with(|| Slot {
                readers: BTreeSet::new(),
                replies: Vec::new(),
            })
            .readers
            .insert(lease.reader);
        Ok(lease)
    }
    pub fn listening(&self, epoch: i64) -> bool {
        self.slots.contains_key(&epoch)
    }
    pub fn add(&mut self, epoch: i64, reply: T, same: impl Fn(&T, &T) -> bool) {
        if let Some(slot) = self.slots.get_mut(&epoch) {
            if !slot.replies.iter().any(|r| same(&reply, r)) {
                slot.replies.insert(0, reply);
            }
        }
    }
    pub fn read(&self, lease: Lease) -> &[T] {
        self.slots
            .get(&lease.epoch)
            .filter(|s| s.readers.contains(&lease.reader))
            .map_or(&[], |s| s.replies.as_slice())
    }
    pub fn leave(&mut self, lease: Lease) {
        if let Some(slot) = self.slots.get_mut(&lease.epoch) {
            slot.readers.remove(&lease.reader);
            if slot.readers.is_empty() {
                self.slots.remove(&lease.epoch);
            }
        }
    }
}
