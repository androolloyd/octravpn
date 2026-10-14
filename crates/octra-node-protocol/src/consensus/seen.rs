// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native bounded FIFO duplicate suppression; duplicate hits do not refresh age.
use super::{Bytes, Error};
use std::collections::{BTreeSet, VecDeque};
pub struct Seen {
    capacity: usize,
    ids: BTreeSet<Bytes>,
    order: VecDeque<Bytes>,
}
impl Seen {
    pub fn new(capacity: i64) -> Result<Self, Error> {
        if capacity <= 0 {
            return Err("consensus seen capacity".into());
        }
        Ok(Self {
            capacity: capacity as usize,
            ids: BTreeSet::new(),
            order: VecDeque::new(),
        })
    }
    pub fn remember(&mut self, id: &[u8]) -> bool {
        if self.ids.contains(id) {
            return false;
        }
        if self.ids.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.ids.remove(&old);
            }
        }
        self.ids.insert(id.to_vec());
        self.order.push_back(id.to_vec());
        true
    }
    pub fn known(&self, id: &[u8]) -> bool {
        self.ids.contains(id)
    }
    pub fn len(&self) -> usize {
        self.ids.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}
