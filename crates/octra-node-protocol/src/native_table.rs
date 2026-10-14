// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Seed-zero native string tables for order-sensitive protocol decisions.
use std::collections::BTreeMap;

/// Seed-zero OCaml string hash, used to reproduce native table traversal.
/// This is Murmur3 with a complete block mix for the padded final string chunk.
pub fn string_hash(key: &[u8]) -> u32 {
    let mut h = 0u32;
    for chunk in key.chunks(4) {
        let mut word = [0; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        let k = u32::from_le_bytes(word)
            .wrapping_mul(0xcc9e_2d51)
            .rotate_left(15)
            .wrapping_mul(0x1b87_3593);
        h = (h ^ k)
            .rotate_left(13)
            .wrapping_mul(5)
            .wrapping_add(0xe654_6b64);
    }
    h ^= key.len() as u32;
    h = (h ^ (h >> 16)).wrapping_mul(0x85eb_ca6b);
    h = (h ^ (h >> 13)).wrapping_mul(0xc2b2_ae35);
    (h ^ (h >> 16)) & 0x3fff_ffff
}

/// Preserves native replacement, resize and fold order with string keys.
/// The constructor size and insertion order must match the native load/decode path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table<T> {
    values: BTreeMap<Vec<u8>, T>,
    buckets: Vec<Vec<Vec<u8>>>,
}
impl<T> Table<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            values: BTreeMap::new(),
            buckets: vec![Vec::new(); capacity.max(16).next_power_of_two()],
        }
    }
    pub fn replace(&mut self, key: Vec<u8>, value: T) {
        if self.values.insert(key.clone(), value).is_some() {
            return;
        }
        let index = string_hash(&key) as usize & (self.buckets.len() - 1);
        self.buckets[index].insert(0, key);
        if self.values.len() > self.buckets.len() * 2 {
            let size = self.buckets.len() * 2;
            let old = std::mem::replace(&mut self.buckets, vec![Vec::new(); size]);
            for key in old.into_iter().flatten() {
                let index = string_hash(&key) as usize & (size - 1);
                self.buckets[index].push(key);
            }
        }
    }
    pub fn remove(&mut self, key: &[u8]) {
        if self.values.remove(key).is_some() {
            let index = string_hash(key) as usize & (self.buckets.len() - 1);
            self.buckets[index].retain(|k| k != key);
        }
    }
    pub fn values(&self) -> &BTreeMap<Vec<u8>, T> {
        &self.values
    }
    pub fn keys(&self) -> impl Iterator<Item = &[u8]> {
        self.buckets.iter().flatten().map(Vec::as_slice)
    }
    pub fn get(&self, key: &[u8]) -> Option<&T> {
        self.values.get(key)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &T)> {
        self.keys().map(|key| (key, &self.values[key]))
    }
}
