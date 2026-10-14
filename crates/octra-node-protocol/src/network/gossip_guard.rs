// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native transaction gossip quotas and the bounded one-second retry cache.
use super::guard::float_compare;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};
#[derive(Clone, Copy, Debug)]
struct Time(f64);
impl PartialEq for Time {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Time {}
impl PartialOrd for Time {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Time {
    fn cmp(&self, other: &Self) -> Ordering {
        float_compare(self.0, other.0)
    }
}
pub struct Seen {
    keys: BTreeMap<Vec<u8>, f64>,
    times: BTreeSet<(Time, Vec<u8>)>,
    last: f64,
}
impl Default for Seen {
    fn default() -> Self {
        Self {
            keys: BTreeMap::new(),
            times: BTreeSet::new(),
            last: f64::NEG_INFINITY,
        }
    }
}
impl Seen {
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
    pub fn recent(&self, now: f64, key: &[u8]) -> bool {
        now.is_finite()
            && now >= self.last
            && self.keys.get(key).is_some_and(|stamp| now - stamp < 1.0)
    }
    fn remove_first(&mut self) {
        if let Some((_, key)) = self.times.pop_first() {
            self.keys.remove(&key);
        }
    }
    pub fn remember(&mut self, now: f64, key: &[u8]) -> bool {
        if !now.is_finite() {
            *self = Self::default();
            return true;
        }
        if now < self.last {
            *self = Self::default();
        }
        while self
            .times
            .first()
            .is_some_and(|(stamp, _)| now - stamp.0 >= 1.0)
        {
            self.remove_first();
        }
        self.last = now;
        if self.keys.contains_key(key) {
            return false;
        }
        if self.keys.len() >= 4096 {
            self.remove_first();
        }
        self.keys.insert(key.to_vec(), now);
        self.times.insert((Time(now), key.to_vec()));
        true
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub window: f64,
    pub max_messages: i64,
    pub max_bytes: i64,
    pub max_payload: i64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            window: 60.0,
            max_messages: 4096,
            max_bytes: 64 * 1024 * 1024,
            max_payload: 5_000_000 + 4096,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Bucket {
    pub start: f64,
    pub messages: i64,
    pub bytes: i64,
    pub last_seen: f64,
}
impl Bucket {
    fn new(now: f64) -> Self {
        Self {
            start: now,
            messages: 0,
            bytes: 0,
            last_seen: now,
        }
    }
}
#[derive(Default)]
pub struct Guard {
    peers: BTreeMap<Vec<u8>, Bucket>,
    pub seen: Seen,
}
impl Guard {
    pub fn len(&self) -> usize {
        self.peers.len()
    }
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
    pub fn snapshot(&self) -> impl Iterator<Item = (&[u8], &Bucket)> {
        self.peers.iter().map(|(key, b)| (key.as_slice(), b))
    }
    pub fn prune(&mut self, now: f64, ttl: f64, maximum: usize) {
        self.peers
            .retain(|_, b| (now - b.last_seen).partial_cmp(&ttl) != Some(Ordering::Greater));
        let overflow = self.peers.len().saturating_sub(maximum);
        if overflow == 0 {
            return;
        }
        let mut entries: Vec<_> = self
            .peers
            .iter()
            .map(|(key, b)| (Time(b.last_seen), key.clone()))
            .collect();
        entries.sort();
        for (_, key) in entries.into_iter().take(overflow) {
            self.peers.remove(&key);
        }
    }
    pub fn admit(
        &mut self,
        config: Config,
        now: f64,
        peer: &[u8],
        bytes: i64,
    ) -> Result<(), &'static str> {
        if bytes > config.max_payload {
            return Err("payload_too_large");
        }
        self.prune(now, 300.0, 4096);
        let b = self
            .peers
            .entry(peer.to_vec())
            .or_insert_with(|| Bucket::new(now));
        b.last_seen = now;
        if now - b.start >= config.window {
            *b = Bucket::new(now);
        }
        let messages = add(b.messages, 1);
        let bytes = add(b.bytes, bytes);
        if messages > config.max_messages {
            Err("message_budget")
        } else if bytes > config.max_bytes {
            Err("byte_budget")
        } else {
            b.messages = messages;
            b.bytes = bytes;
            Ok(())
        }
    }
}
fn add(a: i64, b: i64) -> i64 {
    (a.wrapping_add(b) << 1) >> 1
}
