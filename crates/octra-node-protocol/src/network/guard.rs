// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native peer connection budgets, abuse scores and temporary bans.
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub bad_window: f64,
    pub max_bad: i64,
    pub ban: f64,
    pub connection_window: f64,
    pub max_connections: i64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            bad_window: 60.0,
            max_bad: 3,
            ban: 120.0,
            connection_window: 10.0,
            max_connections: 64,
        }
    }
}
#[derive(Clone, Debug, PartialEq)]
pub struct Score {
    pub bad_count: i64,
    pub connection_count: i64,
    pub ban_until: f64,
    pub last_reason: Vec<u8>,
    pub invalid_frames: i64,
    pub bad_signatures: i64,
    pub stale_roots: i64,
}
struct Entry {
    bad_start: f64,
    connection_start: f64,
    last_seen: f64,
    score: Score,
}
impl Entry {
    fn new(now: f64) -> Self {
        Self {
            bad_start: now,
            connection_start: now,
            last_seen: now,
            score: Score {
                bad_count: 0,
                connection_count: 0,
                ban_until: 0.0,
                last_reason: Vec::new(),
                invalid_frames: 0,
                bad_signatures: 0,
                stale_roots: 0,
            },
        }
    }
    fn until(&self, now: f64) -> f64 {
        if self.score.ban_until > now {
            self.last_seen.max(self.score.ban_until)
        } else {
            self.last_seen
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Bad {
    Noted(i64),
    Banned(f64),
}
#[derive(Default)]
pub struct Guard {
    entries: BTreeMap<Vec<u8>, Entry>,
}
impl Guard {
    pub fn prune(&mut self, now: f64, ttl: f64, maximum: usize) {
        self.entries.retain(|_, e| {
            e.score.ban_until > now
                || (now - e.last_seen).partial_cmp(&ttl) != Some(std::cmp::Ordering::Greater)
        });
        let overflow = self.entries.len().saturating_sub(maximum);
        if overflow == 0 {
            return;
        }
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .map(|(k, e)| (e.until(now), k.clone()))
            .collect();
        entries.sort_by(|a, b| float_compare(a.0, b.0).then_with(|| a.1.cmp(&b.1)));
        for (_, key) in entries.into_iter().take(overflow) {
            self.entries.remove(&key);
        }
    }
    fn entry(&mut self, now: f64, key: &[u8]) -> &mut Entry {
        self.prune(now, 600.0, 4096);
        let e = self
            .entries
            .entry(key.to_vec())
            .or_insert_with(|| Entry::new(now));
        e.last_seen = now;
        e
    }
    pub fn admit(&mut self, config: Config, now: f64, key: &[u8]) -> Result<(), &'static str> {
        let e = self.entry(now, key);
        if e.score.ban_until > now {
            return Err("banned");
        }
        if now - e.connection_start >= config.connection_window {
            e.connection_start = now;
            e.score.connection_count = 0;
        }
        e.score.connection_count = increment(e.score.connection_count);
        if e.score.connection_count > config.max_connections {
            e.score.last_reason = b"connection_budget".to_vec();
            e.score.ban_until = now + config.ban;
            Err("connection_budget")
        } else {
            Ok(())
        }
    }
    pub fn report(&mut self, config: Config, now: f64, key: &[u8], reason: &[u8]) -> Bad {
        let e = self.entry(now, key);
        if now - e.bad_start >= config.bad_window {
            e.bad_start = now;
            e.score.bad_count = 0;
        }
        e.score.bad_count = increment(e.score.bad_count);
        e.score.last_reason = reason.to_vec();
        if [
            b"invalid_frame".as_slice(),
            b"malformed",
            b"decode",
            b"exception",
        ]
        .iter()
        .any(|p| contains(reason, p))
        {
            e.score.invalid_frames = increment(e.score.invalid_frames);
        }
        if contains(reason, b"signature") {
            e.score.bad_signatures = increment(e.score.bad_signatures);
        }
        if contains(reason, b"stale") || contains(reason, b"wrong_height") {
            e.score.stale_roots = increment(e.score.stale_roots);
        }
        if e.score.bad_count >= config.max_bad {
            e.score.ban_until = now + config.ban;
            Bad::Banned(e.score.ban_until)
        } else {
            Bad::Noted(e.score.bad_count)
        }
    }
    pub fn is_banned(&mut self, now: f64, key: &[u8]) -> bool {
        self.prune(now, 600.0, 4096);
        self.entries
            .get(key)
            .is_some_and(|e| e.score.ban_until > now)
    }
    pub fn score(&self, key: &[u8]) -> Option<&Score> {
        self.entries.get(key).map(|e| &e.score)
    }
    pub fn snapshot(&self) -> impl Iterator<Item = (&[u8], &Score)> {
        self.entries
            .iter()
            .map(|(key, e)| (key.as_slice(), &e.score))
    }
}
fn increment(value: i64) -> i64 {
    (value.wrapping_add(1) << 1) >> 1
}
fn contains(text: &[u8], part: &[u8]) -> bool {
    part.is_empty() || text.windows(part.len()).any(|s| s == part)
}
// OCaml's total float comparison treats all NaNs as equal and below non-NaNs.
pub(crate) fn float_compare(a: f64, b: f64) -> std::cmp::Ordering {
    a.partial_cmp(&b)
        .unwrap_or_else(|| (!a.is_nan()).cmp(&(!b.is_nan())))
}
pub fn host_key(address: &[u8]) -> &[u8] {
    address
        .iter()
        .rposition(|b| *b == b':')
        .map_or(address, |i| &address[..i])
}
pub fn identity_key(node_id: &[u8]) -> Vec<u8> {
    [b"node:".as_slice(), node_id].concat()
}
pub fn handshake_penalty(reason: &[u8]) -> Option<&'static str> {
    if contains(reason, b"invalid Ed25519 signature")
        || contains(reason, b"node_id does not match pubkey")
    {
        Some("bad_signature_handshake")
    } else if contains(reason, b"frame_payload_limit") || contains(reason, b"expected HELLO") {
        Some("invalid_frame_handshake")
    } else if contains(reason, b"handshake timeout") {
        Some("timeout_handshake")
    } else {
        None
    }
}
