// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Single policies. These do not select a public network or grant BFT authority.
use crate::{transaction::Transaction, transaction_outcome};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Single,
    Validator,
    Observer,
}
impl Role {
    pub fn of_mode(cli_observer: bool, mode: Option<&[u8]>) -> Self {
        let mode = mode.unwrap_or_default();
        let trim = trim(mode);
        if trim.eq_ignore_ascii_case(b"observer") || cli_observer {
            Self::Observer
        } else if trim.eq_ignore_ascii_case(b"bft") {
            Self::Validator
        } else {
            Self::Single
        }
    }
    pub fn consensus(self) -> bool {
        self != Self::Single
    }
    pub fn voting(self) -> bool {
        self == Self::Validator
    }
    pub fn observer(self) -> bool {
        self == Self::Observer
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Validator => "validator",
            Self::Observer => "observer",
        }
    }
}
pub const EPOCH_SECONDS: f64 = 10.;
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Tick {
    pub apply: bool,
    pub log_tick: bool,
    pub next_sleep: f64,
}
pub fn tick(elapsed: f64) -> Tick {
    Tick {
        apply: elapsed >= EPOCH_SECONDS,
        log_tick: true,
        next_sleep: EPOCH_SECONDS,
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposer {
    pub address: Vec<u8>,
    pub source: &'static str,
    pub commit_round: i64,
}
/// Native accepts a fee recipient/override with length >3; fallback itself does
/// not revalidate addresses. The host supplies the native ordered active set.
pub fn proposer(
    epoch: i64,
    validators: &[Vec<u8>],
    fee: Option<&[u8]>,
    override_proposer: Option<(&[u8], i64)>,
) -> Result<Proposer, String> {
    if let Some(address) = fee.filter(|a| a.len() > 3) {
        return Ok(Proposer {
            address: address.to_vec(),
            source: "env",
            commit_round: 0,
        });
    }
    if let Some((address, round)) = override_proposer.filter(|(a, _)| a.len() > 3) {
        return Ok(Proposer {
            address: address.to_vec(),
            source: "override",
            commit_round: round,
        });
    }
    if validators.is_empty() {
        return Err("missing_fallback_validator".into());
    }
    let index = epoch % (validators.len() as i64);
    let address = validators
        .get(usize::try_from(index).map_err(|_| "List.nth")?)
        .ok_or("List.nth")?
        .clone();
    Ok(Proposer {
        address,
        source: "round_robin_fallback",
        commit_round: 0,
    })
}
/// Preserve the pristine known bug: fee-priority staging is supplied to merge
/// without sorting. An unsorted multi-sender source is refused before execution.
pub fn source(txs: &[Transaction]) -> Result<Vec<Transaction>, transaction_outcome::Error> {
    transaction_outcome::merge(txs, &[])
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Preverify {
    Missing,
    Pending,
    Ready,
    Unavailable(Vec<u8>),
    Failed(Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gate {
    Ready,
    Failed(Vec<u8>),
    Timeout(Vec<u8>),
    Defer { next_count: i64, status: Vec<u8> },
    Unavailable { next_count: i64, reason: Vec<u8> },
}
fn add63(a: i64, b: i64) -> i64 {
    a.wrapping_add(b).wrapping_shl(1) >> 1
}
pub fn preverify_gate(state: &Preverify, count: i64, maximum: i64) -> Gate {
    match state {
        Preverify::Ready => Gate::Ready,
        Preverify::Failed(reason) => Gate::Failed(reason.clone()),
        _ => {
            let next = add63(count, 1);
            if next > maximum {
                Gate::Timeout(match state {
                    Preverify::Missing => b"task not in cache".to_vec(),
                    Preverify::Pending => b"still running".to_vec(),
                    Preverify::Unavailable(reason) => reason.clone(),
                    _ => b"unexpected cache state".to_vec(),
                })
            } else {
                match state {
                    Preverify::Unavailable(reason) => Gate::Unavailable {
                        next_count: next,
                        reason: reason.clone(),
                    },
                    _ => Gate::Defer {
                        next_count: next,
                        status: if *state == Preverify::Missing {
                            b"missing".to_vec()
                        } else {
                            b"pending".to_vec()
                        },
                    },
                }
            }
        }
    }
}

fn trim(raw: &[u8]) -> &[u8] {
    native_trim(raw)
}
/// Native String.trim: vertical tab is deliberately not whitespace.
fn native_trim(raw: &[u8]) -> &[u8] {
    let space = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 12);
    let start = raw.iter().position(|b| !space(b)).unwrap_or(raw.len());
    let end = raw.iter().rposition(|b| !space(b)).map_or(start, |i| i + 1);
    &raw[start..end]
}
/// Single keeps encoded keys exactly as configured, including duplicates and
/// malformed base64. BFT validator parsing must not normalize this reward input.
pub fn validator_pairs(
    current: Option<&[u8]>,
    next: Option<&[u8]>,
    activation: Option<i64>,
    wallet: (&[u8], &[u8]),
    epoch: i64,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    fn parse(raw: Option<&[u8]>) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut rows = raw
            .filter(|r| r.len() > 3)
            .unwrap_or_default()
            .split(|b| *b == b',')
            .filter_map(|item| {
                let entry = native_trim(item);
                if entry.len() <= 3 {
                    return None;
                }
                let mut fields = entry.split(|b| *b == b':');
                let addr = fields.next()?;
                let key = fields.next()?;
                if fields.next().is_some() || addr.len() <= 3 {
                    return None;
                }
                Some((addr.to_vec(), key.to_vec()))
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }
    let mut now = parse(current);
    if now.is_empty() {
        now.push((wallet.0.to_vec(), wallet.1.to_vec()));
    }
    let next = parse(next);
    if !next.is_empty() && activation.is_some_and(|a| epoch >= a) {
        next
    } else {
        now
    }
}
#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub key: Vec<u8>,
    pub timestamp: f64,
    pub pending: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachePrune {
    pub expired: Vec<Vec<u8>>,
    pub overflow: Vec<Vec<u8>>,
}
fn oldest(entries: &[CacheEntry]) -> Vec<&CacheEntry> {
    let mut completed = entries.iter().filter(|e| !e.pending).collect::<Vec<_>>();
    completed.sort_by(|a, b| match (a.timestamp.is_nan(), b.timestamp.is_nan()) {
        (true, true) => std::cmp::Ordering::Equal,
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        (false, false) => a
            .timestamp
            .partial_cmp(&b.timestamp)
            .expect("ordered float"),
    });
    completed
}
/// Entries retain Hashtbl.fold/list-cons order; stable equal-time ordering is
/// part of the native cache eviction transcript. Limits are captured host policy.
pub fn cache_prune(now: f64, ttl: f64, maximum: usize, entries: &[CacheEntry]) -> CachePrune {
    let expired = entries
        .iter()
        .filter(|e| !e.pending && now - e.timestamp > ttl)
        .map(|e| e.key.clone())
        .collect::<Vec<_>>();
    let remaining = entries
        .iter()
        .filter(|e| !expired.contains(&e.key))
        .cloned()
        .collect::<Vec<_>>();
    let sorted = oldest(&remaining);
    let overflow = sorted
        .iter()
        .take(sorted.len().saturating_sub(maximum))
        .map(|e| e.key.clone())
        .collect();
    CachePrune { expired, overflow }
}
pub fn cache_hard_cap(maximum: usize, entries: &[CacheEntry]) -> (Vec<Vec<u8>>, usize) {
    let threshold = maximum + maximum / 5;
    if entries.len() >= threshold {
        let requested = entries.len().saturating_sub(maximum) + 1;
        (
            oldest(entries)
                .into_iter()
                .take(requested)
                .map(|e| e.key.clone())
                .collect(),
            requested,
        )
    } else {
        (vec![], 0)
    }
}
