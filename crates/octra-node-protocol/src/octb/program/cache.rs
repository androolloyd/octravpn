// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Successful code checks are cached by exact bytes and every admission input.
//! Failed or unavailable checks cannot become cached authority.
use super::{Admitted, Error, Keys};
use std::sync::{Mutex, OnceLock};
struct Entry {
    mode: u8,
    points: bool,
    trusted: Keys,
    raw: Vec<u8>,
    admitted: Admitted,
    bytes: usize,
}
static CACHE: OnceLock<Mutex<Vec<Entry>>> = OnceLock::new();
const MAX_BYTES: usize = 32 * 1024 * 1024;
pub(super) fn run(
    mode: u8,
    points: bool,
    trusted: &Keys,
    raw: &[u8],
    compute: impl FnOnce() -> Result<Admitted, Error>,
) -> Result<Admitted, Error> {
    let cache = CACHE.get_or_init(Mutex::default);
    if let Ok(mut entries) = cache.lock() {
        if let Some(index) = entries.iter().position(|entry| {
            entry.mode == mode
                && entry.points == points
                && entry.trusted == *trusted
                && entry.raw == raw
        }) {
            let entry = entries.remove(index);
            let value = entry.admitted.clone();
            entries.insert(0, entry);
            return Ok(value);
        }
    }
    let admitted = compute()?;
    // Reserve conservatively for decoded instructions, certificate facts and
    // collection nodes; an oversized artifact still executes without caching.
    let bytes = raw
        .len()
        .saturating_mul(64)
        .saturating_add(
            admitted
                .code()
                .len()
                .saturating_mul(std::mem::size_of::<super::super::Instruction>() * 4),
        )
        .saturating_add(4096);
    if bytes <= MAX_BYTES {
        if let Ok(mut entries) = cache.lock() {
            entries.retain(|entry| {
                !(entry.mode == mode
                    && entry.points == points
                    && entry.trusted == *trusted
                    && entry.raw == raw)
            });
            entries.insert(
                0,
                Entry {
                    mode,
                    points,
                    trusted: trusted.clone(),
                    raw: raw.to_vec(),
                    admitted: admitted.clone(),
                    bytes,
                },
            );
            let mut used = 0_usize;
            let count = entries
                .iter()
                .take(64)
                .take_while(|entry| {
                    used = used.saturating_add(entry.bytes);
                    used <= MAX_BYTES
                })
                .count();
            entries.truncate(count);
        }
    }
    Ok(admitted)
}
