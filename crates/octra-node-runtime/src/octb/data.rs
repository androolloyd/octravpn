// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{work, Budget, Exec, Instruction as I, Machine, Request, Trap, Value};
use octra_node_protocol::native_integer::parse_integer;
use sha2::{Digest, Sha256};

/// OCaml's machine integer is a signed 63-bit word on the pinned host.
pub(super) fn add(a: i64, b: i64) -> i64 {
    a.wrapping_add(b).wrapping_shl(1) >> 1
}
fn span(base: i64, count: i64, sized: bool) -> bool {
    base >= 0
        && count >= 0
        && (count == 0 && !sized || base <= work::MAX_INT - count + i64::from(!sized))
}
fn trimmed(input: &[u8]) -> &[u8] {
    let space = |b: &u8| matches!(b, b' ' | 12 | b'\n' | b'\r' | b'\t');
    let start = input.iter().position(|b| !space(b)).unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|b| !space(b))
        .map_or(start, |i| i + 1);
    &input[start..end]
}
fn parts(input: &[u8]) -> impl Iterator<Item = &[u8]> {
    input
        .split(|b| *b == b',')
        .map(trimmed)
        .filter(|v| !v.is_empty())
}
pub(super) fn find(text: &[u8], pattern: &[u8]) -> i64 {
    if pattern.is_empty() {
        return 0;
    }
    if pattern.len() > text.len() {
        return -1;
    }
    let mut links = vec![0; pattern.len()];
    let mut matched = 0;
    for index in 1..pattern.len() {
        while matched > 0 && pattern[index] != pattern[matched] {
            matched = links[matched - 1];
        }
        if pattern[index] == pattern[matched] {
            matched += 1;
        }
        links[index] = matched;
    }
    matched = 0;
    for (index, byte) in text.iter().enumerate() {
        while matched > 0 && *byte != pattern[matched] {
            matched = links[matched - 1];
        }
        if *byte == pattern[matched] {
            matched += 1;
        }
        if matched == pattern.len() {
            return (index + 1 - matched) as i64;
        }
    }
    -1
}
impl Machine {
    fn parse_ints(
        &mut self,
        input: &[u8],
        base: i64,
        budget: &mut Option<&mut Budget>,
    ) -> Exec<i64> {
        if !(0..=16_777_216).contains(&base) {
            return Err(Trap::Refused);
        }
        let mut count = 0;
        if let Some(b) = budget {
            let scan = Request::Scan(input.len() as i64);
            self.effort = b
                .charge(self.effort, self.options.limit, 0, &[scan])
                .ok_or(Trap::Refused)?;
            let quote = |count, chars| {
                let (cost, mut requests) = work::parsing(chars, count)?;
                requests.insert(0, scan);
                Some((cost, requests))
            };
            let fits = |count, chars| {
                let (cost, requests) = quote(count, chars)?;
                b.plan(self.effort, self.options.limit, cost, &requests)
            };
            fits(0, 0).ok_or(Trap::Refused)?;
            let mut chars = 0;
            for part in parts(input) {
                if count > 16_777_216 - base {
                    return Err(Trap::Refused);
                }
                count += 1;
                chars += part.len() as i64;
                fits(count, chars).ok_or(Trap::Refused)?;
            }
            let (cost, requests) = quote(count, chars).ok_or(Trap::Refused)?;
            self.effort = b
                .charge(self.effort, self.options.limit, cost, &requests)
                .ok_or(Trap::Refused)?;
            let values: Vec<_> = parts(input)
                .map(|v| parse_integer(v).or_else(|| (!self.options.strict).then(Default::default)))
                .collect::<Option<_>>()
                .ok_or(Trap::Refused)?;
            for (index, value) in values.into_iter().enumerate() {
                self.memory_set(base + index as i64, Value::int(value));
            }
        } else {
            for part in parts(input) {
                let index = base + count;
                if index > 16_777_216 {
                    return Err(Trap::Refused);
                }
                let value =
                    parse_integer(part).or_else(|| (!self.options.strict).then(Default::default));
                let valid = value.is_some();
                if let Some(value) = value {
                    self.memory.insert(index, Value::int(value));
                }
                self.memory_size = self.memory_size.max(index + 1);
                self.charge(2)?;
                count += 1;
                if !valid {
                    return Err(Trap::Refused);
                }
            }
        }
        Ok(count)
    }
    fn key_page(
        &mut self,
        prefix: &[u8],
        after: &[u8],
        base: i64,
        budget: &mut Option<&mut Budget>,
    ) -> Exec<(i64, Vec<u8>)> {
        let candidates = |key: &&Vec<u8>| {
            key.first() != Some(&0)
                && key.starts_with(prefix)
                && (after.is_empty() || &key[prefix.len()..] > after)
        };
        if let Some(b) = budget {
            if !(0..16_777_216).contains(&base) {
                return Ok((0, vec![]));
            }
            let count = 1000.min(16_777_216 - base);
            let capacity = (count as usize + 1).min(self.storage.values().len());
            let scratch = capacity as i64 * 64 + 64;
            let scanned = self
                .storage
                .values()
                .keys()
                .try_fold(0_i64, |total, key| {
                    total
                        .checked_add(key.len() as i64 + 32)
                        .filter(|v| *v <= work::MAX_INT)
                })
                .ok_or(Trap::Refused)?;
            self.effort = b
                .charge(
                    self.effort,
                    self.options.limit,
                    0,
                    &[Request::Scan(scanned), Request::Allocate(scratch)],
                )
                .ok_or(Trap::Refused)?;
            let keys: Vec<_> = self
                .storage
                .values()
                .keys()
                .filter(candidates)
                .take(capacity)
                .collect();
            let more = keys.len() > count as usize;
            let keys: Vec<_> = keys.into_iter().take(count as usize).collect();
            let requests: Vec<_> = keys
                .iter()
                .map(|key| Request::Copy((key.len() - prefix.len()) as i64, 0))
                .collect();
            self.effort = b
                .charge(
                    self.effort,
                    self.options.limit,
                    keys.len() as i64 * 5,
                    &requests,
                )
                .ok_or(Trap::Refused)?;
            let suffixes: Vec<_> = keys
                .into_iter()
                .map(|k| k[prefix.len()..].to_vec())
                .collect();
            let next = if more {
                suffixes.last().cloned().unwrap_or_default()
            } else {
                vec![]
            };
            let count = suffixes.len();
            for (index, suffix) in suffixes.into_iter().enumerate() {
                self.memory_set(base + index as i64, Value::string(suffix));
            }
            Ok((count as i64, next))
        } else {
            let suffixes: Vec<_> = self
                .storage
                .values()
                .keys()
                .filter(candidates)
                .map(|k| k[prefix.len()..].to_vec())
                .collect();
            let mut count = 0;
            let mut last = vec![];
            for suffix in &suffixes {
                let index = add(base, count);
                if count < 1000 && (0..16_777_216).contains(&index) {
                    self.charge(5)?;
                    self.memory_set(index, Value::string(suffix.clone()));
                    last.clone_from(suffix);
                    count += 1;
                }
            }
            Ok((
                count,
                if suffixes.len() > count as usize {
                    last
                } else {
                    vec![]
                },
            ))
        }
    }
    fn memory_text(&self, index: i64) -> Vec<u8> {
        self.memory
            .get(&index)
            .map(|v| v.text().into_owned())
            .unwrap_or_default()
    }
    fn batch_text(&mut self, index: i64, cap: i64, budget: &mut Budget) -> Exec<Vec<u8>> {
        let value = self
            .memory
            .get(&index)
            .cloned()
            .unwrap_or_else(|| Value::string(vec![]));
        if !Self::text_fits(&value, cap) {
            return Err(Trap::Refused);
        }
        self.reserve_value_text(&value, budget)?;
        Ok(value.text().into_owned())
    }
    fn store_batch(
        &mut self,
        keys: i64,
        values: i64,
        count: i64,
        budget: &mut Option<&mut Budget>,
    ) -> Exec {
        if let Some(b) = budget {
            let mut remaining = b.remaining();
            let mut used = self.effort;
            let mut entries = Vec::new();
            for index in 0..count {
                let before = self.effort;
                let cap = remaining.min(b.text_limit());
                let key = self.batch_text(keys + index, cap, b)?;
                if key.is_empty() || key.first() == Some(&0) || key.len() as i64 > remaining {
                    return Err(Trap::Refused);
                }
                let value =
                    self.batch_text(values + index, cap.min(remaining - key.len() as i64), b)?;
                if value.len() > 4_194_304 {
                    return Err(Trap::Refused);
                }
                let request = Request::Write(key.len() as i64, value.len() as i64);
                used = work::charge(used, self.effort - before, self.options.limit)
                    .ok_or(Trap::Refused)?;
                let planned = work::plan(
                    b.limits(),
                    remaining,
                    b.available(),
                    used,
                    self.options.limit,
                    80,
                    &[request],
                )
                .ok_or(Trap::Refused)?;
                used = planned.effort;
                remaining = planned.remaining;
                entries.push((key, value));
            }
            let requests: Vec<_> = entries
                .iter()
                .map(|(k, v)| Request::Write(k.len() as i64, v.len() as i64))
                .collect();
            self.effort = b
                .charge(self.effort, self.options.limit, 80 * count, &requests)
                .ok_or(Trap::Refused)?;
            for (key, value) in entries {
                self.write(key, Some(value));
            }
        } else {
            for index in 0..count.min(1000) {
                let key = self.memory_text(add(keys, index));
                let value = self.memory_text(add(values, index));
                if !key.is_empty() && key.first() != Some(&0) && value.len() <= 4_194_304 {
                    self.write(key, Some(value));
                }
                self.charge(80)?;
            }
        }
        Ok(())
    }
    pub(super) fn data(&mut self, op: &I, budget: &mut Option<&mut Budget>) -> Exec {
        match op {
            I::ParseInts(dest, source, base) => {
                let input = self.text(*source)?;
                let base = self.index(*base)?;
                let count = self.parse_ints(&input, base, budget)?;
                self.set(*dest, Value::int(count))?;
            }
            I::Skeys(dest, prefix, base) | I::SkeysPage(dest, _, prefix, _, base) => {
                let prefix = self.text(*prefix)?;
                let base = self.index(*base)?;
                let after = match op {
                    I::SkeysPage(_, _, _, after, _) => self.text(*after)?,
                    _ => vec![],
                };
                let (count, next) = self.key_page(&prefix, &after, base, budget)?;
                self.set(*dest, Value::int(count))?;
                if let I::SkeysPage(_, dest, _, _, _) = op {
                    self.set(*dest, Value::string(next))?;
                }
            }
            I::Sloadn(keys, values, count) => {
                let keys = self.index(*keys)?;
                let values = self.index(*values)?;
                let count = self.index(*count)?.min(1000);
                if budget.is_some()
                    && count > 0
                    && (!span(keys, count, false) || !span(values, count, true))
                {
                    return Err(Trap::Refused);
                }
                for index in 0..count {
                    let key = self.memory_text(add(keys, index));
                    let value = self.storage.get(&key).cloned().unwrap_or_default();
                    self.memory_set(add(values, index), Value::string(value));
                    self.charge(15)?;
                }
            }
            I::Sstoren(keys, values, count) => {
                self.view_guard(budget)?;
                self.store_batch(
                    self.index(*keys)?,
                    self.index(*values)?,
                    self.index(*count)?,
                    budget,
                )?;
            }
            I::Fstore(dest, source) => {
                self.view_guard(budget)?;
                let input = self.text(*source)?;
                if input.len() > 10_485_760 {
                    self.reverted = true;
                    return Ok(());
                }
                let active = budget.is_some();
                if active {
                    self.bytes(
                        budget,
                        0,
                        0,
                        &[Request::Write(64, input.len() as i64), Request::Copy(64, 0)],
                    )?;
                }
                let hash = hex::encode(Sha256::digest(&input)).into_bytes();
                let cost = (input.len() / 1024) as i64;
                self.blobs.insert(hash.clone(), input);
                if !active {
                    self.charge(cost)?;
                }
                self.set(*dest, Value::string(hash))?;
            }
            I::Fload(dest, source) => {
                let input = self
                    .blobs
                    .get(&self.text(*source)?)
                    .cloned()
                    .unwrap_or_default();
                self.charge((input.len() / 1024) as i64)?;
                self.set(*dest, Value::string(input))?;
            }
            _ => unreachable!("data opcode selected by execution loop"),
        }
        Ok(())
    }
}
