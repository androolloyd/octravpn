// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Fhe_view_policy and gross retained-volume accounting. A shared local
//! memory capability follows nested execution and is never refunded by rollback.
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
const MAX_INT: u128 = (1u128 << 62) - 1;
pub const MEMORY_LIMIT: u64 = 536_870_912;
#[derive(Clone, Debug, Default)]
pub struct Memory(Arc<AtomicU64>);
impl Memory {
    pub fn used(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
    pub fn reserve(&self, amount: u64) -> bool {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(amount).filter(|v| *v <= MEMORY_LIMIT)
            })
            .is_ok()
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    pub slots: u64,
    pub layers: u64,
    pub edges: u64,
}
#[derive(Clone, Copy, Debug)]
pub enum Operation {
    Copy,
    Join,
    Product,
}
#[derive(Clone, Copy, Debug)]
pub struct Plan {
    pub effort: i64,
    pub memory: u64,
}
fn integer(value: u128) -> Option<i64> {
    (value <= MAX_INT).then_some(value as i64)
}
fn mul(values: &[u128]) -> Option<u128> {
    values.iter().try_fold(1u128, |n, v| n.checked_mul(*v))
}
// Preserve the native work-accounting expression and intermediate arithmetic.
#[allow(clippy::manual_div_ceil)]
pub fn sampling(rows: i64, columns: i64, weight: i64, noise: i64, branches: i64) -> Option<u64> {
    if rows <= 0
        || columns <= 0
        || weight < 0
        || weight > columns
        || noise < 0
        || noise > rows
        || branches < 8
    {
        return None;
    }
    let words = (rows as u128 + 63) / 64;
    let noise = if noise < rows { noise + 1 } else { noise } as u128;
    let cost = 32u128
        .checked_mul(weight as u128 + noise)?
        .checked_add(words.checked_mul(weight as u128)?)?;
    integer(cost).map(|n| n as u64)
}
pub fn plan(
    op: Operation,
    base: i64,
    left: Shape,
    right: Shape,
    left_words: u64,
    right_words: u64,
    product_words: u64,
    sample_work: u64,
) -> Option<Plan> {
    if base < 0 || left.slots == 0 || right.slots == 0 || left.slots != right.slots {
        return None;
    }
    let (a, b, s, ae, be) = (
        u128::from(left.layers),
        u128::from(right.layers),
        u128::from(left.slots),
        u128::from(left.edges),
        u128::from(right.edges),
    );
    let pairs = a.checked_mul(b)?;
    let (layers, edges) = match op {
        Operation::Copy => (a, ae),
        Operation::Join => (a.checked_add(b)?, ae.checked_add(be)?),
        Operation::Product => (
            pairs.checked_add(a.checked_add(b)?)?,
            8u128.checked_mul(pairs)?.checked_add(ae.checked_add(be)?)?,
        ),
    };
    let cells = s.checked_mul(1u128.checked_add(layers.checked_add(edges)?)?)?;
    let words = match op {
        Operation::Copy => u128::from(left_words),
        Operation::Join => u128::from(left_words).checked_add(right_words.into())?,
        Operation::Product => u128::from(left_words)
            .checked_add(right_words.into())?
            .checked_add(mul(&[product_words.into(), 8, pairs])?)?,
    };
    if layers > 4096 || cells > 65_536 || words > 1_048_576 {
        return None;
    }
    let storage = 16u128.checked_mul(cells)?.checked_add(words)?;
    let effort = match op {
        Operation::Copy | Operation::Join => storage,
        Operation::Product if a == 0 || b == 0 => storage.max(10_000),
        Operation::Product => {
            let layer = mul(&[a, b, s, 10_000])? / 4;
            let edge = mul(&[ae.checked_add(be)?, s])? / 8;
            storage.max(layer.checked_add(edge)?.max(10_000))
        }
    };
    let traversal = match op {
        Operation::Copy => 0,
        Operation::Join => layers.checked_mul(layers + 1)?,
        Operation::Product => mul(&[2, layers, layers + 1])?,
    };
    let samples = if matches!(op, Operation::Product) {
        mul(&[sample_work.into(), 8, pairs])?
    } else {
        0
    };
    let total = integer(effort.checked_add(traversal.checked_add(samples)?)?)?;
    let memory = 4096u128
        .checked_add(mul(&[1024, cells])?)?
        .checked_add(mul(&[4096, layers.checked_add(edges)?])?)?
        .checked_add(mul(&[128, words])?)?;
    Some(Plan {
        effort: (total - base).max(0),
        memory: u64::try_from(memory).ok()?,
    })
}
pub fn key_image(raw: &[u8]) -> Option<u64> {
    let first = *raw.first()?;
    if first != 0xec {
        return Some(raw.len() as u64);
    }
    let size = u32::from_be_bytes(raw.get(1..5)?.try_into().ok()?) as u64;
    (size <= 33_554_432 && size <= (raw.len() - 5) as u64 * 64).then_some(size)
}
pub fn key_decode(raw: &[u8]) -> Option<u64> {
    270_336u64.checked_add(8u64.checked_mul((raw.len() as u64).checked_add(key_image(raw)?)?)?)
}
pub fn key_value(image: u64) -> Option<u64> {
    270_336u64.checked_add(8u64.checked_mul(image)?)
}
pub fn cipher_decode(length: usize) -> Option<u64> {
    4096u64
        .checked_add(16u64.checked_mul(length as u64)?)?
        .checked_add(65_536 * 64)
}
// Preserve the native work-accounting expression and intermediate arithmetic.
#[allow(clippy::manual_div_ceil)]
pub fn key_effort(volume: u64, active: bool) -> Option<i64> {
    let divisor = if active { 16 } else { 64 };
    integer((u128::from(volume) + divisor - 1) / divisor)
}
pub fn key_read_effort(raw: &[u8], active: bool) -> Option<i64> {
    key_effort((raw.len() as u64).checked_add(key_image(raw)?)?, active)
}
// Preserve the native work-accounting expression and intermediate arithmetic.
#[allow(clippy::manual_div_ceil)]
pub fn decode_effort(length: usize) -> Option<i64> {
    integer((length as u128 + 15) / 16)
}
pub fn key_output_effort(raw: &[u8]) -> Option<i64> {
    let size = if raw.first() == Some(&0xec) {
        u32::from_be_bytes(raw.get(1..5)?.try_into().ok()?) as usize
    } else {
        raw.len()
    };
    if size > 18_000_000 {
        return None;
    }
    decode_effort(size)
}
