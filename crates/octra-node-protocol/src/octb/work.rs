// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native VM integer effort and shared byte/receipt accounting. Reservations are
//! charged only when the complete plan succeeds; consumed work is never refunded.
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive};

pub const MAX_INT: i64 = (1_i64 << 62) - 1;
pub const MAX_STRING: i64 = (1_i64 << 57) - 9;
pub const ITEM_CAP: i64 = 1_000_000;

pub fn charge(used: i64, cost: i64, limit: i64) -> Option<i64> {
    if used < 0 || cost < 0 || limit < 0 || used > limit || cost > limit - used {
        None
    } else {
        Some(used + cost)
    }
}
pub fn charge_integer(used: i64, cost: &BigInt, limit: i64) -> Option<i64> {
    charge(used, cost.to_i64().filter(|v| *v <= MAX_INT)?, limit)
}
fn nonnegative(value: i128) -> Option<i64> {
    (0..=i128::from(MAX_INT))
        .contains(&value)
        .then_some(value as i64)
}
pub fn scaled_product(values: &[i64], divisor: i64) -> Option<i64> {
    if divisor <= 0 || values.iter().any(|v| *v < 0) {
        return None;
    }
    let product = values.iter().fold(BigInt::from(1), |a, v| a * v) / divisor;
    product.to_i64().filter(|v| *v <= MAX_INT)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegerOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,
    Abs,
}
impl IntegerOp {
    pub fn variable(self, left: &BigInt, right: &BigInt) -> BigInt {
        let left = BigInt::from(left.bits().max(1).div_ceil(64));
        let right = BigInt::from(right.bits().max(1).div_ceil(64));
        match self {
            Self::Add | Self::Sub => left.max(right),
            Self::Mul | Self::Div | Self::Mod => left * right,
            Self::Neg | Self::Abs => left,
        }
    }
    pub fn cost(self, active: bool, base: i64, left: &BigInt, right: &BigInt) -> BigInt {
        BigInt::from(base)
            + if active {
                self.variable(left, right)
            } else {
                BigInt::from(0)
            }
    }
    pub fn eval(self, left: &BigInt, right: &BigInt) -> Option<BigInt> {
        Some(match self {
            Self::Add => left + right,
            Self::Sub => left - right,
            Self::Mul => left * right,
            Self::Div if right.sign() != num_bigint::Sign::NoSign => left / right,
            Self::Mod if right.sign() != num_bigint::Sign::NoSign => left % right,
            Self::Div | Self::Mod => return None,
            Self::Neg => -left,
            Self::Abs => left.abs(),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub key_bytes: i64,
    pub value_bytes: i64,
    pub copy_bytes: i64,
    pub write_bytes: i64,
    pub alloc_bytes: i64,
    pub unit_bytes: i64,
}
impl Limits {
    pub const CONSENSUS: Self = Self {
        key_bytes: 16_777_216,
        value_bytes: 4_194_304,
        copy_bytes: 16_777_216,
        write_bytes: 4_194_304,
        alloc_bytes: 134_217_728,
        unit_bytes: 32,
    };
    pub fn valid(self) -> bool {
        [self.key_bytes, self.value_bytes, self.copy_bytes]
            .iter()
            .all(|v| (0..=MAX_STRING).contains(v))
            && self.write_bytes >= 0
            && self.alloc_bytes >= 0
            && self.unit_bytes > 0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Write(i64, i64),
    Erase(i64),
    Copy(i64, i64),
    Allocate(i64),
    Scan(i64),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoding {
    pub max_bytes: i64,
    pub requests: Vec<Request>,
}
pub fn parsing(length: i64, cells: i64) -> Option<(i64, Vec<Request>)> {
    if length < 0 || cells < 0 {
        return None;
    }
    let base = nonnegative(i128::from(cells) * 2)?;
    let memory = nonnegative(i128::from(cells) * 96 + i128::from(length) * 2)?;
    Some((base, vec![Request::Scan(length), Request::Allocate(memory)]))
}
pub fn encoded_size(length: i64) -> Option<i64> {
    if length < 0 {
        return None;
    }
    let size = (i128::from(length) + 2) / 3 * 4;
    (size <= i128::from(MAX_STRING)).then_some(size as i64)
}
pub fn cell_bytes(count: i64, bits: i64) -> Option<i64> {
    if count < 0 || bits < 0 {
        return None;
    }
    nonnegative(i128::from(count) * (80 + (i128::from(bits) + 7) / 8))
}
pub fn decoding(length: i64, cells: i64, bits: i64, cached: bool) -> Option<Decoding> {
    if length < 0 {
        return None;
    }
    let memory = cell_bytes(cells, bits)?;
    let capacity = (i128::from(length) + 3) / 4 * 3;
    if capacity > i128::from(MAX_STRING) {
        return None;
    }
    let allocated = nonnegative(i128::from(memory) + if cached { 0 } else { capacity * 2 })?;
    let mut requests = Vec::with_capacity(2);
    if !cached {
        requests.push(Request::Scan(length));
    }
    requests.push(Request::Allocate(allocated));
    Some(Decoding {
        max_bytes: capacity as i64,
        requests,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub effort: i64,
    pub remaining: i64,
    pub available: i64,
}
pub fn plan(
    limits: Limits,
    remaining: i64,
    available: i64,
    used: i64,
    limit: i64,
    base: i64,
    requests: &[Request],
) -> Option<Plan> {
    if !limits.valid()
        || remaining < 0
        || remaining > limits.write_bytes
        || available < 0
        || available > limits.alloc_bytes
        || used < 0
        || limit < used
        || base < 0
    {
        return None;
    }
    let mut effort = i128::from(base);
    let mut written = 0_i128;
    let mut allocated = 0_i128;
    for request in requests {
        let (bytes, added, created) = match *request {
            Request::Write(key, value) => {
                if key <= 0 || value < 0 || key > limits.key_bytes || value > limits.value_bytes {
                    return None;
                }
                let bytes = i128::from(key) + i128::from(value);
                (bytes, bytes, 0)
            }
            Request::Erase(key) => {
                if key < 0 {
                    return None;
                }
                let bytes = i128::from(key);
                (bytes, bytes, 0)
            }
            Request::Copy(left, right) => {
                let bytes = i128::from(left) + i128::from(right);
                if left < 0 || right < 0 || bytes > i128::from(limits.copy_bytes) {
                    return None;
                }
                (bytes, 0, bytes)
            }
            Request::Allocate(size) => {
                if size < 0 {
                    return None;
                }
                let bytes = i128::from(size);
                (bytes, 0, bytes)
            }
            Request::Scan(size) => {
                if size < 0 {
                    return None;
                }
                (i128::from(size), 0, 0)
            }
        };
        effort += (bytes + i128::from(limits.unit_bytes) - 1) / i128::from(limits.unit_bytes);
        written += added;
        allocated += created;
        if effort > i128::from(limit - used)
            || written > i128::from(remaining)
            || allocated > i128::from(available)
        {
            return None;
        }
    }
    if effort > i128::from(limit - used) {
        return None;
    }
    Some(Plan {
        effort: used + effort as i64,
        remaining: remaining - written as i64,
        available: available - allocated as i64,
    })
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Budget {
    limits: Limits,
    remaining: i64,
    available: i64,
    event_left: i64,
    event_count: i64,
}
impl Default for Budget {
    fn default() -> Self {
        Self::new(Limits::CONSENSUS).unwrap()
    }
}
impl Budget {
    pub fn new(limits: Limits) -> Option<Self> {
        limits.valid().then_some(Self {
            limits,
            remaining: limits.write_bytes,
            available: limits.alloc_bytes,
            event_left: 4_194_304,
            event_count: 256,
        })
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }
    pub fn remaining(&self) -> i64 {
        self.remaining
    }
    pub fn available(&self) -> i64 {
        self.available
    }
    pub fn event_left(&self) -> i64 {
        self.event_left
    }
    pub fn event_count(&self) -> i64 {
        self.event_count
    }
    pub fn text_limit(&self) -> i64 {
        self.limits
            .key_bytes
            .max(self.limits.value_bytes)
            .max(self.limits.copy_bytes)
    }
    pub fn plan(&self, used: i64, limit: i64, base: i64, requests: &[Request]) -> Option<Plan> {
        plan(
            self.limits,
            self.remaining,
            self.available,
            used,
            limit,
            base,
            requests,
        )
    }
    pub fn charge(
        &mut self,
        used: i64,
        limit: i64,
        base: i64,
        requests: &[Request],
    ) -> Option<i64> {
        let p = self.plan(used, limit, base, requests)?;
        self.remaining = p.remaining;
        self.available = p.available;
        Some(p.effort)
    }
    pub fn output(&mut self, used: i64, limit: i64, size: i64) -> Option<i64> {
        if size < 0 || size > self.event_left {
            return None;
        }
        let effort = self.charge(used, limit, 0, &[Request::Allocate(size)])?;
        self.event_left -= size;
        Some(effort)
    }
    pub fn emit(&mut self, used: i64, limit: i64, size: i64) -> Option<i64> {
        if size < 0 || self.event_count == 0 {
            return None;
        }
        let size = if self.event_count == 256 && size < MAX_INT {
            size + 1
        } else {
            size
        };
        let effort = self.output(used, limit, size)?;
        self.event_count -= 1;
        Some(effort)
    }
}
pub fn text_size(limit: i64, value: &[u8]) -> Option<i64> {
    if limit < 2 || value.len() as u64 > (limit - 2) as u64 {
        return None;
    }
    let mut size = 2;
    for byte in value {
        let width = match byte {
            b'"' | b'\\' | 8 | 12 | b'\n' | b'\r' | b'\t' => 2,
            0..=31 | 127 => 6,
            _ => 1,
        };
        if width > limit - size {
            return None;
        }
        size += width;
    }
    Some(size)
}
pub fn event_size(
    limit: i64,
    address: &[u8],
    depth: i64,
    name: &[u8],
    values: &[&[u8]],
) -> Option<i64> {
    let mut left = limit.checked_sub(
        b"{\"program\":,\"contract\":,\"depth\":,\"event\":,\"values\":[]}".len() as i64,
    )?;
    for value in [address, address] {
        left -= text_size(left, value)?;
    }
    left -= depth.to_string().len() as i64;
    left -= text_size(left, name)?;
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            left -= 1;
        }
        left -= text_size(left, value)?;
    }
    Some(limit - left)
}
