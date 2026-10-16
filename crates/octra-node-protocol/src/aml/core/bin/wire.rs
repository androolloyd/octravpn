// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native little-significance integer bits and MSB-first packed bytes.
use super::{BigInt, BigUint, Bits, Code, CodeId, Codes, Decoded, Sign, Zero, MAX_BITS};
struct Writer {
    bits: Bits,
}
impl Writer {
    fn add(&mut self, bits: &[bool]) -> Option<()> {
        if bits.len() > MAX_BITS - self.bits.len() {
            return None;
        }
        self.bits.extend_from_slice(bits);
        Some(())
    }
    fn positive(&mut self, value: &BigUint) -> Option<()> {
        let width = value.bits();
        if width == 0 || width.checked_mul(2)? > (MAX_BITS - self.bits.len()) as u64 {
            return None;
        }
        for index in 0..width - 1 {
            self.add(if value.bit(index) {
                &[true, false]
            } else {
                &[false, true]
            })?;
        }
        self.add(&[false, false])
    }
    fn natural(&mut self, value: &BigInt) -> Option<()> {
        if value.sign() == Sign::Minus {
            None
        } else if value.is_zero() {
            self.add(&[false, false])
        } else {
            self.add(&[false, true])?;
            self.positive(value.magnitude())
        }
    }
    fn integer(&mut self, value: &BigInt) -> Option<()> {
        if value.is_zero() {
            self.add(&[false, false])
        } else {
            self.add(if value.sign() == Sign::Minus {
                &[true, false]
            } else {
                &[false, true]
            })?;
            self.positive(value.magnitude())
        }
    }
}
pub fn encode(codes: &Codes, root: CodeId) -> Option<Bits> {
    let mut out = Writer { bits: vec![] };
    let mut pending = vec![root];
    while let Some(id) = pending.pop() {
        match codes.get(id) {
            Code::Num(value) => {
                out.add(&[false, false])?;
                out.natural(value)?;
            }
            Code::Int(value) => {
                out.add(&[false, true])?;
                out.integer(value)?;
            }
            Code::Nil => out.add(&[true, false])?,
            Code::Cons(first, second) => {
                out.add(&[true, true, false])?;
                pending.push(*second);
                pending.push(*first);
            }
            Code::Tag(tag, body) => {
                out.add(&[true, true, true])?;
                out.natural(tag)?;
                pending.push(*body);
            }
        }
    }
    Some(out.bits)
}
struct Reader<'a> {
    bits: &'a [bool],
    at: usize,
}
impl Reader<'_> {
    fn bit(&mut self) -> Option<bool> {
        let value = *self.bits.get(self.at)?;
        self.at += 1;
        Some(value)
    }
    fn positive(&mut self) -> Option<BigInt> {
        let mut value = BigUint::zero();
        let mut place = 0;
        loop {
            match (self.bit()?, self.bit()?) {
                (false, false) => {
                    value.set_bit(place, true);
                    return Some(BigInt::from(value));
                }
                (false, true) => (),
                (true, false) => value.set_bit(place, true),
                (true, true) => return None,
            }
            place += 1;
        }
    }
    fn natural(&mut self) -> Option<BigInt> {
        match (self.bit()?, self.bit()?) {
            (false, false) => Some(BigInt::zero()),
            (false, true) => self.positive(),
            _ => None,
        }
    }
    fn integer(&mut self) -> Option<BigInt> {
        match (self.bit()?, self.bit()?) {
            (false, false) => Some(BigInt::zero()),
            (false, true) => self.positive(),
            (true, false) => self.positive().map(|value| -value),
            _ => None,
        }
    }
}
enum Frame {
    First,
    Second(CodeId),
    Mark(BigInt),
}
pub fn decode(bits: &[bool]) -> Option<Decoded> {
    if bits.len() > MAX_BITS {
        return None;
    }
    let mut reader = Reader { bits, at: 0 };
    let mut fuel = bits.len() + 1;
    let mut codes = Codes::default();
    let mut frames = vec![];
    'parse: loop {
        if fuel == 0 {
            return None;
        }
        fuel -= 1;
        let mut value = match (reader.bit()?, reader.bit()?) {
            (false, false) => codes.num(reader.natural()?),
            (false, true) => codes.integer(reader.integer()?),
            (true, false) => codes.nil(),
            (true, true) => {
                if reader.bit()? {
                    frames.push(Frame::Mark(reader.natural()?));
                } else {
                    frames.push(Frame::First);
                }
                continue;
            }
        };
        loop {
            match frames.pop() {
                None => {
                    if reader.at != bits.len() || encode(&codes, value)?.as_slice() != bits {
                        return None;
                    }
                    return Some(Decoded { codes, root: value });
                }
                Some(Frame::First) => {
                    frames.push(Frame::Second(value));
                    continue 'parse;
                }
                Some(Frame::Second(first)) => value = codes.cons(first, value),
                Some(Frame::Mark(tag)) => value = codes.tag(tag, value),
            }
        }
    }
}
pub fn pack(bits: &[bool]) -> Option<Vec<u8>> {
    if bits.len() > MAX_BITS {
        return None;
    }
    let mut out = vec![0; bits.len().div_ceil(8)];
    for (index, bit) in bits.iter().enumerate() {
        if *bit {
            out[index / 8] |= 1 << (7 - index % 8);
        }
    }
    Some(out)
}
// These intentionally compare distinct native fields/length units.
#[allow(clippy::suspicious_operation_groupings)]
pub fn unpack(size: i64, raw: &[u8]) -> Option<Bits> {
    let size = usize::try_from(size).ok()?;
    if size > MAX_BITS || raw.len() != size.div_ceil(8) {
        return None;
    }
    let bits: Bits = (0..size)
        .map(|index| raw[index / 8] & (1 << (7 - index % 8)) != 0)
        .collect();
    if pack(&bits)?.as_slice() == raw {
        Some(bits)
    } else {
        None
    }
}
fn u32_size(value: usize) -> Option<[u8; 4]> {
    if value > MAX_BITS {
        None
    } else {
        Some(u32::try_from(value).ok()?.to_be_bytes())
    }
}
pub fn transcript(records: &[Bits]) -> Option<Vec<u8>> {
    let mut out = u32_size(records.len())?.to_vec();
    for bits in records {
        out.extend(u32_size(bits.len())?);
        out.extend(pack(bits)?);
    }
    Some(out)
}
