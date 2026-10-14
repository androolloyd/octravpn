// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Shared OCaml Zarith and machine-integer input rules.
use num_bigint::BigInt;
/// Zarith's base-detecting numeric string input. In particular, an empty digit
/// sequence is zero, underscores after the first digit are ignored, and whitespace
/// is rejected. These legacy forms are normalized to decimal by transaction identity.
pub fn parse_integer(raw: &[u8]) -> Option<BigInt> {
    let (negative, raw) = match raw.first() {
        Some(b'-') => (true, &raw[1..]),
        Some(b'+') => (false, &raw[1..]),
        _ => (false, raw),
    };
    let raw = if negative {
        raw.strip_prefix(b"+").unwrap_or(raw)
    } else {
        raw
    };
    let (base, digits) = if raw.starts_with(b"0x") || raw.starts_with(b"0X") {
        (16, &raw[2..])
    } else if raw.starts_with(b"0o") || raw.starts_with(b"0O") {
        (8, &raw[2..])
    } else if raw.starts_with(b"0b") || raw.starts_with(b"0B") {
        (2, &raw[2..])
    } else {
        (10, raw)
    };
    if digits.first() == Some(&b'_') {
        return None;
    }
    let digits: Vec<_> = digits.iter().copied().filter(|b| *b != b'_').collect();
    if digits.is_empty() {
        return Some(BigInt::from(0));
    }
    if !digits.iter().all(|b| match b {
        b'0'..=b'9' => u32::from(*b - b'0') < base,
        b'a'..=b'f' => u32::from(*b - b'a' + 10) < base,
        b'A'..=b'F' => u32::from(*b - b'A' + 10) < base,
        _ => false,
    }) {
        return None;
    }
    let value = BigInt::parse_bytes(&digits, base)?;
    Some(if negative { -value } else { value })
}
fn parse_native_word(raw: &[u8], bits: u32) -> Option<i64> {
    let (negative, raw) = match raw.first() {
        Some(b'-') => (true, &raw[1..]),
        Some(b'+') => (false, &raw[1..]),
        _ => (false, raw),
    };
    let (base, unsigned, digits) = match raw.get(..2) {
        Some(b"0x" | b"0X") => (16, true, &raw[2..]),
        Some(b"0o" | b"0O") => (8, true, &raw[2..]),
        Some(b"0b" | b"0B") => (2, true, &raw[2..]),
        Some(b"0u" | b"0U") => (10, true, &raw[2..]),
        _ => (10, false, raw),
    };
    if digits.is_empty() || digits.first() == Some(&b'_') {
        return None;
    }
    let mut value = 0_u64;
    for &byte in digits {
        if byte == b'_' {
            continue;
        }
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        if u64::from(digit) >= base {
            return None;
        }
        value = value.checked_mul(base)?.checked_add(u64::from(digit))?;
    }
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1_u64 << bits) - 1
    };
    let limit = if unsigned {
        mask
    } else if negative {
        1_u64 << (bits - 1)
    } else {
        (1_u64 << (bits - 1)) - 1
    };
    if value > limit {
        return None;
    }
    if negative {
        value = value.wrapping_neg() & mask;
    }
    Some(((value << (64 - bits)) as i64) >> (64 - bits))
}
pub fn parse_int64(raw: &[u8]) -> Option<i64> {
    parse_native_word(raw, 64)
}
pub fn parse_int63(raw: &[u8]) -> Option<i64> {
    parse_native_word(raw, 63)
}
