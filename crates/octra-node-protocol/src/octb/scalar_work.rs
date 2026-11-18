// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Width limits and work charges for integers and numeric text
//! (`lib/vm/runtime/scalar_work.ml`). Active from rule `scalar_work`.
use num_bigint::{BigInt, Sign};

/// Widest integer, in bits, a register, storage cell or input may hold.
pub const BIT_LIMIT: u64 = 65_536;
/// Longest text that may be parsed as an integer.
pub const TEXT_LIMIT: usize = 65_536;

pub const CONSENSUS_ID: &str = "scalar_work:bits_65536:parse_chars_65536:scan_32:parse_square:decimal_square:load_16:minimum_1000000:wasm_integer:receipt_decimal";

fn units(length: usize) -> BigInt {
    BigInt::from(length.div_ceil(32))
}
/// Reading `length` bytes of text without parsing it.
pub fn scan(length: usize) -> BigInt {
    units(length)
}
/// Parsing `length` characters of numeric text.
pub fn parse(length: usize) -> BigInt {
    let cells = units(length);
    &cells + &cells * &cells
}
/// Rendering `number` in decimal.
pub fn decimal(number: &BigInt) -> BigInt {
    let cells = BigInt::from(1 + number.bits() / 64);
    &cells + &cells * &cells
}
pub fn valid(number: &BigInt) -> bool {
    number.bits() <= BIT_LIMIT
}
pub fn text_ok(text: &[u8]) -> bool {
    text.len() <= TEXT_LIMIT
}
/// Loading `length` bytes of program code.
pub fn load(length: usize) -> BigInt {
    BigInt::from(length) * 16
}
/// The effort a caller may grant: unchanged before activation; afterwards a
/// declared limit, never below 1,000,000, never above the prior allowance.
pub fn allowance(active: bool, declared: &BigInt, prior: i64) -> i64 {
    if !active {
        return prior;
    }
    if declared.sign() == Sign::Minus {
        return 0;
    }
    // OCaml `Z.fits_int`: a 63-bit signed integer.
    match i64::try_from(declared) {
        Ok(value) if value < (1 << 62) => prior.min(value.max(1_000_000)),
        _ => prior,
    }
}
/// A JSON parameter as the scalar-work rule prices it.
pub enum Param<'a> {
    /// An integer literal, by its text.
    Integer(&'a str),
    String(&'a str),
    /// A boolean, null, float or small integer.
    Unit,
    /// Anything else: arrays and objects are refused.
    Other,
}
/// Price of a parameter list; `None` when any parameter is refused.
pub fn json_cost<'a>(values: impl IntoIterator<Item = Param<'a>>) -> Option<BigInt> {
    let mut total = BigInt::from(0);
    for value in values {
        total += match value {
            Param::Integer(text) if text_ok(text.as_bytes()) => parse(text.len()),
            Param::Integer(_) | Param::Other => return None,
            Param::String(text) => scan(text.len()),
            Param::Unit => BigInt::from(1),
        };
    }
    Some(total)
}
/// `number` rendered in decimal equals `text`, without rendering numbers that
/// cannot match.
pub fn decimal_equal(number: &BigInt, text: &[u8]) -> bool {
    let length = text.len() as u64;
    let bits = number.bits();
    let digits = length.saturating_sub(u64::from(number.sign() == Sign::Minus));
    if length == 0 || digits == 0 || digits > bits + 1 || bits > digits * 4 {
        return false;
    }
    number.to_string().as_bytes() == text
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decimal_equal_matches_rendering() {
        for n in [-1000_i64, -12, -1, 0, 1, 9, 10, 12, 99, 100, 1 << 40] {
            let n = BigInt::from(n);
            assert!(decimal_equal(&n, n.to_string().as_bytes()));
            for other in ["", "-", "-0", "+1", "01", "x"] {
                assert_eq!(decimal_equal(&n, other.as_bytes()), n.to_string() == other);
            }
        }
    }
    #[test]
    fn costs() {
        assert_eq!(scan(0), 0.into());
        assert_eq!(scan(33), 2.into());
        assert_eq!(parse(64), 6.into());
        assert_eq!(decimal(&BigInt::from(0)), 2.into());
        assert_eq!(decimal(&(BigInt::from(1) << 64)), 6.into());
        assert!(valid(&((BigInt::from(1) << 65_536) - 1)));
        assert!(!valid(&(BigInt::from(1) << 65_536)));
        assert_eq!(allowance(true, &BigInt::from(5), 2_000_000), 1_000_000);
        assert_eq!(allowance(true, &BigInt::from(-5), 2_000_000), 0);
        assert_eq!(allowance(false, &BigInt::from(-5), 2_000_000), 2_000_000);
    }
}
