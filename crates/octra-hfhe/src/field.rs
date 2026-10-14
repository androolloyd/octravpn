// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// Port of pvac/include/pvac/core/field.hpp at d3e834919bd586e81f947d0dae91becc6c43c756.
//! Canonical arithmetic in the Mersenne field 2^127 - 1.
//! This is a compatibility port, not a claim of audited constant-time code.

const MODULUS: u128 = (1_u128 << 127) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp(u128);

impl Fp {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);

    pub fn from_u64(value: u64) -> Self {
        Self(u128::from(value))
    }

    pub fn from_words(lo: u64, hi: u64) -> Self {
        Self::reduce(u128::from(lo) | (u128::from(hi) << 64))
    }

    fn reduce(value: u128) -> Self {
        let folded = (value & MODULUS) + (value >> 127);
        let (difference, borrow) = folded.overflowing_sub(MODULUS);
        let keep = u128::from(borrow).wrapping_neg();
        Self((folded & keep) | (difference & !keep))
    }

    pub fn words(self) -> (u64, u64) {
        (self.0 as u64, (self.0 >> 64) as u64)
    }
    pub fn to_bytes_le(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    /// Wire serialization requires a reduced field element.
    pub fn from_bytes_le(bytes: [u8; 16]) -> Option<Self> {
        let value = u128::from_le_bytes(bytes);
        (value < MODULUS).then_some(Self(value))
    }

    pub fn to_i64(self) -> Option<i64> {
        if self.0 <= i64::MAX as u128 {
            return Some(self.0 as i64);
        }
        if self.0 <= MODULUS / 2 {
            return None;
        }
        let magnitude = MODULUS - self.0;
        match magnitude.cmp(&(1_u128 << 63)) {
            std::cmp::Ordering::Greater => None,
            std::cmp::Ordering::Equal => Some(i64::MIN),
            std::cmp::Ordering::Less => Some(-(magnitude as i64)),
        }
    }

    pub fn pow_u64(self, exponent: u64) -> Self {
        self.pow_u128(u128::from(exponent))
    }

    pub fn pow_u128(self, mut exponent: u128) -> Self {
        let mut result = Self::ONE;
        let mut base = self;
        while exponent != 0 {
            if exponent & 1 != 0 {
                result = result * base;
            }
            base = base * base;
            exponent >>= 1;
        }
        result
    }

    /// Upstream returns zero for inverse(0); preserve that behavior.
    pub fn inverse(self) -> Self {
        let mut table = [Self::ONE; 32];
        table[1] = self;
        for index in 2..32 {
            table[index] = table[index - 1] * self;
        }
        let exponent = MODULUS - 2;
        let mut result = Self::ONE;
        let mut position = 126_i32;
        while position >= 0 {
            if (exponent >> position) & 1 == 0 {
                result = result * result;
                position -= 1;
                continue;
            }
            let lower = (position - 4).max(0);
            let width = position - lower + 1;
            let index = ((exponent >> lower) & ((1_u128 << width) - 1)) as usize;
            for _ in 0..width {
                result = result * result;
            }
            result = result * table[index];
            position = lower - 1;
        }
        result
    }
}

impl zeroize::Zeroize for Fp {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl std::ops::Add for Fp {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self::reduce(self.0 + other.0)
    }
}
impl std::ops::Neg for Fp {
    type Output = Self;
    fn neg(self) -> Self {
        Self::reduce(MODULUS - self.0)
    }
}
impl std::ops::Sub for Fp {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        self + -other
    }
}
impl std::ops::Mul for Fp {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        let (a0, a1) = self.words();
        let (b0, b1) = other.words();
        let low_product = u128::from(a0) * u128::from(b0);
        let middle =
            u128::from(a0) * u128::from(b1) + u128::from(a1) * u128::from(b0) + (low_product >> 64);
        let upper = u128::from(a1) * u128::from(b1) + (middle >> 64);
        // Fold the 254-bit product at bit 127. Both halves are < p;
        // their sum fits u128 and reduce performs the final Mersenne fold.
        let low = (low_product as u64 as u128) | ((middle & ((1_u128 << 63) - 1)) << 64);
        let high = (middle >> 63 & 1) | (upper << 1);
        Self::reduce(low + high)
    }
}
