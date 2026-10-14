// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Ristretto scalar arithmetic, including the retained Prior reduction.
//! Raw construction preserves noncanonical encodings; wire callers validate them.
use zeroize::{Zeroize, Zeroizing};

use crate::field::Fp;

const ORDER: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

#[derive(Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct Scalar([u64; 4]);

impl Scalar {
    pub const ZERO: Self = Self([0; 4]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    pub const fn from_u64(value: u64) -> Self {
        Self([value, 0, 0, 0])
    }
    pub const fn from_words(words: [u64; 4]) -> Self {
        Self(words)
    }
    pub const fn to_words(self) -> [u64; 4] {
        self.0
    }
    pub fn from_bytes_raw(bytes: &[u8; 32]) -> Self {
        let mut words = Zeroizing::new([0; 4]);
        for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        Self(*words)
    }
    pub fn to_bytes(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (output, word) in bytes.chunks_exact_mut(8).zip(self.0) {
            output.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
    pub fn is_canonical(&self) -> bool {
        for (word, limit) in self.0.iter().zip(ORDER).rev() {
            match word.cmp(&limit) {
                std::cmp::Ordering::Less => return true,
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => {}
            }
        }
        false
    }
    pub fn from_fp(value: Fp) -> Self {
        let (lo, hi) = value.words();
        Self([lo, hi, 0, 0])
    }
    pub fn from_fp_signed(value: Fp) -> Self {
        if value.words().1 & (1 << 62) != 0 {
            -Self::from_fp(-value)
        } else {
            Self::from_fp(value)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ScalarRule {
    #[default]
    Prior,
    Wide,
}

impl ScalarRule {
    pub fn reduce(self, words: &[u64; 8]) -> Scalar {
        let mut remainder = Zeroizing::new([0_u64; 5]);
        for &word in words.iter().rev() {
            remainder.copy_within(0..4, 1);
            remainder[0] = word;
            let high = match self {
                // Prior deliberately truncates the shift to 64 bits before
                // widening. This retained behavior differs from modular math.
                Self::Prior => u128::from((remainder[3] >> 60) | (remainder[4] << 4)),
                Self::Wide => (u128::from(remainder[3]) >> 60) | (u128::from(remainder[4]) << 4),
            };
            remainder[3] &= 0x0fff_ffff_ffff_ffff;
            remainder[4] = 0;
            if high == 0 {
                continue;
            }
            let low_product = high.wrapping_mul(u128::from(ORDER[0]));
            let high_product = high
                .wrapping_mul(u128::from(ORDER[1]))
                .wrapping_add(low_product >> 64);
            let sub = Zeroizing::new([
                low_product as u64,
                high_product as u64,
                (high_product >> 64) as u64,
            ]);
            let mut borrow = 0_u128;
            for index in 0..4 {
                borrow = u128::from(remainder[index])
                    .wrapping_sub(u128::from(sub.get(index).copied().unwrap_or(0)))
                    .wrapping_sub((borrow >> 64) & 1);
                remainder[index] = borrow as u64;
            }
            if (borrow >> 64) & 1 != 0 {
                let mut carry = 0_u128;
                for (word, modulus) in remainder[..4].iter_mut().zip(ORDER) {
                    carry = u128::from(*word) + u128::from(modulus) + (carry >> 64);
                    *word = carry as u64;
                }
            }
        }
        for _ in 0..2 {
            let mut borrow = 0_u128;
            let mut difference = Zeroizing::new([0_u64; 4]);
            for index in 0..4 {
                let value = u128::from(remainder[index])
                    .wrapping_sub(u128::from(ORDER[index]))
                    .wrapping_sub(borrow & 1);
                difference[index] = value as u64;
                borrow = value >> 127;
            }
            if borrow & 1 == 0 {
                remainder[..4].copy_from_slice(difference.as_ref());
            }
        }
        Scalar([remainder[0], remainder[1], remainder[2], remainder[3]])
    }

    pub fn reduce_bytes(self, bytes: &[u8; 64]) -> Scalar {
        let mut words = Zeroizing::new([0; 8]);
        for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        self.reduce(&words)
    }

    pub fn reduce256(self, bytes: &[u8; 32]) -> Scalar {
        let mut words = Zeroizing::new([0; 8]);
        for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        self.reduce(&words)
    }

    pub fn mul(self, left: Scalar, right: Scalar) -> Scalar {
        let mut words = Zeroizing::new([0; 8]);
        for i in 0..4 {
            let mut carry = 0_u128;
            for j in 0..4 {
                carry = carry
                    .wrapping_add(u128::from(left.0[i]) * u128::from(right.0[j]))
                    .wrapping_add(u128::from(words[i + j]));
                words[i + j] = carry as u64;
                carry >>= 64;
            }
            words[i + 4] = carry as u64;
        }
        self.reduce(&words)
    }

    /// Preserve the native exponentiation, including zero and raw scalar inputs.
    pub fn inverse(self, value: Scalar) -> Scalar {
        let exponent = [ORDER[0] - 2, ORDER[1], ORDER[2], ORDER[3]];
        let mut output = Zeroizing::new(Scalar::ONE);
        let mut base = Zeroizing::new(value);
        for bit in 0..256 {
            if (exponent[bit >> 6] >> (bit & 63)) & 1 != 0 {
                *output = self.mul(*output, *base);
            }
            *base = self.mul(*base, *base);
        }
        *output
    }
}

impl std::ops::Add for Scalar {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        let mut words = Zeroizing::new([0; 8]);
        let mut carry = 0_u128;
        for (index, (&a, &b)) in self.0.iter().zip(&other.0).enumerate() {
            carry += u128::from(a) + u128::from(b);
            words[index] = carry as u64;
            carry >>= 64;
        }
        words[4] = carry as u64;
        ScalarRule::Prior.reduce(&words)
    }
}

impl std::ops::Sub for Scalar {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        let mut negative = Zeroizing::new([0; 4]);
        let mut borrow = 0_u128;
        for index in 0..4 {
            let difference = u128::from(ORDER[index])
                .wrapping_sub(u128::from(other.0[index]))
                .wrapping_sub(borrow);
            negative[index] = difference as u64;
            borrow = (difference >> 64) & 1;
        }
        self + Self(*negative)
    }
}

impl std::ops::Neg for Scalar {
    type Output = Self;
    fn neg(self) -> Self {
        Self::ZERO - self
    }
}
