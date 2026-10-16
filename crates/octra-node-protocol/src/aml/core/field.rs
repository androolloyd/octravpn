// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_fp's canonical field used by AML core encoded values.
use num_bigint::{BigInt, Sign};
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Field(BigInt);
pub fn modulus() -> BigInt {
    (BigInt::from(1u8) << 127usize) - 1
}
pub fn valid(value: &BigInt) -> bool {
    value.sign() != Sign::Minus && value < &modulus()
}
impl Field {
    pub fn new(value: BigInt) -> Option<Self> {
        valid(&value).then_some(Self(value))
    }
    pub fn reduce(value: &BigInt) -> Self {
        let modulus = modulus();
        let value = value % &modulus;
        Self(if value.sign() == Sign::Minus {
            value + modulus
        } else {
            value
        })
    }
    pub fn value(&self) -> &BigInt {
        &self.0
    }
    pub fn text(&self) -> Vec<u8> {
        self.0.to_string().into_bytes()
    }
    pub fn add(&self, right: &Self) -> Self {
        Self::reduce(&(&self.0 + &right.0))
    }
    pub fn multiply(&self, right: &Self) -> Self {
        Self::reduce(&(&self.0 * &right.0))
    }
}
