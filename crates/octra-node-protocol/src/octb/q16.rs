// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Integer-only Fixed_q16 arithmetic from the adopted native runtime. Division
//! truncates toward zero; arithmetic shifts round down, as Zarith does.
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};
pub const SCALE: i64 = 65_536;
const LN_TWO: i64 = 45_426;

pub fn in_range(value: &BigInt) -> bool {
    value.magnitude().bits() <= 63
}
pub fn mul(a: &BigInt, b: &BigInt) -> BigInt {
    (a * b) >> 16
}
pub fn round(value: &BigInt, bits: u32) -> Option<BigInt> {
    if !(1..=62).contains(&bits) {
        return None;
    }
    let half = BigInt::from(1) << (bits - 1);
    Some(if value.is_negative() {
        -((value.abs() + half) >> bits)
    } else {
        (value + half) >> bits
    })
}
fn round_div(value: &BigInt, divisor: i64) -> BigInt {
    let rounded = (value.abs() + (divisor >> 1)) / divisor;
    if value.is_negative() {
        -rounded
    } else {
        rounded
    }
}
pub fn exp(value: &BigInt) -> BigInt {
    let value = value
        .clamp(&BigInt::from(-16 * SCALE), &BigInt::from(8 * SCALE))
        .clone();
    let exponent = round_div(&value, LN_TWO);
    let reduced = value - &exponent * LN_TWO;
    let mut term = BigInt::from(SCALE);
    let mut total = term.clone();
    for index in 1..13 {
        term = mul(&term, &reduced) / index;
        total += &term;
    }
    // The input clamp bounds this exponent to [-23, 12].
    let exponent = exponent.to_i32().expect("bounded Q16 exponent");
    if exponent >= 0 {
        (total << exponent as u32).min(BigInt::from(i64::MAX))
    } else {
        let shift = exponent.unsigned_abs();
        (total + (BigInt::from(1) << (shift - 1))) >> shift
    }
}
pub fn scale_floor(value: &BigInt, total: &BigInt) -> Option<BigInt> {
    (!value.is_negative() && total.is_positive()).then(|| value * SCALE / total)
}
fn inv_sqrt(value: &BigInt) -> Option<BigInt> {
    if !value.is_positive() {
        return None;
    }
    let root = (value * SCALE).sqrt();
    root.is_positive()
        .then(|| BigInt::from(SCALE * SCALE) / root)
}
fn ln(value: &BigInt) -> Option<BigInt> {
    if !value.is_positive() || !in_range(value) {
        return None;
    }
    let mut normalized = value.clone();
    let mut exponent = 0_i64;
    while normalized >= BigInt::from(SCALE * 2) {
        normalized >>= 1;
        exponent += 1;
    }
    while normalized < BigInt::from(SCALE) {
        normalized <<= 1;
        exponent -= 1;
    }
    let z = (&normalized - SCALE) * SCALE / (&normalized + SCALE);
    let square = mul(&z, &z);
    let mut power = z;
    let mut sum = BigInt::zero();
    for index in 0..16 {
        sum += &power / (2 * index + 1);
        power = mul(&power, &square);
    }
    Some(sum * 2 + exponent * LN_TWO)
}
fn sin0(value: &BigInt) -> BigInt {
    let square = mul(value, value);
    let cube = mul(&square, value);
    let fifth = mul(&cube, &square);
    let seventh = mul(&fifth, &square);
    value - cube / 6 + fifth / 120 - seventh / 5040
}
fn cos0(value: &BigInt) -> BigInt {
    let square = mul(value, value);
    let fourth = mul(&square, &square);
    let sixth = mul(&fourth, &square);
    BigInt::from(SCALE) - square / 2 + fourth / 24 - sixth / 720
}
fn sin_cos(angle: &BigInt) -> (BigInt, BigInt) {
    let mut angle: BigInt = angle % 411_775;
    if angle.is_negative() {
        angle += 411_775;
    }
    if angle <= BigInt::from(102_944) {
        (sin0(&angle), cos0(&angle))
    } else if angle <= BigInt::from(205_887) {
        let reduced = BigInt::from(205_887) - angle;
        (sin0(&reduced), -cos0(&reduced))
    } else if angle <= BigInt::from(308_831) {
        let reduced = angle - 205_887;
        (-sin0(&reduced), -cos0(&reduced))
    } else {
        let reduced = BigInt::from(411_775) - angle;
        (-sin0(&reduced), cos0(&reduced))
    }
}
pub fn silu(value: &BigInt) -> Option<BigInt> {
    if !in_range(value) {
        return None;
    }
    let denominator = exp(&-value) + SCALE;
    denominator
        .is_positive()
        .then(|| mul(value, &(BigInt::from(SCALE * SCALE) / denominator)))
}
// Preserve the native remainder guard and zero-divisor short-circuit order.
#[allow(clippy::manual_is_multiple_of)]
pub fn rope(values: &[BigInt], base: &BigInt, position: i64) -> Option<Vec<BigInt>> {
    if values.is_empty()
        || values.len() % 2 != 0
        || !base.is_positive()
        || !in_range(base)
        || !values.iter().all(in_range)
    {
        return None;
    }
    let base_log = ln(base)?;
    let half = values.len() / 2;
    let mut result = vec![BigInt::zero(); values.len()];
    for index in 0..half {
        let exponent = BigInt::from(2 * index) * SCALE / values.len();
        let frequency = exp(&-mul(&exponent, &base_log));
        let (sine, cosine) = sin_cos(&(frequency * position));
        result[index] = mul(&values[index], &cosine) - mul(&values[index + half], &sine);
        result[index + half] = mul(&values[index], &sine) + mul(&values[index + half], &cosine);
    }
    result.iter().all(in_range).then_some(result)
}
pub fn dot(left: &[BigInt], right: &[BigInt]) -> BigInt {
    left.iter().zip(right).map(|(a, b)| mul(a, b)).sum()
}
pub fn pairwise(left: &[BigInt], right: &[BigInt], product: bool) -> Option<Vec<BigInt>> {
    if left.len() != right.len() || !left.iter().chain(right).all(in_range) {
        return None;
    }
    let result: Vec<_> = left
        .iter()
        .zip(right)
        .map(|(a, b)| if product { mul(a, b) } else { a + b })
        .collect();
    result.iter().all(in_range).then_some(result)
}
pub fn softmax(values: &[BigInt]) -> Option<Vec<BigInt>> {
    let maximum = values.iter().max()?;
    let weights: Vec<_> = values.iter().map(|v| exp(&(v - maximum))).collect();
    let total: BigInt = weights.iter().sum();
    let mut result: Vec<_> = weights
        .iter()
        .map(|v| scale_floor(v, &total))
        .collect::<Option<_>>()?;
    let mut best = 0;
    for index in 1..weights.len() {
        if weights[index] > weights[best] {
            best = index;
        }
    }
    let used: BigInt = result.iter().sum();
    result[best] += BigInt::from(SCALE) - used;
    result.iter().all(in_range).then_some(result)
}
pub fn layer(
    values: &[BigInt],
    gamma: &[BigInt],
    beta: &[BigInt],
    math: bool,
) -> Option<Vec<BigInt>> {
    if values.is_empty()
        || gamma.len() != values.len()
        || beta.len() != values.len()
        || !values.iter().chain(gamma).chain(beta).all(in_range)
    {
        return None;
    }
    let mean: BigInt = values.iter().sum::<BigInt>() / values.len();
    let square: BigInt = values.iter().map(|v| (v - &mean).pow(2)).sum();
    let variance = square / (BigInt::from(values.len()) * SCALE);
    let inverse = inv_sqrt(&(variance + 1))?;
    let result: Vec<_> = values
        .iter()
        .zip(gamma)
        .zip(beta)
        .map(|((v, g), b)| mul(g, &mul(&(v - &mean), &inverse)) + b)
        .collect();
    (!math || result.iter().all(in_range)).then_some(result)
}
pub fn rms(values: &[BigInt], gamma: &[BigInt], math: bool) -> Option<Vec<BigInt>> {
    if values.is_empty() || gamma.len() != values.len() || !values.iter().chain(gamma).all(in_range)
    {
        return None;
    }
    let square: BigInt = values.iter().map(|v| v * v).sum();
    let inverse = inv_sqrt(&(square / (BigInt::from(values.len()) * SCALE) + 1))?;
    let result: Vec<_> = values
        .iter()
        .zip(gamma)
        .map(|(v, g)| mul(g, &mul(v, &inverse)))
        .collect();
    (!math || result.iter().all(in_range)).then_some(result)
}
// Preserve the native remainder guard and zero-divisor short-circuit order.
#[allow(clippy::manual_is_multiple_of)]
pub fn attention(
    query: &[BigInt],
    key: &[BigInt],
    value: &[BigInt],
    tokens: usize,
    heads: usize,
    key_heads: usize,
    width: usize,
) -> Option<Vec<BigInt>> {
    if tokens == 0 || heads == 0 || key_heads == 0 || width == 0 || heads % key_heads != 0 {
        return None;
    }
    let query_size = heads.checked_mul(width)?;
    let key_size = tokens.checked_mul(key_heads)?.checked_mul(width)?;
    if query.len() != query_size
        || key.len() != key_size
        || value.len() != key_size
        || !query.iter().chain(key).chain(value).all(in_range)
    {
        return None;
    }
    let inverse = inv_sqrt(&(BigInt::from(width) * SCALE))?;
    let group = heads / key_heads;
    let mut result = Vec::with_capacity(query_size);
    for head in 0..heads {
        let q = &query[head * width..(head + 1) * width];
        let key_head = head / group;
        let scores: Vec<_> = (0..tokens)
            .map(|token| {
                let offset = (token * key_heads + key_head) * width;
                mul(&dot(q, &key[offset..offset + width]), &inverse)
            })
            .collect();
        let maximum = scores.iter().max()?;
        let weights: Vec<_> = scores.iter().map(|v| exp(&(v - maximum))).collect();
        let total: BigInt = weights.iter().sum();
        // Native attention uses floors without softmax's residual adjustment.
        let probabilities: Vec<_> = weights
            .iter()
            .map(|v| scale_floor(v, &total))
            .collect::<Option<_>>()?;
        for dimension in 0..width {
            result.push(
                (0..tokens)
                    .map(|token| {
                        let offset = (token * key_heads + key_head) * width + dimension;
                        mul(&probabilities[token], &value[offset])
                    })
                    .sum(),
            );
        }
    }
    result.iter().all(in_range).then_some(result)
}
