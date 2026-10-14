// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Exact native inner-product proof folding and verification.
#![allow(clippy::many_single_char_names)] // Match the native proof equations.
use zeroize::Zeroizing;

use super::{
    generators::{generators, log2_size, multi_scalar_mul, point_valid, Point, MAX_VECTOR_SIZE},
    transcript::Transcript,
};
use crate::{
    scalar::{Scalar, ScalarRule},
    Error,
};

#[derive(Clone, PartialEq, Eq)]
pub struct InnerProductProof {
    pub l: Vec<Point>,
    pub r: Vec<Point>,
    pub a: Scalar,
    pub b: Scalar,
}

impl InnerProductProof {
    pub fn points_valid(&self) -> bool {
        self.l.len() == self.r.len()
            && self.l.iter().all(point_valid)
            && self.r.iter().all(point_valid)
    }
}

fn scalar_buffer(length: usize) -> Result<Zeroizing<Vec<Scalar>>, Error> {
    let mut values = Zeroizing::new(Vec::new());
    values
        .try_reserve_exact(length)
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    values.resize(length, Scalar::ZERO);
    Ok(values)
}

fn point_buffer(length: usize) -> Result<Vec<Point>, Error> {
    let mut points = Vec::new();
    points
        .try_reserve_exact(length)
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    points.resize(length, [0; 32]);
    Ok(points)
}

pub fn inner_product(a: &[Scalar], b: &[Scalar], rule: ScalarRule) -> Result<Scalar, Error> {
    if a.len() != b.len() {
        return Err(Error("HFHE inner product shape rejected"));
    }
    Ok(a.iter().zip(b).fold(Scalar::ZERO, |sum, (&left, &right)| {
        sum + rule.mul(left, right)
    }))
}

/// The native prover requires four equally sized, nonempty power-of-two vectors.
/// Witness buffers are erased when each folding round replaces them.
pub fn prove(
    transcript: &mut Transcript,
    q: &Point,
    mut a: Zeroizing<Vec<Scalar>>,
    mut b: Zeroizing<Vec<Scalar>>,
    mut g: Vec<Point>,
    mut h: Vec<Point>,
) -> Result<InnerProductProof, Error> {
    let mut n = a.len();
    if n != b.len() || n != g.len() || n != h.len() || !n.is_power_of_two() {
        return Err(Error("HFHE inner product shape rejected"));
    }
    let logarithm = log2_size(n)?;
    let rule = transcript.rule;
    let mut left = Vec::with_capacity(logarithm);
    let mut right = Vec::with_capacity(logarithm);
    for _ in 0..logarithm {
        let half = n / 2;
        let mut cross_left = Zeroizing::new(Scalar::ZERO);
        let mut cross_right = Zeroizing::new(Scalar::ZERO);
        for index in 0..half {
            *cross_left = *cross_left + rule.mul(a[index], b[half + index]);
            *cross_right = *cross_right + rule.mul(a[half + index], b[index]);
        }
        let mut scalars = scalar_buffer(n + 1)?;
        let mut points = point_buffer(n + 1)?;
        for index in 0..half {
            scalars[index] = a[index];
            points[index] = g[half + index];
            scalars[half + index] = b[half + index];
            points[half + index] = h[index];
        }
        scalars[n] = *cross_left;
        points[n] = *q;
        let l = multi_scalar_mul(&scalars, &points)?;
        for index in 0..half {
            scalars[index] = a[half + index];
            points[index] = g[index];
            scalars[half + index] = b[index];
            points[half + index] = h[half + index];
        }
        scalars[n] = *cross_right;
        let r = multi_scalar_mul(&scalars, &points)?;
        transcript.append_point(b"L", &l);
        transcript.append_point(b"R", &r);
        let u = transcript.challenge_scalar(b"u");
        let u_inverse = rule.inverse(u);
        left.push(l);
        right.push(r);
        let mut next_a = scalar_buffer(half)?;
        let mut next_b = scalar_buffer(half)?;
        let mut next_g = point_buffer(half)?;
        let mut next_h = point_buffer(half)?;
        for index in 0..half {
            next_a[index] = rule.mul(a[index], u) + rule.mul(a[half + index], u_inverse);
            next_b[index] = rule.mul(b[index], u_inverse) + rule.mul(b[half + index], u);
            next_g[index] = multi_scalar_mul(&[u_inverse, u], &[g[index], g[half + index]])?;
            next_h[index] = multi_scalar_mul(&[u, u_inverse], &[h[index], h[half + index]])?;
        }
        a = next_a;
        b = next_b;
        g = next_g;
        h = next_h;
        n = half;
    }
    Ok(InnerProductProof {
        l: left,
        r: right,
        a: a[0],
        b: b[0],
    })
}

pub fn verification_scalars(challenges: &[Scalar], rule: ScalarRule) -> Result<Vec<Scalar>, Error> {
    let logarithm = challenges.len();
    let shift = u32::try_from(logarithm).map_err(|_| Error("HFHE inner product shape rejected"))?;
    let n = 1_usize
        .checked_shl(shift)
        .ok_or(Error("HFHE inner product shape rejected"))?;
    let mut inverse = scalar_buffer(logarithm)?;
    for (value, &challenge) in inverse.iter_mut().zip(challenges) {
        *value = rule.inverse(challenge);
    }
    let mut scalars = Vec::new();
    scalars
        .try_reserve_exact(n)
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    scalars.resize(n, Scalar::ZERO);
    scalars[0] = Scalar::ONE;
    for value in inverse.iter() {
        scalars[0] = rule.mul(scalars[0], *value);
    }
    for index in 1..n {
        let bit = index.ilog2() as usize;
        let challenge_index = logarithm - 1 - bit;
        let squared = rule.mul(challenges[challenge_index], challenges[challenge_index]);
        scalars[index] = rule.mul(scalars[index ^ (1 << bit)], squared);
    }
    Ok(scalars)
}

pub fn batch_inverse(values: &[Scalar], rule: ScalarRule) -> Result<Vec<Scalar>, Error> {
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let mut prefix = scalar_buffer(values.len())?;
    prefix[0] = values[0];
    for index in 1..values.len() {
        prefix[index] = rule.mul(prefix[index - 1], values[index]);
    }
    let mut inverse_all = Zeroizing::new(rule.inverse(prefix[values.len() - 1]));
    let mut result = Vec::new();
    result
        .try_reserve_exact(values.len())
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    result.resize(values.len(), Scalar::ZERO);
    for index in (1..values.len()).rev() {
        result[index] = rule.mul(*inverse_all, prefix[index - 1]);
        *inverse_all = rule.mul(*inverse_all, values[index]);
    }
    result[0] = *inverse_all;
    Ok(result)
}

pub fn verify(
    transcript: &mut Transcript,
    p: &Point,
    q: &Point,
    proof: &InnerProductProof,
    n: usize,
) -> Result<bool, Error> {
    let logarithm = proof.l.len();
    if proof.r.len() != logarithm {
        return Ok(false);
    }
    let Ok(shift) = u32::try_from(logarithm) else {
        return Ok(false);
    };
    if 1_usize.checked_shl(shift) != Some(n) {
        return Ok(false);
    }
    verify_fold(transcript, p, q, proof, n, None)
}

/// The R1CS verifier's weighted-H variant has stricter point/shape prechecks
/// than the standalone IPP verifier. Rejected prechecks leave the transcript intact.
pub fn verify_with_y(
    transcript: &mut Transcript,
    p: &Point,
    q: &Point,
    proof: &InnerProductProof,
    n: usize,
    y_inverse: &[Scalar],
) -> Result<bool, Error> {
    if !point_valid(p)
        || !point_valid(q)
        || !proof.points_valid()
        || n == 0
        || n > MAX_VECTOR_SIZE
        || y_inverse.len() != n
    {
        return Ok(false);
    }
    let Ok(shift) = u32::try_from(proof.l.len()) else {
        return Ok(false);
    };
    if 1_usize.checked_shl(shift) != Some(n) {
        return Ok(false);
    }
    verify_fold(transcript, p, q, proof, n, Some(y_inverse))
}

fn verify_fold(
    transcript: &mut Transcript,
    p: &Point,
    q: &Point,
    proof: &InnerProductProof,
    n: usize,
    y_inverse: Option<&[Scalar]>,
) -> Result<bool, Error> {
    let logarithm = proof.l.len();
    let rule = transcript.rule;
    let mut challenges = Vec::with_capacity(logarithm);
    for (left, right) in proof.l.iter().zip(&proof.r) {
        transcript.append_point(b"L", left);
        transcript.append_point(b"R", right);
        challenges.push(transcript.challenge_scalar(b"u"));
    }
    // Native generator lookup necessarily rejects this size after consuming the
    // challenges. Avoid allocating its enormous intermediate scalar vectors.
    if n > MAX_VECTOR_SIZE {
        return Err(Error("pvac: generator size rejected"));
    }
    let scalars_s = verification_scalars(&challenges, rule)?;
    let scalars_s_inverse = batch_inverse(&scalars_s, rule)?;
    let mut scalars = scalar_buffer(2 * n + 2 * logarithm + 1)?;
    let mut points = point_buffer(scalars.len())?;
    let generator = generators();
    for index in 0..n {
        scalars[index] = rule.mul(proof.a, scalars_s[index]);
        points[index] = generator.g(index)?;
        let h_scalar = rule.mul(proof.b, scalars_s_inverse[index]);
        scalars[n + index] = y_inverse.map_or(h_scalar, |y| rule.mul(h_scalar, y[index]));
        points[n + index] = generator.h(index)?;
    }
    scalars[2 * n] = rule.mul(proof.a, proof.b);
    points[2 * n] = *q;
    let mut squares = Vec::with_capacity(logarithm);
    for &challenge in &challenges {
        squares.push(rule.mul(challenge, challenge));
    }
    let inverse_squares = batch_inverse(&squares, rule)?;
    for index in 0..logarithm {
        let offset = 2 * n + 1 + 2 * index;
        scalars[offset] = -squares[index];
        points[offset] = proof.l[index];
        scalars[offset + 1] = -inverse_squares[index];
        points[offset + 1] = proof.r[index];
    }
    Ok(multi_scalar_mul(&scalars, &points)? == *p)
}
