// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native rank-one constraint proofs, including retained scalar semantics.
#![allow(clippy::many_single_char_names)] // Match the native proof equations.
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use super::{
    generators::{self, Point},
    inner_product::{self, InnerProductProof},
    transcript::Transcript,
};
use crate::{
    scalar::{Scalar, ScalarRule},
    Error,
};

pub const MAX_GATES: usize = 1 << 20;
pub const MAX_COMMITTED: usize = 1 << 16;
pub const MAX_TERMS: usize = 1 << 22;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LimitProfile {
    #[default]
    Default,
    KeySwitchRefresh,
}

impl LimitProfile {
    pub fn constraint_limit(self) -> usize {
        match self {
            Self::Default => 1_500_000,
            Self::KeySwitchRefresh => 1_550_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VarType {
    One,
    Committed,
    MultLeft,
    MultRight,
    MultOut,
    Invalid(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Variable {
    pub kind: VarType,
    pub index: usize,
}

impl Variable {
    pub fn one() -> Self {
        Self {
            kind: VarType::One,
            index: 0,
        }
    }
    pub fn committed(index: usize) -> Self {
        Self {
            kind: VarType::Committed,
            index,
        }
    }
    pub fn mult_left(index: usize) -> Self {
        Self {
            kind: VarType::MultLeft,
            index,
        }
    }
    pub fn mult_right(index: usize) -> Self {
        Self {
            kind: VarType::MultRight,
            index,
        }
    }
    pub fn mult_out(index: usize) -> Self {
        Self {
            kind: VarType::MultOut,
            index,
        }
    }

    fn valid(self, gates: usize, committed: usize) -> bool {
        match self.kind {
            VarType::One => self.index == 0,
            VarType::Committed => self.index < committed,
            VarType::MultLeft | VarType::MultRight | VarType::MultOut => self.index < gates,
            VarType::Invalid(_) => false,
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct LinearCombination {
    pub terms: Vec<(Variable, Scalar)>,
}

impl LinearCombination {
    pub fn new(variable: Variable) -> Self {
        Self::with_coefficient(variable, Scalar::ONE)
    }
    pub fn with_coefficient(variable: Variable, coefficient: Scalar) -> Self {
        Self {
            terms: vec![(variable, coefficient)],
        }
    }
    pub fn scale(&self, scalar: Scalar, rule: ScalarRule) -> Self {
        Self {
            terms: self
                .terms
                .iter()
                .map(|&(variable, coefficient)| (variable, rule.mul(coefficient, scalar)))
                .collect(),
        }
    }
    pub fn plus_constant(mut self, constant: Scalar) -> Self {
        self.terms.push((Variable::one(), constant));
        self
    }
}

impl std::ops::AddAssign<&Self> for LinearCombination {
    fn add_assign(&mut self, other: &Self) {
        self.terms.extend_from_slice(&other.terms);
    }
}
impl std::ops::SubAssign<&Self> for LinearCombination {
    fn sub_assign(&mut self, other: &Self) {
        self.terms.extend(
            other
                .terms
                .iter()
                .map(|&(variable, coefficient)| (variable, -coefficient)),
        );
    }
}

#[derive(Clone)]
pub struct ConstraintSystem {
    pub num_gates: usize,
    pub num_committed: usize,
    pub constraints: Vec<LinearCombination>,
}

impl ConstraintSystem {
    pub fn padded_gates(&self) -> Result<usize, Error> {
        generators::next_power_of_2(self.num_gates.max(1))
    }
    pub fn valid(&self, padded: usize, profile: LimitProfile) -> bool {
        if padded == 0
            || padded > MAX_GATES
            || self.num_gates > MAX_GATES
            || self.num_committed > MAX_COMMITTED
            || self.constraints.len() > profile.constraint_limit()
        {
            return false;
        }
        let mut terms = 0;
        for constraint in &self.constraints {
            if constraint.terms.len() > MAX_TERMS - terms {
                return false;
            }
            terms += constraint.terms.len();
            if constraint
                .terms
                .iter()
                .any(|&(variable, _)| !variable.valid(self.num_gates, self.num_committed))
            {
                return false;
            }
        }
        true
    }
}

#[derive(Clone)]
pub struct Proof {
    pub a_i: Point,
    pub a_o: Point,
    pub s: Point,
    /// Native T_1, T_3, T_4, T_5, T_6 order.
    pub t: [Point; 5],
    pub t_x: Scalar,
    pub t_x_blinding: Scalar,
    pub e_blinding: Scalar,
    pub ipp: InnerProductProof,
    pub commitments: Vec<Point>,
}

const T_LABELS: [&[u8]; 5] = [b"T_1", b"T_3", b"T_4", b"T_5", b"T_6"];

pub(crate) fn allocate<T>(count: usize) -> Result<Vec<T>, Error> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    Ok(output)
}

fn zeros(count: usize) -> Result<Zeroizing<Vec<Scalar>>, Error> {
    let mut values = allocate(count)?;
    values.resize(count, Scalar::ZERO);
    Ok(Zeroizing::new(values))
}

// Grow into a fresh protected allocation so a reallocated witness buffer is
// erased before it is released. Reserve only while the destination is empty.
fn push_secret<T: Copy + Zeroize>(values: &mut Zeroizing<Vec<T>>, value: T) -> Result<(), Error> {
    if values.len() == values.capacity() {
        let capacity = values.len().saturating_mul(2).max(4);
        let mut replacement = Zeroizing::new(allocate(capacity)?);
        replacement.extend_from_slice(values);
        *values = replacement;
    }
    values.push(value);
    Ok(())
}

fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R, rule: ScalarRule) -> Result<Scalar, Error> {
    let mut bytes = Zeroizing::new([0; 64]);
    // Native sc_random draws eight little-endian u64s, in this order.
    for chunk in bytes.chunks_exact_mut(8) {
        rng.try_fill_bytes(chunk)
            .map_err(|_| Error("HFHE entropy unavailable"))?;
    }
    Ok(rule.reduce_bytes(&bytes))
}

fn witness_commitment(left: &[Scalar], right: &[Scalar], blind: Scalar) -> Result<Point, Error> {
    let table = generators::generators();
    let count = left.len();
    let mut scalars = Zeroizing::new(allocate(count + right.len() + 1)?);
    let mut points = allocate(count + right.len() + 1)?;
    for (index, &value) in left.iter().enumerate() {
        scalars.push(value);
        points.push(table.g(index)?);
    }
    for (index, &value) in right.iter().enumerate() {
        scalars.push(value);
        points.push(table.h(index)?);
    }
    scalars.push(blind);
    points.push(generators::pedersen_blinding());
    generators::multi_scalar_mul(&scalars, &points)
}

struct Weights {
    left: Zeroizing<Vec<Scalar>>,
    right: Zeroizing<Vec<Scalar>>,
    out: Zeroizing<Vec<Scalar>>,
    committed: Zeroizing<Vec<Scalar>>,
    constant: Scalar,
}

fn aggregate(
    constraints: &[LinearCombination],
    gates: usize,
    committed: usize,
    challenge: Scalar,
    rule: ScalarRule,
) -> Result<Weights, Error> {
    let mut output = Weights {
        left: zeros(gates)?,
        right: zeros(gates)?,
        out: zeros(gates)?,
        committed: zeros(committed)?,
        constant: Scalar::ZERO,
    };
    let mut power = Scalar::ONE;
    for constraint in constraints {
        for &(variable, coefficient) in &constraint.terms {
            let value = rule.mul(power, coefficient);
            let target = match variable.kind {
                VarType::One => Some(&mut output.constant),
                VarType::Committed => output.committed.get_mut(variable.index),
                VarType::MultLeft => output.left.get_mut(variable.index),
                VarType::MultRight => output.right.get_mut(variable.index),
                VarType::MultOut => output.out.get_mut(variable.index),
                VarType::Invalid(_) => None,
            };
            if let Some(target) = target {
                *target = *target + value;
            }
        }
        power = rule.mul(power, challenge);
    }
    Ok(output)
}

fn powers(value: Scalar, count: usize, rule: ScalarRule) -> Result<Zeroizing<Vec<Scalar>>, Error> {
    let mut output = zeros(count)?;
    if count > 0 {
        output[0] = Scalar::ONE;
    }
    for index in 1..count {
        output[index] = rule.mul(output[index - 1], value);
    }
    Ok(output)
}

fn header(
    transcript: &mut Transcript,
    gates: usize,
    committed: usize,
    constraints: usize,
    points: &[Point],
) {
    transcript.append_u64(b"n", gates as u64);
    transcript.append_u64(b"m", committed as u64);
    transcript.append_u64(b"q", constraints as u64);
    for point in points {
        transcript.append_point(b"V", point);
    }
}

fn commitment_messages(transcript: &mut Transcript, proof: &Proof) {
    transcript.append_point(b"A_I", &proof.a_i);
    transcript.append_point(b"A_O", &proof.a_o);
    transcript.append_point(b"S", &proof.s);
}

fn scalar_messages(transcript: &mut Transcript, proof: &Proof) {
    transcript.append_scalar(b"t_x", &proof.t_x);
    transcript.append_scalar(b"t_x_blinding", &proof.t_x_blinding);
    transcript.append_scalar(b"e_blinding", &proof.e_blinding);
}

fn valid_points(proof: &Proof) -> bool {
    proof.ipp.l.len() == proof.ipp.r.len()
        && [&proof.a_i, &proof.a_o, &proof.s]
            .into_iter()
            .chain(proof.t.iter())
            .chain(proof.commitments.iter())
            .chain(proof.ipp.l.iter())
            .chain(proof.ipp.r.iter())
            .all(|point| {
                curve25519_dalek::ristretto::CompressedRistretto(*point)
                    .decompress()
                    .is_some()
            })
}

/// Bind the externally expected commitments before accepting this result; the
/// native R1CS verifier only binds the commitments carried inside the proof.
pub fn verify(
    transcript: &mut Transcript,
    system: &ConstraintSystem,
    proof: &Proof,
    profile: LimitProfile,
) -> Result<bool, Error> {
    if system.num_gates > MAX_GATES {
        return Ok(false);
    }
    let Ok(count) = system.padded_gates() else {
        return Ok(false);
    };
    if !system.valid(count, profile)
        || proof.commitments.len() != system.num_committed
        || !valid_points(proof)
    {
        return Ok(false);
    }
    let rule = transcript.rule;
    header(
        transcript,
        count,
        system.num_committed,
        system.constraints.len(),
        &proof.commitments,
    );
    commitment_messages(transcript, proof);
    let y = transcript.challenge_scalar(b"y");
    let z = transcript.challenge_scalar(b"z");
    for (label, point) in T_LABELS.into_iter().zip(&proof.t) {
        transcript.append_point(label, point);
    }
    let x = transcript.challenge_scalar(b"x");
    scalar_messages(transcript, proof);
    let w = transcript.challenge_scalar(b"w");
    let x_powers = powers(x, 7, rule)?;
    let y_inverse = powers(rule.inverse(y), count, rule)?;
    let weights = aggregate(&system.constraints, count, system.num_committed, z, rule)?;
    let mut delta = Scalar::ZERO;
    for index in 0..count {
        delta = delta
            + rule.mul(
                rule.mul(y_inverse[index], weights.right[index]),
                weights.left[index],
            );
    }
    let t_left = generators::pedersen_commit(&proof.t_x, &proof.t_x_blinding);
    let mut scalars = allocate(system.num_committed + 6)?;
    let mut points = allocate(system.num_committed + 6)?;
    scalars.push(rule.mul(x_powers[2], delta - weights.constant));
    points.push(generators::pedersen_b());
    for (&weight, &point) in weights.committed.iter().zip(&proof.commitments) {
        scalars.push(-rule.mul(x_powers[2], weight));
        points.push(point);
    }
    for (&power, &point) in [
        x_powers[1],
        x_powers[3],
        x_powers[4],
        x_powers[5],
        x_powers[6],
    ]
    .iter()
    .zip(&proof.t)
    {
        scalars.push(power);
        points.push(point);
    }
    if generators::multi_scalar_mul(&scalars, &points)? != t_left {
        return Ok(false);
    }
    let q = generators::base_mul(&w);
    let table = generators::generators();
    table.precompute(count)?;
    scalars.clear();
    points.clear();
    scalars
        .try_reserve_exact(2 * count + 5)
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    points
        .try_reserve_exact(2 * count + 5)
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    for index in 0..count {
        scalars.push(rule.mul(x, rule.mul(y_inverse[index], weights.right[index])));
        points.push(table.g(index)?);
    }
    for index in 0..count {
        scalars.push(
            rule.mul(
                y_inverse[index],
                weights.out[index] + rule.mul(weights.left[index], x),
            ) - Scalar::ONE,
        );
        points.push(table.h(index)?);
    }
    scalars.extend_from_slice(&[
        x,
        x_powers[2],
        x_powers[3],
        -proof.e_blinding,
        rule.mul(proof.t_x, w),
    ]);
    points.extend_from_slice(&[
        proof.a_i,
        proof.a_o,
        proof.s,
        generators::pedersen_blinding(),
        generators::pedersen_b(),
    ]);
    let p = generators::multi_scalar_mul(&scalars, &points)?;
    inner_product::verify_with_y(transcript, &p, &q, &proof.ipp, count, &y_inverse)
}

pub struct Prover {
    rule: ScalarRule,
    witness: bool,
    committed: Zeroizing<Vec<[Scalar; 2]>>,
    gates: Zeroizing<Vec<[Scalar; 3]>>,
    constraints: Vec<LinearCombination>,
    gate_total: usize,
    committed_total: usize,
}

impl Prover {
    pub fn rule(&self) -> ScalarRule {
        self.rule
    }

    pub fn new(rule: ScalarRule) -> Self {
        Self {
            rule,
            witness: true,
            committed: Zeroizing::new(Vec::new()),
            gates: Zeroizing::new(Vec::new()),
            constraints: Vec::new(),
            gate_total: 0,
            committed_total: 0,
        }
    }
    pub fn verification(rule: ScalarRule) -> Self {
        Self {
            witness: false,
            ..Self::new(rule)
        }
    }
    pub fn num_gates(&self) -> usize {
        if self.witness {
            self.gates.len()
        } else {
            self.gate_total
        }
    }
    pub fn num_committed(&self) -> usize {
        if self.witness {
            self.committed.len()
        } else {
            self.committed_total
        }
    }
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }
    pub fn constraints(&self) -> &[LinearCombination] {
        &self.constraints
    }
    pub fn system(&self) -> ConstraintSystem {
        ConstraintSystem {
            num_gates: self.num_gates(),
            num_committed: self.num_committed(),
            constraints: self.constraints.clone(),
        }
    }

    /// Consume the builder without cloning its potentially large constraint set.
    pub fn into_system(self) -> ConstraintSystem {
        ConstraintSystem {
            num_gates: self.num_gates(),
            num_committed: self.num_committed(),
            constraints: self.constraints,
        }
    }

    pub fn commit(&mut self, value: Scalar, blind: Scalar) -> Result<Variable, Error> {
        let index = self.num_committed();
        if self.witness {
            push_secret(&mut self.committed, [value, blind])?;
        } else {
            self.committed_total += 1;
        }
        Ok(Variable::committed(index))
    }

    pub fn allocate(
        &mut self,
        left: Scalar,
        right: Scalar,
    ) -> Result<(Variable, Variable, Variable), Error> {
        let index = self.num_gates();
        if self.witness {
            push_secret(&mut self.gates, [left, right, self.rule.mul(left, right)])?;
        } else {
            self.gate_total += 1;
        }
        Ok((
            Variable::mult_left(index),
            Variable::mult_right(index),
            Variable::mult_out(index),
        ))
    }

    pub fn multiply(
        &mut self,
        left: &LinearCombination,
        right: &LinearCombination,
    ) -> Result<(Variable, Variable, Variable), Error> {
        let left_value = if self.witness {
            self.evaluate(left)?
        } else {
            Scalar::ZERO
        };
        let right_value = if self.witness {
            self.evaluate(right)?
        } else {
            Scalar::ZERO
        };
        let variables = self.allocate(left_value, right_value)?;
        let mut left = left.clone();
        left -= &LinearCombination::new(variables.0);
        let mut right = right.clone();
        right -= &LinearCombination::new(variables.1);
        self.constrain(left)?;
        self.constrain(right)?;
        Ok(variables)
    }

    pub fn constrain(&mut self, constraint: LinearCombination) -> Result<(), Error> {
        self.constraints
            .try_reserve(1)
            .map_err(|_| Error("HFHE allocation unavailable"))?;
        self.constraints.push(constraint);
        Ok(())
    }

    /// Draw proving randomness from a cryptographic RNG. Prior arithmetic is
    /// retained exactly, including native proofs that do not verify.
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        transcript: &mut Transcript,
        rng: &mut R,
        profile: LimitProfile,
    ) -> Result<Proof, Error> {
        if !self.witness {
            return Err(Error("pvac: proof witness is missing"));
        }
        if transcript.rule != self.rule {
            return Err(Error("pvac: scalar rule mismatch"));
        }
        let n = self.gates.len();
        let m = self.committed.len();
        let mut terms = 0_usize;
        for constraint in &self.constraints {
            if constraint.terms.len() > MAX_TERMS - terms {
                return Err(Error("pvac: r1cs prover limits exceeded"));
            }
            terms += constraint.terms.len();
        }
        if n > MAX_GATES || m > MAX_COMMITTED || self.constraints.len() > profile.constraint_limit()
        {
            return Err(Error("pvac: r1cs prover limits exceeded"));
        }
        let count = generators::next_power_of_2(n.max(1))?;
        let rule = self.rule;
        let mut commitments = allocate(m)?;
        for values in self.committed.iter() {
            commitments.push(generators::pedersen_commit(&values[0], &values[1]));
        }
        header(transcript, count, m, self.constraints.len(), &commitments);
        let mut a_left = zeros(count)?;
        let mut a_right = zeros(count)?;
        let mut a_out = zeros(count)?;
        for (index, values) in self.gates.iter().enumerate() {
            a_left[index] = values[0];
            a_right[index] = values[1];
            a_out[index] = values[2];
        }
        let mut s_left = zeros(count)?;
        let mut s_right = zeros(count)?;
        for index in 0..count {
            s_left[index] = random_scalar(rng, rule)?;
            s_right[index] = random_scalar(rng, rule)?;
        }
        let alpha = Zeroizing::new(random_scalar(rng, rule)?);
        let beta = Zeroizing::new(random_scalar(rng, rule)?);
        let rho = Zeroizing::new(random_scalar(rng, rule)?);
        let table = generators::generators();
        table.precompute(count)?;
        let a_i = witness_commitment(&a_left, &a_right, *alpha)?;
        let a_o = witness_commitment(&a_out, &[], *beta)?;
        let s = witness_commitment(&s_left, &s_right, *rho)?;
        transcript.append_point(b"A_I", &a_i);
        transcript.append_point(b"A_O", &a_o);
        transcript.append_point(b"S", &s);
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        let weights = aggregate(&self.constraints, count, m, z, rule)?;
        let y_powers = powers(y, count, rule)?;
        let y_inverse = powers(rule.inverse(y), count, rule)?;
        let mut l1 = zeros(count)?;
        let l2 = a_out;
        let l3 = s_left;
        let mut r0 = zeros(count)?;
        let mut r1 = zeros(count)?;
        let mut r3 = zeros(count)?;
        for index in 0..count {
            l1[index] = a_left[index] + rule.mul(y_inverse[index], weights.right[index]);
            r0[index] = weights.out[index] - y_powers[index];
            r1[index] = rule.mul(y_powers[index], a_right[index]) + weights.left[index];
            r3[index] = rule.mul(y_powers[index], s_right[index]);
        }
        drop(a_left);
        drop(a_right);
        drop(s_right);
        let inner =
            |left: &[Scalar], right: &[Scalar]| inner_product::inner_product(left, right, rule);
        let coefficients = Zeroizing::new([
            inner(&l1, &r0)?,
            inner(&l2, &r1)? + inner(&l3, &r0)?,
            inner(&l1, &r3)? + inner(&l3, &r1)?,
            inner(&l2, &r3)?,
            inner(&l3, &r3)?,
        ]);
        let mut tau = Zeroizing::new([Scalar::ZERO; 5]);
        let mut t = [[0; 32]; 5];
        for value in tau.iter_mut() {
            *value = random_scalar(rng, rule)?;
        }
        for index in 0..5 {
            t[index] = generators::pedersen_commit(&coefficients[index], &tau[index]);
        }
        for (label, point) in T_LABELS.into_iter().zip(&t) {
            transcript.append_point(label, point);
        }
        let x = transcript.challenge_scalar(b"x");
        let x2 = rule.mul(x, x);
        let x3 = rule.mul(x2, x);
        let x4 = rule.mul(x3, x);
        let x5 = rule.mul(x4, x);
        let x6 = rule.mul(x5, x);
        let mut l_eval = zeros(count)?;
        let mut r_eval = zeros(count)?;
        for index in 0..count {
            l_eval[index] =
                (rule.mul(l1[index], x) + rule.mul(l2[index], x2)) + rule.mul(l3[index], x3);
            r_eval[index] = (r0[index] + rule.mul(r1[index], x)) + rule.mul(r3[index], x3);
        }
        drop(l1);
        drop(l2);
        drop(l3);
        drop(r0);
        drop(r1);
        drop(r3);
        let t_x = inner(&l_eval, &r_eval)?;
        let mut tau_x = Zeroizing::new(rule.mul(tau[0], x));
        let mut weighted_blind = Zeroizing::new(Scalar::ZERO);
        for (weight, values) in weights.committed.iter().zip(self.committed.iter()) {
            *weighted_blind = *weighted_blind + rule.mul(*weight, values[1]);
        }
        *tau_x = *tau_x - rule.mul(*weighted_blind, x2);
        for (&blind, power) in tau[1..].iter().zip([x3, x4, x5, x6]) {
            *tau_x = *tau_x + rule.mul(blind, power);
        }
        let e_blinding = (rule.mul(x, *alpha) + rule.mul(x2, *beta)) + rule.mul(x3, *rho);
        transcript.append_scalar(b"t_x", &t_x);
        transcript.append_scalar(b"t_x_blinding", &tau_x);
        transcript.append_scalar(b"e_blinding", &e_blinding);
        let w = transcript.challenge_scalar(b"w");
        let q = generators::base_mul(&w);
        let g = table.g_vec(count)?;
        let mut h = table.h_vec(count)?;
        for (point, scalar) in h.iter_mut().zip(y_inverse.iter()) {
            *point = generators::point_mul(point, scalar)?;
        }
        let ipp = inner_product::prove(transcript, &q, l_eval, r_eval, g, h)?;
        Ok(Proof {
            a_i,
            a_o,
            s,
            t,
            t_x,
            t_x_blinding: *tau_x,
            e_blinding,
            ipp,
            commitments,
        })
    }

    fn evaluate(&self, combination: &LinearCombination) -> Result<Scalar, Error> {
        let mut output = Zeroizing::new(Scalar::ZERO);
        for &(variable, coefficient) in &combination.terms {
            let value = match variable.kind {
                VarType::One => Some(Scalar::ONE),
                VarType::Committed => self.committed.get(variable.index).map(|values| values[0]),
                VarType::MultLeft => self.gates.get(variable.index).map(|values| values[0]),
                VarType::MultRight => self.gates.get(variable.index).map(|values| values[1]),
                VarType::MultOut => self.gates.get(variable.index).map(|values| values[2]),
                VarType::Invalid(_) => None,
            }
            .ok_or(Error("HFHE proof variable index rejected"))?;
            *output = *output + self.rule.mul(coefficient, value);
        }
        Ok(*output)
    }
}
