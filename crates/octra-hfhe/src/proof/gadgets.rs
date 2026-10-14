// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Exact native R1CS constraints for bit ranges and Mersenne-field arithmetic.
use zeroize::Zeroizing;

use super::r1cs::{LinearCombination as Combination, Prover, Variable};
use crate::{
    field::Fp,
    scalar::{Scalar, ScalarRule},
    Error,
};

pub const POW2_64: Scalar = Scalar::from_words([0, 1, 0, 0]);
pub const MERSENNE_P: Scalar = Scalar::from_words([u64::MAX, 0x7fff_ffff_ffff_ffff, 0, 0]);

pub struct Witness {
    pub variable: Variable,
    pub value: Zeroizing<Scalar>,
}
impl Witness {
    pub fn pair(&self) -> (Variable, Scalar) {
        (self.variable, *self.value)
    }
}

pub struct Limbs {
    pub variables: [Variable; 2],
    pub values: Zeroizing<[Scalar; 2]>,
}

pub struct BoundValue {
    pub value: Witness,
    pub limbs: Limbs,
}

pub struct FoldedTerm {
    pub combination: Combination,
    pub value: Zeroizing<Scalar>,
}

pub fn range_check(
    prover: &mut Prover,
    variable: Variable,
    value: Scalar,
    bits: usize,
) -> Result<(), Error> {
    // Native asserts this precondition; reject it without aborting the host.
    if bits == 0 || bits > 252 {
        return Err(Error("HFHE range gadget bits rejected"));
    }
    let words = Zeroizing::new(value.to_words());
    let mut reconstruction = Combination::default();
    let mut power = Scalar::ONE;
    for bit in 0..bits {
        let value = Zeroizing::new(Scalar::from_u64((words[bit / 64] >> (bit % 64)) & 1));
        let (left, right, out) = prover.allocate(*value, Scalar::ONE - *value)?;
        prover.constrain(Combination::new(out))?;
        let mut sum = Combination::new(left);
        sum += &Combination::new(right);
        sum -= &Combination::new(Variable::one());
        prover.constrain(sum)?;
        reconstruction += &Combination::with_coefficient(left, power);
        power = prover.rule().mul(power, Scalar::from_u64(2));
    }
    reconstruction -= &Combination::new(variable);
    prover.constrain(reconstruction)
}

pub fn reject_modulus_alias(
    prover: &mut Prover,
    variable: Variable,
    value: Scalar,
) -> Result<(), Error> {
    let delta = Zeroizing::new(MERSENNE_P - value);
    let inverse = Zeroizing::new(prover.rule().inverse(*delta));
    let (delta_var, _, product) = prover.allocate(*delta, *inverse)?;
    let mut relation = Combination::new(delta_var);
    relation += &Combination::new(variable);
    relation -= &Combination::with_coefficient(Variable::one(), MERSENNE_P);
    prover.constrain(relation)?;
    let mut relation = Combination::new(product);
    relation -= &Combination::new(Variable::one());
    prover.constrain(relation)
}

pub fn decompose(
    prover: &mut Prover,
    variable: Variable,
    value: Scalar,
    canonical: bool,
) -> Result<Limbs, Error> {
    let words = Zeroizing::new(value.to_words());
    let values = Zeroizing::new([Scalar::from_u64(words[0]), Scalar::from_u64(words[1])]);
    let (low, _, _) = prover.allocate(values[0], Scalar::ONE)?;
    let (high, _, _) = prover.allocate(values[1], Scalar::ONE)?;
    let mut relation = Combination::new(low);
    relation += &Combination::with_coefficient(high, POW2_64);
    relation -= &Combination::new(variable);
    prover.constrain(relation)?;
    range_check(prover, low, values[0], 64)?;
    range_check(prover, high, values[1], 63)?;
    if canonical {
        reject_modulus_alias(prover, variable, value)?;
    }
    Ok(Limbs {
        variables: [low, high],
        values,
    })
}

pub fn multiply(
    prover: &mut Prover,
    left: (Variable, Scalar),
    right: (Variable, Scalar),
    canonical: bool,
) -> Result<Witness, Error> {
    let rule = prover.rule();
    let left_limbs = decompose(prover, left.0, left.1, canonical)?;
    let right_limbs = decompose(prover, right.0, right.1, canonical)?;
    let mut products = Zeroizing::new([Scalar::ZERO; 4]);
    let mut variables = [Variable::one(); 4];
    for (index, (left, right)) in [(0, 0), (0, 1), (1, 0), (1, 1)].into_iter().enumerate() {
        variables[index] = prover
            .multiply(
                &Combination::new(left_limbs.variables[left]),
                &Combination::new(right_limbs.variables[right]),
            )?
            .2;
        products[index] = rule.mul(left_limbs.values[left], right_limbs.values[right]);
    }
    let two = Scalar::from_u64(2);
    let folded = Zeroizing::new(
        (products[0] + rule.mul(POW2_64, products[1] + products[2])) + rule.mul(two, products[3]),
    );
    let left_words = Zeroizing::new(left.1.to_words());
    let right_words = Zeroizing::new(right.1.to_words());
    let output = Zeroizing::new(Scalar::from_fp(
        Fp::from_words(left_words[0], left_words[1])
            * Fp::from_words(right_words[0], right_words[1]),
    ));
    let quotient = Zeroizing::new(rule.mul(*folded - *output, rule.inverse(MERSENNE_P)));
    let (output_var, _, _) = prover.allocate(*output, Scalar::ONE)?;
    let (quotient_var, _, _) = prover.allocate(*quotient, Scalar::ONE)?;
    let (_, _, multiple) = prover.multiply(
        &Combination::new(quotient_var),
        &Combination::with_coefficient(Variable::one(), MERSENNE_P),
    )?;
    let mut relation = Combination::new(multiple);
    for (&variable, coefficient) in variables.iter().zip([Scalar::ONE, POW2_64, POW2_64, two]) {
        relation -= &Combination::with_coefficient(variable, coefficient);
    }
    relation += &Combination::new(output_var);
    prover.constrain(relation)?;
    range_check(prover, output_var, *output, 127)?;
    if canonical {
        reject_modulus_alias(prover, output_var, *output)?;
    }
    range_check(prover, quotient_var, *quotient, 66)?;
    Ok(Witness {
        variable: output_var,
        value: output,
    })
}

pub fn cube(
    prover: &mut Prover,
    input: (Variable, Scalar),
    canonical: bool,
) -> Result<Witness, Error> {
    let square = multiply(prover, input, input, canonical)?;
    multiply(prover, square.pair(), input, canonical)
}

pub fn fifth(
    prover: &mut Prover,
    input: (Variable, Scalar),
    canonical: bool,
) -> Result<Witness, Error> {
    let square = multiply(prover, input, input, canonical)?;
    let fourth = multiply(prover, square.pair(), square.pair(), canonical)?;
    multiply(prover, fourth.pair(), input, canonical)
}

pub fn bind_commitment_value(
    prover: &mut Prover,
    signed: Variable,
    value: Fp,
    canonical: bool,
) -> Result<BoundValue, Error> {
    let scalar = Zeroizing::new(Scalar::from_fp(value));
    let high = Zeroizing::new(Scalar::from_u64((value.words().1 >> 62) & 1));
    let (left, right, out) = prover.allocate(*high, Scalar::ONE - *high)?;
    prover.constrain(Combination::new(out))?;
    let mut sum = Combination::new(left);
    sum += &Combination::new(right);
    sum -= &Combination::new(Variable::one());
    prover.constrain(sum)?;
    let (variable, _, _) = prover.allocate(*scalar, Scalar::ONE)?;
    let mut relation = Combination::new(variable);
    relation -= &Combination::new(signed);
    relation -= &Combination::with_coefficient(left, MERSENNE_P);
    prover.constrain(relation)?;
    let limbs = decompose(prover, variable, *scalar, canonical)?;
    Ok(BoundValue {
        value: Witness {
            variable,
            value: scalar,
        },
        limbs,
    })
}

pub fn multiply_constant_folded(constant: Fp, limbs: &Limbs, rule: ScalarRule) -> FoldedTerm {
    let words = constant.words();
    let low = Scalar::from_u64(words.0);
    let high = Scalar::from_u64(words.1);
    let two = Scalar::from_u64(2);
    let coefficients = [
        low,
        rule.mul(POW2_64, low),
        rule.mul(POW2_64, high),
        rule.mul(two, high),
    ];
    let mut combination = Combination::default();
    for (index, coefficient) in [0, 1, 0, 1].into_iter().zip(coefficients) {
        combination += &Combination::with_coefficient(limbs.variables[index], coefficient);
    }
    let value = (rule.mul(low, limbs.values[0])
        + rule.mul(rule.mul(POW2_64, low), limbs.values[1]))
        + (rule.mul(rule.mul(POW2_64, high), limbs.values[0])
            + rule.mul(rule.mul(two, high), limbs.values[1]));
    FoldedTerm {
        combination,
        value: Zeroizing::new(value),
    }
}
