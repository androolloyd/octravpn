// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native zero and amount relation proofs. Backend activation remains separately gated.
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use super::{
    gadgets::{self, BoundValue, Limbs, Witness, MERSENNE_P},
    generators::{self, Point},
    r1cs::{self, LimitProfile, LinearCombination as Combination, Prover, Variable},
    transcript::Transcript,
};
use crate::{
    cipher::Cipher,
    circuit_prf, decrypt,
    field::Fp,
    keys::{CircuitProfile, PublicKey, SecretKey},
    scalar::{Scalar, ScalarRule},
    Error,
};

#[derive(Clone)]
pub struct ZeroProof {
    pub proof: r1cs::Proof,
    pub is_bound: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BoundProfile {
    #[default]
    Standard,
    KeySwitchRefresh,
    HistoricalMigration,
    Range,
}

impl BoundProfile {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::Standard | Self::KeySwitchRefresh => b"pvac.verify_zero_bound.key_bound",
            Self::HistoricalMigration => b"pvac.historical_migration.bound",
            Self::Range => b"pvac.verify_zero_bound_range.key_bound",
        }
    }
    fn kind(self) -> &'static [u8] {
        match self {
            Self::Standard | Self::KeySwitchRefresh => b"bound",
            Self::HistoricalMigration => b"historical_migration",
            Self::Range => b"bound_range",
        }
    }
    fn limit_profile(self) -> LimitProfile {
        match self {
            Self::KeySwitchRefresh | Self::HistoricalMigration => LimitProfile::KeySwitchRefresh,
            _ => LimitProfile::Default,
        }
    }
    fn base_limit(self, public: &PublicKey) -> usize {
        base_layer_limit(
            public,
            matches!(self, Self::KeySwitchRefresh | Self::HistoricalMigration),
        )
    }
}

pub(crate) struct AmountBinding {
    pub amount: u64,
    pub blinding: Zeroizing<Scalar>,
    pub range_bits: usize,
}

pub(crate) struct CircuitValues<'a> {
    pub secret: &'a SecretKey,
    pub masks: &'a [Zeroizing<Vec<Fp>>],
    pub inverse: &'a [Zeroizing<Vec<Fp>>],
}

struct Slot {
    mask: Option<Witness>,
    inverse: Witness,
    limbs: Limbs,
}

type Wiring = Vec<Vec<Option<Slot>>>;

fn zero_fields(count: usize) -> Result<Vec<Fp>, Error> {
    let mut fields = r1cs::allocate(count)?;
    fields.resize(count, Fp::ZERO);
    Ok(fields)
}

pub fn layer_coefficients(public: &PublicKey, cipher: &Cipher) -> Result<Vec<Vec<Fp>>, Error> {
    let mut output = r1cs::allocate(cipher.layers.len())?;
    for _ in &cipher.layers {
        output.push(zero_fields(cipher.slots)?);
    }
    for edge in &cipher.edges {
        let row = output
            .get_mut(edge.layer_id as usize)
            .ok_or(Error("pvac: edge layer out of range"))?;
        let generator = public
            .powers
            .get(edge.idx as usize)
            .ok_or(Error("pvac: edge public-key index out of range"))?;
        if edge.weights.len() != cipher.slots {
            return Err(Error("pvac: edge weight/slots size mismatch"));
        }
        for (value, &weight) in row.iter_mut().zip(&edge.weights) {
            let term = weight * *generator;
            *value = if edge.ch == 0 {
                *value + term
            } else {
                *value - term
            };
        }
    }
    Ok(output)
}

pub fn amount_terms_present(cipher: &Cipher, coefficients: &[Vec<Fp>]) -> Result<bool, Error> {
    if cipher.slots == 0 || coefficients.len() != cipher.layers.len() {
        return Ok(false);
    }
    let mut factors = r1cs::allocate(cipher.layers.len())?;
    for layer in &cipher.layers {
        if layer.rule == 0 && !factors.contains(&layer.seed) {
            factors.push(layer.seed);
        }
    }
    let mut monomials: Vec<Vec<usize>> = r1cs::allocate(cipher.layers.len())?;
    for (index, layer) in cipher.layers.iter().enumerate() {
        let mut powers = r1cs::allocate(factors.len())?;
        powers.resize(factors.len(), 0_usize);
        if layer.rule == 0 {
            let Some(position) = factors.iter().position(|factor| *factor == layer.seed) else {
                return Ok(false);
            };
            powers[position] = 1;
        } else if layer.rule == 1 && (layer.pa as usize) < index && (layer.pb as usize) < index {
            for (factor, power) in powers.iter_mut().enumerate() {
                let Some(sum) = monomials[layer.pa as usize][factor]
                    .checked_add(monomials[layer.pb as usize][factor])
                else {
                    return Ok(false);
                };
                *power = sum;
            }
        } else {
            return Ok(false);
        }
        monomials.push(powers);
    }
    for slot in 0..cipher.slots {
        let mut terms: Vec<&[usize]> = r1cs::allocate(cipher.layers.len())?;
        let mut sums: Vec<Fp> = r1cs::allocate(cipher.layers.len())?;
        for (layer, coefficient) in coefficients.iter().enumerate() {
            if coefficient.len() != cipher.slots {
                return Ok(false);
            }
            if let Some(index) = terms
                .iter()
                .position(|term| *term == monomials[layer].as_slice())
            {
                sums[index] = sums[index] + coefficient[slot];
            } else {
                terms.push(&monomials[layer]);
                sums.push(coefficient[slot]);
            }
        }
        if sums.iter().all(|value| *value == Fp::ZERO) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn base_layer_indices(cipher: &Cipher) -> Result<Vec<usize>, Error> {
    let mut indices = r1cs::allocate(cipher.layers.len())?;
    indices.extend(
        cipher
            .layers
            .iter()
            .enumerate()
            .filter_map(|(index, layer)| (layer.rule == 0).then_some(index)),
    );
    Ok(indices)
}

pub fn base_layer_limit(public: &PublicKey, key_switch: bool) -> usize {
    match public.circuit_profile {
        1 => 8,
        2 if key_switch => 6,
        2 => 5,
        _ => 0,
    }
}

pub fn shape_ok(cipher: &Cipher, base_limit: usize) -> bool {
    if cipher.slots != 1
        || cipher.layers.is_empty()
        || cipher.layers.len() > 16
        || cipher.edges.len() > 4096
    {
        return false;
    }
    let mut bases = 0;
    for layer in &cipher.layers {
        match layer.rule {
            0 => bases += 1,
            1 => (),
            _ => return false,
        }
    }
    bases > 0 && bases <= base_limit
}

fn profile(public: &PublicKey) -> Result<CircuitProfile, Error> {
    match public.circuit_profile {
        1 => Ok(CircuitProfile::MimcX3V6),
        2 => Ok(CircuitProfile::MimcX5V7),
        _ => Err(Error("pvac: circuit prf profile rejected")),
    }
}

pub(crate) fn append_context(
    transcript: &mut Transcript,
    public: &PublicKey,
    cipher: &Cipher,
    kind: &[u8],
    amount: Option<&Point>,
) -> Result<(), Error> {
    let profile = profile(public)?;
    transcript.append_message(
        b"proof_version",
        circuit_prf::proof_version(profile).as_bytes(),
    );
    transcript.append_message(b"proof_kind", kind);
    if profile == CircuitProfile::MimcX5V7 {
        transcript.append_u64(b"circuit_prf_profile", u64::from(public.circuit_profile));
    }
    transcript.append_point(b"registered_key_commitment", &public.circuit_commit);
    transcript.append_message(b"commit_ct", &cipher.commitment(public));
    if let Some(amount) = amount {
        transcript.append_point(b"amount_commitment", amount);
    }
    Ok(())
}

fn circuit_shape(cipher: &Cipher, coefficients: &[Vec<Fp>], bound: bool) -> Result<(), Error> {
    if coefficients.len() != cipher.layers.len() {
        return Err(Error("pvac: coefficient/layer size mismatch"));
    }
    for (index, (layer, coefficients)) in cipher.layers.iter().zip(coefficients).enumerate() {
        if coefficients.len() != cipher.slots {
            return Err(Error("pvac: coefficient/slots size mismatch"));
        }
        if layer.rule == 1 && (layer.pa as usize >= index || layer.pb as usize >= index) {
            return Err(Error("pvac: invalid product parent"));
        }
        if layer.rule == 1 && (!layer.pc.is_empty() || (bound && !layer.r_pc.is_empty())) {
            return Err(Error(if bound {
                "pvac: product layer must not contain proof commitments"
            } else {
                "pvac: product layer must not contain PC"
            }));
        }
        if layer.rule > 1 {
            return Err(Error("pvac: invalid layer rule"));
        }
    }
    Ok(())
}

fn wiring(cipher: &Cipher) -> Result<Wiring, Error> {
    let mut rows = r1cs::allocate(cipher.layers.len())?;
    for _ in &cipher.layers {
        let mut row = r1cs::allocate(cipher.slots)?;
        row.resize_with(cipher.slots, || None);
        rows.push(row);
    }
    Ok(rows)
}

fn get_slot(wiring: &Wiring, layer: usize, slot: usize) -> Result<&Slot, Error> {
    wiring
        .get(layer)
        .and_then(|row| row.get(slot))
        .and_then(Option::as_ref)
        .ok_or(Error("HFHE proof layer wiring rejected"))
}

fn get_value(
    values: Option<&[Zeroizing<Vec<Fp>>]>,
    layer: usize,
    slot: usize,
) -> Result<Fp, Error> {
    values.map_or(Ok(Fp::ZERO), |values| {
        values
            .get(layer)
            .and_then(|row| row.get(slot))
            .copied()
            .ok_or(Error("HFHE proof witness shape rejected"))
    })
}

fn final_constraints(
    prover: &mut Prover,
    cipher: &Cipher,
    coefficients: &[Vec<Fp>],
    wiring: &Wiring,
    amount: Option<&AmountBinding>,
    check_range: bool,
) -> Result<(), Error> {
    let amount_scalar = Zeroizing::new(Scalar::from_u64(amount.map_or(0, |value| value.amount)));
    let amount_var = if let Some(amount) = amount {
        let variable = prover.commit(*amount_scalar, *amount.blinding)?;
        if check_range && amount.range_bits > 0 {
            gadgets::range_check(prover, variable, *amount_scalar, amount.range_bits)?;
        }
        Some(variable)
    } else {
        None
    };
    for slot in 0..cipher.slots {
        let constant = if cipher.c0.is_empty() {
            Fp::ZERO
        } else {
            *cipher
                .c0
                .get(slot)
                .ok_or(Error("HFHE proof constant shape rejected"))?
        };
        let constant_scalar = Scalar::from_fp(constant);
        let mut combination = Combination::default();
        if constant != Fp::ZERO {
            combination += &Combination::with_coefficient(Variable::one(), constant_scalar);
        }
        if let Some(variable) = amount_var {
            combination -= &Combination::new(variable);
        }
        let mut total = Zeroizing::new(if amount.is_some() {
            constant_scalar - *amount_scalar
        } else {
            constant_scalar
        });
        for (layer, coefficients) in coefficients.iter().enumerate() {
            if coefficients[slot] == Fp::ZERO {
                continue;
            }
            let folded = gadgets::multiply_constant_folded(
                coefficients[slot],
                &get_slot(wiring, layer, slot)?.limbs,
                prover.rule(),
            );
            combination += &folded.combination;
            *total = *total + *folded.value;
        }
        let quotient = Zeroizing::new(prover.rule().mul(*total, prover.rule().inverse(MERSENNE_P)));
        let (variable, _, _) = prover.allocate(*quotient, Scalar::ONE)?;
        let (_, _, product) = prover.multiply(
            &Combination::new(variable),
            &Combination::with_coefficient(Variable::one(), MERSENNE_P),
        )?;
        let mut relation = Combination::new(product);
        relation -= &combination;
        prover.constrain(relation)?;
        gadgets::range_check(prover, variable, *quotient, 73)?;
    }
    Ok(())
}

pub(crate) fn build_legacy_circuit(
    prover: &mut Prover,
    cipher: &Cipher,
    coefficients: &[Vec<Fp>],
    bases: &[usize],
    values: Option<&CircuitValues<'_>>,
    amount: Option<&AmountBinding>,
    strict_amount: bool,
) -> Result<(), Error> {
    circuit_shape(cipher, coefficients, false)?;
    if amount.is_some() && strict_amount && !amount_terms_present(cipher, coefficients)? {
        return Err(Error("pvac: amount relation has no layer term"));
    }
    let mut wiring = wiring(cipher)?;
    for &layer in bases {
        let base = cipher
            .layers
            .get(layer)
            .ok_or(Error("HFHE proof base layer rejected"))?;
        for (slot, destination) in wiring[layer].iter_mut().enumerate() {
            let inverse =
                Zeroizing::new(get_value(values.map(|values| values.inverse), layer, slot)?);
            let signed = Zeroizing::new(if values.is_some() {
                Scalar::from_fp_signed(*inverse)
            } else {
                Scalar::ZERO
            });
            let blind = Zeroizing::new(values.map_or(Scalar::ZERO, |values| {
                Scalar::from_bytes_raw(&circuit_prf::rho(values.secret, base.seed.nonce, slot))
            }));
            let committed = prover.commit(*signed, *blind)?;
            let BoundValue { value, limbs } =
                gadgets::bind_commitment_value(prover, committed, *inverse, false)?;
            *destination = Some(Slot {
                mask: None,
                inverse: value,
                limbs,
            });
        }
    }
    for (index, layer) in cipher.layers.iter().enumerate() {
        if layer.rule != 1 {
            continue;
        }
        for slot in 0..cipher.slots {
            let left = get_slot(&wiring, layer.pa as usize, slot)?.inverse.pair();
            let right = get_slot(&wiring, layer.pb as usize, slot)?.inverse.pair();
            let value = gadgets::multiply(prover, left, right, false)?;
            let limbs = gadgets::decompose(prover, value.variable, *value.value, false)?;
            wiring[index][slot] = Some(Slot {
                mask: None,
                inverse: value,
                limbs,
            });
        }
    }
    final_constraints(prover, cipher, coefficients, &wiring, amount, false)
}

struct CircuitState {
    combination: Combination,
    value: Zeroizing<Scalar>,
    field: Zeroizing<Fp>,
}

fn add_key_constant(
    prover: &mut Prover,
    key: &BoundValue,
    key_field: Fp,
    state: &CircuitState,
    constant: Fp,
    existing: Option<&Witness>,
) -> Result<Witness, Error> {
    let output = Zeroizing::new(existing.map_or_else(
        || Scalar::from_fp((*state.field + key_field) + constant),
        |existing| *existing.value,
    ));
    let variable = if let Some(existing) = existing {
        existing.variable
    } else {
        let (variable, one, _) = prover.allocate(*output, Scalar::ONE)?;
        let mut relation = Combination::new(one);
        relation -= &Combination::new(Variable::one());
        prover.constrain(relation)?;
        variable
    };
    let constant_scalar = Scalar::from_fp(constant);
    let total = Zeroizing::new(((*state.value + *key.value.value) + constant_scalar) - *output);
    let quotient = Zeroizing::new(prover.rule().mul(*total, prover.rule().inverse(MERSENNE_P)));
    let (quotient_var, _, _) = prover.allocate(*quotient, Scalar::ONE)?;
    let (_, _, product) = prover.multiply(
        &Combination::new(quotient_var),
        &Combination::with_coefficient(Variable::one(), MERSENNE_P),
    )?;
    let mut relation = state.combination.clone();
    relation += &Combination::new(key.value.variable);
    relation += &Combination::with_coefficient(Variable::one(), constant_scalar);
    relation -= &Combination::new(variable);
    relation -= &Combination::new(product);
    prover.constrain(relation)?;
    gadgets::range_check(prover, quotient_var, *quotient, 3)?;
    Ok(Witness {
        variable,
        value: output,
    })
}

#[allow(clippy::too_many_arguments)] // Native circuit controls are kept explicit.
pub(crate) fn build_key_bound_circuit(
    prover: &mut Prover,
    public: &PublicKey,
    cipher: &Cipher,
    coefficients: &[Vec<Fp>],
    bases: &[usize],
    values: Option<&CircuitValues<'_>>,
    amount: Option<&AmountBinding>,
    force_alias_rejection: bool,
    strict_amount: bool,
) -> Result<(), Error> {
    let profile = profile(public)?;
    let reject_aliases = force_alias_rejection || profile == CircuitProfile::MimcX5V7;
    circuit_shape(cipher, coefficients, true)?;
    if amount.is_some() && strict_amount && !amount_terms_present(cipher, coefficients)? {
        return Err(Error("pvac: amount relation has no layer term"));
    }
    let mut wiring = wiring(cipher)?;
    let key_field = Zeroizing::new(values.map_or(Fp::ZERO, |values| match profile {
        CircuitProfile::MimcX3V6 => values.secret.circuit_key_v6,
        CircuitProfile::MimcX5V7 => values.secret.circuit_key,
    }));
    let key_signed =
        Zeroizing::new(values.map_or(Scalar::ZERO, |_| Scalar::from_fp_signed(*key_field)));
    let key_blind = Zeroizing::new(values.map_or(Scalar::ZERO, |values| {
        ScalarRule::Prior.reduce256(match profile {
            CircuitProfile::MimcX3V6 => &values.secret.circuit_blind_v6,
            CircuitProfile::MimcX5V7 => &values.secret.circuit_blind,
        })
    }));
    let key_committed = prover.commit(*key_signed, *key_blind)?;
    let key = gadgets::bind_commitment_value(prover, key_committed, *key_field, reject_aliases)?;
    for &layer in bases {
        let base = cipher
            .layers
            .get(layer)
            .ok_or(Error("HFHE proof base layer rejected"))?;
        for (slot, destination) in wiring[layer].iter_mut().enumerate() {
            let mask = Zeroizing::new(get_value(values.map(|values| values.masks), layer, slot)?);
            let inverse =
                Zeroizing::new(get_value(values.map(|values| values.inverse), layer, slot)?);
            let mask_signed =
                Zeroizing::new(values.map_or(Scalar::ZERO, |_| Scalar::from_fp_signed(*mask)));
            let inverse_signed =
                Zeroizing::new(values.map_or(Scalar::ZERO, |_| Scalar::from_fp_signed(*inverse)));
            let alpha = Zeroizing::new(values.map_or(Scalar::ZERO, |values| {
                Scalar::from_bytes_raw(&circuit_prf::r_alpha(values.secret, base.seed.nonce, slot))
            }));
            let rho = Zeroizing::new(values.map_or(Scalar::ZERO, |values| {
                Scalar::from_bytes_raw(&circuit_prf::rho(values.secret, base.seed.nonce, slot))
            }));
            let mask_committed = prover.commit(*mask_signed, *alpha)?;
            let inverse_committed = prover.commit(*inverse_signed, *rho)?;
            let mask_bound =
                gadgets::bind_commitment_value(prover, mask_committed, *mask, reject_aliases)?;
            let inverse_bound = gadgets::bind_commitment_value(
                prover,
                inverse_committed,
                *inverse,
                reject_aliases,
            )?;
            let field = Zeroizing::new(circuit_prf::challenge(
                public,
                base.seed.ztag,
                base.seed.nonce,
                slot,
            )?);
            let value = Zeroizing::new(Scalar::from_fp(*field));
            let mut state = CircuitState {
                combination: Combination::with_coefficient(Variable::one(), *value),
                value,
                field,
            };
            for round in 0..circuit_prf::ROUNDS {
                let constant = circuit_prf::round_constant(profile, round);
                let intermediate_field = Zeroizing::new((*state.field + *key_field) + constant);
                let intermediate =
                    add_key_constant(prover, &key, *key_field, &state, constant, None)?;
                let power = match profile {
                    CircuitProfile::MimcX3V6 => {
                        gadgets::cube(prover, intermediate.pair(), reject_aliases)?
                    }
                    CircuitProfile::MimcX5V7 => {
                        gadgets::fifth(prover, intermediate.pair(), reject_aliases)?
                    }
                };
                state = CircuitState {
                    combination: Combination::new(power.variable),
                    value: power.value,
                    field: Zeroizing::new(circuit_prf::power(profile, *intermediate_field)),
                };
            }
            add_key_constant(
                prover,
                &key,
                *key_field,
                &state,
                Fp::ONE,
                Some(&mask_bound.value),
            )?;
            let product = gadgets::multiply(
                prover,
                mask_bound.value.pair(),
                inverse_bound.value.pair(),
                reject_aliases,
            )?;
            let mut relation = Combination::new(product.variable);
            relation -= &Combination::new(Variable::one());
            prover.constrain(relation)?;
            *destination = Some(Slot {
                mask: Some(mask_bound.value),
                inverse: inverse_bound.value,
                limbs: inverse_bound.limbs,
            });
        }
    }
    for (index, layer) in cipher.layers.iter().enumerate() {
        if layer.rule != 1 {
            continue;
        }
        for slot in 0..cipher.slots {
            let left = get_slot(&wiring, layer.pa as usize, slot)?;
            let right = get_slot(&wiring, layer.pb as usize, slot)?;
            let mask = gadgets::multiply(
                prover,
                left.mask
                    .as_ref()
                    .ok_or(Error("HFHE proof mask wiring rejected"))?
                    .pair(),
                right
                    .mask
                    .as_ref()
                    .ok_or(Error("HFHE proof mask wiring rejected"))?
                    .pair(),
                reject_aliases,
            )?;
            let inverse = gadgets::multiply(
                prover,
                left.inverse.pair(),
                right.inverse.pair(),
                reject_aliases,
            )?;
            let product = gadgets::multiply(prover, mask.pair(), inverse.pair(), reject_aliases)?;
            let mut relation = Combination::new(product.variable);
            relation -= &Combination::new(Variable::one());
            prover.constrain(relation)?;
            let limbs =
                gadgets::decompose(prover, inverse.variable, *inverse.value, reject_aliases)?;
            wiring[index][slot] = Some(Slot {
                mask: Some(mask),
                inverse,
                limbs,
            });
        }
    }
    final_constraints(prover, cipher, coefficients, &wiring, amount, true)
}

fn transcript(
    domain: &[u8],
    public: &PublicKey,
    cipher: &Cipher,
    bases: &[usize],
    rule: ScalarRule,
    kind: &[u8],
    amount: Option<&Point>,
) -> Result<Transcript, Error> {
    let mut transcript = Transcript::new(domain, rule);
    transcript.append_u64(b"nL", cipher.layers.len() as u64);
    transcript.append_u64(b"S", cipher.slots as u64);
    transcript.append_u64(b"nB", bases.len() as u64);
    append_context(&mut transcript, public, cipher, kind, amount)?;
    Ok(transcript)
}

pub(crate) fn inverse_masks(
    masks: &[Zeroizing<Vec<Fp>>],
) -> Result<Vec<Zeroizing<Vec<Fp>>>, Error> {
    let mut output = r1cs::allocate(masks.len())?;
    for row in masks {
        let mut inverse = Zeroizing::new(r1cs::allocate(row.len())?);
        inverse.extend(row.iter().map(|value| value.inverse()));
        output.push(inverse);
    }
    Ok(output)
}

pub(crate) fn masks(
    public: &PublicKey,
    secret: &SecretKey,
    cipher: &Cipher,
) -> Result<Vec<Zeroizing<Vec<Fp>>>, Error> {
    // Imported Cipher values already enforce parent ordering. Keep this check
    // for future internal constructors before entering the indexed evaluator.
    for (index, layer) in cipher.layers.iter().enumerate() {
        if layer.rule == 1 && (layer.pa as usize >= index || layer.pb as usize >= index) {
            return Err(Error("pvac: invalid product parent"));
        }
    }
    decrypt::layer_masks(public, secret, cipher, decrypt::DecPolicy::Standard)
}

pub fn make_zero<R: RngCore + CryptoRng>(
    public: &PublicKey,
    secret: &SecretKey,
    cipher: &Cipher,
    rule: ScalarRule,
    rng: &mut R,
) -> Result<ZeroProof, Error> {
    if !shape_ok(cipher, base_layer_limit(public, false)) {
        return Err(Error("pvac: key-bound proof shape rejected"));
    }
    let masks = masks(public, secret, cipher)?;
    let inverse = inverse_masks(&masks)?;
    let coefficients = layer_coefficients(public, cipher)?;
    let bases = base_layer_indices(cipher)?;
    let values = CircuitValues {
        secret,
        masks: &masks,
        inverse: &inverse,
    };
    let mut prover = Prover::new(rule);
    build_key_bound_circuit(
        &mut prover,
        public,
        cipher,
        &coefficients,
        &bases,
        Some(&values),
        None,
        false,
        true,
    )?;
    let mut transcript = transcript(
        b"pvac.verify_zero.key_bound",
        public,
        cipher,
        &bases,
        rule,
        b"zero",
        None,
    )?;
    Ok(ZeroProof {
        proof: prover.prove(&mut transcript, rng, LimitProfile::Default)?,
        is_bound: false,
    })
}

#[allow(clippy::too_many_arguments)] // Amount, profile, arithmetic and entropy are independent native inputs.
pub fn make_bound<R: RngCore + CryptoRng>(
    public: &PublicKey,
    secret: &SecretKey,
    cipher: &Cipher,
    amount: u64,
    blinding: Scalar,
    profile: BoundProfile,
    rule: ScalarRule,
    rng: &mut R,
) -> Result<ZeroProof, Error> {
    if profile == BoundProfile::HistoricalMigration && public.circuit_profile != 1 {
        return Err(Error(
            "pvac: historical migration requires historical proof profile",
        ));
    }
    if !shape_ok(cipher, profile.base_limit(public)) {
        return Err(Error("pvac: key-bound proof shape rejected"));
    }
    let coefficients = layer_coefficients(public, cipher)?;
    if !amount_terms_present(cipher, &coefficients)? {
        return Err(Error("pvac: amount relation has no layer term"));
    }
    let masks = masks(public, secret, cipher)?;
    let inverse = inverse_masks(&masks)?;
    let bases = base_layer_indices(cipher)?;
    let values = CircuitValues {
        secret,
        masks: &masks,
        inverse: &inverse,
    };
    let binding = AmountBinding {
        amount,
        blinding: Zeroizing::new(blinding),
        range_bits: if profile == BoundProfile::Range {
            64
        } else {
            0
        },
    };
    let mut prover = Prover::new(rule);
    build_key_bound_circuit(
        &mut prover,
        public,
        cipher,
        &coefficients,
        &bases,
        Some(&values),
        Some(&binding),
        profile == BoundProfile::HistoricalMigration,
        true,
    )?;
    let commitment = generators::pedersen_commit(&Scalar::from_u64(amount), &binding.blinding);
    let mut transcript = transcript(
        profile.domain(),
        public,
        cipher,
        &bases,
        rule,
        profile.kind(),
        Some(&commitment),
    )?;
    Ok(ZeroProof {
        proof: prover.prove(&mut transcript, rng, profile.limit_profile())?,
        is_bound: true,
    })
}

fn commitments_match(
    public: &PublicKey,
    cipher: &Cipher,
    bases: &[usize],
    proof: &ZeroProof,
    amount: Option<&Point>,
) -> bool {
    let expected = 1 + bases.len() * cipher.slots * 2;
    if proof.proof.commitments.len() != expected + usize::from(amount.is_some())
        || proof.proof.commitments[0] != public.circuit_commit
    {
        return false;
    }
    for (base, &layer) in bases.iter().enumerate() {
        let layer = &cipher.layers[layer];
        if layer.r_pc.len() != cipher.slots || layer.pc.len() != cipher.slots {
            return false;
        }
        for slot in 0..cipher.slots {
            let index = 1 + 2 * (base * cipher.slots + slot);
            if proof.proof.commitments[index] != layer.r_pc[slot]
                || proof.proof.commitments[index + 1] != layer.pc[slot]
            {
                return false;
            }
        }
    }
    amount.is_none_or(|amount| proof.proof.commitments[expected] == *amount)
}

pub fn verify_zero(
    public: &PublicKey,
    cipher: &Cipher,
    proof: &ZeroProof,
    rule: ScalarRule,
) -> Result<bool, Error> {
    if !cipher.compatible_with(public)
        || !shape_ok(cipher, base_layer_limit(public, false))
        || public.circuit_commit == [0; 32]
    {
        return Ok(false);
    }
    let bases = base_layer_indices(cipher)?;
    if !commitments_match(public, cipher, &bases, proof, None) {
        return Ok(false);
    }
    let coefficients = layer_coefficients(public, cipher)?;
    let mut prover = Prover::verification(rule);
    build_key_bound_circuit(
        &mut prover,
        public,
        cipher,
        &coefficients,
        &bases,
        None,
        None,
        false,
        true,
    )?;
    let mut transcript = transcript(
        b"pvac.verify_zero.key_bound",
        public,
        cipher,
        &bases,
        rule,
        b"zero",
        None,
    )?;
    r1cs::verify(
        &mut transcript,
        &prover.into_system(),
        &proof.proof,
        LimitProfile::Default,
    )
}

/// `strict_amount = false` preserves native historical amount verification.
/// Callers must select that compatibility policy explicitly.
pub fn verify_bound(
    public: &PublicKey,
    cipher: &Cipher,
    proof: &ZeroProof,
    amount: &Point,
    profile: BoundProfile,
    strict_amount: bool,
    rule: ScalarRule,
) -> Result<bool, Error> {
    if profile == BoundProfile::HistoricalMigration && public.circuit_profile != 1 {
        return Ok(false);
    }
    if !cipher.compatible_with(public)
        || !shape_ok(cipher, profile.base_limit(public))
        || public.circuit_commit == [0; 32]
    {
        return Ok(false);
    }
    let coefficients = layer_coefficients(public, cipher)?;
    if strict_amount && !amount_terms_present(cipher, &coefficients)? {
        return Ok(false);
    }
    let bases = base_layer_indices(cipher)?;
    if !commitments_match(public, cipher, &bases, proof, Some(amount)) {
        return Ok(false);
    }
    let binding = AmountBinding {
        amount: 0,
        blinding: Zeroizing::new(Scalar::ZERO),
        range_bits: if profile == BoundProfile::Range {
            64
        } else {
            0
        },
    };
    let mut prover = Prover::verification(rule);
    build_key_bound_circuit(
        &mut prover,
        public,
        cipher,
        &coefficients,
        &bases,
        None,
        Some(&binding),
        profile == BoundProfile::HistoricalMigration,
        strict_amount,
    )?;
    let mut transcript = transcript(
        profile.domain(),
        public,
        cipher,
        &bases,
        rule,
        profile.kind(),
        Some(amount),
    )?;
    r1cs::verify(
        &mut transcript,
        &prover.into_system(),
        &proof.proof,
        profile.limit_profile(),
    )
}

pub fn verify_embedded_range(
    public: &PublicKey,
    cipher: &Cipher,
    proof: &ZeroProof,
    strict_amount: bool,
    rule: ScalarRule,
) -> Result<bool, Error> {
    if !cipher.compatible_with(public) || !shape_ok(cipher, base_layer_limit(public, false)) {
        return Ok(false);
    }
    let bases = base_layer_indices(cipher)?;
    let index = 1 + bases.len() * cipher.slots * 2;
    if proof.proof.commitments.len() != index + 1 {
        return Ok(false);
    }
    verify_bound(
        public,
        cipher,
        proof,
        &proof.proof.commitments[index],
        BoundProfile::Range,
        strict_amount,
        rule,
    )
}

#[cfg(test)]
#[path = "zero_tests.rs"]
mod tests;
