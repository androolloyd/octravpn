// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native legacy range proof composition. The native aggregated verifier is disabled.
use super::{
    r1cs::{self, LimitProfile, Prover},
    transcript::Transcript,
    zero::{self, CircuitValues, ZeroProof},
};
use crate::{
    cipher::Cipher,
    encrypt,
    field::Fp,
    keys::{PublicKey, SecretKey},
    scalar::ScalarRule,
    Error,
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

pub const RANGE_BITS: usize = 64;
pub const MAX_VALUE_LAYERS: usize = 512;
pub const MAX_VALUE_EDGES: usize = 65536;
pub const MAX_BIT_LAYERS: usize = 4;
pub const MAX_BIT_EDGES: usize = 8192;

#[derive(Clone)]
pub struct RangeProof {
    pub ct_bit: Vec<Cipher>,
    pub bit_proofs: Vec<ZeroProof>,
    pub lc_proof: ZeroProof,
}
#[derive(Clone)]
pub struct AggregatedRangeProof {
    pub ct_bit: Vec<Cipher>,
    pub proof: r1cs::Proof,
}

pub fn value_cipher_ok(public: &PublicKey, cipher: &Cipher) -> bool {
    cipher.compatible_with(public)
        && cipher.slots == 1
        && cipher.layers.len() <= MAX_VALUE_LAYERS
        && cipher.edges.len() <= MAX_VALUE_EDGES
}
pub fn bit_cipher_ok(public: &PublicKey, cipher: &Cipher, slots: usize) -> bool {
    cipher.compatible_with(public)
        && cipher.slots == slots
        && cipher.layers.len() <= MAX_BIT_LAYERS
        && cipher.edges.len() <= MAX_BIT_EDGES
}
fn index_count_ok(public: &PublicKey) -> bool {
    public.params.basis >= 8
}
fn bit_check(
    public: &PublicKey,
    cipher: &Cipher,
    index: usize,
    math: bool,
) -> Result<Cipher, Error> {
    let minus_one = cipher.subtract_constant(Fp::ONE, math)?;
    let seed = std::array::from_fn(|k| ((index * 37 + k * 13 + 0xa0) & 255) as u8);
    cipher.multiply_seeded(public, &minus_one, &seed, 8, math, 0)
}
fn difference(public: &PublicKey, bits: &[Cipher], value: &Cipher) -> Result<Cipher, Error> {
    if bits.len() != RANGE_BITS {
        return Err(Error("HFHE range bit count rejected"));
    }
    let mut sum = bits[0].clone();
    for (index, bit) in bits.iter().enumerate().skip(1) {
        sum = sum.add(public, &bit.scale(Fp::from_u64(1_u64 << index)))?;
    }
    sum.subtract(public, value)
}

/// Exact sequential native construction. The native host may schedule bit proofs
/// in parallel; entropy interleaving across its workers is not a wire contract.
pub fn make_range<R: RngCore + CryptoRng>(
    public: &PublicKey,
    secret: &SecretKey,
    cipher: &Cipher,
    value: u64,
    rule: ScalarRule,
    rng: &mut R,
) -> Result<RangeProof, Error> {
    if !value_cipher_ok(public, cipher) {
        return Err(Error("pvac: range proof value rejected"));
    }
    if !index_count_ok(public) {
        return Err(Error("pvac: index count exceeds domain"));
    }
    let mut bits = r1cs::allocate(RANGE_BITS)?;
    let mut proofs = r1cs::allocate(RANGE_BITS)?;
    for index in 0..RANGE_BITS {
        let bit = encrypt::value_random(public, secret, (value >> index) & 1, rng)?;
        let check = bit_check(public, &bit, index, rule == ScalarRule::Wide)?;
        proofs.push(zero::make_zero(public, secret, &check, rule, rng)?);
        bits.push(bit);
    }
    let difference = difference(public, &bits, cipher)?;
    let lc_proof = zero::make_zero(public, secret, &difference, rule, rng)?;
    Ok(RangeProof {
        ct_bit: bits,
        bit_proofs: proofs,
        lc_proof,
    })
}
pub fn verify_range(
    public: &PublicKey,
    cipher: &Cipher,
    proof: &RangeProof,
    rule: ScalarRule,
) -> Result<bool, Error> {
    if !value_cipher_ok(public, cipher)
        || proof.ct_bit.len() != RANGE_BITS
        || proof.bit_proofs.len() != RANGE_BITS
    {
        return Ok(false);
    }
    if proof
        .ct_bit
        .iter()
        .any(|bit| !bit_cipher_ok(public, bit, cipher.slots))
    {
        return Ok(false);
    }
    if !index_count_ok(public) && proof.ct_bit.iter().any(|bit| !bit.layers.is_empty()) {
        return Ok(false);
    }
    for (index, (bit, proof)) in proof.ct_bit.iter().zip(&proof.bit_proofs).enumerate() {
        let check = bit_check(public, bit, index, rule == ScalarRule::Wide)?;
        if !zero::verify_zero(public, &check, proof, rule)? {
            return Ok(false);
        }
    }
    zero::verify_zero(
        public,
        &difference(public, &proof.ct_bit, cipher)?,
        &proof.lc_proof,
        rule,
    )
}

struct Prepared {
    cipher: Cipher,
    masks: Vec<Zeroizing<Vec<Fp>>>,
    inverse: Vec<Zeroizing<Vec<Fp>>>,
    coefficients: Vec<Vec<Fp>>,
    bases: Vec<usize>,
}
fn prepare(public: &PublicKey, secret: &SecretKey, cipher: Cipher) -> Result<Prepared, Error> {
    let masks = zero::masks(public, secret, &cipher)?;
    let inverse = zero::inverse_masks(&masks)?;
    let coefficients = zero::layer_coefficients(public, &cipher)?;
    let bases = zero::base_layer_indices(&cipher)?;
    Ok(Prepared {
        cipher,
        masks,
        inverse,
        coefficients,
        bases,
    })
}
fn build_aggregated(
    public: &PublicKey,
    secret: &SecretKey,
    cipher: &Cipher,
    bits: &[Cipher],
    rule: ScalarRule,
) -> Result<(Prover, Transcript), Error> {
    if bits.len() != RANGE_BITS {
        return Err(Error("HFHE range bit count rejected"));
    }
    let mut data = r1cs::allocate(RANGE_BITS + 1)?;
    for (index, bit) in bits.iter().enumerate() {
        data.push(prepare(
            public,
            secret,
            bit_check(public, bit, index, false)?,
        )?);
    }
    data.push(prepare(public, secret, difference(public, bits, cipher)?)?);
    let mut prover = Prover::new(rule);
    for item in &data {
        let values = CircuitValues {
            secret,
            masks: &item.masks,
            inverse: &item.inverse,
        };
        zero::build_legacy_circuit(
            &mut prover,
            &item.cipher,
            &item.coefficients,
            &item.bases,
            Some(&values),
            None,
            true,
        )?;
    }
    let mut transcript = Transcript::new(b"pvac.range_proof.aggregated", rule);
    transcript.append_u64(b"RANGE_BITS", RANGE_BITS as u64);
    for item in &data {
        transcript.append_u64(b"nL", item.cipher.layers.len() as u64);
        transcript.append_u64(b"S", item.cipher.slots as u64);
        transcript.append_u64(b"nB", item.bases.len() as u64);
    }
    Ok((prover, transcript))
}
pub fn make_aggregated_range<R: RngCore + CryptoRng>(
    public: &PublicKey,
    secret: &SecretKey,
    cipher: &Cipher,
    value: u64,
    rule: ScalarRule,
    rng: &mut R,
) -> Result<AggregatedRangeProof, Error> {
    if !value_cipher_ok(public, cipher) {
        return Err(Error("pvac: aggregated range value rejected"));
    }
    if !index_count_ok(public) {
        return Err(Error("pvac: index count exceeds domain"));
    }
    let mut bits = r1cs::allocate(RANGE_BITS)?;
    for index in 0..RANGE_BITS {
        bits.push(encrypt::value_random(
            public,
            secret,
            (value >> index) & 1,
            rng,
        )?);
    }
    let (prover, mut transcript) = build_aggregated(public, secret, cipher, &bits, rule)?;
    Ok(AggregatedRangeProof {
        ct_bit: bits,
        proof: prover.prove(&mut transcript, rng, LimitProfile::Default)?,
    })
}
/// Deliberate native protocol policy; do not enable this verifier as a cleanup.
pub fn verify_aggregated_range(
    _public: &PublicKey,
    _cipher: &Cipher,
    _proof: &AggregatedRangeProof,
) -> bool {
    false
}

#[cfg(test)]
#[path = "range_tests.rs"]
mod tests;
