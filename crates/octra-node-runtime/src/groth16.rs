// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native OG16V1/OG16P1 BN254 verification. Wire coordinates and public inputs
//! must be canonical; reducing an out-of-field integer would accept other bytes.
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};

pub const MAX_INPUTS: usize = 32;

/// VM preflight intentionally checks shape before the proof's magic or points.
/// An invalid but correctly sized proof still pays the per-input effort.
pub fn shape(key: &[u8], proof: &[u8], inputs: &[u8]) -> Option<usize> {
    if key.get(..6)? != b"OG16V1" {
        return None;
    }
    let count = u32::from_be_bytes(key.get(6..10)?.try_into().ok()?) as usize;
    (count <= MAX_INPUTS
        && key.len() == 458 + (count + 1) * 64
        && proof.len() == 262
        && inputs.len() == count * 32)
        .then_some(count)
}

struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn field<F: PrimeField>(&mut self) -> Option<F> {
        let raw = self.0.get(..32)?;
        let field = F::from_be_bytes_mod_order(raw);
        if field.into_bigint().to_bytes_be().as_slice() != raw {
            return None;
        }
        self.0 = &self.0[32..];
        Some(field)
    }
    fn g1(&mut self) -> Option<G1Affine> {
        let point = G1Affine::new_unchecked(self.field::<Fq>()?, self.field::<Fq>()?);
        (!point.is_zero()
            && point.is_on_curve()
            && point.is_in_correct_subgroup_assuming_on_curve())
        .then_some(point)
    }
    fn fq2(&mut self) -> Option<Fq2> {
        Some(Fq2::new(self.field()?, self.field()?))
    }
    fn g2(&mut self) -> Option<G2Affine> {
        let point = G2Affine::new_unchecked(self.fq2()?, self.fq2()?);
        (!point.is_zero()
            && point.is_on_curve()
            && point.is_in_correct_subgroup_assuming_on_curve())
        .then_some(point)
    }
}

/// Every allocation is bounded by the native 32-public-input limit. Malformed
/// data is a false proof, never a backend outage or a partially accepted key.
pub fn verify(key: &[u8], proof: &[u8], inputs: &[u8]) -> bool {
    let run = || {
        let count = shape(key, proof, inputs)?;
        if proof.get(..6)? != b"OG16P1" {
            return None;
        }
        let mut key = Reader(&key[10..]);
        let key = VerifyingKey::<Bn254> {
            alpha_g1: key.g1()?,
            beta_g2: key.g2()?,
            gamma_g2: key.g2()?,
            delta_g2: key.g2()?,
            gamma_abc_g1: (0..=count).map(|_| key.g1()).collect::<Option<Vec<_>>>()?,
        };
        let mut proof = Reader(&proof[6..]);
        let proof = Proof::<Bn254> {
            a: proof.g1()?,
            b: proof.g2()?,
            c: proof.g1()?,
        };
        let mut inputs = Reader(inputs);
        let inputs = (0..count)
            .map(|_| inputs.field::<Fr>())
            .collect::<Option<Vec<_>>>()?;
        Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&key), &proof, &inputs).ok()
    };
    run().unwrap_or(false)
}
