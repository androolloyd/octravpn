// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native public recryption shape policy and equality proofs.
use crate::{
    cipher::Cipher,
    keys::{PublicKey, SecretKey},
    proof::zero::{self, ZeroProof},
    scalar::ScalarRule,
    Error,
};
use rand::{CryptoRng, RngCore};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub max_output_layers: usize,
    pub max_output_edges: usize,
    pub max_slots: usize,
    pub require_smaller: bool,
}
impl Key {
    pub fn new(
        max_output_layers: usize,
        max_output_edges: usize,
        max_slots: usize,
    ) -> Result<Self, Error> {
        if max_output_layers == 0 {
            return Err(Error(
                "pvac: make_public_recrypt_key: max_output_layers is zero",
            ));
        }
        if max_output_edges == 0 {
            return Err(Error(
                "pvac: make_public_recrypt_key: max_output_edges is zero",
            ));
        }
        Ok(Self {
            max_output_layers,
            max_output_edges,
            max_slots,
            require_smaller: true,
        })
    }
    pub fn shape_ok(&self, public: &PublicKey, input: &Cipher, output: &Cipher) -> bool {
        input.compatible_with(public)
            && output.compatible_with(public)
            && input.slots == output.slots
            && (self.max_slots == 0 || output.slots <= self.max_slots)
            && output.layers.len() <= self.max_output_layers
            && output.edges.len() <= self.max_output_edges
            && (!self.require_smaller
                || output.layers.len() < input.layers.len()
                || output.edges.len() < input.edges.len())
    }
}
#[derive(Clone)]
pub struct Proof {
    pub equality: ZeroProof,
    pub output_layers: usize,
    pub output_edges: usize,
}
pub struct Bundle {
    pub output: Cipher,
    pub proof: Proof,
}
pub fn prove<R: RngCore + CryptoRng>(
    public: &PublicKey,
    secret: &SecretKey,
    input: &Cipher,
    output: &Cipher,
    rng: &mut R,
) -> Result<Proof, Error> {
    Ok(Proof {
        equality: zero::make_zero(
            public,
            secret,
            &input.subtract(public, output)?,
            ScalarRule::Prior,
            rng,
        )?,
        output_layers: output.layers.len(),
        output_edges: output.edges.len(),
    })
}
pub fn verify(
    public: &PublicKey,
    key: &Key,
    input: &Cipher,
    output: &Cipher,
    proof: &Proof,
) -> Result<bool, Error> {
    if !key.shape_ok(public, input, output)
        || proof.equality.is_bound
        || proof.output_layers != output.layers.len()
        || proof.output_edges != output.edges.len()
    {
        return Ok(false);
    }
    zero::verify_zero(
        public,
        &input.subtract(public, output)?,
        &proof.equality,
        ScalarRule::Prior,
    )
}
#[allow(clippy::too_many_arguments)] // Native public profile, reset graph controls and proving entropy.
pub fn bundle_seeded<R: RngCore + CryptoRng>(
    public: &PublicKey,
    secret: &SecretKey,
    key: &Key,
    input: &Cipher,
    seed: &[u8; 32],
    out_layers: usize,
    edges_per_layer: usize,
    rng: &mut R,
) -> Result<Bundle, Error> {
    let output =
        super::legacy::reset_seeded(public, secret, input, seed, out_layers, edges_per_layer)?;
    if !key.shape_ok(public, input, &output) {
        return Err(Error(
            "pvac: make_public_recrypt_bundle_seeded: output rejected by public profile",
        ));
    }
    let proof = prove(public, secret, input, &output, rng)?;
    Ok(Bundle { output, proof })
}
