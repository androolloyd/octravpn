// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native scoped encryption. Direct native source evaluation remains disabled upstream.
use crate::{
    cipher::Cipher,
    encrypt,
    field::Fp,
    keys::{PublicKey, SecretKey},
    seeded_rng::CtrRng,
    Error,
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceDomain {
    Native,
    Reusable,
}
pub fn encrypt_seeded(
    public: &PublicKey,
    secret: &SecretKey,
    values: &[Fp],
    seed: &[u8; 32],
    domain: SourceDomain,
) -> Result<Cipher, Error> {
    if values.is_empty() {
        return Err(Error(match domain {
            SourceDomain::Native => "pvac: nat encrypt value rejected",
            SourceDomain::Reusable => "pvac: ru encrypt value rejected",
        }));
    }
    let scoped = encrypt::seed_scope(
        public,
        seed,
        match domain {
            SourceDomain::Native => b"nat",
            SourceDomain::Reusable => b"ru",
        },
        values.len(),
        0,
        values,
    );
    encrypt::synthesize(public, secret, values, 0, &mut CtrRng::seeded(&scoped))
}
fn next_seed(rng: &mut CtrRng) -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0; 32]);
    for word in seed.chunks_exact_mut(8) {
        word.copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    seed
}
pub fn encrypt_random<R: RngCore + CryptoRng>(
    public: &PublicKey,
    secret: &SecretKey,
    values: &[Fp],
    rng: &mut R,
) -> Result<Cipher, Error> {
    if values.is_empty() {
        return Err(Error("pvac: encrypt value rejected"));
    }
    let mut seed = Zeroizing::new([0; 32]);
    rng.try_fill_bytes(&mut *seed)
        .map_err(|_| Error("HFHE entropy unavailable"))?;
    let mut seeded = CtrRng::seeded(&seed);
    let mut mask = crate::circuit_prf::reserve_fields(values.len())?;
    let mut positive = crate::circuit_prf::reserve_fields(values.len())?;
    for value in values {
        let random = seeded.fp_nonzero();
        mask.push(random);
        positive.push(*value + random);
    }
    let left_seed = next_seed(&mut seeded);
    let right_seed = next_seed(&mut seeded);
    let mut left = encrypt_seeded(public, secret, &positive, &left_seed, SourceDomain::Native)?;
    for value in mask.iter_mut() {
        *value = -*value;
    }
    let right = encrypt_seeded(public, secret, &mask, &right_seed, SourceDomain::Native)?;
    let offset = left.layers.len() as u32;
    left.layers.extend(right.layers);
    left.edges.extend(right.edges.into_iter().map(|mut edge| {
        edge.layer_id += offset;
        edge
    }));
    left.compact_over_budget(public)?;
    Ok(left)
}
/// Native ru_cipher/nat_cipher policy in the adopted revision.
pub fn source_cipher_allowed(_public: &PublicKey, _cipher: &Cipher) -> bool {
    false
}
