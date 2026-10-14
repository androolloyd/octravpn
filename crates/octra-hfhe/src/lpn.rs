// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! The retained LPN PRF. Active circuit PRF profiles are a separate port.
use zeroize::Zeroizing;

use crate::{
    field::Fp,
    keys::{PublicKey, SecretKey},
    seeded_rng::{derive_key, domain_hash, CtrRng},
    Error,
};

fn rng(public: &PublicKey, secret: &SecretKey, tag: u64, nonce: [u64; 2], domain: &[u8]) -> CtrRng {
    let (key, counter) = derive_key(
        &secret.prf_key,
        public.canon_tag,
        &public.h_digest,
        tag,
        nonce,
        domain,
    );
    CtrRng::new(&key, counter)
}

pub fn y_bits(
    public: &PublicKey,
    secret: &SecretKey,
    tag: u64,
    nonce: [u64; 2],
    domain: &[u8],
) -> Result<Zeroizing<Vec<u64>>, Error> {
    let params = public.params;
    if params.lpn_n <= 0 || params.lpn_t <= 0 || params.lpn_tau_den <= 0 {
        return Err(Error("pvac: params lpn shape rejected"));
    }
    let words = (params.lpn_n as usize).div_ceil(64);
    if secret.lpn_bits.len() < words {
        return Err(Error("HFHE secret LPN shape rejected"));
    }
    let mut stream = rng(public, secret, tag, nonce, domain);
    let mut output = Zeroizing::new(vec![0; (params.lpn_t as usize).div_ceil(64)]);
    let mut row = Zeroizing::new(vec![0; words]);
    for index in 0..params.lpn_t as usize {
        stream.fill_u64(&mut row);
        let dot = row
            .iter()
            .zip(&secret.lpn_bits)
            .fold(0_u64, |acc, (&a, &b)| acc ^ (a & b))
            .count_ones()
            & 1;
        let noise =
            u32::from(stream.bounded(params.lpn_tau_den as u64) < params.lpn_tau_num as u64);
        output[index >> 6] ^= u64::from(dot ^ noise) << (index & 63);
    }
    Ok(output)
}

fn carryless_product(a: u64, b: u64) -> u128 {
    let mut product = 0;
    for bit in 0..64 {
        let mask = u128::from((a >> bit) & 1).wrapping_neg();
        product ^= (u128::from(b) << bit) & mask;
    }
    product
}

/// Native toep_127 returns the low 127 bits of the binary convolution.
/// Terms above bit 127 cannot affect that result; zero-pad short inputs.
pub fn toeplitz_127(top: &[u64], y: &[u64]) -> [u64; 2] {
    let word = |input: &[u64], index| input.get(index).copied().unwrap_or(0);
    let low = carryless_product(word(y, 0), word(top, 0));
    let high =
        carryless_product(word(y, 1), word(top, 0)) ^ carryless_product(word(y, 0), word(top, 1));
    let product = low ^ (high << 64);
    // The native helper masks bit 127 before normalizing the Mersenne field.
    [product as u64, ((product >> 64) as u64) & (u64::MAX >> 1)]
}

pub fn prf_core(
    public: &PublicKey,
    secret: &SecretKey,
    tag: u64,
    nonce: [u64; 2],
    domain: &[u8],
) -> Result<Fp, Error> {
    let y = y_bits(public, secret, tag, nonce, domain)?;
    let (key, counter) = derive_key(
        &secret.prf_key,
        public.canon_tag,
        &public.h_digest,
        tag,
        nonce,
        b"pvac.dom.toeplitz",
    );
    let mut stream = CtrRng::new(&key, counter ^ domain_hash(domain));
    let mut top = Zeroizing::new(vec![0; (public.params.lpn_t as usize + 127).div_ceil(64)]);
    stream.fill_u64(&mut top);
    let [lo, hi] = toeplitz_127(&top, &y);
    let value = Fp::from_words(lo, hi);
    Ok(if value == Fp::ZERO { Fp::ONE } else { value })
}

pub fn prf_r(
    public: &PublicKey,
    secret: &SecretKey,
    tag: u64,
    nonce: [u64; 2],
) -> Result<Fp, Error> {
    let r1 = prf_core(public, secret, tag, nonce, b"pvac.prf.r.1")?;
    let r2 = prf_core(public, secret, tag, nonce, b"pvac.prf.r.2")?;
    let r3 = prf_core(public, secret, tag, nonce, b"pvac.prf.r.3")?;
    Ok(r1 * r2 * r3)
}

pub fn prf_noise(
    public: &PublicKey,
    secret: &SecretKey,
    tag: u64,
    nonce: [u64; 2],
) -> Result<Fp, Error> {
    let r1 = prf_core(public, secret, tag, nonce, b"pvac.prf.noise.1")?;
    let r2 = prf_core(public, secret, tag, nonce, b"pvac.prf.noise.2")?;
    let r3 = prf_core(public, secret, tag, nonce, b"pvac.prf.noise.3")?;
    Ok(r1 * r2 * r3)
}
