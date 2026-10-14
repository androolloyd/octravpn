// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Active v6/v7 circuit masks, LPN-v2 noise and layer commitment transcripts.
//! Domains, reductions and the v6 zero substitution preserve the adopted pin.
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::Zeroizing;

use crate::{
    field::Fp,
    keys::{signed_commitment, CircuitProfile, PublicKey, SecretKey},
    lpn,
    seeded_rng::{derive_key, domain_hash, CtrRng},
    Error,
};

pub const ROUNDS: usize = 91;
pub type LayerCommitments = (Vec<[u8; 32]>, Vec<[u8; 32]>);

pub(crate) fn reserve_fields(count: usize) -> Result<Zeroizing<Vec<Fp>>, Error> {
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(count)
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    Ok(output)
}

fn reserve_points(count: usize) -> Result<Vec<[u8; 32]>, Error> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    Ok(output)
}

fn profile(public: &PublicKey) -> Result<CircuitProfile, Error> {
    match public.circuit_profile {
        1 => Ok(CircuitProfile::MimcX3V6),
        2 => Ok(CircuitProfile::MimcX5V7),
        _ => Err(Error("pvac: circuit prf profile rejected")),
    }
}

fn field_from_hash(bytes: &[u8; 32]) -> Fp {
    let lo = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) & (u64::MAX >> 1);
    let value = Fp::from_words(lo, hi);
    if value == Fp::ZERO {
        Fp::ONE
    } else {
        value
    }
}

fn words_hash(domain: &[u8], words: &[u64]) -> [u8; 32] {
    let mut hash = Sha256::new();
    Digest::update(&mut hash, domain);
    for word in words {
        Digest::update(&mut hash, word.to_le_bytes());
    }
    hash.finalize().into()
}

pub fn proof_version(profile: CircuitProfile) -> &'static str {
    match profile {
        CircuitProfile::MimcX3V6 => "pvac-v6-key-bound",
        CircuitProfile::MimcX5V7 => "pvac-v7-key-bound-x5",
    }
}

pub fn power(profile: CircuitProfile, value: Fp) -> Fp {
    let square = value * value;
    match profile {
        CircuitProfile::MimcX3V6 => square * value,
        CircuitProfile::MimcX5V7 => square * square * value,
    }
}

pub fn round_constant(profile: CircuitProfile, round: usize) -> Fp {
    let domain: &[u8] = match profile {
        CircuitProfile::MimcX3V6 => b"pvac.v6.circuit_prf.mimc.round",
        CircuitProfile::MimcX5V7 => b"pvac.v7.circuit_prf.mimc.round",
    };
    field_from_hash(&words_hash(domain, &[round as u64]))
}

pub fn challenge(public: &PublicKey, tag: u64, nonce: [u64; 2], slot: usize) -> Result<Fp, Error> {
    let domain: &[u8] = match profile(public)? {
        CircuitProfile::MimcX3V6 => b"pvac.v6.circuit_prf.challenge",
        CircuitProfile::MimcX5V7 => b"pvac.v7.circuit_prf.challenge",
    };
    let mut hash = Sha256::new();
    Digest::update(&mut hash, domain);
    Digest::update(&mut hash, public.canon_tag.to_le_bytes());
    Digest::update(&mut hash, public.h_digest);
    for word in [tag, nonce[0], nonce[1], slot as u64] {
        Digest::update(&mut hash, word.to_le_bytes());
    }
    Ok(field_from_hash(&hash.finalize().into()))
}

pub fn prf_r(
    public: &PublicKey,
    secret: &SecretKey,
    tag: u64,
    nonce: [u64; 2],
    slot: usize,
) -> Result<Fp, Error> {
    let profile = profile(public)?;
    let key = match profile {
        CircuitProfile::MimcX3V6 => &secret.circuit_key_v6,
        CircuitProfile::MimcX5V7 => &secret.circuit_key,
    };
    let mut state = Zeroizing::new(challenge(public, tag, nonce, slot)?);
    for round in 0..ROUNDS {
        *state = power(profile, *state + *key + round_constant(profile, round));
    }
    *state = *state + *key + Fp::ONE;
    Ok(
        if profile == CircuitProfile::MimcX3V6 && *state == Fp::ZERO {
            Fp::ONE
        } else {
            *state
        },
    )
}

pub fn slots(
    public: &PublicKey,
    secret: &SecretKey,
    tag: u64,
    nonce: [u64; 2],
    count: usize,
) -> Result<Zeroizing<Vec<Fp>>, Error> {
    let mut output = reserve_fields(count)?;
    for slot in 0..count {
        output.push(prf_r(public, secret, tag, nonce, slot)?);
    }
    Ok(output)
}

pub fn slots_nonzero(slots: &[Fp]) -> bool {
    slots.iter().all(|&value| value != Fp::ZERO)
}

fn scalar(secret: &SecretKey, nonce: [u64; 2], slot: usize, domain: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hash = Sha256::new();
    Digest::update(&mut hash, domain);
    for word in &secret.prf_key {
        Digest::update(&mut hash, Zeroizing::new(word.to_le_bytes()).as_ref());
    }
    for word in [nonce[0], nonce[1], slot as u64] {
        Digest::update(&mut hash, word.to_le_bytes());
    }
    let mut digest = Zeroizing::new([0; 32]);
    hash.finalize_into((&mut *digest).into());
    let reduced = Zeroizing::new(Scalar::from_bytes_mod_order(*digest));
    digest.copy_from_slice(reduced.as_bytes());
    digest
}

pub fn rho(secret: &SecretKey, nonce: [u64; 2], slot: usize) -> Zeroizing<[u8; 32]> {
    scalar(secret, nonce, slot, b"pvac.prf.rho")
}

pub fn rho_prod(secret: &SecretKey, nonce: [u64; 2], slot: usize) -> Zeroizing<[u8; 32]> {
    scalar(secret, nonce, slot, b"pvac.prf.rho.prod")
}

pub fn r_alpha(secret: &SecretKey, nonce: [u64; 2], slot: usize) -> Zeroizing<[u8; 32]> {
    scalar(secret, nonce, slot, b"pvac.v6.prf.r.alpha")
}

/// Returns `(R_PC, PC)` in native layer order.
pub fn layer_commitments(
    secret: &SecretKey,
    nonce: [u64; 2],
    masks: &[Fp],
) -> Result<LayerCommitments, Error> {
    let mut r_pc = reserve_points(masks.len())?;
    let mut pc = reserve_points(masks.len())?;
    for (slot, &mask) in masks.iter().enumerate() {
        r_pc.push(signed_commitment(mask, &r_alpha(secret, nonce, slot)));
        pc.push(signed_commitment(mask.inverse(), &rho(secret, nonce, slot)));
    }
    Ok((r_pc, pc))
}

pub fn product_commitments(
    secret: &SecretKey,
    nonce: [u64; 2],
    a: &[Fp],
    b: &[Fp],
) -> Result<Vec<[u8; 32]>, Error> {
    if a.len() != b.len() {
        return Err(Error("HFHE product mask shape rejected"));
    }
    let mut output = reserve_points(a.len())?;
    output.extend(a.iter().zip(b).enumerate().map(|(slot, (&a, &b))| {
        signed_commitment((a * b).inverse(), &rho_prod(secret, nonce, slot))
    }));
    Ok(output)
}

pub fn base_commitment(public: &PublicKey, tag: u64, nonce: [u64; 2], masks: &[Fp]) -> [u8; 32] {
    // This transcript binds count, not mask values. The separate Pedersen
    // commitments bind those values. The native explicit length is 14 bytes.
    words_hash(
        b"pvac.dom.r_com",
        &[
            public.canon_tag,
            tag,
            nonce[0],
            nonce[1],
            masks.len() as u64,
        ],
    )
}

pub fn product_commitment(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    Digest::update(&mut hash, b"pvac.dom.r_com");
    Digest::update(&mut hash, a);
    Digest::update(&mut hash, b);
    hash.finalize().into()
}

fn carryless_product(a: u64, b: u64) -> u128 {
    let mut product = 0;
    for bit in 0..64 {
        let mask = u128::from((a >> bit) & 1).wrapping_neg();
        product ^= (u128::from(b) << bit) & mask;
    }
    product
}

/// The v2 PRF extracts bits `[bits-1, bits+125]` of the full convolution.
/// Compute only the convolution words intersecting that public output window.
pub fn toeplitz_127_full(top: &[u64], y: &[u64], bits: usize) -> Result<[u64; 2], Error> {
    if bits == 0 {
        return Err(Error("pvac: toeplitz width rejected"));
    }
    let top_bits = bits
        .checked_add(126)
        .ok_or(Error("pvac: toeplitz shape rejected"))?;
    if y.len() != bits.div_ceil(64) || top.len() != top_bits.div_ceil(64) {
        return Err(Error("pvac: toeplitz shape rejected"));
    }
    let offset = bits - 1;
    let first_word = offset >> 6;
    let last_word = (offset + 126) >> 6;
    let mut window = Zeroizing::new([0_u64; 3]);
    for (i, &word) in y.iter().enumerate() {
        let word = if i + 1 == y.len() && bits & 63 != 0 {
            word & ((1 << (bits & 63)) - 1)
        } else {
            word
        };
        for k in first_word..=last_word {
            if let Some(j) = k.checked_sub(i) {
                if let Some(&top_word) = top.get(j) {
                    window[k - first_word] ^= carryless_product(word, top_word) as u64;
                }
            }
            if let Some(j) = k.checked_sub(i + 1) {
                if let Some(&top_word) = top.get(j) {
                    window[k - first_word] ^= (carryless_product(word, top_word) >> 64) as u64;
                }
            }
        }
    }
    let shift = offset & 63;
    let mut output = if shift != 0 {
        [
            (window[0] >> shift) | (window[1] << (64 - shift)),
            (window[1] >> shift) | (window[2] << (64 - shift)),
        ]
    } else {
        [window[0], window[1]]
    };
    output[1] &= u64::MAX >> 1;
    Ok(output)
}

pub fn lpn_v2_core(
    public: &PublicKey,
    secret: &SecretKey,
    tag: u64,
    nonce: [u64; 2],
    domain: &[u8],
) -> Result<Fp, Error> {
    let y = lpn::y_bits(public, secret, tag, nonce, domain)?;
    let (key, counter) = derive_key(
        &secret.prf_key,
        public.canon_tag,
        &public.h_digest,
        tag,
        nonce,
        b"pvac.dom.toeplitz",
    );
    let mut rng = CtrRng::new(&key, counter ^ domain_hash(domain));
    let mut top = Zeroizing::new(vec![0; (public.params.lpn_t as usize + 126).div_ceil(64)]);
    rng.fill_u64(&mut top);
    let [lo, hi] = toeplitz_127_full(&top, &y, public.params.lpn_t as usize)?;
    let result = Fp::from_words(lo, hi);
    Ok(if result == Fp::ZERO { Fp::ONE } else { result })
}

pub fn lpn_v2_noise(
    public: &PublicKey,
    secret: &SecretKey,
    tag: u64,
    nonce: [u64; 2],
) -> Result<Fp, Error> {
    let a = lpn_v2_core(public, secret, tag, nonce, b"pvac.v2.prf.noise.1")?;
    let b = lpn_v2_core(public, secret, tag, nonce, b"pvac.v2.prf.noise.2")?;
    let c = lpn_v2_core(public, secret, tag, nonce, b"pvac.v2.prf.noise.3")?;
    Ok(a * b * c)
}

pub fn delta_scalar(
    public: &PublicKey,
    secret: &SecretKey,
    tag: u64,
    nonce: [u64; 2],
    gid: u32,
    kind: u8,
) -> Result<Fp, Error> {
    let index = u64::from(gid) + 1;
    let kind = u64::from(kind) + 1;
    let nonce = [
        nonce[0] ^ 0x9e37_79b9_7f4a_7c15_u64.wrapping_mul(index) ^ kind,
        nonce[1] ^ 0x94d0_49bb_1331_11eb_u64.wrapping_mul(index) ^ (kind << 32),
    ];
    let tag = tag ^ 0x517c_c1b7_2722_0a95_u64.wrapping_mul(index) ^ (kind << 48);
    lpn_v2_noise(public, secret, tag, nonce)
}

pub fn delta_slots(
    public: &PublicKey,
    secret: &SecretKey,
    tag: u64,
    nonce: [u64; 2],
    gid: u32,
    kind: u8,
    count: usize,
) -> Result<Zeroizing<Vec<Fp>>, Error> {
    if count == 1 {
        return Ok(Zeroizing::new(vec![delta_scalar(
            public, secret, tag, nonce, gid, kind,
        )?]));
    }
    let mut xof = Shake256::default();
    Update::update(&mut xof, b"pvac.delta.slot");
    for word in secret.prf_key.iter().copied().chain([
        tag,
        nonce[0],
        nonce[1],
        u64::from(gid) + 1,
        u64::from(kind) + 1,
    ]) {
        Update::update(&mut xof, &word.to_le_bytes());
    }
    let mut stream = xof.finalize_xof();
    let mut output = reserve_fields(count)?;
    let mut bytes = Zeroizing::new([0; 16]);
    while output.len() < count {
        stream.read(bytes.as_mut());
        let lo = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let hi = u64::from_le_bytes(bytes[8..].try_into().unwrap()) & (u64::MAX >> 1);
        // Match native's pre-reduction nonzero check, including the p -> 0 case.
        if lo != 0 || hi != 0 {
            output.push(Fp::from_words(lo, hi));
        }
    }
    Ok(output)
}
