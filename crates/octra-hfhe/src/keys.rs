// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Seeded key generation and v5 key serialization from the adopted PVAC pin.
//! Parameters are trusted local configuration; network profile policy belongs
//! to the backend adapter. Secret material has no Debug or Clone implementation.
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{compression, field::Fp, matrix, seeded_rng::CtrRng, Error};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Params {
    pub basis: i32,
    pub m_bits: i32,
    pub n_bits: i32,
    pub h_col_weight: i32,
    pub x_col_weight: i32,
    pub error_weight: i32,
    pub noise_entropy_bits: f64,
    pub tuple2_fraction: f64,
    pub depth_slope_bits: f64,
    pub edge_budget: u64,
    pub lpn_n: i32,
    pub lpn_t: i32,
    pub lpn_tau_num: i32,
    pub lpn_tau_den: i32,
    pub recrypt_lo: f64,
    pub recrypt_hi: f64,
    pub recrypt_rounds: i32,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            basis: 337,
            m_bits: 8192,
            n_bits: 16384,
            h_col_weight: 192,
            x_col_weight: 128,
            error_weight: 128,
            noise_entropy_bits: 120.0,
            tuple2_fraction: 0.55,
            depth_slope_bits: 16.0,
            edge_budget: 1_200_000,
            lpn_n: 4096,
            lpn_t: 16384,
            lpn_tau_num: 1,
            lpn_tau_den: 8,
            recrypt_lo: 0.48,
            recrypt_hi: 0.52,
            recrypt_rounds: 8,
        }
    }
}

impl Params {
    pub fn validate(self) -> Result<(), Error> {
        if self.basis < 3 {
            return Err(Error("pvac: params basis rejected"));
        }
        if self.m_bits <= 0 || self.n_bits <= 0 {
            return Err(Error("pvac: params matrix shape rejected"));
        }
        if self.h_col_weight < 0 || self.h_col_weight > self.m_bits {
            return Err(Error("pvac: params H weight rejected"));
        }
        if self.x_col_weight < 0 || self.x_col_weight > self.n_bits {
            return Err(Error("pvac: params X weight rejected"));
        }
        if self.error_weight < 0 || self.error_weight > self.m_bits {
            return Err(Error("pvac: params noise weight rejected"));
        }
        if self.lpn_n <= 0 || self.lpn_t <= 0 || self.lpn_tau_den <= 0 {
            return Err(Error("pvac: params lpn shape rejected"));
        }
        if !((1_u128 << 127) - 2).is_multiple_of(self.basis as u128) {
            return Err(Error("pvac: keygen_from_seed: prm.B does not divide pm1"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BitVec {
    pub nbits: usize,
    pub words: Vec<u64>,
}

pub struct PublicKey {
    pub(crate) params: Params,
    pub(crate) canon_tag: u64,
    pub(crate) h: Vec<BitVec>,
    pub(crate) permutation: Vec<i32>,
    pub(crate) inverse: Vec<i32>,
    pub(crate) h_digest: [u8; 32],
    pub(crate) omega: Fp,
    pub(crate) powers: Vec<Fp>,
    pub(crate) circuit_commit: [u8; 32],
    pub(crate) circuit_profile: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitProfile {
    MimcX3V6 = 1,
    MimcX5V7 = 2,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    pub(crate) prf_key: [u64; 4],
    pub(crate) circuit_key: Fp,
    pub(crate) circuit_blind: [u8; 32],
    pub(crate) circuit_key_v6: Fp,
    pub(crate) circuit_blind_v6: [u8; 32],
    pub(crate) lpn_bits: Vec<u64>,
}

fn hash_parts(label: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(label);
    hash.update(bytes);
    hash.finalize().into()
}

fn field_from_hash(bytes: &[u8; 32]) -> Fp {
    let lo = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) & (u64::MAX >> 1);
    let result = Fp::from_words(lo, hi);
    if result == Fp::ZERO {
        Fp::ONE
    } else {
        result
    }
}

/// The native H is a single Elligator map of this SHA-256 domain. The second
/// map of zero is the identity, so dalek's two-map API gives that same point.
/// Native generator and commitment vectors enforce this compatibility.
pub fn pedersen_h() -> [u8; 32] {
    pedersen_h_point().compress().to_bytes()
}

fn pedersen_h_point() -> RistrettoPoint {
    let mut uniform = [0; 64];
    uniform[..32].copy_from_slice(&Sha256::digest(b"pvac.rist.pedersen.H"));
    uniform[31] &= 0x7f;
    RistrettoPoint::from_uniform_bytes(&uniform)
}

pub fn signed_commitment(value: Fp, blind: &[u8; 32]) -> [u8; 32] {
    let negative = value.words().1 & (1 << 62) != 0;
    let magnitude = if negative { -value } else { value };
    let mut bytes = Zeroizing::new([0; 32]);
    bytes[..16].copy_from_slice(&magnitude.to_bytes_le());
    let scalar = Zeroizing::new(Scalar::from_bytes_mod_order(*bytes));
    let signed = Zeroizing::new(if negative { -*scalar } else { *scalar });
    let blinding = Zeroizing::new(Scalar::from_bytes_mod_order(*blind));
    (*signed * RISTRETTO_BASEPOINT_POINT + *blinding * pedersen_h_point())
        .compress()
        .to_bytes()
}

fn make_matrix(params: Params, tag: u64) -> Result<(Vec<BitVec>, [u8; 32]), Error> {
    let mut columns = Vec::with_capacity(params.n_bits as usize);
    let mut hash = Sha256::new();
    hash.update(b"H|v2");
    for word in [params.m_bits, params.n_bits, params.h_col_weight] {
        hash.update((word as u64).to_le_bytes());
    }
    let bits = params.m_bits as usize;
    for col in 0..params.n_bits {
        let words = [
            bits as u64,
            params.n_bits as u64,
            params.h_col_weight as u64,
            col as u64,
            tag,
        ];
        let weight =
            matrix::mixed_weight(params.h_col_weight as usize, bits, b"pvac.H.weight", &words);
        let rows = matrix::choose_k(weight as i32, params.m_bits, b"pvac.dom.h_gen", &words, 0)?;
        let mut column = BitVec {
            nbits: bits,
            words: vec![0; bits.div_ceil(64)],
        };
        for row in rows {
            column.words[row >> 6] |= 1 << (row & 63);
        }
        let bytes = bits.div_ceil(8);
        for word in column.words.iter().take(bytes / 8) {
            hash.update(word.to_le_bytes());
        }
        if !bytes.is_multiple_of(8) {
            hash.update(&column.words[bytes / 8].to_le_bytes()[..bytes % 8]);
        }
        columns.push(column);
    }
    Ok((columns, hash.finalize().into()))
}

fn prime_factors(mut value: i32) -> Vec<i32> {
    let mut primes = Vec::new();
    let mut divisor = 2;
    while i64::from(divisor) * i64::from(divisor) <= i64::from(value) {
        if value % divisor == 0 {
            primes.push(divisor);
            while value % divisor == 0 {
                value /= divisor;
            }
        }
        divisor += 1;
    }
    if value > 1 {
        primes.push(value);
    }
    primes
}

pub fn keygen_from_seed(params: Params, seed: &[u8; 32]) -> Result<(PublicKey, SecretKey), Error> {
    params.validate()?;
    let master = Zeroizing::new(hash_parts(b"OCTRA_PVAC_MASTER_V1", seed));
    let tag_bytes = hash_parts(b"OCTRA_PVAC_TAG", master.as_ref());
    let tag = u64::from_le_bytes(tag_bytes[..8].try_into().unwrap());
    let (h, h_digest) = make_matrix(params, tag)?;
    let (permutation, inverse) = matrix::permutation(tag, params.m_bits as usize);
    let sk_seed = Zeroizing::new(hash_parts(b"OCTRA_PVAC_SK", master.as_ref()));
    let mut rng = CtrRng::seeded(&sk_seed);
    let mut secret = SecretKey {
        prf_key: [0; 4],
        circuit_key: Fp::ZERO,
        circuit_blind: [0; 32],
        circuit_key_v6: Fp::ZERO,
        circuit_blind_v6: [0; 32],
        lpn_bits: vec![0; (params.lpn_n as usize).div_ceil(64)],
    };
    rng.fill_u64(&mut secret.prf_key);
    secret.circuit_key_v6 = field_from_hash(&Zeroizing::new(hash_parts(
        b"pvac.v6.circuit_prf.key",
        master.as_ref(),
    )));
    secret.circuit_blind_v6 = hash_parts(b"pvac.v6.circuit_prf.blind", master.as_ref());
    secret.circuit_key = field_from_hash(&Zeroizing::new(hash_parts(
        b"pvac.v7.circuit_prf.key",
        master.as_ref(),
    )));
    secret.circuit_blind = hash_parts(b"pvac.v7.circuit_prf.blind", master.as_ref());
    let circuit_commit = signed_commitment(secret.circuit_key, &secret.circuit_blind);
    rng.fill_u64(&mut secret.lpn_bits);
    if params.lpn_n & 63 != 0 {
        *secret.lpn_bits.last_mut().unwrap() &= (1 << (params.lpn_n & 63)) - 1;
    }
    let exponent = ((1_u128 << 127) - 2) / params.basis as u128;
    let gen_seed = Zeroizing::new(hash_parts(b"OCTRA_PVAC_GEN", master.as_ref()));
    let mut generators = CtrRng::seeded(&gen_seed);
    let generator = loop {
        let value = generators.fp_nonzero().pow_u128(exponent);
        if value != Fp::ONE {
            break value;
        }
    };
    let mut powers = vec![Fp::ONE; params.basis as usize];
    for index in 1..powers.len() {
        powers[index] = powers[index - 1] * generator;
    }
    let primes = prime_factors(params.basis);
    let omega = loop {
        let value = generators.fp_nonzero().pow_u128(exponent);
        if value != Fp::ONE
            && primes
                .iter()
                .all(|prime| value.pow_u64((params.basis / prime) as u64) != Fp::ONE)
        {
            break value;
        }
    };
    Ok((
        PublicKey {
            params,
            canon_tag: tag,
            h,
            permutation,
            inverse,
            h_digest,
            omega,
            powers,
            circuit_commit,
            circuit_profile: 2,
        },
        secret,
    ))
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}
fn push_i32(output: &mut Vec<u8>, value: i32) {
    output.extend_from_slice(&value.to_le_bytes());
}

impl PublicKey {
    pub fn bit_words(&self) -> Result<u64, Error> {
        if self.params.m_bits <= 0 {
            return Err(Error("pubkey bit size rejected"));
        }
        Ok((self.params.m_bits as u64).div_ceil(64))
    }
    /// Native retained-key image accounting; this is separate from compressed
    /// wire length and from the allocator's implementation-specific footprint.
    pub fn image_size(&self) -> Result<u64, Error> {
        let mut size = 219u64;
        let mut add = |count: usize, width: u64| -> Result<(), Error> {
            size = size
                .checked_add(
                    (count as u64)
                        .checked_mul(width)
                        .ok_or(Error("pubkey image size overflow"))?,
                )
                .filter(|n| *n < 1u64 << 62)
                .ok_or(Error("pubkey image size overflow"))?;
            Ok(())
        };
        add(self.h.len(), 16)?;
        for row in &self.h {
            add(row.words.len(), 8)?;
        }
        add(self.permutation.len(), 4)?;
        add(self.inverse.len(), 4)?;
        add(self.powers.len(), 16)?;
        Ok(size)
    }
    pub fn set_circuit_profile(&mut self, secret: &SecretKey, profile: CircuitProfile) {
        self.circuit_profile = profile as u8;
        let (key, blind) = match profile {
            CircuitProfile::MimcX3V6 => (secret.circuit_key_v6, &secret.circuit_blind_v6),
            CircuitProfile::MimcX5V7 => (secret.circuit_key, &secret.circuit_blind),
        };
        self.circuit_commit = signed_commitment(key, blind);
    }

    pub fn params(&self) -> Params {
        self.params
    }

    pub fn supports_alias_rejection(&self) -> bool {
        self.circuit_profile == CircuitProfile::MimcX5V7 as u8
    }
    pub fn h_digest(&self) -> [u8; 32] {
        self.h_digest
    }
    pub fn circuit_commitment(&self) -> [u8; 32] {
        self.circuit_commit
    }

    pub fn to_raw_bytes(&self) -> Vec<u8> {
        let mut output = b"PVAC\x05\x01".to_vec();
        let params = self.params;
        for value in [
            params.basis,
            params.m_bits,
            params.n_bits,
            params.h_col_weight,
            params.x_col_weight,
            params.error_weight,
        ] {
            push_i32(&mut output, value);
        }
        for value in [
            params.noise_entropy_bits,
            params.tuple2_fraction,
            params.depth_slope_bits,
        ] {
            output.extend_from_slice(&value.to_le_bytes());
        }
        push_u64(&mut output, params.edge_budget);
        for value in [
            params.lpn_n,
            params.lpn_t,
            params.lpn_tau_num,
            params.lpn_tau_den,
        ] {
            push_i32(&mut output, value);
        }
        for value in [params.recrypt_lo, params.recrypt_hi] {
            output.extend_from_slice(&value.to_le_bytes());
        }
        push_i32(&mut output, params.recrypt_rounds);
        push_u64(&mut output, self.canon_tag);
        push_u64(&mut output, self.h.len() as u64);
        for column in &self.h {
            push_u64(&mut output, column.nbits as u64);
            push_u64(&mut output, column.words.len() as u64);
            for &word in &column.words {
                push_u64(&mut output, word);
            }
        }
        for permutation in [&self.permutation, &self.inverse] {
            push_u64(&mut output, permutation.len() as u64);
            for &value in permutation {
                push_i32(&mut output, value);
            }
        }
        output.extend_from_slice(&self.h_digest);
        output.extend_from_slice(&self.omega.to_bytes_le());
        push_u64(&mut output, self.powers.len() as u64);
        for value in &self.powers {
            output.extend_from_slice(&value.to_bytes_le());
        }
        output.extend_from_slice(&self.circuit_commit);
        output.push(self.circuit_profile);
        output
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        compression::pack(&self.to_raw_bytes())
    }
}

impl SecretKey {
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        // Reserve the final size before writing secrets: reallocating a Vec
        // would free earlier allocations without wiping their secret bytes.
        let mut output = Zeroizing::new(Vec::with_capacity(142 + self.lpn_bits.len() * 8));
        output.extend_from_slice(b"PVAC\x05\x02");
        for &word in &self.prf_key {
            push_u64(&mut output, word);
        }
        output.extend_from_slice(&self.circuit_key.to_bytes_le());
        output.extend_from_slice(&self.circuit_blind);
        output.extend_from_slice(&self.circuit_key_v6.to_bytes_le());
        output.extend_from_slice(&self.circuit_blind_v6);
        push_u64(&mut output, self.lpn_bits.len() as u64);
        for &word in &self.lpn_bits {
            push_u64(&mut output, word);
        }
        output
    }
}
