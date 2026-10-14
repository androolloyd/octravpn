// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted legacy recryption arithmetic and its explicit public-key rank audit.
use crate::{
    cipher::{Cipher, Layer},
    circuit_prf, encrypt,
    field::Fp,
    keys::{PublicKey, SecretKey},
    matrix, product,
    proof::{r1cs, zero},
    seeded_rng::CtrRng,
    Error,
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

pub struct EvalKey {
    pub zero_pool: Vec<Cipher>,
    pub enc_one: Cipher,
}
pub fn make_eval_key<R: RngCore + CryptoRng>(
    public: &PublicKey,
    secret: &SecretKey,
    pool_size: usize,
    depth: i32,
    rng: &mut R,
) -> Result<EvalKey, Error> {
    let mut zero_pool = r1cs::allocate(pool_size)?;
    for _ in 0..pool_size {
        zero_pool.push(encrypt::fields_random(
            public,
            secret,
            &[Fp::ZERO],
            depth,
            rng,
        )?);
    }
    Ok(EvalKey {
        zero_pool,
        enc_one: encrypt::value_random(public, secret, 1, rng)?,
    })
}
#[allow(clippy::cast_precision_loss, clippy::manual_range_contains)] // Preserve native density and NaN comparisons.
pub fn sigma_needs_balance(public: &PublicKey, cipher: &Cipher) -> bool {
    if cipher.edges.is_empty() {
        return true;
    }
    let ones = cipher
        .edges
        .iter()
        .flat_map(|edge| &edge.sigma.words)
        .map(|word| u64::from(word.count_ones()))
        .sum::<u64>();
    let total = cipher.edges.len() as f64 * f64::from(public.params.m_bits);
    let density = ones as f64 / total;
    density < 0.495 || density > 0.505
}
fn rebalance_with(
    public: &PublicKey,
    key: &EvalKey,
    cipher: &Cipher,
    mut select: impl FnMut(usize) -> Result<usize, Error>,
) -> Result<Cipher, Error> {
    if key.zero_pool.is_empty() || cipher.edges.is_empty() {
        return Ok(cipher.clone());
    }
    let mut result = cipher.clone();
    for _ in 0..8 {
        if !sigma_needs_balance(public, &result) {
            break;
        }
        result = result.add(public, &key.zero_pool[select(key.zero_pool.len())?])?;
        result.apply_ubk(public)?;
        result.compact_over_budget(public)?;
    }
    result.compact_edges(public)?;
    result.compact_layers()?;
    Ok(result)
}
pub fn rebalance_seeded(
    public: &PublicKey,
    key: &EvalKey,
    cipher: &Cipher,
    seed: &[u8; 32],
) -> Result<Cipher, Error> {
    let mut rng = CtrRng::seeded(seed);
    rebalance_with(public, key, cipher, |count| {
        Ok(rng.bounded(count as u64) as usize)
    })
}
pub fn rebalance_random<R: RngCore + CryptoRng>(
    public: &PublicKey,
    key: &EvalKey,
    cipher: &Cipher,
    rng: &mut R,
) -> Result<Cipher, Error> {
    rebalance_with(public, key, cipher, |count| {
        let mut bytes = Zeroizing::new([0; 8]);
        rng.try_fill_bytes(&mut *bytes)
            .map_err(|_| Error("HFHE entropy unavailable"))?;
        Ok((u64::from_le_bytes(*bytes) % count as u64) as usize)
    })
}

pub struct RecryptKey {
    slots: usize,
    layers: Vec<Layer>,
    bias: Zeroizing<Vec<Vec<Fp>>>,
    mix: Zeroizing<Vec<Vec<Vec<Fp>>>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicAudit {
    pub slots: usize,
    pub old_layers: usize,
    pub target_layers: usize,
    pub rank: Vec<usize>,
    pub quotient: Vec<usize>,
    pub reusable_public_safe: bool,
}
fn zero_row(slots: usize) -> Result<Vec<Fp>, Error> {
    let mut row = r1cs::allocate(slots)?;
    row.resize(slots, Fp::ZERO);
    Ok(row)
}
fn matrix(rows: usize, cols: usize) -> Result<Vec<Vec<Fp>>, Error> {
    let mut output = r1cs::allocate(rows)?;
    for _ in 0..rows {
        output.push(zero_row(cols)?);
    }
    Ok(output)
}
fn make_layer(
    public: &PublicKey,
    secret: &SecretKey,
    slots: usize,
    rng: &mut CtrRng,
) -> Result<Layer, Error> {
    let mut layer = Layer::default();
    for _ in 0..16 {
        layer.seed.nonce = rng.nonce128();
        layer.seed.ztag = matrix::layer_tag(public.canon_tag, layer.seed.nonce);
        let masks = circuit_prf::slots(public, secret, layer.seed.ztag, layer.seed.nonce, slots)?;
        if !masks.is_empty() && circuit_prf::slots_nonzero(&masks) {
            layer.r_com =
                circuit_prf::base_commitment(public, layer.seed.ztag, layer.seed.nonce, &masks);
            (layer.r_pc, layer.pc) =
                circuit_prf::layer_commitments(secret, layer.seed.nonce, &masks)?;
            return Ok(layer);
        }
    }
    Err(Error(
        "pvac: recrypt circuit prf nonzero mask generation failed",
    ))
}
pub fn make_key_seeded(
    public: &PublicKey,
    secret: &SecretKey,
    cipher: &Cipher,
    out_layers: usize,
    seed: &[u8; 32],
) -> Result<RecryptKey, Error> {
    if !cipher.compatible_with(public) {
        return Err(Error(
            "pvac: make_recrypt_key_seeded: cipher/pubkey mismatch",
        ));
    }
    if out_layers == 0 {
        return Err(Error("pvac: make_recrypt_key_seeded: out_layers is zero"));
    }
    let mut rng = CtrRng::seeded(seed);
    let mut layers = r1cs::allocate(out_layers)?;
    for _ in 0..out_layers {
        layers.push(make_layer(public, secret, cipher.slots, &mut rng)?);
    }
    let old_inverse = zero::inverse_masks(&zero::masks(public, secret, cipher)?)?;
    let mut new_inverse = r1cs::allocate(layers.len())?;
    for layer in &layers {
        let mut masks = circuit_prf::slots(
            public,
            secret,
            layer.seed.ztag,
            layer.seed.nonce,
            cipher.slots,
        )?;
        for mask in masks.iter_mut() {
            *mask = mask.inverse();
        }
        new_inverse.push(masks);
    }
    let mut bias = Zeroizing::new(matrix(cipher.layers.len(), cipher.slots)?);
    let mut mix = Zeroizing::new(r1cs::allocate(cipher.layers.len())?);
    for (old_id, inverse) in old_inverse.iter().enumerate() {
        let mut row = Zeroizing::new(matrix(out_layers, cipher.slots)?);
        let mut sum = Zeroizing::new(zero_row(cipher.slots)?);
        for (new_id, target) in row.iter_mut().enumerate() {
            for (slot, value) in target.iter_mut().enumerate() {
                *value = rng.fp_nonzero();
                sum[slot] = sum[slot] + *value * new_inverse[new_id][slot];
            }
        }
        for (slot, value) in bias[old_id].iter_mut().enumerate() {
            *value = inverse[slot] - sum[slot];
        }
        // Move the protected allocation without copying the key's coefficients.
        mix.push(std::mem::take(&mut *row));
    }
    Ok(RecryptKey {
        slots: cipher.slots,
        layers,
        bias,
        mix,
    })
}
impl RecryptKey {
    pub fn compatible_with(&self, cipher: &Cipher) -> bool {
        self.slots == cipher.slots
            && !self.layers.is_empty()
            && self.bias.len() == cipher.layers.len()
            && self.mix.len() == cipher.layers.len()
            && self.bias.iter().all(|row| row.len() == cipher.slots)
            && self.mix.iter().all(|matrix| {
                matrix.len() == self.layers.len()
                    && matrix.iter().all(|row| row.len() == cipher.slots)
            })
    }
    fn rank(&self, slot: usize) -> Result<usize, Error> {
        let mut values = Zeroizing::new(matrix(self.mix.len(), self.layers.len())?);
        for (row, source) in values.iter_mut().zip(self.mix.iter()) {
            for (value, column) in row.iter_mut().zip(source) {
                *value = column[slot];
            }
        }
        let mut rank = 0;
        for col in 0..self.layers.len() {
            if rank >= values.len() {
                break;
            }
            let Some(pivot) = (rank..values.len()).find(|&row| values[row][col] != Fp::ZERO) else {
                continue;
            };
            values.swap(pivot, rank);
            let inverse = Zeroizing::new(values[rank][col].inverse());
            for value in &mut values[rank][col..] {
                *value = *value * *inverse;
            }
            for row in 0..values.len() {
                if row == rank || values[row][col] == Fp::ZERO {
                    continue;
                }
                let factor = Zeroizing::new(values[row][col]);
                for column in col..self.layers.len() {
                    values[row][column] = values[row][column] - *factor * values[rank][column];
                }
            }
            rank += 1;
        }
        Ok(rank)
    }
    pub fn audit(&self, cipher: &Cipher) -> Result<PublicAudit, Error> {
        if !self.compatible_with(cipher) {
            return Err(Error(
                "pvac: audit_recrypt_public_key: recrypt key mismatch",
            ));
        }
        let mut rank = r1cs::allocate(self.slots)?;
        let mut quotient = r1cs::allocate(self.slots)?;
        let mut safe = true;
        for slot in 0..self.slots {
            let value = self.rank(slot)?;
            rank.push(value);
            quotient.push(cipher.layers.len() - value);
            safe &= value == cipher.layers.len();
        }
        Ok(PublicAudit {
            slots: self.slots,
            old_layers: cipher.layers.len(),
            target_layers: self.layers.len(),
            rank,
            quotient,
            reusable_public_safe: safe,
        })
    }
    pub fn require_reusable_public_safe(&self, cipher: &Cipher) -> Result<(), Error> {
        if !self.audit(cipher)?.reusable_public_safe {
            return Err(Error("pvac: public recrypt key leaks quotient relations"));
        }
        Ok(())
    }
}
pub fn apply_seeded(
    public: &PublicKey,
    key: &RecryptKey,
    cipher: &Cipher,
    seed: &[u8; 32],
    edges_per_layer: usize,
) -> Result<Cipher, Error> {
    if !cipher.compatible_with(public) {
        return Err(Error(
            "pvac: ct_recrypt_apply_seeded: cipher/pubkey mismatch",
        ));
    }
    if !key.compatible_with(cipher) {
        return Err(Error("pvac: ct_recrypt_apply_seeded: recrypt key mismatch"));
    }
    let mut rng = CtrRng::seeded(seed);
    let mut output = Cipher {
        slots: cipher.slots,
        layers: key.layers.clone(),
        edges: Vec::new(),
        c0: if cipher.c0.is_empty() {
            zero_row(cipher.slots)?
        } else {
            cipher.c0.clone()
        },
    };
    let mut targets = Zeroizing::new(matrix(key.layers.len(), cipher.slots)?);
    for edge in &cipher.edges {
        for slot in 0..cipher.slots {
            let coefficient = edge.weights[slot] * public.powers[edge.idx as usize];
            let coefficient = if edge.ch == 1 {
                -coefficient
            } else {
                coefficient
            };
            output.c0[slot] =
                output.c0[slot] + coefficient * key.bias[edge.layer_id as usize][slot];
            for (new_id, target) in targets.iter_mut().enumerate() {
                target[slot] =
                    target[slot] + coefficient * key.mix[edge.layer_id as usize][new_id][slot];
            }
        }
    }
    for (new_id, target) in targets.iter().enumerate() {
        if target.iter().all(|&value| value == Fp::ZERO) {
            continue;
        }
        output.edges.extend(product::emit_repack(
            public,
            &output.layers[new_id],
            new_id as u32,
            target,
            edges_per_layer.max(1),
            &mut rng,
            0,
        )?);
    }
    output.compact_over_budget(public)?;
    output.compact_edges(public)?;
    output.compact_layers()?;
    Ok(output)
}
pub fn reset_seeded(
    public: &PublicKey,
    secret: &SecretKey,
    cipher: &Cipher,
    seed: &[u8; 32],
    out_layers: usize,
    edges_per_layer: usize,
) -> Result<Cipher, Error> {
    let key = make_key_seeded(public, secret, cipher, out_layers, seed)?;
    apply_seeded(public, &key, cipher, seed, edges_per_layer)
}
