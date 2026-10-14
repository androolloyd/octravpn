// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native encryption. RNG draws and graph order preserve the native format.
#![allow(clippy::suboptimal_flops)] // Preserve native rounding for each qualified target.
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    arithmetic::{guard_budget, merge_edges},
    cipher::{Cipher, Edge, Layer, RSeed},
    circuit_prf,
    field::Fp,
    keys::{PublicKey, SecretKey},
    matrix,
    seeded_rng::CtrRng,
    Error,
};

pub fn plan_noise(public: &PublicKey, depth: i32) -> Result<(usize, usize), Error> {
    let p = public.params;
    // The adopted -O2 native build contracts this expression on ARM, but its
    // x86 SSE build does not. Boundary vectors qualify the current target;
    // cross-architecture/compiler equality remains a separate gate.
    let depth = f64::from(depth.max(0));
    let cap = if cfg!(target_arch = "aarch64") {
        p.depth_slope_bits.mul_add(depth, p.noise_entropy_bits)
    } else {
        p.noise_entropy_bits + p.depth_slope_bits * depth
    };
    let cost = f64::from(p.basis).log2();
    let count = |fraction: f64, divisor: f64| {
        let value = (cap * fraction / divisor.max(1e-6)).floor();
        // Native conversion outside int range is undefined; never allocate from it.
        if !value.is_finite() || value > f64::from(i32::MAX) {
            return Err(Error("HFHE noise budget outside supported range"));
        }
        Ok(value.max(0.0) as usize)
    };
    let mut n2 = count(p.tuple2_fraction, 2.0 * cost)?;
    let mut n3 = count(1.0 - p.tuple2_fraction, 3.0 * cost)?;
    if n2 + n3 == 1 {
        if n3 > 0 {
            n3 += 1;
        } else {
            n2 += 1;
        }
    }
    Ok((n2, n3))
}

fn signed(value: Fp, sign: u8) -> Fp {
    if sign == 1 {
        -value
    } else {
        value
    }
}

trait EncryptionRng {
    fn word(&mut self) -> Result<u64, Error>;
    fn bounded(&mut self, maximum: u64) -> Result<u64, Error>;
    fn fp_nonzero(&mut self) -> Result<Fp, Error> {
        loop {
            let value = Fp::from_words(self.word()?, self.word()? & (u64::MAX >> 1));
            if value != Fp::ZERO {
                return Ok(value);
            }
        }
    }
    fn nonce128(&mut self) -> Result<[u64; 2], Error> {
        Ok([self.word()?, self.word()?])
    }
}
impl EncryptionRng for CtrRng {
    fn word(&mut self) -> Result<u64, Error> {
        Ok(self.next_u64())
    }
    fn bounded(&mut self, maximum: u64) -> Result<u64, Error> {
        Ok(Self::bounded(self, maximum))
    }
}
struct SystemEntropy<'a, R>(&'a mut R);
impl<R: RngCore + CryptoRng> EncryptionRng for SystemEntropy<'_, R> {
    fn word(&mut self) -> Result<u64, Error> {
        let mut bytes = Zeroizing::new([0; 8]);
        self.0
            .try_fill_bytes(&mut *bytes)
            .map_err(|_| Error("HFHE entropy unavailable"))?;
        Ok(u64::from_le_bytes(*bytes))
    }
    fn bounded(&mut self, maximum: u64) -> Result<u64, Error> {
        Ok(self.word()? % maximum)
    }
}

/// The raw, single-layer native primitive; callers supply a continuing seeded stream.
pub fn synthesize(
    public: &PublicKey,
    secret: &SecretKey,
    values: &[Fp],
    depth: i32,
    rng: &mut CtrRng,
) -> Result<Cipher, Error> {
    synthesize_with(public, secret, values, depth, rng)
}

/// Native unseeded encryption draws, supplied by the host's cryptographic entropy source.
pub fn synthesize_random<R: RngCore + CryptoRng>(
    public: &PublicKey,
    secret: &SecretKey,
    values: &[Fp],
    depth: i32,
    rng: &mut R,
) -> Result<Cipher, Error> {
    synthesize_with(public, secret, values, depth, &mut SystemEntropy(rng))
}

fn avoid(rng: &mut impl EncryptionRng, basis: usize, excluded: &[usize]) -> Result<usize, Error> {
    if excluded.len() >= basis {
        return Err(Error("pvac: selector exhausted"));
    }
    loop {
        let index = rng.bounded(basis as u64)? as usize;
        if !excluded.contains(&index) {
            return Ok(index);
        }
    }
}

struct Node {
    index: usize,
    sign: u8,
    weights: Zeroizing<Vec<Fp>>,
}

fn emit(
    public: &PublicKey,
    seed: RSeed,
    mask: &[Fp],
    node: &Node,
    rng: &mut impl EncryptionRng,
) -> Result<Edge, Error> {
    let idx = node.index as u16;
    Ok(Edge {
        layer_id: 0,
        idx,
        ch: node.sign,
        weights: node
            .weights
            .iter()
            .zip(mask)
            .map(|(&a, &b)| a * b)
            .collect(),
        sigma: matrix::sigma(public, seed, idx, node.sign, rng.word()?, 0)?,
    })
}

fn synthesize_with(
    public: &PublicKey,
    secret: &SecretKey,
    values: &[Fp],
    depth: i32,
    rng: &mut impl EncryptionRng,
) -> Result<Cipher, Error> {
    let slots = values.len();
    let mut layer = Layer::default();
    let mut masks = Zeroizing::new(Vec::new());
    for _ in 0..16 {
        layer.seed.nonce = rng.nonce128()?;
        layer.seed.ztag = matrix::layer_tag(public.canon_tag, layer.seed.nonce);
        let candidate =
            circuit_prf::slots(public, secret, layer.seed.ztag, layer.seed.nonce, slots)?;
        if !candidate.is_empty() && circuit_prf::slots_nonzero(&candidate) {
            masks = candidate;
            break;
        }
    }
    if masks.is_empty() {
        return Err(Error("pvac: circuit prf nonzero mask generation failed"));
    }
    let (n2, n3) = plan_noise(public, depth)?;
    let mut deltas = Vec::new();
    deltas
        .try_reserve_exact(n2 + n3)
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    let mut target = Zeroizing::new(values.to_vec());
    for group in 0..n2 + n3 {
        let delta = circuit_prf::delta_slots(
            public,
            secret,
            layer.seed.ztag,
            layer.seed.nonce,
            group as u32,
            u8::from(group >= n2),
            slots,
        )?;
        for (a, &b) in target.iter_mut().zip(delta.iter()) {
            *a = *a - b;
        }
        deltas.push(delta);
    }
    layer.r_com = circuit_prf::base_commitment(public, layer.seed.ztag, layer.seed.nonce, &masks);
    (layer.r_pc, layer.pc) = circuit_prf::layer_commitments(secret, layer.seed.nonce, &masks)?;
    let basis = public.params.basis as usize;
    let mut used = Vec::with_capacity(8);
    let mut nodes = Vec::with_capacity(8);
    for _ in 0..8 {
        let weights = Zeroizing::new(
            (0..slots)
                .map(|_| rng.fp_nonzero())
                .collect::<Result<Vec<_>, _>>()?,
        );
        let index = avoid(rng, basis, &used)?;
        used.push(index);
        nodes.push(Node {
            index,
            sign: (rng.word()? & 1) as u8,
            weights,
        });
    }
    for node in &nodes[..7] {
        for (value, &weight) in target.iter_mut().zip(node.weights.iter()) {
            *value = *value - signed(weight * public.powers[node.index], node.sign);
        }
    }
    let last = &mut nodes[7];
    let inverse = public.powers[last.index].inverse();
    for (weight, &remainder) in last.weights.iter_mut().zip(target.iter()) {
        *weight = signed(remainder * inverse, last.sign);
    }
    let mut edges = Vec::new();
    for node in nodes {
        edges.push(emit(public, layer.seed, &masks, &node, rng)?);
    }
    for (group, delta) in deltas.iter().enumerate() {
        let a = rng.bounded(basis as u64)? as usize;
        let b = avoid(rng, basis, &[a])?;
        if group < n2 {
            let sa = (rng.word()? & 1) as u8;
            let mut ra = Zeroizing::new(vec![Fp::ZERO; slots]);
            let mut rb = Zeroizing::new(vec![Fp::ZERO; slots]);
            let inverse = public.powers[b].inverse();
            for j in 0..slots {
                ra[j] = rng.fp_nonzero()?;
                rb[j] = (ra[j] * public.powers[a] - signed(delta[j], sa)) * inverse;
            }
            for node in [
                Node {
                    index: a,
                    sign: sa,
                    weights: ra,
                },
                Node {
                    index: b,
                    sign: sa ^ 1,
                    weights: rb,
                },
            ] {
                edges.push(emit(public, layer.seed, &masks, &node, rng)?);
            }
        } else {
            let c = avoid(rng, basis, &[a, b])?;
            let sa = (rng.word()? & 1) as u8;
            let sb = (rng.word()? & 1) as u8;
            let sc = (rng.word()? & 1) as u8;
            let inverse = signed(public.powers[c], sc).inverse();
            let mut ra = Zeroizing::new(vec![Fp::ZERO; slots]);
            let mut rb = Zeroizing::new(vec![Fp::ZERO; slots]);
            let mut rc = Zeroizing::new(vec![Fp::ZERO; slots]);
            for j in 0..slots {
                ra[j] = rng.fp_nonzero()?;
                rb[j] = rng.fp_nonzero()?;
                rc[j] = (delta[j]
                    - signed(ra[j] * public.powers[a], sa)
                    - signed(rb[j] * public.powers[b], sb))
                    * inverse;
            }
            for node in [
                Node {
                    index: a,
                    sign: sa,
                    weights: ra,
                },
                Node {
                    index: b,
                    sign: sb,
                    weights: rb,
                },
                Node {
                    index: c,
                    sign: sc,
                    weights: rc,
                },
            ] {
                edges.push(emit(public, layer.seed, &masks, &node, rng)?);
            }
        }
    }
    merge_edges(public, &mut edges)?;
    for i in (2..=edges.len()).rev() {
        edges.swap(i - 1, rng.bounded(i as u64)? as usize);
    }
    Ok(Cipher {
        slots,
        layers: vec![layer],
        edges,
        c0: vec![Fp::ZERO; slots],
    })
}

pub fn seed_scope(
    public: &PublicKey,
    seed: &[u8; 32],
    operation: &[u8],
    slots: usize,
    depth: i32,
    values: &[Fp],
) -> Zeroizing<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"pvac.enc.seed.v2");
    hash.update(seed);
    hash.update(public.canon_tag.to_be_bytes());
    hash.update(public.h_digest);
    hash.update(
        &operation[..operation
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(operation.len())],
    );
    for word in [slots as u64, i64::from(depth) as u64, values.len() as u64] {
        hash.update(word.to_be_bytes());
    }
    for value in values {
        let (lo, hi) = value.words();
        hash.update(lo.to_be_bytes());
        hash.update(hi.to_be_bytes());
    }
    let mut output = Zeroizing::new([0; 32]);
    hash.finalize_into((&mut *output).into());
    output
}

fn wrapped(
    public: &PublicKey,
    secret: &SecretKey,
    values: &[Fp],
    operation: &[u8],
    depth: i32,
    seed: &[u8; 32],
) -> Result<Cipher, Error> {
    let scope = seed_scope(public, seed, operation, values.len(), depth, values);
    let mut rng = CtrRng::seeded(&scope);
    let mut mask = Zeroizing::new(
        (0..values.len())
            .map(|_| rng.fp_nonzero())
            .collect::<Vec<_>>(),
    );
    let positive = Zeroizing::new(
        values
            .iter()
            .zip(mask.iter())
            .map(|(&a, &b)| a + b)
            .collect::<Vec<_>>(),
    );
    let mut a = synthesize(public, secret, &positive, depth, &mut rng)?;
    for value in mask.iter_mut() {
        *value = -*value;
    }
    let b = synthesize(public, secret, &mask, depth, &mut rng)?;
    let offset = a.layers.len() as u32;
    a.layers.extend(b.layers);
    a.edges.extend(b.edges.into_iter().map(|mut edge| {
        edge.layer_id += offset;
        edge
    }));
    guard_budget(public, &mut a)?;
    Ok(a)
}

pub fn value_seeded(
    public: &PublicKey,
    secret: &SecretKey,
    value: u64,
    seed: &[u8; 32],
) -> Result<Cipher, Error> {
    wrapped(
        public,
        secret,
        &[Fp::from_words(value, 0)],
        b"value",
        0,
        seed,
    )
}

pub fn value_depth_seeded(
    public: &PublicKey,
    secret: &SecretKey,
    value: u64,
    depth: i32,
    seed: &[u8; 32],
) -> Result<Cipher, Error> {
    wrapped(
        public,
        secret,
        &[Fp::from_words(value, 0)],
        b"value_depth",
        depth,
        seed,
    )
}

pub fn values_seeded(
    public: &PublicKey,
    secret: &SecretKey,
    values: &[u64],
    seed: &[u8; 32],
) -> Result<Cipher, Error> {
    let fields = Zeroizing::new(
        values
            .iter()
            .map(|&value| Fp::from_words(value, 0))
            .collect::<Vec<_>>(),
    );
    wrapped(public, secret, &fields, b"values", 0, seed)
}

pub fn zero_seeded(
    public: &PublicKey,
    secret: &SecretKey,
    seed: &[u8; 32],
) -> Result<Cipher, Error> {
    wrapped(public, secret, &[Fp::ZERO], b"zero", 0, seed)
}

/// Wrapped unseeded encryption. The adopted Clang build evaluates the positive
/// argument first; ciphertext bytes and entropy draws are qualified separately.
pub fn fields_random<R: RngCore + CryptoRng>(
    public: &PublicKey,
    secret: &SecretKey,
    values: &[Fp],
    depth: i32,
    rng: &mut R,
) -> Result<Cipher, Error> {
    let mut rng = SystemEntropy(rng);
    let mut mask = Zeroizing::new(
        values
            .iter()
            .map(|_| rng.fp_nonzero())
            .collect::<Result<Vec<_>, _>>()?,
    );
    let positive = Zeroizing::new(
        values
            .iter()
            .zip(mask.iter())
            .map(|(&a, &b)| a + b)
            .collect::<Vec<_>>(),
    );
    let mut left = synthesize_with(public, secret, &positive, depth, &mut rng)?;
    for value in mask.iter_mut() {
        *value = -*value;
    }
    let right = synthesize_with(public, secret, &mask, depth, &mut rng)?;
    let offset = left.layers.len() as u32;
    left.layers.extend(right.layers);
    left.edges.extend(right.edges.into_iter().map(|mut edge| {
        edge.layer_id += offset;
        edge
    }));
    guard_budget(public, &mut left)?;
    Ok(left)
}
pub fn value_random<R: RngCore + CryptoRng>(
    public: &PublicKey,
    secret: &SecretKey,
    value: u64,
    rng: &mut R,
) -> Result<Cipher, Error> {
    fields_random(public, secret, &[Fp::from_u64(value)], 0, rng)
}
