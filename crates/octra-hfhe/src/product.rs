// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Seeded native ciphertext multiplication, including repack draw order.
use sha2::{Digest, Sha256};

use crate::{
    arithmetic::guard_budget,
    cipher::{Cipher, Edge, Layer, RSeed},
    field::Fp,
    keys::PublicKey,
    matrix,
    seeded_rng::CtrRng,
    Error,
};

fn allocate<T>(capacity: usize) -> Result<Vec<T>, Error> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    Ok(output)
}

fn zeros(length: usize) -> Result<Vec<Fp>, Error> {
    let mut output = allocate(length)?;
    output.resize(length, Fp::ZERO);
    Ok(output)
}

fn multiply(left: &[Fp], right: &[Fp]) -> Result<Vec<Fp>, Error> {
    if left.len() != right.len() {
        return Err(Error("pvac: field mul: vector size mismatch"));
    }
    let mut output = allocate(left.len())?;
    output.extend(left.iter().zip(right).map(|(&a, &b)| a * b));
    Ok(output)
}

fn fold_edges(public: &PublicKey, cipher: &Cipher) -> Result<Vec<Vec<Fp>>, Error> {
    if !cipher.compatible_with(public) {
        return Err(Error(
            "pvac: fold_edges: cipher is incompatible with public key",
        ));
    }
    let mut sums = allocate(cipher.layers.len())?;
    for _ in &cipher.layers {
        sums.push(zeros(cipher.slots)?);
    }
    for edge in &cipher.edges {
        let generator = public.powers[edge.idx as usize];
        for (sum, &weight) in sums[edge.layer_id as usize].iter_mut().zip(&edge.weights) {
            let value = weight * generator;
            *sum = if edge.ch == 0 {
                *sum + value
            } else {
                *sum - value
            };
        }
    }
    Ok(sums)
}

fn product_layer(public: &PublicKey, layers: &[Layer], a: u32, b: u32, rng: &mut CtrRng) -> Layer {
    let nonce = rng.nonce128();
    let (pa, pb) = if a < b { (a, b) } else { (b, a) };
    let mut hash = Sha256::new();
    hash.update(b"pvac.dom.r_com");
    hash.update(layers[pa as usize].r_com);
    hash.update(layers[pb as usize].r_com);
    Layer {
        rule: 1,
        seed: RSeed {
            ztag: matrix::layer_tag(public.canon_tag, nonce),
            nonce,
        },
        pa,
        pb,
        r_com: hash.finalize().into(),
        ..Layer::default()
    }
}

pub(crate) fn emit_repack(
    public: &PublicKey,
    layer: &Layer,
    layer_id: u32,
    target: &[Fp],
    count: usize,
    rng: &mut CtrRng,
    draw_factor: usize,
) -> Result<Vec<Edge>, Error> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let basis = public.params.basis;
    if basis <= 0 || count > basis as usize || count > usize::from(u16::MAX) + 1 {
        return Err(Error("pvac: index count exceeds domain"));
    }
    let mut indices = Vec::with_capacity(count);
    while indices.len() < count {
        // The native cast occurs before duplicate rejection.
        let index = rng.bounded(basis as u64) as u16;
        if !indices.contains(&index) {
            indices.push(index);
        }
    }
    let specs: Vec<_> = indices
        .into_iter()
        .map(|index| (index, (rng.next_u64() & 1) as u8))
        .collect();
    let mut sum = zeros(target.len())?;
    let mut edges = Vec::with_capacity(count);
    for (position, &(index, sign)) in specs.iter().enumerate() {
        let weights = if position + 1 < count {
            let mut weights = allocate(target.len())?;
            weights.extend((0..target.len()).map(|_| rng.fp_nonzero()));
            for (total, &weight) in sum.iter_mut().zip(&weights) {
                let value = weight * public.powers[index as usize];
                *total = if sign == 0 {
                    *total + value
                } else {
                    *total - value
                };
            }
            weights
        } else {
            let inverse = public.powers[((basis - i32::from(index)) % basis) as usize];
            let mut weights = allocate(target.len())?;
            weights.extend(target.iter().zip(&sum).map(|(&target, &total)| {
                let difference = target - total;
                (if sign == 1 { -difference } else { difference }) * inverse
            }));
            weights
        };
        edges.push(Edge {
            layer_id,
            idx: index,
            ch: sign,
            weights,
            sigma: matrix::sigma(public, layer.seed, index, sign, rng.next_u64(), draw_factor)?,
        });
    }
    Ok(edges)
}

fn append_scaled(
    target: &mut Vec<Edge>,
    source: &[Edge],
    scale: &[Fp],
    offset: u32,
) -> Result<(), Error> {
    if scale.iter().all(|value| *value == Fp::ZERO) {
        return Ok(());
    }
    for edge in source {
        let mut scaled = edge.clone();
        scaled.layer_id = scaled.layer_id.wrapping_add(offset);
        scaled.weights = multiply(&edge.weights, scale)?;
        target.push(scaled);
    }
    Ok(())
}

fn build_product(
    public: &PublicKey,
    a: &Cipher,
    b: Option<&Cipher>,
    repack: usize,
    rng: &mut CtrRng,
    draw_factor: usize,
) -> Result<Cipher, Error> {
    let sums_a = fold_edges(public, a)?;
    let sums_b = b.map(|b| fold_edges(public, b)).transpose()?;
    let mut result = Cipher {
        slots: a.slots,
        c0: zeros(a.slots)?,
        layers: a.layers.clone(),
        edges: Vec::new(),
    };
    let offset = result.layers.len() as u32;
    if let Some(b) = b {
        result
            .layers
            .extend(b.layers.iter().cloned().map(|mut layer| {
                if layer.rule == 1 {
                    layer.pa = layer.pa.wrapping_add(offset);
                    layer.pb = layer.pb.wrapping_add(offset);
                }
                layer
            }));
    }
    for (la, sum_a) in sums_a.iter().enumerate() {
        let partners = sums_b.as_deref().unwrap_or(&sums_a);
        let start = if b.is_some() { 0 } else { la };
        for (lb, sum_b) in partners.iter().enumerate().skip(start) {
            let parent_b = if b.is_some() {
                offset.wrapping_add(lb as u32)
            } else {
                lb as u32
            };
            let layer = product_layer(public, &result.layers, la as u32, parent_b, rng);
            let id = result.layers.len() as u32;
            result.layers.push(layer);
            let mut target = multiply(sum_a, sum_b)?;
            if b.is_none() && la != lb {
                for value in &mut target {
                    *value = *value + *value;
                }
            }
            result.edges.extend(emit_repack(
                public,
                &result.layers[id as usize],
                id,
                &target,
                repack,
                rng,
                draw_factor,
            )?);
        }
    }
    guard_budget(public, &mut result)?;
    result.compact_layers()?;
    Ok(result)
}

impl Cipher {
    pub fn multiply_seeded(
        &self,
        public: &PublicKey,
        other: &Self,
        seed: &[u8; 32],
        repack_slots: usize,
        math: bool,
        draw_factor: usize,
    ) -> Result<Self, Error> {
        if self.slots != other.slots {
            return Err(Error("pvac: ct_mul: slot count mismatch between operands"));
        }
        let mut rng = CtrRng::seeded(seed);
        let a0 = if math && self.c0.is_empty() {
            zeros(self.slots)?
        } else {
            self.c0.clone()
        };
        let b0 = if math && other.c0.is_empty() {
            zeros(other.slots)?
        } else {
            other.c0.clone()
        };
        let mut a = self.clone();
        let mut b = other.clone();
        a.c0 = zeros(a.slots)?;
        b.c0 = zeros(b.slots)?;
        let offset = a.layers.len() as u32;
        let mut result = build_product(
            public,
            &a,
            Some(&b),
            repack_slots.max(1),
            &mut rng,
            draw_factor,
        )?;
        append_scaled(&mut result.edges, &b.edges, &a0, offset)?;
        append_scaled(&mut result.edges, &a.edges, &b0, 0)?;
        result.c0 = multiply(&a0, &b0)?;
        guard_budget(public, &mut result)?;
        result.compact_layers()?;
        Ok(result)
    }

    pub fn square_seeded(
        &self,
        public: &PublicKey,
        seed: &[u8; 32],
        repack_slots: usize,
        math: bool,
    ) -> Result<Self, Error> {
        let mut rng = CtrRng::seeded(seed);
        let a0 = if math && self.c0.is_empty() {
            zeros(self.slots)?
        } else {
            self.c0.clone()
        };
        let mut a = self.clone();
        a.c0 = zeros(a.slots)?;
        let mut result = build_product(public, &a, None, repack_slots.max(1), &mut rng, 0)?;
        let mut twice = allocate(a0.len())?;
        twice.extend(a0.iter().map(|&value| value + value));
        append_scaled(&mut result.edges, &a.edges, &twice, 0)?;
        result.c0 = multiply(&a0, &a0)?;
        guard_budget(public, &mut result)?;
        result.compact_layers()?;
        Ok(result)
    }
}
