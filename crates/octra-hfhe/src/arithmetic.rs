// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native linear ciphertext arithmetic and graph compaction.
use crate::{
    cipher::{Cipher, Edge},
    field::Fp,
    keys::PublicKey,
    Error,
};

pub(crate) fn merge_edges(public: &PublicKey, edges: &mut Vec<Edge>) -> Result<(), Error> {
    let Some(first) = edges.first() else {
        return Ok(());
    };
    let basis = public.params.basis;
    if basis <= 0 {
        return Err(Error("pvac: merge basis rejected"));
    }
    let slots = first.weights.len();
    if slots == 0 {
        return Err(Error("pvac: merge slot shape rejected"));
    }
    let mut max_layer = 0;
    for edge in edges.iter() {
        if edge.idx as usize >= basis as usize {
            return Err(Error("pvac: merge edge index rejected"));
        }
        if ![0, 1].contains(&edge.ch) {
            return Err(Error("pvac: merge edge sign rejected"));
        }
        if edge.weights.len() != slots {
            return Err(Error("pvac: merge edge width rejected"));
        }
        if edge.sigma.nbits != public.params.m_bits as usize {
            return Err(Error("pvac: merge edge sigma rejected"));
        }
        max_layer = max_layer.max(edge.layer_id);
    }
    if max_layer as usize + 1 > usize::MAX / basis as usize {
        return Err(Error("pvac: merge edge domain rejected"));
    }
    let position = |edge: &Edge| (edge.layer_id, edge.idx, edge.ch == 1);
    edges.sort_by_key(position);
    let mut input = std::mem::take(edges).into_iter().peekable();
    while let Some(mut sum) = input.next() {
        while input
            .peek()
            .is_some_and(|next| position(&sum) == position(next))
        {
            let next = input.next().unwrap();
            for (left, right) in sum.weights.iter_mut().zip(next.weights) {
                *left = *left + right;
            }
            for (left, right) in sum.sigma.words.iter_mut().zip(next.sigma.words) {
                *left ^= right;
            }
        }
        if sum.weights.iter().any(|value| *value != Fp::ZERO)
            || sum.sigma.words.iter().any(|word| *word != 0)
        {
            edges.push(sum);
        }
    }
    Ok(())
}

pub(crate) fn guard_budget(public: &PublicKey, cipher: &mut Cipher) -> Result<(), Error> {
    if cipher.edges.len() as u64 > public.params.edge_budget {
        merge_edges(public, &mut cipher.edges)?;
    }
    Ok(())
}

impl Cipher {
    /// Match the native soft budget: compact once above the threshold, without
    /// rejecting a result that still exceeds it.
    pub fn compact_over_budget(&mut self, public: &PublicKey) -> Result<(), Error> {
        guard_budget(public, self)
    }

    pub fn compact_edges(&mut self, public: &PublicKey) -> Result<(), Error> {
        merge_edges(public, &mut self.edges)
    }

    pub fn compact_layers(&mut self) -> Result<(), Error> {
        if self.validate_structure().is_err() {
            return Err(Error("pvac: compact layers shape rejected"));
        }
        let mut live = vec![false; self.layers.len()];
        for edge in &self.edges {
            live[edge.layer_id as usize] = true;
        }
        // Structural validation makes every product parent precede its child;
        // reverse traversal computes the same closure as the native fixed point.
        for index in (0..self.layers.len()).rev() {
            let layer = &self.layers[index];
            if live[index] && layer.rule == 1 {
                live[layer.pa as usize] = true;
                live[layer.pb as usize] = true;
            }
        }
        if live.iter().all(|value| *value) {
            return Ok(());
        }
        let mut remap = vec![u32::MAX; self.layers.len()];
        let mut layers = Vec::new();
        for (index, layer) in std::mem::take(&mut self.layers).into_iter().enumerate() {
            if live[index] {
                remap[index] = layers.len() as u32;
                layers.push(layer);
            }
        }
        for layer in &mut layers {
            if layer.rule == 1 {
                layer.pa = remap[layer.pa as usize];
                layer.pb = remap[layer.pb as usize];
            }
        }
        for edge in &mut self.edges {
            edge.layer_id = remap[edge.layer_id as usize];
        }
        self.layers = layers;
        Ok(())
    }

    pub fn scale(&self, factor: Fp) -> Self {
        let mut result = self.clone();
        for edge in &mut result.edges {
            for weight in &mut edge.weights {
                *weight = *weight * factor;
            }
        }
        for value in &mut result.c0 {
            *value = *value * factor;
        }
        result
    }

    pub fn negate(&self) -> Self {
        self.scale(-Fp::ONE)
    }

    pub fn add(&self, public: &PublicKey, other: &Self) -> Result<Self, Error> {
        if self.slots != other.slots {
            return Err(Error("pvac: ct_add: slot count mismatch between operands"));
        }
        let mut result = self.clone();
        if result.c0.is_empty() {
            result.c0.clone_from(&other.c0);
        } else if !other.c0.is_empty() {
            for (left, right) in result.c0.iter_mut().zip(&other.c0) {
                *left = *left + *right;
            }
        }
        let offset = result.layers.len() as u32;
        result
            .layers
            .extend(other.layers.iter().cloned().map(|mut layer| {
                if layer.rule == 1 {
                    layer.pa = layer.pa.wrapping_add(offset);
                    layer.pb = layer.pb.wrapping_add(offset);
                }
                layer
            }));
        result
            .edges
            .extend(other.edges.iter().cloned().map(|mut edge| {
                edge.layer_id = edge.layer_id.wrapping_add(offset);
                edge
            }));
        guard_budget(public, &mut result)?;
        result.compact_layers()?;
        Ok(result)
    }

    pub fn subtract(&self, public: &PublicKey, other: &Self) -> Result<Self, Error> {
        self.add(public, &other.negate())
    }

    pub fn add_constant(&self, value: Fp, math: bool) -> Result<Self, Error> {
        let mut result = self.clone();
        if math && result.c0.is_empty() {
            result
                .c0
                .try_reserve_exact(result.slots)
                .map_err(|_| Error("HFHE allocation unavailable"))?;
            result.c0.resize(result.slots, Fp::ZERO);
        }
        for constant in &mut result.c0 {
            *constant = *constant + value;
        }
        Ok(result)
    }

    pub fn subtract_constant(&self, value: Fp, math: bool) -> Result<Self, Error> {
        self.add_constant(-value, math)
    }

    pub fn divide_constant(&self, value: Fp) -> Result<Self, Error> {
        if value == Fp::ZERO {
            return Err(Error("pvac: zero divisor"));
        }
        Ok(self.scale(value.inverse()))
    }

    pub fn mul_constant_u64(&self, value: u64) -> Self {
        self.scale(Fp::from_u64(value))
    }

    pub fn mul_constant_i64(&self, value: i64) -> Self {
        let magnitude = Fp::from_u64(value.unsigned_abs());
        self.scale(if value < 0 { -magnitude } else { magnitude })
    }
}
