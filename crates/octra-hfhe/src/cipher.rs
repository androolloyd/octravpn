// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Ciphertext structure shared by the native-compatible wire and arithmetic ports.
use crate::{
    field::Fp,
    keys::{BitVec, PublicKey},
    Error,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RSeed {
    pub ztag: u64,
    pub nonce: [u64; 2],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Layer {
    pub rule: u8,
    pub seed: RSeed,
    pub pa: u32,
    pub pb: u32,
    pub r_com: [u8; 32],
    pub r_pc: Vec<[u8; 32]>,
    pub pc: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Edge {
    pub layer_id: u32,
    pub idx: u16,
    pub ch: u8,
    pub weights: Vec<Fp>,
    pub sigma: BitVec,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cipher {
    pub(crate) layers: Vec<Layer>,
    pub(crate) edges: Vec<Edge>,
    pub(crate) c0: Vec<Fp>,
    pub(crate) slots: usize,
}

impl Default for Cipher {
    fn default() -> Self {
        Self {
            layers: Vec::new(),
            edges: Vec::new(),
            c0: Vec::new(),
            slots: 1,
        }
    }
}

impl Cipher {
    /// Hash the native commitment transcript, which is distinct from wire bytes.
    pub fn commitment(&self, public: &PublicKey) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"pvac.dom.commit");
        hash.update(public.h_digest);
        hash.update(public.canon_tag.to_le_bytes());
        hash.update((self.layers.len() as u64).to_le_bytes());
        for layer in &self.layers {
            hash.update([layer.rule]);
            if layer.rule == 0 {
                hash.update(layer.seed.ztag.to_le_bytes());
                for nonce in layer.seed.nonce {
                    hash.update(nonce.to_le_bytes());
                }
            } else {
                hash.update(u64::from(layer.pa).to_le_bytes());
                hash.update(u64::from(layer.pb).to_le_bytes());
            }
            hash.update(layer.r_com);
            for points in [&layer.r_pc, &layer.pc] {
                hash.update((points.len() as u64).to_le_bytes());
                for point in points {
                    hash.update(point);
                }
            }
        }
        hash.update((self.slots as u64).to_le_bytes());
        hash.update((self.c0.len() as u64).to_le_bytes());
        for value in &self.c0 {
            hash.update(value.to_bytes_le());
        }
        hash.update((self.edges.len() as u64).to_le_bytes());
        for edge in &self.edges {
            hash.update(u64::from(edge.layer_id).to_le_bytes());
            hash.update(u64::from(edge.idx).to_le_bytes());
            hash.update([edge.ch]);
            hash.update((edge.weights.len() as u64).to_le_bytes());
            for value in &edge.weights {
                hash.update(value.to_bytes_le());
            }
            let mut remaining = edge.sigma.nbits.div_ceil(8);
            for word in &edge.sigma.words {
                let take = remaining.min(8);
                hash.update(&word.to_le_bytes()[..take]);
                remaining -= take;
            }
        }
        hash.finalize().into()
    }

    /// Apply the public UBK permutation. Return an error for out-of-bounds
    /// shapes that would make the native helper access memory outside a vector.
    pub fn apply_ubk(&mut self, public: &PublicKey) -> Result<(), Error> {
        let mut sigmas = Vec::with_capacity(self.edges.len());
        for edge in &self.edges {
            let mut words = vec![0; edge.sigma.nbits.div_ceil(64)];
            for (index, &input) in edge.sigma.words.iter().enumerate() {
                let mut value = input;
                while value != 0 {
                    let source = index * 64 + value.trailing_zeros() as usize;
                    if source < edge.sigma.nbits {
                        let destination = *public
                            .inverse
                            .get(source)
                            .ok_or(Error("HFHE sigma permutation shape rejected"))?
                            as usize;
                        let word = words
                            .get_mut(destination >> 6)
                            .ok_or(Error("HFHE sigma permutation shape rejected"))?;
                        *word |= 1 << (destination & 63);
                    }
                    value &= value - 1;
                }
            }
            sigmas.push(words);
        }
        for (edge, words) in self.edges.iter_mut().zip(sigmas) {
            edge.sigma.words = words;
        }
        Ok(())
    }

    pub fn slots(&self) -> usize {
        self.slots
    }

    /// Native private-balance recovery counts base layers, including repeated
    /// seeds. This is deliberately different from counting distinct masks.
    pub fn base_layers(&self) -> Result<usize, Error> {
        self.validate_structure()
            .map_err(|_| Error("cipher structure rejected"))?;
        Ok(self.layers.iter().filter(|layer| layer.rule == 0).count())
    }

    pub fn compatible_with(&self, public: &PublicKey) -> bool {
        public.validate_shape().is_ok()
            && self.validate_structure().is_ok()
            && self.edges.iter().all(|edge| {
                (edge.idx as usize) < public.powers.len()
                    && edge.sigma.nbits == public.params.m_bits as usize
            })
    }

    /// The exact native structural checks, independent of network profile policy.
    pub fn validate_structure(&self) -> Result<(), Error> {
        if self.slots == 0 {
            return Err(Error("pvac_ser: cipher slots must be positive"));
        }
        if !self.c0.is_empty() && self.c0.len() != self.slots {
            return Err(Error("pvac_ser: c0/slots size mismatch"));
        }
        for (index, layer) in self.layers.iter().enumerate() {
            if ![0, 1].contains(&layer.rule) {
                return Err(Error("pvac_ser: invalid layer rule"));
            }
            if layer.rule == 1 && (layer.pa as usize >= index || layer.pb as usize >= index) {
                return Err(Error("pvac_ser: invalid product parent"));
            }
            if layer.rule == 1 && !layer.pc.is_empty() {
                return Err(Error("pvac_ser: product layer must not contain PC"));
            }
            if layer.rule == 1 && !layer.r_pc.is_empty() {
                return Err(Error("pvac_ser: product layer must not contain R_PC"));
            }
            if !layer.pc.is_empty() && layer.pc.len() != self.slots {
                return Err(Error("pvac_ser: layer PC/slots size mismatch"));
            }
            if !layer.r_pc.is_empty() && layer.r_pc.len() != self.slots {
                return Err(Error("pvac_ser: layer R_PC/slots size mismatch"));
            }
        }
        for edge in &self.edges {
            if edge.layer_id as usize >= self.layers.len() {
                return Err(Error("pvac_ser: edge layer out of range"));
            }
            if ![0, 1].contains(&edge.ch) {
                return Err(Error("pvac_ser: invalid edge sign"));
            }
            if edge.weights.len() != self.slots {
                return Err(Error("pvac_ser: edge weight/slots size mismatch"));
            }
        }
        Ok(())
    }
}

impl Cipher {
    /// Exact FFI wrapped-scalar shape predicate; this does not verify proofs.
    pub fn is_wrapped_scalar(&self) -> bool {
        self.validate_structure().is_ok()
            && self.slots == 1
            && self.layers.len() == 2
            && self.c0 == [Fp::ZERO]
            && self
                .layers
                .iter()
                .all(|layer| layer.rule == 0 && layer.r_pc.len() == 1 && layer.pc.len() == 1)
    }
}
