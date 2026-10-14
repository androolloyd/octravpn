// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native v1-v5 cipher decoding, with the adopted v3 outgoing encoding.
use crate::{
    cipher::{Cipher, Edge, Layer, RSeed},
    field::Fp,
    keys::BitVec,
    Error,
};
use curve25519_dalek::ristretto::CompressedRistretto;

struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
    fn cipher(&mut self, version: u8, strict: bool, cap: bool) -> Result<Cipher, Error> {
        let raw_slots = self.u64()?;
        if raw_slots == 0 && (strict || cap) {
            return Err(Error("pvac_ser: cipher slots must be positive"));
        }
        if raw_slots > usize::MAX as u64
            || (cap && raw_slots > 1 << 16)
            || (strict && version >= 4 && raw_slots > 8)
        {
            return Err(Error("pvac_ser: cipher slots exceed maximum"));
        }
        let slots = raw_slots as usize;
        let count = self.count(8)?;
        if slots != 0
            && (strict || cap)
            && version >= 4
            && (slots > 1 << 12 || count > (1 << 12) / slots)
        {
            return Err(Error("pvac_ser: public cipher size exceeds maximum"));
        }
        let layers = (0..count)
            .map(|_| self.layer(version, slots))
            .collect::<Result<_, _>>()?;
        let count = self.count(16)?;
        let c0 = (0..count).map(|_| self.fp()).collect::<Result<_, _>>()?;
        let count = self.count(8)?;
        let edges = (0..count).map(|_| self.edge()).collect::<Result<_, _>>()?;
        Ok(Cipher {
            layers,
            edges,
            c0,
            slots,
        })
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let result = self
            .data
            .get(self.position..self.position.saturating_add(N))
            .ok_or(Error("pvac_ser: truncated"))?;
        self.position += N;
        Ok(result.try_into().unwrap())
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.bytes::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.bytes()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.bytes()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.bytes()?))
    }
    fn fp(&mut self) -> Result<Fp, Error> {
        Fp::from_bytes_le(self.bytes()?).ok_or(Error("pvac_ser: noncanonical field element"))
    }
    fn count(&mut self, width: usize) -> Result<usize, Error> {
        let count = self.u64()?;
        self.check_count(count, width)?;
        Ok(count as usize)
    }
    fn check_count(&self, count: u64, width: usize) -> Result<(), Error> {
        if width > 0 && count > (self.remaining() / width) as u64 {
            return Err(Error("pvac_ser: count exceeds remaining data"));
        }
        if count > 1 << 24 {
            return Err(Error("pvac_ser: count exceeds maximum"));
        }
        Ok(())
    }
    fn points(&mut self) -> Result<Vec<[u8; 32]>, Error> {
        let count = self.count(32)?;
        (0..count)
            .map(|_| {
                let bytes = self.bytes()?;
                if CompressedRistretto(bytes).decompress().is_none() {
                    return Err(Error("pvac_ser: invalid Ristretto point encoding"));
                }
                Ok(bytes)
            })
            .collect()
    }
    fn bitvec(&mut self) -> Result<BitVec, Error> {
        let nbits = self.u64()?;
        let count = self.u64()?;
        if nbits > 1 << 20 {
            return Err(Error("pvac_ser: bitvec too large"));
        }
        self.check_count(count, 8)?;
        if count != nbits.div_ceil(64) {
            return Err(Error("pvac_ser: bitvec word count mismatch"));
        }
        Ok(BitVec {
            nbits: nbits as usize,
            words: (0..count).map(|_| self.u64()).collect::<Result<_, _>>()?,
        })
    }
    fn layer(&mut self, version: u8, slots: usize) -> Result<Layer, Error> {
        let mut layer = Layer {
            rule: self.u8()?,
            ..Layer::default()
        };
        if layer.rule == 0 {
            layer.seed = RSeed {
                ztag: self.u64()?,
                nonce: [self.u64()?, self.u64()?],
            };
        } else {
            layer.pa = self.u32()?;
            layer.pb = self.u32()?;
        }
        if version < 4 {
            layer.r_com = self.bytes()?;
        }
        if version == 3 {
            layer.r_pc = self.points()?;
        }
        if (2..4).contains(&version) {
            layer.pc = self.points()?;
        }
        if version >= 4 && layer.rule == 0 {
            layer
                .r_pc
                .try_reserve_exact(slots)
                .map_err(|_| Error("HFHE allocation unavailable"))?;
            layer.r_pc.resize(slots, [0; 32]);
        }
        Ok(layer)
    }
    fn edge(&mut self) -> Result<Edge, Error> {
        let layer_id = self.u32()?;
        let idx = self.u16()?;
        let ch = self.u8()?;
        let count = self.count(16)?;
        let weights = (0..count).map(|_| self.fp()).collect::<Result<_, _>>()?;
        Ok(Edge {
            layer_id,
            idx,
            ch,
            weights,
            sigma: self.bitvec()?,
        })
    }
}

impl Cipher {
    /// Serialize the adopted native v3 format. Cipher bytes are not compressed.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate_structure()?;
        let mut out = b"PVAC\x03\x00".to_vec();
        out.extend_from_slice(&(self.slots as u64).to_le_bytes());
        out.extend_from_slice(&(self.layers.len() as u64).to_le_bytes());
        for layer in &self.layers {
            out.push(layer.rule);
            if layer.rule == 0 {
                out.extend_from_slice(&layer.seed.ztag.to_le_bytes());
                for nonce in layer.seed.nonce {
                    out.extend_from_slice(&nonce.to_le_bytes());
                }
            } else {
                out.extend_from_slice(&layer.pa.to_le_bytes());
                out.extend_from_slice(&layer.pb.to_le_bytes());
            }
            out.extend_from_slice(&layer.r_com);
            for points in [&layer.r_pc, &layer.pc] {
                out.extend_from_slice(&(points.len() as u64).to_le_bytes());
                for point in points {
                    out.extend_from_slice(point);
                }
            }
        }
        out.extend_from_slice(&(self.c0.len() as u64).to_le_bytes());
        for value in &self.c0 {
            out.extend_from_slice(&value.to_bytes_le());
        }
        out.extend_from_slice(&(self.edges.len() as u64).to_le_bytes());
        for edge in &self.edges {
            out.extend_from_slice(&edge.layer_id.to_le_bytes());
            out.extend_from_slice(&edge.idx.to_le_bytes());
            out.push(edge.ch);
            out.extend_from_slice(&(edge.weights.len() as u64).to_le_bytes());
            for value in &edge.weights {
                out.extend_from_slice(&value.to_bytes_le());
            }
            out.extend_from_slice(&(edge.sigma.nbits as u64).to_le_bytes());
            out.extend_from_slice(&(edge.sigma.words.len() as u64).to_le_bytes());
            for word in &edge.sigma.words {
                out.extend_from_slice(&word.to_le_bytes());
            }
        }
        Ok(out)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        Self::from_bytes_with_policy(data, true, true)
    }

    /// Preserve the native reader's policy flags. Disabling both flags is the
    /// historical trusted-input mode; its sizes must be bounded by the caller.
    pub fn from_bytes_with_policy(data: &[u8], strict: bool, cap: bool) -> Result<Self, Error> {
        let mut reader = Reader::new(data);
        if &reader.bytes::<4>()? != b"PVAC" {
            return Err(Error("pvac_ser: bad magic"));
        }
        let version = reader.u8()?;
        if !(1..=5).contains(&version) {
            return Err(Error("pvac_ser: bad version"));
        }
        if reader.u8()? != 0 {
            return Err(Error("pvac_ser: wrong type tag"));
        }
        let cipher = reader.cipher(version, strict, cap)?;
        if reader.remaining() != 0 {
            return Err(Error("pvac_ser: trailing cipher bytes"));
        }
        cipher.validate_structure()?;
        Ok(cipher)
    }
}

pub(crate) fn read_raw(data: &[u8], version: u8) -> Result<(Cipher, usize), Error> {
    let mut reader = Reader::new(data);
    let cipher = reader.cipher(version, true, true)?;
    cipher.validate_structure()?;
    Ok((cipher, reader.position))
}
