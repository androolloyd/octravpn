// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! The v1-v5 native key reader. Preserve error precedence and legacy defaults.
use curve25519_dalek::ristretto::CompressedRistretto;

use crate::{
    compression,
    field::Fp,
    keys::{BitVec, Params, PublicKey, SecretKey},
    Error,
};

struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let bytes = self
            .data
            .get(self.position..self.position.saturating_add(N))
            .ok_or(Error("pvac_ser: truncated"))?;
        self.position += N;
        Ok(bytes.try_into().unwrap())
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.bytes::<1>()?[0])
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.bytes()?))
    }
    fn i32(&mut self) -> Result<i32, Error> {
        Ok(i32::from_le_bytes(self.bytes()?))
    }
    fn f64(&mut self) -> Result<f64, Error> {
        Ok(f64::from_le_bytes(self.bytes()?))
    }
    fn fp(&mut self) -> Result<Fp, Error> {
        Fp::from_bytes_le(self.bytes()?).ok_or(Error("pvac_ser: noncanonical field element"))
    }
    fn count(&mut self, size: usize) -> Result<usize, Error> {
        let count = self.u64()?;
        self.check_count(count, size)?;
        Ok(count as usize)
    }
    fn check_count(&self, count: u64, size: usize) -> Result<(), Error> {
        if size > 0 && count > (self.remaining() / size) as u64 {
            return Err(Error("pvac_ser: count exceeds remaining data"));
        }
        if count > 1 << 24 {
            return Err(Error("pvac_ser: count exceeds maximum"));
        }
        Ok(())
    }
    fn header(&mut self, expected: u8) -> Result<u8, Error> {
        if &self.bytes::<4>()? != b"PVAC" {
            return Err(Error("pvac_ser: bad magic"));
        }
        let version = self.u8()?;
        if !(1..=5).contains(&version) {
            return Err(Error("pvac_ser: bad version"));
        }
        if self.u8()? != expected {
            return Err(Error("pvac_ser: wrong type tag"));
        }
        Ok(version)
    }
    fn bitvec(&mut self) -> Result<BitVec, Error> {
        let bits = self.u64()?;
        let count = self.u64()?;
        if bits > 1 << 20 {
            return Err(Error("pvac_ser: bitvec too large"));
        }
        self.check_count(count, 8)?;
        if count != bits.div_ceil(64) {
            return Err(Error("pvac_ser: bitvec word count mismatch"));
        }
        let mut words = Vec::with_capacity(count as usize);
        for _ in 0..count {
            words.push(self.u64()?);
        }
        Ok(BitVec {
            nbits: bits as usize,
            words,
        })
    }
    fn permutation(&mut self) -> Result<Vec<i32>, Error> {
        let count = self.count(4)?;
        (0..count).map(|_| self.i32()).collect()
    }
    fn params(&mut self) -> Result<Params, Error> {
        Ok(Params {
            basis: self.i32()?,
            m_bits: self.i32()?,
            n_bits: self.i32()?,
            h_col_weight: self.i32()?,
            x_col_weight: self.i32()?,
            error_weight: self.i32()?,
            noise_entropy_bits: self.f64()?,
            tuple2_fraction: self.f64()?,
            depth_slope_bits: self.f64()?,
            edge_budget: self.u64()?,
            lpn_n: self.i32()?,
            lpn_t: self.i32()?,
            lpn_tau_num: self.i32()?,
            lpn_tau_den: self.i32()?,
            recrypt_lo: self.f64()?,
            recrypt_hi: self.f64()?,
            recrypt_rounds: self.i32()?,
        })
    }
}

impl PublicKey {
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.first() == Some(&0xec) {
            Self::from_raw_bytes(&compression::unpack(data)?)
        } else {
            Self::from_raw_bytes(data)
        }
    }

    pub fn from_raw_bytes(data: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(data);
        let version = reader.header(1)?;
        let params = reader.params()?;
        let canon_tag = reader.u64()?;
        let columns = reader.count(8)?;
        let mut h = Vec::with_capacity(columns);
        for _ in 0..columns {
            h.push(reader.bitvec()?);
        }
        let permutation = reader.permutation()?;
        let inverse = reader.permutation()?;
        let h_digest = reader.bytes()?;
        let omega = reader.fp()?;
        let count = reader.count(16)?;
        let mut powers = Vec::with_capacity(count);
        for _ in 0..count {
            powers.push(reader.fp()?);
        }
        let circuit_commit = if version >= 3 {
            let bytes = reader.bytes()?;
            if CompressedRistretto(bytes).decompress().is_none() {
                return Err(Error("pvac_ser: invalid Ristretto point encoding"));
            }
            bytes
        } else {
            [0; 32]
        };
        let circuit_profile = if version >= 5 { reader.u8()? } else { 1 };
        if reader.remaining() != 0 {
            return Err(Error("pvac_ser: trailing pubkey bytes"));
        }
        let key = Self {
            params,
            canon_tag,
            h,
            permutation,
            inverse,
            h_digest,
            omega,
            powers,
            circuit_commit,
            circuit_profile,
        };
        key.validate_shape()?;
        Ok(key)
    }

    pub(crate) fn validate_shape(&self) -> Result<(), Error> {
        if self.params.basis <= 0 || self.params.m_bits <= 0 || self.params.n_bits <= 0 {
            return Err(Error("pvac_ser: invalid public key dimensions"));
        }
        if self.h.len() != self.params.n_bits as usize {
            return Err(Error("pvac_ser: H column count mismatch"));
        }
        let bits = self.params.m_bits as usize;
        if self.permutation.len() != bits || self.inverse.len() != bits {
            return Err(Error("pvac_ser: UBK size mismatch"));
        }
        let error = Error("pvac_ser: invalid UBK permutation");
        let mut seen_perm = vec![false; bits];
        let mut seen_inv = vec![false; bits];
        for (&p, &q) in self.permutation.iter().zip(&self.inverse) {
            if p < 0 || q < 0 || p as usize >= bits || q as usize >= bits {
                return Err(error);
            }
            if seen_perm[p as usize] || seen_inv[q as usize] {
                return Err(error);
            }
            seen_perm[p as usize] = true;
            seen_inv[q as usize] = true;
        }
        for (index, &p) in self.permutation.iter().enumerate() {
            if self.inverse[p as usize] != index as i32 {
                return Err(error);
            }
        }
        if self.powers.len() != self.params.basis as usize
            || self.h.iter().any(|column| column.nbits != bits)
            || ![1, 2].contains(&self.circuit_profile)
        {
            return Err(error);
        }
        Ok(())
    }
}

impl SecretKey {
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(data);
        let version = reader.header(2)?;
        let mut secret = Self {
            prf_key: [0; 4],
            circuit_key: Fp::ZERO,
            circuit_blind: [0; 32],
            circuit_key_v6: Fp::ZERO,
            circuit_blind_v6: [0; 32],
            lpn_bits: Vec::new(),
        };
        for word in &mut secret.prf_key {
            *word = reader.u64()?;
        }
        if version >= 3 {
            secret.circuit_key = reader.fp()?;
            secret.circuit_blind = reader.bytes()?;
        }
        if version >= 5 {
            secret.circuit_key_v6 = reader.fp()?;
            secret.circuit_blind_v6 = reader.bytes()?;
        } else {
            secret.circuit_key_v6 = secret.circuit_key;
            secret.circuit_blind_v6 = secret.circuit_blind;
        }
        let count = reader.count(8)?;
        secret.lpn_bits.reserve_exact(count);
        for _ in 0..count {
            secret.lpn_bits.push(reader.u64()?);
        }
        if reader.remaining() != 0 {
            return Err(Error("pvac_ser: trailing seckey bytes"));
        }
        Ok(secret)
    }
}
