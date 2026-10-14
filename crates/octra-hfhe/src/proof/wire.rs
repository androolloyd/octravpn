// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native zero proof wire format. Decoding validates encoding, not proof truth.
use super::{
    generators::{self, Point},
    inner_product::InnerProductProof,
    r1cs::{self, Proof},
    zero::ZeroProof,
};
use crate::{scalar::Scalar, Error};
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl Reader<'_> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
    fn raw<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let value = self
            .bytes
            .get(self.position..self.position.saturating_add(N))
            .ok_or(Error("pvac_ser: truncated"))?;
        self.position += N;
        Ok(value.try_into().unwrap())
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.raw::<1>()?[0])
    }
    fn count(&mut self, width: usize) -> Result<usize, Error> {
        let count = u64::from_le_bytes(self.raw()?);
        if count > self.remaining() as u64 / width as u64 {
            return Err(Error("pvac_ser: count exceeds remaining data"));
        }
        if count > 1 << 24 {
            return Err(Error("pvac_ser: count exceeds maximum"));
        }
        usize::try_from(count).map_err(|_| Error("HFHE allocation unavailable"))
    }
    fn point(&mut self) -> Result<Point, Error> {
        let point = self.raw()?;
        if !generators::point_valid(&point) {
            return Err(Error("pvac_ser: invalid Ristretto point encoding"));
        }
        Ok(point)
    }
    fn scalar(&mut self) -> Result<Scalar, Error> {
        let scalar = Scalar::from_bytes_raw(&self.raw()?);
        if !scalar.is_canonical() {
            return Err(Error("pvac_ser: non-canonical scalar encoding"));
        }
        Ok(scalar)
    }
    fn points(&mut self, count: usize) -> Result<Vec<Point>, Error> {
        let mut points = r1cs::allocate(count)?;
        for _ in 0..count {
            points.push(self.point()?);
        }
        Ok(points)
    }
    #[allow(clippy::many_single_char_names)] // Native proof field names and wire order.
    fn proof(&mut self) -> Result<Proof, Error> {
        let a_i = self.point()?;
        let a_o = self.point()?;
        let s = self.point()?;
        let mut t = [[0; 32]; 5];
        for point in &mut t {
            *point = self.point()?;
        }
        let t_x = self.scalar()?;
        let t_x_blinding = self.scalar()?;
        let e_blinding = self.scalar()?;
        let count = self.count(32)?;
        let l = self.points(count)?;
        let r = self.points(count)?;
        let a = self.scalar()?;
        let b = self.scalar()?;
        let count = self.count(32)?;
        let commitments = self.points(count)?;
        Ok(Proof {
            a_i,
            a_o,
            s,
            t,
            t_x,
            t_x_blinding,
            e_blinding,
            ipp: InnerProductProof { l, r, a, b },
            commitments,
        })
    }
}
impl ZeroProof {
    /// Native OCaml FFI encoding: no envelope, and trailing bytes are ignored.
    pub fn from_raw_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader { bytes, position: 0 };
        Ok(Self {
            proof: reader.proof()?,
            is_bound: reader.byte()? != 0,
        })
    }
    pub fn to_raw_bytes(&self) -> Result<Vec<u8>, Error> {
        self.encode(false)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode(bytes, 6, "pvac_ser: trailing zero proof bytes")
    }
    pub fn from_bound_range_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode(bytes, 7, "pvac_ser: trailing bound range proof bytes")
    }
    fn decode(bytes: &[u8], tag: u8, trailing: &'static str) -> Result<Self, Error> {
        let mut reader = Reader { bytes, position: 0 };
        if reader.raw::<4>()? != *b"PVAC" {
            return Err(Error("pvac_ser: bad magic"));
        }
        if !(1..=5).contains(&reader.byte()?) {
            return Err(Error("pvac_ser: bad version"));
        }
        if reader.byte()? != tag {
            return Err(Error("pvac_ser: wrong type tag"));
        }
        let proof = reader.proof()?;
        let is_bound = reader.byte()? != 0;
        if reader.remaining() != 0 {
            return Err(Error(trailing));
        }
        Ok(Self { proof, is_bound })
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.encode(true)
    }
    fn encode(&self, envelope: bool) -> Result<Vec<u8>, Error> {
        // The native writer emits both IPP vectors even when callers supplied unequal
        // lengths; retain that behavior rather than normalizing malformed objects.
        let count = self
            .proof
            .ipp
            .l
            .len()
            .checked_add(self.proof.ipp.r.len())
            .and_then(|n| n.checked_add(self.proof.commitments.len()))
            .and_then(|n| n.checked_mul(32))
            .and_then(|n| n.checked_add(439))
            .ok_or(Error("HFHE allocation unavailable"))?;
        let mut bytes = r1cs::allocate(count)?;
        if envelope {
            bytes.extend_from_slice(b"PVAC\x03\x06");
        }
        for point in [&self.proof.a_i, &self.proof.a_o, &self.proof.s]
            .into_iter()
            .chain(&self.proof.t)
        {
            bytes.extend_from_slice(point);
        }
        for scalar in [
            self.proof.t_x,
            self.proof.t_x_blinding,
            self.proof.e_blinding,
        ] {
            bytes.extend_from_slice(&scalar.to_bytes());
        }
        bytes.extend_from_slice(&(self.proof.ipp.l.len() as u64).to_le_bytes());
        for point in self.proof.ipp.l.iter().chain(&self.proof.ipp.r) {
            bytes.extend_from_slice(point);
        }
        for scalar in [self.proof.ipp.a, self.proof.ipp.b] {
            bytes.extend_from_slice(&scalar.to_bytes());
        }
        bytes.extend_from_slice(&(self.proof.commitments.len() as u64).to_le_bytes());
        for point in &self.proof.commitments {
            bytes.extend_from_slice(point);
        }
        bytes.push(u8::from(self.is_bound));
        Ok(bytes)
    }
}

impl ZeroProof {
    pub fn to_bound_range_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = self.to_bytes()?;
        bytes[5] = 7;
        Ok(bytes)
    }
}

use super::range::{AggregatedRangeProof, RangeProof, RANGE_BITS};
use crate::{cipher::Cipher, cipher_wire};
#[derive(Clone)]
pub enum AnyRangeProof {
    Legacy(RangeProof),
    Aggregated(AggregatedRangeProof),
    Bound(ZeroProof),
}
impl AnyRangeProof {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 6 {
            return Err(Error("pvac_ser: range proof too short"));
        }
        let tag = bytes[5];
        if tag == 7 {
            return ZeroProof::from_bound_range_bytes(bytes).map(Self::Bound);
        }
        if tag != 4 && tag != 5 {
            return Err(Error("pvac_ser: unknown range proof tag"));
        }
        let mut reader = Reader { bytes, position: 0 };
        if reader.raw::<4>()? != *b"PVAC" {
            return Err(Error("pvac_ser: bad magic"));
        }
        let version = reader.byte()?;
        if !(1..=5).contains(&version) {
            return Err(Error("pvac_ser: bad version"));
        }
        reader.byte()?;
        let count = u64::from_le_bytes(reader.raw()?);
        if count != RANGE_BITS as u64 {
            return Err(Error("pvac_ser: unexpected range proof bit length"));
        }
        if count > reader.remaining() as u64 / 8 {
            return Err(Error("pvac_ser: count exceeds remaining data"));
        }
        let mut bits = r1cs::allocate(RANGE_BITS)?;
        for _ in 0..RANGE_BITS {
            let (cipher, consumed) = cipher_wire::read_raw(&bytes[reader.position..], version)?;
            reader.position += consumed;
            bits.push(cipher);
        }
        let result = if tag == 4 {
            let mut bit_proofs = r1cs::allocate(RANGE_BITS)?;
            for _ in 0..RANGE_BITS {
                bit_proofs.push(ZeroProof {
                    proof: reader.proof()?,
                    is_bound: reader.byte()? != 0,
                });
            }
            let lc_proof = ZeroProof {
                proof: reader.proof()?,
                is_bound: reader.byte()? != 0,
            };
            Self::Legacy(RangeProof {
                ct_bit: bits,
                bit_proofs,
                lc_proof,
            })
        } else {
            Self::Aggregated(AggregatedRangeProof {
                ct_bit: bits,
                proof: reader.proof()?,
            })
        };
        if reader.remaining() != 0 {
            return Err(Error(if tag == 4 {
                "pvac_ser: trailing range proof bytes"
            } else {
                "pvac_ser: trailing aggregated range proof bytes"
            }));
        }
        Ok(result)
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let (mut bytes, bits): (Vec<u8>, &[Cipher]) = match self {
            Self::Bound(proof) => return proof.to_bound_range_bytes(),
            Self::Legacy(proof) => (b"PVAC\x03\x04".to_vec(), &proof.ct_bit),
            Self::Aggregated(proof) => (b"PVAC\x03\x05".to_vec(), &proof.ct_bit),
        };
        append(&mut bytes, &(bits.len() as u64).to_le_bytes())?;
        for bit in bits {
            append(&mut bytes, &bit.to_bytes()?[6..])?;
        }
        match self {
            Self::Legacy(proof) => {
                for bit in proof
                    .bit_proofs
                    .iter()
                    .chain(std::iter::once(&proof.lc_proof))
                {
                    append(&mut bytes, &bit.to_bytes()?[6..])?;
                }
            }
            Self::Aggregated(proof) => {
                let encoded = ZeroProof {
                    proof: proof.proof.clone(),
                    is_bound: false,
                }
                .to_bytes()?;
                append(&mut bytes, &encoded[6..encoded.len() - 1])?;
            }
            Self::Bound(_) => unreachable!(),
        }
        Ok(bytes)
    }
}
fn append(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    output.extend_from_slice(bytes);
    Ok(())
}
