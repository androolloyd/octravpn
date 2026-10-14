// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native generator domains and canonical Ristretto group operations.
use std::sync::{Mutex, OnceLock};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as GroupScalar,
    traits::MultiscalarMul,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{keys, scalar::Scalar, Error};

pub type Point = [u8; 32];
pub const MAX_VECTOR_SIZE: usize = 1 << 20;

fn reserve<T>(count: usize) -> Result<Vec<T>, Error> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    Ok(output)
}

pub fn hash_to_point(domain: &[u8], index: u64) -> Point {
    let mut hash = Sha256::new();
    let length = domain
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(domain.len());
    hash.update(&domain[..length]);
    hash.update(index.to_le_bytes());
    let mut uniform = [0; 64];
    hash.finalize_into((&mut uniform[..32]).into());
    uniform[31] &= 0x7f;
    // The second map of zero is identity, matching upstream's single map.
    RistrettoPoint::from_uniform_bytes(&uniform)
        .compress()
        .to_bytes()
}

#[derive(Default)]
struct Cache {
    g: Vec<Point>,
    h: Vec<Point>,
}

impl Cache {
    fn ensure(&mut self, count: usize) -> Result<(), Error> {
        if count > MAX_VECTOR_SIZE {
            return Err(Error("pvac: generator size rejected"));
        }
        if self.g.len() != self.h.len() {
            return Err(Error("pvac: generator table shape rejected"));
        }
        if self.g.len() >= count {
            return Ok(());
        }
        let mut g = reserve(count)?;
        let mut h = reserve(count)?;
        g.extend_from_slice(&self.g);
        h.extend_from_slice(&self.h);
        for index in self.g.len()..count {
            g.push(hash_to_point(b"pvac.bp.gen.G", index as u64));
            h.push(hash_to_point(b"pvac.bp.gen.H", index as u64));
        }
        self.g = g;
        self.h = h;
        Ok(())
    }
}

#[derive(Default)]
pub struct GeneratorTable {
    cache: Mutex<Cache>,
}

impl GeneratorTable {
    pub fn new() -> Self {
        Self::default()
    }

    fn cache(&self) -> Result<std::sync::MutexGuard<'_, Cache>, Error> {
        self.cache
            .lock()
            .map_err(|_| Error("HFHE generator cache unavailable"))
    }

    pub fn precompute(&self, count: usize) -> Result<(), Error> {
        self.cache()?.ensure(count)
    }

    pub fn g(&self, index: usize) -> Result<Point, Error> {
        if index >= MAX_VECTOR_SIZE {
            return Err(Error("pvac: generator size rejected"));
        }
        let mut cache = self.cache()?;
        cache.ensure(index + 1)?;
        Ok(cache.g[index])
    }

    pub fn h(&self, index: usize) -> Result<Point, Error> {
        if index >= MAX_VECTOR_SIZE {
            return Err(Error("pvac: generator size rejected"));
        }
        let mut cache = self.cache()?;
        cache.ensure(index + 1)?;
        Ok(cache.h[index])
    }

    pub fn g_vec(&self, count: usize) -> Result<Vec<Point>, Error> {
        let mut cache = self.cache()?;
        cache.ensure(count)?;
        let mut output = reserve(count)?;
        output.extend_from_slice(&cache.g[..count]);
        Ok(output)
    }

    pub fn h_vec(&self, count: usize) -> Result<Vec<Point>, Error> {
        let mut cache = self.cache()?;
        cache.ensure(count)?;
        let mut output = reserve(count)?;
        output.extend_from_slice(&cache.h[..count]);
        Ok(output)
    }
}

pub fn generators() -> &'static GeneratorTable {
    static TABLE: OnceLock<GeneratorTable> = OnceLock::new();
    TABLE.get_or_init(GeneratorTable::new)
}

pub fn g(index: usize) -> Result<Point, Error> {
    generators().g(index)
}
pub fn h(index: usize) -> Result<Point, Error> {
    generators().h(index)
}
pub fn g_vec(count: usize) -> Result<Vec<Point>, Error> {
    generators().g_vec(count)
}
pub fn h_vec(count: usize) -> Result<Vec<Point>, Error> {
    generators().h_vec(count)
}

pub fn next_power_of_2(count: usize) -> Result<usize, Error> {
    if count > MAX_VECTOR_SIZE {
        return Err(Error("pvac: vector size rejected"));
    }
    Ok(count.max(1).next_power_of_two())
}

pub fn log2_size(count: usize) -> Result<usize, Error> {
    if count == 0 || count > MAX_VECTOR_SIZE || !count.is_power_of_two() {
        return Err(Error("pvac: log2 size rejected"));
    }
    Ok(count.trailing_zeros() as usize)
}

fn decode(point: &Point) -> Result<RistrettoPoint, Error> {
    CompressedRistretto(*point)
        .decompress()
        .ok_or(Error("pvac: invalid Ristretto point encoding"))
}

pub fn point_valid(point: &Point) -> bool {
    decode(point).is_ok()
}

fn group_scalar(scalar: &Scalar) -> Zeroizing<GroupScalar> {
    // Group arithmetic reads all native scalar bits modulo group order; this
    // reduction must not replace the separate Prior/Wide proof scalar rules.
    Zeroizing::new(GroupScalar::from_bytes_mod_order(scalar.to_bytes()))
}

pub fn identity() -> Point {
    [0; 32]
}
pub fn pedersen_b() -> Point {
    RISTRETTO_BASEPOINT_POINT.compress().to_bytes()
}
pub fn pedersen_blinding() -> Point {
    keys::pedersen_h()
}

pub fn point_add(a: &Point, b: &Point) -> Result<Point, Error> {
    Ok((decode(a)? + decode(b)?).compress().to_bytes())
}

pub fn point_sub(a: &Point, b: &Point) -> Result<Point, Error> {
    Ok((decode(a)? - decode(b)?).compress().to_bytes())
}

pub fn point_mul(point: &Point, scalar: &Scalar) -> Result<Point, Error> {
    Ok((decode(point)? * *group_scalar(scalar))
        .compress()
        .to_bytes())
}

pub fn base_mul(scalar: &Scalar) -> Point {
    (RISTRETTO_BASEPOINT_POINT * *group_scalar(scalar))
        .compress()
        .to_bytes()
}

pub fn pedersen_commit(value: &Scalar, blind: &Scalar) -> Point {
    // This fixed locally derived point is always a valid encoding.
    let h = CompressedRistretto(pedersen_blinding())
        .decompress()
        .unwrap();
    (RISTRETTO_BASEPOINT_POINT * *group_scalar(value) + h * *group_scalar(blind))
        .compress()
        .to_bytes()
}

pub fn multi_scalar_mul(scalars: &[Scalar], points: &[Point]) -> Result<Point, Error> {
    if scalars.len() != points.len() {
        return Err(Error("HFHE multiscalar shape rejected"));
    }
    let mut decoded = reserve(points.len())?;
    for point in points {
        decoded.push(decode(point)?);
    }
    let mut reduced = Zeroizing::new(reserve(scalars.len())?);
    for scalar in scalars {
        reduced.push(*group_scalar(scalar));
    }
    Ok(
        RistrettoPoint::multiscalar_mul(reduced.iter(), decoded.iter())
            .compress()
            .to_bytes(),
    )
}
