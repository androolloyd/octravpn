// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Pinned SHA-256 matrix sampling. Draw order is part of the format.
use std::collections::HashSet;

use sha2::{Digest, Sha256};

use crate::{
    cipher::RSeed,
    keys::{BitVec, PublicKey},
    Error,
};

pub fn layer_tag(canon_tag: u64, nonce: [u64; 2]) -> u64 {
    prg_u64(b"pvac.dom.ztag", &[canon_tag, nonce[0], nonce[1]])
}

pub(crate) fn sigma(
    public: &PublicKey,
    seed: RSeed,
    idx: u16,
    ch: u8,
    salt: u64,
    draw_factor: usize,
) -> Result<BitVec, Error> {
    let params = public.params;
    let words = [
        public.canon_tag,
        seed.ztag,
        seed.nonce[0],
        seed.nonce[1],
        u64::from(idx),
        u64::from(ch),
        salt,
    ];
    let cols = choose_k(
        params.x_col_weight,
        params.n_bits,
        b"pvac.dom.x_seed",
        &words,
        draw_factor,
    )?;
    let mut output = BitVec {
        nbits: params.m_bits as usize,
        words: vec![0; (params.m_bits as usize).div_ceil(64)],
    };
    for col in cols {
        for (word, source) in output.words.iter_mut().zip(&public.h[col].words) {
            *word ^= source;
        }
    }
    // Imported keys retain signed weights, including -1 becoming zero on the
    // native mixed-weight branch. Key generation itself rejects negatives.
    let count = params.error_weight
        + i32::from(
            params.error_weight < params.m_bits && prg_u64(b"pvac.noise.weight", &words) & 1 != 0,
        );
    for row in choose_k(count, params.m_bits, b"pvac.dom.noise", &words, draw_factor)? {
        output.words[row >> 6] ^= 1 << (row & 63);
    }
    Ok(output)
}

struct HashRng {
    prefix: Sha256,
    counter: u64,
    buffer: [u8; 32],
    index: usize,
    remaining: Option<usize>,
}

fn transcript(label: &[u8], words: &[u64]) -> Sha256 {
    let mut hash = Sha256::new();
    let length = label
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(label.len());
    hash.update(&label[..length]);
    for word in words {
        hash.update(word.to_le_bytes());
    }
    hash
}

impl HashRng {
    fn new(label: &[u8], words: &[u64], remaining: Option<usize>) -> Self {
        Self {
            prefix: transcript(label, words),
            counter: 0,
            buffer: [0; 32],
            index: 32,
            remaining,
        }
    }

    fn next(&mut self) -> Result<u64, Error> {
        if let Some(remaining) = &mut self.remaining {
            if *remaining == 0 {
                return Err(Error("pvac: sampling effort exhausted"));
            }
            *remaining -= 1;
        }
        if self.index == 32 {
            let mut hash = self.prefix.clone();
            hash.update(self.counter.to_le_bytes());
            self.counter = self.counter.wrapping_add(1);
            self.buffer = hash.finalize().into();
            self.index = 0;
        }
        let result =
            u64::from_le_bytes(self.buffer[self.index..self.index + 8].try_into().unwrap());
        self.index += 8;
        Ok(result)
    }

    fn bounded(&mut self, maximum: u64) -> Result<u64, Error> {
        if maximum <= 1 {
            return Ok(0);
        }
        let limit = u64::MAX - u64::MAX % maximum;
        loop {
            let value = self.next()?;
            // Upstream's SHA RNG accepts equality; its AES RNG does not.
            if value <= limit {
                return Ok(value % maximum);
            }
        }
    }
}

pub fn prg_u64(label: &[u8], words: &[u64]) -> u64 {
    let digest = transcript(label, words).finalize();
    u64::from_le_bytes(digest[..8].try_into().unwrap())
}

pub fn mixed_weight(base: usize, limit: usize, label: &[u8], words: &[u64]) -> usize {
    base + usize::from(base < limit && prg_u64(label, words) & 1 != 0)
}

pub fn choose_k(
    count: i32,
    domain: i32,
    label: &[u8],
    words: &[u64],
    draw_factor: usize,
) -> Result<Vec<usize>, Error> {
    if count < 0 || domain < 0 {
        return Err(Error("pvac: unique sample negative domain rejected"));
    }
    if count > domain {
        return Err(Error("pvac: unique sample exceeds domain"));
    }
    let count = count as usize;
    let remaining = if draw_factor == 0 {
        None
    } else {
        Some(
            count
                .checked_mul(draw_factor)
                .ok_or(Error("pvac: sampling effort overflow"))?,
        )
    };
    let mut rng = HashRng::new(label, words, remaining);
    let mut used = HashSet::new();
    used.try_reserve(count)
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| Error("HFHE allocation unavailable"))?;
    while output.len() < count {
        let value = rng.bounded(domain as u64)? as usize;
        if used.insert(value) {
            output.push(value);
        }
    }
    Ok(output)
}

pub(crate) fn permutation(tag: u64, bits: usize) -> (Vec<i32>, Vec<i32>) {
    let mut rng = HashRng::new(b"UBK", &[tag], None);
    let mut perm: Vec<_> = (0..bits as i32).collect();
    for index in (1..bits).rev() {
        let other = rng.bounded(index as u64 + 1).unwrap() as usize;
        perm.swap(index, other);
    }
    let mut inverse = vec![0; bits];
    for (index, &position) in perm.iter().enumerate() {
        inverse[position as usize] = index as i32;
    }
    (perm, inverse)
}
