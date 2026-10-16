// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// Port of pvac/core/seedable_rng.hpp and pvac/crypto/lpn.hpp at the adopted pin.
//! The exact native AES-256 counter stream, including bounded sampling draws.
use aes::{
    cipher::{Block, BlockEncrypt, KeyInit},
    Aes256,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::field::Fp;

pub struct CtrRng {
    aes: Aes256,
    counter: u64,
    buffered: u64,
    has_buffered: bool,
}

/// Native PVAC backend identity used by consensus profiles and key records.
pub fn aes_kat() -> [u8; 16] {
    let key: [u8; 32] = Sha256::digest(b"pvac.aes.kat.key").into();
    let mut rng = CtrRng::seeded(&key);
    let mut output = [0; 16];
    output[..8].copy_from_slice(&rng.next_u64().to_le_bytes());
    output[8..].copy_from_slice(&rng.next_u64().to_le_bytes());
    output
}

impl Drop for CtrRng {
    fn drop(&mut self) {
        self.counter.zeroize();
        self.buffered.zeroize();
        // aes's zeroize feature clears the expanded key on drop.
    }
}

impl CtrRng {
    pub fn new(key: &[u8; 32], nonce: u64) -> Self {
        Self {
            aes: Aes256::new(key.into()),
            counter: nonce,
            buffered: 0,
            has_buffered: false,
        }
    }
    pub fn seeded(key: &[u8; 32]) -> Self {
        Self::new(key, 0)
    }

    pub fn next_u64(&mut self) -> u64 {
        if self.has_buffered {
            let word = self.buffered;
            self.buffered.zeroize();
            self.has_buffered = false;
            return word;
        }
        let mut block = Block::<Aes256>::default();
        block[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.aes.encrypt_block(&mut block);
        self.counter = self.counter.wrapping_add(1);
        self.buffered = u64::from_le_bytes(block[8..].try_into().unwrap());
        self.has_buffered = true;
        let result = u64::from_le_bytes(block[..8].try_into().unwrap());
        block.as_mut_slice().zeroize();
        result
    }
    pub fn fill_u64(&mut self, output: &mut [u64]) {
        for word in output {
            *word = self.next_u64();
        }
    }
    pub fn bounded(&mut self, maximum: u64) -> u64 {
        if maximum <= 1 {
            return 0;
        }
        let limit = u64::MAX - (u64::MAX % maximum);
        loop {
            let value = self.next_u64();
            if value < limit {
                return value % maximum;
            }
        }
    }
    pub fn fp_nonzero(&mut self) -> Fp {
        loop {
            let value = Fp::from_words(self.next_u64(), self.next_u64() & (u64::MAX >> 1));
            if value != Fp::ZERO {
                return value;
            }
        }
    }
    pub fn nonce128(&mut self) -> [u64; 2] {
        [self.next_u64(), self.next_u64()]
    }
}

pub fn domain_hash(domain: &[u8]) -> u64 {
    domain
        .iter()
        .take_while(|&&byte| byte != 0)
        .fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        })
}

/// Mirrors derive_aes_key's little-endian transcript and nonce derivation.
pub fn derive_key(
    prf_key: &[u64; 4],
    canon_tag: u64,
    h_digest: &[u8; 32],
    seed_tag: u64,
    nonce: [u64; 2],
    domain: &[u8],
) -> (Zeroizing<[u8; 32]>, u64) {
    let domain_hash = domain_hash(domain);
    let mut hash = Sha256::new();
    for word in prf_key {
        hash.update(word.to_le_bytes());
    }
    hash.update(canon_tag.to_le_bytes());
    hash.update(h_digest);
    for word in [seed_tag, nonce[0], nonce[1], domain_hash] {
        hash.update(word.to_le_bytes());
    }
    let mut key = Zeroizing::new([0; 32]);
    hash.finalize_into((&mut *key).into());
    (key, domain_hash ^ nonce[0])
}
