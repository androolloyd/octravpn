// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native contract identity, over the complete deployed artifact bytes.
use sha2::{Digest, Sha256};

pub fn address(code: &[u8], deployer: &[u8], nonce: i64) -> Vec<u8> {
    let material = [code, b":", deployer, b":", nonce.to_string().as_bytes()].concat();
    let mut encoded = bs58::encode(Sha256::digest(&material)).into_string();
    let mut suffix = 0_u64;
    while encoded.len() < 44 {
        let more = [material.as_slice(), suffix.to_string().as_bytes()].concat();
        encoded.push_str(&bs58::encode(Sha256::digest(more)).into_string());
        suffix += 1;
    }
    [b"oct".as_slice(), &encoded.as_bytes()[..44]].concat()
}
