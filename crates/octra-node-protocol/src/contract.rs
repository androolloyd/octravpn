// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native contract identity, over the complete deployed artifact bytes.
use sha2::{Digest, Sha256};

/// Native Consensus_vm_transition representation: raw SHA-256 or the first
/// SHA-256 half of a canonical text root. Validate the entire supplied text.
pub fn tree_hash(root: &[u8]) -> Result<Vec<u8>, &'static str> {
    match root.len() {
        32 => Ok(root.to_vec()),
        64 | 128 if root.iter().all(u8::is_ascii_hexdigit) => {
            hex::decode(&root[..64]).map_err(|_| "previous state root is invalid")
        }
        _ => Err("previous state root is invalid"),
    }
}

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
