//! `cast sha256` / `cast keccak` helpers.
//!
//! Octra uses SHA-256 throughout (address, tx hash, route commit).
//! `cast keccak` is an alias for muscle memory with `cast keccak`
//! in Foundry, *not* keccak-256. If you need keccak proper, this CLI
//! isn't your tool today.

use anyhow::Result;
use sha2::{Digest, Sha256};

pub fn sha256_cmd(input: &str) -> Result<()> {
    let bytes = decode_input(input);
    let mut h = Sha256::new();
    h.update(&bytes);
    println!("0x{}", hex::encode(h.finalize()));
    Ok(())
}

fn decode_input(s: &str) -> Vec<u8> {
    let stripped = s.trim().trim_start_matches("0x");
    if stripped.is_empty() {
        return Vec::new();
    }
    if stripped.len() % 2 == 0 && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(stripped).unwrap_or_default();
    }
    s.as_bytes().to_vec()
}
