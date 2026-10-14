// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// Port of net/epoch_index_commitment.ml at d3e834919bd586e81f947d0dae91becc6c43c756.
//! Epoch-index commitments and the consensus state-root fold.
//!
//! Inputs are byte strings because OCaml strings may contain raw hashes.
//! Signed transaction IDs, length framing, and storage-root normalization
//! deliberately match upstream, including its 64-character hex prefix rule.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub txid: i64,
    pub hash: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("epoch index commitment: invalid tx hash")]
    InvalidHash,
    #[error("epoch index commitment: invalid root")]
    InvalidRoot,
    #[error("epoch index commitment: duplicate txid")]
    DuplicateTxid,
}

fn put(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(value.len().to_string().as_bytes());
    buffer.push(b':');
    buffer.extend_from_slice(value);
    buffer.push(b'\n');
}

fn put_integer(buffer: &mut Vec<u8>, value: i64) {
    buffer.extend_from_slice(value.to_string().as_bytes());
    buffer.push(b'\n');
}

pub fn normalize_hash(hash: &[u8]) -> Result<String, Error> {
    if hash.len() == 32 {
        return Ok(hex::encode(hash));
    }
    if hash.len() != 64 || !hash.iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::InvalidHash);
    }
    // ASCII was checked, so UTF-8 decoding cannot fail.
    Ok(String::from_utf8(hash.to_ascii_lowercase()).unwrap())
}

pub fn root_hex(root: &[u8]) -> Result<String, Error> {
    if root.len() >= 64 && root.iter().all(u8::is_ascii_hexdigit) {
        return Ok(String::from_utf8(root[..64].to_ascii_lowercase()).unwrap());
    }
    if root.len() == 32 {
        return Ok(hex::encode(root));
    }
    if root.is_empty() {
        return Err(Error::InvalidRoot);
    }
    let mut buffer = Vec::new();
    put(&mut buffer, b"octra:eic:storage-root-string:v1");
    put(&mut buffer, root);
    Ok(hex::encode(Sha256::digest(buffer)))
}

pub fn epoch_hash(epoch_id: i64, items: &[Item]) -> Result<Hash, Error> {
    let mut ordered: Vec<_> = items.iter().collect();
    ordered.sort_by_key(|item| item.txid);
    let mut previous = None;
    let mut normalized = Vec::with_capacity(ordered.len());
    for item in ordered {
        if previous == Some(item.txid) {
            return Err(Error::DuplicateTxid);
        }
        normalized.push((item.txid, normalize_hash(&item.hash)?));
        previous = Some(item.txid);
    }
    let mut buffer = Vec::new();
    put(&mut buffer, b"octra:eic:epoch:v1");
    put_integer(&mut buffer, epoch_id);
    put_integer(&mut buffer, items.len() as i64);
    for (txid, hash) in normalized {
        put_integer(&mut buffer, txid);
        put(&mut buffer, hash.as_bytes());
    }
    Ok(Sha256::digest(buffer).into())
}

pub fn genesis_root() -> Hash {
    Sha256::digest(b"octra:eic:genesis:v1").into()
}

pub fn root_hash(previous: &[u8], epoch_hash: &[u8]) -> Result<Hash, Error> {
    let mut buffer = Vec::new();
    put(&mut buffer, b"octra:eic:root:v1");
    // Upstream frames the previous root verbatim, including raw byte strings.
    put(&mut buffer, previous);
    put(&mut buffer, normalize_hash(epoch_hash)?.as_bytes());
    Ok(Sha256::digest(buffer).into())
}

pub fn next_root(previous: &[u8], epoch_id: i64, items: &[Item]) -> Result<(Hash, Hash), Error> {
    let epoch = epoch_hash(epoch_id, items)?;
    Ok((epoch, root_hash(previous, &epoch)?))
}

pub fn items_from_hashes(start_txid: i64, hashes: &[Vec<u8>]) -> Result<Vec<Item>, Error> {
    hashes
        .iter()
        .enumerate()
        .map(|(index, hash)| {
            Ok(Item {
                // Int64.add in the upstream primitive wraps at the signed boundary.
                txid: start_txid.wrapping_add(index as i64),
                hash: normalize_hash(hash)?.into_bytes(),
            })
        })
        .collect()
}

pub fn folded_state_root(ledger: &[u8], epoch_index: &[u8]) -> Result<Hash, Error> {
    let mut buffer = Vec::new();
    put(&mut buffer, b"octra:eic:state-root:v1");
    put(&mut buffer, root_hex(ledger)?.as_bytes());
    put(&mut buffer, root_hex(epoch_index)?.as_bytes());
    Ok(Sha256::digest(buffer).into())
}
