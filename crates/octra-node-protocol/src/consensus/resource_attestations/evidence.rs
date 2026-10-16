// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    domain_hash, encoded, hash_encoded, proof_payload_hash, Attestation, AttestationKind, Error,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleSide {
    Left,
    Right,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleStep {
    pub side: MerkleSide,
    pub sibling_hash: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageEvidence {
    pub leaf_index: i64,
    pub leaf_count: i64,
    pub chunk: Vec<u8>,
    pub path: Vec<MerkleStep>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsefulHashChainEvidence {
    pub input: Vec<u8>,
    pub iterations: i64,
    pub result: Vec<u8>,
}

pub fn merkle_side_to_u8(side: MerkleSide) -> u8 {
    match side {
        MerkleSide::Left => 1,
        MerkleSide::Right => 2,
    }
}
pub fn merkle_side_of_u8(side: u8) -> Result<MerkleSide, Error> {
    match side {
        1 => Ok(MerkleSide::Left),
        2 => Ok(MerkleSide::Right),
        _ => Err("bad merkle side".into()),
    }
}
pub fn byte_leading_zero_bits(byte: i64) -> i64 {
    (0..8)
        .rev()
        .take_while(|bit| byte & (1 << bit) == 0)
        .count() as i64
}
pub fn leading_zero_bits(digest: &[u8]) -> i64 {
    let mut total = 0;
    for byte in digest {
        let count = i64::from(byte.leading_zeros());
        total += count;
        if count != 8 {
            break;
        }
    }
    total
}
pub fn encode_pow_evidence(nonce: &[u8]) -> Result<Vec<u8>, Error> {
    encoded(|w| w.put_bytes(nonce))
}
pub fn pow_proof_hash(nonce: &[u8]) -> Result<[u8; 32], Error> {
    Ok(proof_payload_hash(&encode_pow_evidence(nonce)?))
}
pub fn pow_attempt_hash(
    challenge: &[u8],
    a: &Attestation,
    nonce: &[u8],
) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:pow_attestation_attempt:v1", |w| {
        w.put_hash32(challenge)?;
        w.put_bytes(&a.chain_id)?;
        w.put_u64(a.epoch_id as u64)?;
        w.put_bytes(&a.node_id)?;
        w.put_bytes(&a.commitment)?;
        w.put_hash32(&a.proof_hash)?;
        w.put_u64(a.weight as u64)?;
        w.put_bytes(nonce)
    })
}
pub fn assigned(commitment: &[u8], max_weight: i64, a: &Attestation) -> bool {
    !commitment.is_empty()
        && a.commitment == commitment
        && max_weight > 0
        && a.weight > 0
        && a.weight <= max_weight
}
pub fn verify_pow_attestation(
    challenge: &[u8],
    commitment: &[u8],
    max_weight: i64,
    difficulty: i64,
    a: &Attestation,
    nonce: &[u8],
) -> Result<bool, Error> {
    Ok(assigned(commitment, max_weight, a)
        && challenge.len() == 32
        && a.kind == AttestationKind::Pow
        && (0..=256).contains(&difficulty)
        && a.proof_hash == pow_proof_hash(nonce)?
        && leading_zero_bits(&pow_attempt_hash(challenge, a, nonce)?) >= difficulty)
}
pub fn storage_leaf_hash(chunk: &[u8]) -> [u8; 32] {
    domain_hash(b"octra:storage_chunk_leaf:v1", chunk)
}
pub fn storage_parent_hash(left: &[u8], right: &[u8]) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:storage_merkle_parent:v1", |w| {
        w.put_hash32(left)?;
        w.put_hash32(right)
    })
}
pub fn storage_path(e: &StorageEvidence) -> bool {
    if e.leaf_count <= 0 || e.leaf_index < 0 || e.leaf_index >= e.leaf_count {
        return false;
    }
    let (mut index, mut count) = (e.leaf_index, e.leaf_count);
    for step in &e.path {
        if count <= 1
            || step.sibling_hash.len() != 32
            || (step.side == MerkleSide::Left) != (index % 2 == 1)
        {
            return false;
        }
        index /= 2;
        count = count / 2 + count % 2;
    }
    index == 0 && count == 1
}
pub fn merkle_root_from_evidence(e: &StorageEvidence) -> Result<[u8; 32], Error> {
    let mut current = storage_leaf_hash(&e.chunk);
    for step in &e.path {
        current = match step.side {
            MerkleSide::Left => storage_parent_hash(&step.sibling_hash, &current)?,
            MerkleSide::Right => storage_parent_hash(&current, &step.sibling_hash)?,
        };
    }
    Ok(current)
}
pub fn encode_storage_evidence(e: &StorageEvidence) -> Result<Vec<u8>, Error> {
    encoded(|w| {
        w.put_u64(e.leaf_index as u64)?;
        w.put_u64(e.leaf_count as u64)?;
        w.put_bytes(&e.chunk)?;
        w.put_list(&e.path, |w, s| {
            w.put_u8(merkle_side_to_u8(s.side))?;
            w.put_hash32(&s.sibling_hash)
        })
    })
}
pub fn storage_evidence_hash(e: &StorageEvidence) -> Result<[u8; 32], Error> {
    Ok(proof_payload_hash(&encode_storage_evidence(e)?))
}
pub fn u64_prefix(digest: &[u8]) -> Result<i64, Error> {
    Ok(i64::from_be_bytes(
        digest
            .get(..8)
            .ok_or("index out of bounds")?
            .try_into()
            .map_err(|_| Error::from("index out of bounds"))?,
    ))
}
pub fn storage_challenge_index(
    challenge: &[u8],
    leaf_count: i64,
    a: &Attestation,
) -> Result<Option<i64>, Error> {
    if leaf_count <= 0 || challenge.len() != 32 {
        return Ok(None);
    }
    let digest = hash_encoded(b"octra:storage_attestation_index:v1", |w| {
        w.put_hash32(challenge)?;
        w.put_bytes(&a.chain_id)?;
        w.put_u64(a.epoch_id as u64)?;
        w.put_bytes(&a.node_id)?;
        w.put_bytes(&a.commitment)
    })?;
    Ok(Some(u64_prefix(&digest)?.wrapping_abs() % leaf_count))
}
pub fn verify_storage_attestation(
    challenge: &[u8],
    commitment: &[u8],
    max_weight: i64,
    leaf_count: i64,
    a: &Attestation,
    e: &StorageEvidence,
) -> Result<bool, Error> {
    if !assigned(commitment, max_weight, a) || e.leaf_count != leaf_count {
        return Ok(false);
    }
    let Some(index) = storage_challenge_index(challenge, leaf_count, a)? else {
        return Ok(false);
    };
    Ok(a.kind == AttestationKind::Storage
        && a.commitment.len() == 32
        && storage_path(e)
        && e.leaf_index == index
        && a.proof_hash == storage_evidence_hash(e)?
        && merkle_root_from_evidence(e)? == a.commitment.as_slice())
}
pub fn useful_hash_chain_task_id(
    challenge: &[u8],
    input: &[u8],
    iterations: i64,
) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:pouw_hash_chain_task:v1", |w| {
        w.put_hash32(challenge)?;
        w.put_bytes(input)?;
        w.put_u32(iterations as u32)
    })
}
pub fn useful_hash_chain_result(input: &[u8], iterations: i64) -> Result<Option<[u8; 32]>, Error> {
    if iterations < 0 {
        return Ok(None);
    }
    let mut current = domain_hash(b"octra:pouw_hash_chain_input:v1", input);
    for index in 0..iterations {
        current = hash_encoded(b"octra:pouw_hash_chain_step:v1", |w| {
            w.put_u32(index as u32)?;
            w.put_hash32(&current)
        })?;
    }
    Ok(Some(current))
}
pub fn encode_useful_hash_chain_evidence(e: &UsefulHashChainEvidence) -> Result<Vec<u8>, Error> {
    encoded(|w| {
        w.put_bytes(&e.input)?;
        w.put_u32(e.iterations as u32)?;
        w.put_hash32(&e.result)
    })
}
pub fn useful_hash_chain_evidence_hash(e: &UsefulHashChainEvidence) -> Result<[u8; 32], Error> {
    Ok(proof_payload_hash(&encode_useful_hash_chain_evidence(e)?))
}
pub fn verify_useful_hash_chain_attestation(
    challenge: &[u8],
    commitment: &[u8],
    max_weight: i64,
    min_iterations: i64,
    max_iterations: i64,
    a: &Attestation,
    e: &UsefulHashChainEvidence,
) -> Result<bool, Error> {
    if !assigned(commitment, max_weight, a)
        || challenge.len() != 32
        || min_iterations < 1
        || e.iterations < min_iterations
        || e.iterations > max_iterations
    {
        return Ok(false);
    }
    let Some(result) = useful_hash_chain_result(&e.input, e.iterations)? else {
        return Ok(false);
    };
    Ok(a.kind == AttestationKind::Useful
        && e.result == result
        && a.commitment == useful_hash_chain_task_id(challenge, &e.input, e.iterations)?
        && a.proof_hash == useful_hash_chain_evidence_hash(e)?)
}
