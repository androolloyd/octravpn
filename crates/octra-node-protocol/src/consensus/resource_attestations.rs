// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Optional native resource model. This module does not enable committees.
use crate::{
    network::{domain_hash, verify_ed25519},
    oce1::{Error, Reader, Writer},
};
use ed25519_dalek::{Signer, SigningKey};
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use std::{cmp::Ordering, collections::BTreeMap};

mod evidence;
mod plugins;
pub use evidence::*;
pub use plugins::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationKind {
    Pow,
    Storage,
    Useful,
    Finality,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    pub chain_id: Vec<u8>,
    pub epoch_id: i64,
    pub node_id: Vec<u8>,
    pub kind: AttestationKind,
    pub commitment: Vec<u8>,
    pub proof_hash: Vec<u8>,
    pub weight: i64,
    pub score: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    pub node_id: Vec<u8>,
    pub amount: i64,
}
pub type NodeMap = BTreeMap<Vec<u8>, BigInt>;

pub fn attestation_kind_to_u8(kind: AttestationKind) -> u8 {
    match kind {
        AttestationKind::Pow => 1,
        AttestationKind::Storage => 2,
        AttestationKind::Useful => 3,
        AttestationKind::Finality => 4,
    }
}
pub fn attestation_kind_of_u8(kind: u8) -> Result<AttestationKind, Error> {
    match kind {
        1 => Ok(AttestationKind::Pow),
        2 => Ok(AttestationKind::Storage),
        3 => Ok(AttestationKind::Useful),
        4 => Ok(AttestationKind::Finality),
        _ => Err("bad resource attestation kind".into()),
    }
}
pub fn attestation_kind_to_string(kind: AttestationKind) -> &'static str {
    match kind {
        AttestationKind::Pow => "pow",
        AttestationKind::Storage => "storage",
        AttestationKind::Useful => "useful",
        AttestationKind::Finality => "finality",
    }
}
pub(super) fn encoded(f: impl FnOnce(&mut Writer) -> Result<(), Error>) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new();
    f(&mut w)?;
    Ok(w.into_bytes())
}
pub(super) fn hash_encoded(
    tag: &[u8],
    f: impl FnOnce(&mut Writer) -> Result<(), Error>,
) -> Result<[u8; 32], Error> {
    Ok(domain_hash(tag, &encoded(f)?))
}
pub fn proof_payload_hash(payload: &[u8]) -> [u8; 32] {
    domain_hash(b"octra:resource_proof_payload:v1", payload)
}
pub fn unsigned_attestation(
    chain_id: Vec<u8>,
    epoch_id: i64,
    node_id: Vec<u8>,
    kind: AttestationKind,
    commitment: Vec<u8>,
    proof_hash: Vec<u8>,
    weight: i64,
) -> Attestation {
    Attestation {
        chain_id,
        epoch_id,
        node_id,
        kind,
        commitment,
        proof_hash,
        weight,
        score: vec![0; 32],
        signature: vec![0; 64],
    }
}
fn write_unsigned(w: &mut Writer, a: &Attestation) -> Result<(), Error> {
    w.put_bytes(&a.chain_id)?;
    w.put_u64(a.epoch_id as u64)?;
    w.put_bytes(&a.node_id)?;
    w.put_u8(attestation_kind_to_u8(a.kind))?;
    w.put_bytes(&a.commitment)?;
    w.put_hash32(&a.proof_hash)?;
    w.put_u64(a.weight as u64)
}
pub fn attestation_score(challenge: &[u8], a: &Attestation) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:resource_attestation_score:v1", |w| {
        write_unsigned(w, a)?;
        w.put_hash32(challenge)
    })
}
pub fn with_score(challenge: &[u8], mut a: Attestation) -> Result<Attestation, Error> {
    a.score = attestation_score(challenge, &a)?.to_vec();
    Ok(a)
}
pub fn attestation_sign_bytes(a: &Attestation) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:resource_attestation_sign:v1", |w| {
        write_unsigned(w, a)?;
        w.put_hash32(&a.score)
    })
}
pub fn attestation_id(a: &Attestation) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:resource_attestation_id:v1", |w| {
        w.put_hash32(&attestation_sign_bytes(a)?)?;
        w.put_sig64(&a.signature)
    })
}
pub(super) fn sign(priv_raw: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let bytes: &[u8; 32] = priv_raw
        .try_into()
        .map_err(|_| Error::from("Ed25519 sign: invalid private key"))?;
    Ok(SigningKey::from_bytes(bytes)
        .sign(message)
        .to_bytes()
        .to_vec())
}
pub fn sign_attestation(priv_raw: &[u8], mut a: Attestation) -> Result<Attestation, Error> {
    a.signature = sign(priv_raw, &attestation_sign_bytes(&a)?)?;
    Ok(a)
}
pub fn verify_attestation_signature(pubkey: &[u8], a: &Attestation) -> Result<bool, Error> {
    Ok(verify_ed25519(
        pubkey,
        &attestation_sign_bytes(a)?,
        &a.signature,
    ))
}
pub fn is_well_formed(a: &Attestation) -> bool {
    !a.chain_id.is_empty()
        && !a.node_id.is_empty()
        && a.weight > 0
        && a.proof_hash.len() == 32
        && a.score.len() == 32
        && a.signature.len() == 64
}
pub fn compare_attestation(a: &Attestation, b: &Attestation) -> Ordering {
    a.score
        .cmp(&b.score)
        .then_with(|| a.node_id.cmp(&b.node_id))
        .then_with(|| attestation_kind_to_u8(a.kind).cmp(&attestation_kind_to_u8(b.kind)))
        .then_with(|| a.proof_hash.cmp(&b.proof_hash))
        .then_with(|| a.commitment.cmp(&b.commitment))
}
pub fn take<T: Clone>(n: i64, values: &[T]) -> Vec<T> {
    values
        .iter()
        .take(usize::try_from(n).unwrap_or(0))
        .cloned()
        .collect()
}
pub fn select_committee(size: i64, values: &[Attestation]) -> Vec<Attestation> {
    let mut values: Vec<_> = values
        .iter()
        .filter(|a| is_well_formed(a))
        .cloned()
        .collect();
    values.sort_by(compare_attestation);
    take(size, &values)
}
pub fn sum_weight(values: &[Attestation]) -> BigInt {
    values.iter().map(|a| BigInt::from(a.weight)).sum()
}
pub fn quorum_weight(total: &BigInt) -> BigInt {
    (total * 2) / 3 + 1
}
pub fn qc_intersection_floor(total: &BigInt, left: &BigInt, right: &BigInt) -> BigInt {
    (left + right - total).max(BigInt::zero())
}
pub fn conflicting_qc_impossible(total: &BigInt, byzantine: &BigInt) -> bool {
    let quorum = quorum_weight(total);
    qc_intersection_floor(total, &quorum, &quorum) > *byzantine
}
pub fn add_amount(node: &[u8], amount: &BigInt, mut rewards: NodeMap) -> NodeMap {
    *rewards.entry(node.to_vec()).or_default() += amount;
    rewards
}
pub fn proportional_amount(budget: &BigInt, total: &BigInt, weight: i64) -> Result<BigInt, Error> {
    if total.is_zero() {
        return Err("division by zero".into());
    }
    Ok((budget * weight) / total)
}
pub fn distribute_resource_rewards(
    budget: i64,
    values: &[Attestation],
) -> Result<Vec<Payout>, Error> {
    let values: Vec<_> = values
        .iter()
        .filter(|a| is_well_formed(a))
        .cloned()
        .collect();
    let total = sum_weight(&values);
    if budget <= 0 || total <= BigInt::zero() {
        return Ok(vec![]);
    }
    let budget = BigInt::from(budget);
    let mut rewards = NodeMap::new();
    for a in &values {
        rewards = add_amount(
            &a.node_id,
            &proportional_amount(&budget, &total, a.weight)?,
            rewards,
        );
    }
    let mut remainder = &budget - rewards.values().sum::<BigInt>();
    let mut sorted = values;
    sorted.sort_by(compare_attestation);
    for a in &sorted {
        if remainder <= BigInt::zero() {
            break;
        }
        rewards = add_amount(&a.node_id, &BigInt::from(1), rewards);
        remainder -= 1;
    }
    rewards
        .into_iter()
        .map(|(node_id, amount)| {
            Ok(Payout {
                node_id,
                amount: amount.to_i64().ok_or("Z.Overflow")?,
            })
        })
        .collect()
}
pub fn encode_attestation(a: &Attestation) -> Result<Vec<u8>, Error> {
    encoded(|w| {
        write_unsigned(w, a)?;
        w.put_hash32(&a.score)?;
        w.put_sig64(&a.signature)
    })
}
pub fn decode_attestation(raw: &[u8]) -> Result<Attestation, Error> {
    let mut r = Reader::new(raw);
    let chain_id = r.get_bytes_bounded(128)?.to_vec();
    let epoch_id = r.get_u64()? as i64;
    let node_id = r.get_bytes_bounded(128)?.to_vec();
    let kind = attestation_kind_of_u8(r.get_u8()?)?;
    let commitment = r.get_bytes_bounded(64 * 1024)?.to_vec();
    let proof_hash = r.get_hash32()?.to_vec();
    let weight = r.get_u64()? as i64;
    let score = r.get_hash32()?.to_vec();
    let signature = r.get_sig64()?.to_vec();
    r.finish()?;
    Ok(Attestation {
        chain_id,
        epoch_id,
        node_id,
        kind,
        commitment,
        proof_hash,
        weight,
        score,
        signature,
    })
}
pub fn attestations_root(values: &[Attestation]) -> Result<[u8; 32], Error> {
    let mut values = values.to_vec();
    values.sort_by(compare_attestation);
    hash_encoded(b"octra:resource_attestations_root:v1", |w| {
        w.put_list(&values, |w, a| w.put_hash32(&attestation_id(a)?))
    })
}
// Native evaluates the two products and their sum separately; FMA changes bits.
#[allow(clippy::suboptimal_flops)]
pub fn kl_divergence(p: f64, q: f64) -> Result<f64, Error> {
    if p <= 0. || p >= 1. || q <= 0. || q >= 1. {
        return Err("kl_divergence".into());
    }
    Ok(p * (p / q).ln() + (1. - p) * ((1. - p) / (1. - q)).ln())
}
// Match OCaml float_of_int, including rounding above the f64 integer range.
#[allow(clippy::cast_precision_loss)]
pub fn committee_capture_bound(size: i64, adversarial: f64, capture: f64) -> Result<f64, Error> {
    if size <= 0 {
        Err("committee_capture_bound".into())
    } else if adversarial <= 0. {
        Ok(0.)
    } else if adversarial >= capture {
        Ok(1.)
    } else {
        // OCaml negates the size before multiplying. LLVM may move that
        // negation to the product, which changes a propagated NaN's sign.
        let negative_size = std::hint::black_box(-(size as f64));
        Ok((negative_size * kl_divergence(capture, adversarial)?).exp())
    }
}
