// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Optional in-memory resource admission. Proof verification remains separate.
use super::resource_attestations as resource;
use crate::{
    native_table::Table,
    network::domain_hash,
    oce1::{Error, Writer},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Disabled,
    Capacity,
    ChainMismatch,
    EpochTooOld,
    EpochTooNew,
    MissingChallenge,
    Malformed,
    BadScore,
    UnknownNode,
    BadSignature,
    ConflictingIdentity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Accept,
    Reject(Reason),
    Quarantine(Reason),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub current_epoch: i64,
    pub fraud_window: i64,
    pub future_window: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub node_id: Vec<u8>,
    pub epoch_id: i64,
    pub reason: Reason,
    pub attestation_id: Vec<u8>,
    pub observed_epoch: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    pub accepted: Table<resource::Attestation>,
    pub identity_index: Table<Vec<u8>>,
    pub rejected: Table<Evidence>,
    pub quarantined: Table<Evidence>,
}
pub const MAX_ACCEPTED: usize = 4096;
pub const MAX_EVIDENCE: usize = 4096;
pub fn create_pool() -> Pool {
    Pool {
        accepted: Table::new(256),
        identity_index: Table::new(256),
        rejected: Table::new(64),
        quarantined: Table::new(64),
    }
}
pub fn reason_to_string(reason: Reason) -> &'static str {
    match reason {
        Reason::Disabled => "disabled",
        Reason::Capacity => "capacity",
        Reason::ChainMismatch => "chain_mismatch",
        Reason::EpochTooOld => "epoch_too_old",
        Reason::EpochTooNew => "epoch_too_new",
        Reason::MissingChallenge => "missing_challenge",
        Reason::Malformed => "malformed",
        Reason::BadScore => "bad_score",
        Reason::UnknownNode => "unknown_node",
        Reason::BadSignature => "bad_signature",
        Reason::ConflictingIdentity => "conflicting_identity",
    }
}
pub fn decision_to_string(decision: Decision) -> String {
    match decision {
        Decision::Accept => "accept".into(),
        Decision::Reject(r) => format!("reject:{}", reason_to_string(r)),
        Decision::Quarantine(r) => format!("quarantine:{}", reason_to_string(r)),
    }
}
pub fn identity_key(a: &resource::Attestation) -> Vec<u8> {
    let mut key = a.node_id.clone();
    key.extend_from_slice(
        format!(
            "|{}|{}",
            a.epoch_id,
            resource::attestation_kind_to_u8(a.kind)
        )
        .as_bytes(),
    );
    key
}
pub fn evidence_id(e: &Evidence) -> Result<[u8; 32], Error> {
    let mut w = Writer::new();
    w.put_bytes(&e.node_id)?;
    w.put_u64(e.epoch_id as u64)?;
    w.put_bytes(reason_to_string(e.reason).as_bytes())?;
    w.put_hash32(&e.attestation_id)?;
    w.put_u64(e.observed_epoch as u64)?;
    Ok(domain_hash(
        b"octra:resource_admission_evidence:v1",
        &w.into_bytes(),
    ))
}
pub fn evidence(
    window: Window,
    reason: Reason,
    a: &resource::Attestation,
) -> Result<Evidence, Error> {
    Ok(Evidence {
        node_id: a.node_id.clone(),
        epoch_id: a.epoch_id,
        reason,
        attestation_id: resource::attestation_id(a)?.to_vec(),
        observed_epoch: window.current_epoch,
    })
}
pub fn valid_window(w: Window) -> bool {
    w.current_epoch >= 0 && w.fraud_window >= 0 && w.future_window >= 0
}
pub fn expired(w: Window, epoch: i64) -> bool {
    epoch < w.current_epoch && w.current_epoch.wrapping_sub(epoch) > w.fraud_window
}
fn remove_where<T>(table: &mut Table<T>, mut remove: impl FnMut(&T) -> bool) {
    let keys: Vec<_> = table
        .iter()
        .filter(|(_, v)| remove(v))
        .map(|(k, _)| k.to_vec())
        .collect();
    for key in keys {
        table.remove(&key);
    }
}
pub fn prune(pool: &mut Pool, w: Window) {
    remove_where(&mut pool.accepted, |a| expired(w, a.epoch_id));
    remove_where(&mut pool.identity_index, |id| {
        pool.accepted.get(id).is_none()
    });
    remove_where(&mut pool.rejected, |e| expired(w, e.observed_epoch));
    remove_where(&mut pool.quarantined, |e| expired(w, e.observed_epoch));
}
pub fn classify(
    chain: &[u8],
    challenge: &[u8],
    w: Window,
    pubkey: &mut impl FnMut(&[u8]) -> Option<Vec<u8>>,
    pool: &Pool,
    a: &resource::Attestation,
) -> Result<Decision, Error> {
    use Decision::{Accept, Quarantine, Reject};
    if !valid_window(w) || challenge.len() != 32 || a.epoch_id < 0 || !resource::is_well_formed(a) {
        return Ok(Reject(Reason::Malformed));
    }
    if a.chain_id != chain {
        return Ok(Reject(Reason::ChainMismatch));
    }
    if expired(w, a.epoch_id) {
        return Ok(Reject(Reason::EpochTooOld));
    }
    if a.epoch_id > w.current_epoch && a.epoch_id.wrapping_sub(w.current_epoch) > w.future_window {
        return Ok(Reject(Reason::EpochTooNew));
    }
    if a.score != resource::attestation_score(challenge, a)? {
        return Ok(Reject(Reason::BadScore));
    }
    let Some(key) = pubkey(&a.node_id) else {
        return Ok(Quarantine(Reason::UnknownNode));
    };
    if !resource::verify_attestation_signature(&key, a)? {
        return Ok(Reject(Reason::BadSignature));
    }
    let id = resource::attestation_id(a)?;
    if pool
        .identity_index
        .get(&identity_key(a))
        .is_some_and(|existing| existing.as_slice() != id)
    {
        return Ok(Quarantine(Reason::ConflictingIdentity));
    }
    if pool.accepted.get(&id).is_none() && pool.accepted.values().len() >= MAX_ACCEPTED {
        return Ok(Reject(Reason::Capacity));
    }
    Ok(Accept)
}
pub fn remember(
    pool: &mut Pool,
    w: Window,
    decision: Decision,
    a: &resource::Attestation,
) -> Result<(), Error> {
    let id = resource::attestation_id(a)?.to_vec();
    match decision {
        Decision::Accept => {
            pool.accepted.replace(id.clone(), a.clone());
            pool.identity_index.replace(identity_key(a), id);
        }
        Decision::Reject(reason) => {
            let e = evidence(w, reason, a)?;
            if pool.rejected.values().len() < MAX_EVIDENCE {
                pool.rejected.replace(evidence_id(&e)?.to_vec(), e);
            }
        }
        Decision::Quarantine(reason) => {
            let e = evidence(w, reason, a)?;
            if pool.quarantined.values().len() < MAX_EVIDENCE {
                pool.quarantined.replace(evidence_id(&e)?.to_vec(), e);
            }
        }
    }
    Ok(())
}
pub fn ingest(
    chain: &[u8],
    challenge: &[u8],
    w: Window,
    pubkey: &mut impl FnMut(&[u8]) -> Option<Vec<u8>>,
    pool: &mut Pool,
    a: &resource::Attestation,
) -> Result<Decision, Error> {
    if valid_window(w) {
        prune(pool, w);
    }
    let decision = classify(chain, challenge, w, pubkey, pool, a)?;
    if decision != Decision::Reject(Reason::Malformed) {
        remember(pool, w, decision, a)?;
    }
    Ok(decision)
}
fn folded<T: Clone>(table: &Table<T>) -> Vec<T> {
    let mut values: Vec<_> = table.iter().map(|(_, v)| v.clone()).collect();
    values.reverse();
    values
}
pub fn accepted(pool: &Pool) -> Vec<resource::Attestation> {
    folded(&pool.accepted)
}
pub fn rejected(pool: &Pool) -> Vec<Evidence> {
    folded(&pool.rejected)
}
pub fn quarantined(pool: &Pool) -> Vec<Evidence> {
    folded(&pool.quarantined)
}
