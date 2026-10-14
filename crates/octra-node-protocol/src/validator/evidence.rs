// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{admission::Candidate, Error};
use crate::consensus::evidence::VoteConflict;
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub(crate) id: Vec<u8>,
    pub(crate) offender: Vec<u8>,
    pub(crate) evidence_epoch: i64,
}
impl Verified {
    pub fn id(&self) -> &[u8] {
        &self.id
    }
    pub fn offender(&self) -> &[u8] {
        &self.offender
    }
    pub fn evidence_epoch(&self) -> i64 {
        self.evidence_epoch
    }
}
pub fn verify(
    chain: &[u8],
    current_epoch: i64,
    evidence_epochs: i64,
    candidate: &Candidate,
    conflict: &VoteConflict,
) -> Result<Verified, Error> {
    let vote = &conflict.first;
    if evidence_epochs <= 0 {
        return Err("validator evidence window is not positive".into());
    }
    if vote.chain_id != chain {
        return Err("validator evidence chain mismatch".into());
    }
    if vote.validator != candidate.address {
        return Err("validator evidence offender mismatch".into());
    }
    if vote.epoch_id < candidate.bonded_epoch {
        return Err("validator evidence predates current bond".into());
    }
    if vote.epoch_id > current_epoch {
        return Err("validator evidence epoch is in the future".into());
    }
    if current_epoch.wrapping_sub(vote.epoch_id) >= evidence_epochs {
        return Err("validator evidence expired".into());
    }
    if !conflict.verify(&candidate.pubkey).unwrap_or(false) {
        return Err("invalid validator evidence signatures".into());
    }
    let id = conflict
        .id()
        .map_err(|_| Error::from("invalid validator evidence signatures"))?;
    Ok(Verified {
        id: STANDARD.encode(id).into_bytes(),
        offender: candidate.address.clone(),
        evidence_epoch: vote.epoch_id,
    })
}
