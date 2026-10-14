// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Parent-certificate participants for native reward and committee derivation.
use super::{Bytes, Error, ParentCommit};
use num_bigint::BigInt;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Participant {
    pub address: Bytes,
    pub pubkey: Bytes,
    pub weight: BigInt,
}
pub fn participants(parent: &ParentCommit) -> Vec<Bytes> {
    let mut v: Vec<_> = parent
        .certificate
        .precommits
        .iter()
        .map(|v| v.validator.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}
pub fn signed_weight(parent: &ParentCommit) -> Option<BigInt> {
    parent.validator_set.signed_weight(&participants(parent))
}
pub fn participant_set(parent: &ParentCommit) -> Result<Vec<Participant>, Error> {
    participants(parent)
        .into_iter()
        .map(|address| {
            let public = parent
                .validator_set
                .validators
                .iter()
                .rev()
                .find(|v| v.address == address)
                .map(|v| v.pubkey.clone());
            let weight = parent
                .validator_set
                .weight(&address)
                .filter(|w| **w > BigInt::from(0));
            match (public, weight) {
                (Some(pubkey), Some(weight)) => Ok(Participant {
                    address,
                    pubkey,
                    weight: weight.clone(),
                }),
                _ => Err("parent commit participant is not in validator set".into()),
            }
        })
        .collect()
}
pub fn proposer(parent: &ParentCommit) -> Result<Participant, Error> {
    let address = &parent.certificate.header.creator_addr;
    let public = parent.validator_set.public_key(address);
    let weight = parent
        .validator_set
        .weight(address)
        .filter(|w| **w > BigInt::from(0));
    match (public, weight) {
        (Some(pubkey), Some(weight)) => Ok(Participant {
            address: address.clone(),
            pubkey: pubkey.to_vec(),
            weight: weight.clone(),
        }),
        _ => Err("parent commit proposer is not in validator set".into()),
    }
}
pub fn same_block(left: &ParentCommit, right: &ParentCommit) -> bool {
    left.certificate.epoch_id == right.certificate.epoch_id
        && left.certificate.proposal_id == right.certificate.proposal_id
        && left.certificate.header == right.certificate.header
}
