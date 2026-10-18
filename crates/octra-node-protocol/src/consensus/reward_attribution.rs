// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native reward attribution and its binding to finalized parent participants.
use super::{
    parent, policy, reward, Bytes, Error, Finalize, ParentCommit, RewardMember, RewardSource,
    ValidatorSet, CURRENT_VERSION, LEGACY_VERSION,
};
use crate::{
    epoch_rewards::{Attribution, Validator},
    transaction::{decode_base64, RuleMode},
};
use base64::{engine::general_purpose::STANDARD, Engine};

pub mod legacy;

pub fn full_set(proposer: &[u8], public_keys: &[(Bytes, Bytes)]) -> Attribution {
    Attribution {
        proposer: proposer.to_vec(),
        proposer_public_key: public_keys
            .iter()
            .find(|(address, _)| address == proposer)
            .map(|(_, key)| key.clone()),
        validators: public_keys
            .iter()
            .map(|(address, key)| Validator {
                address: address.clone(),
                public_key: Some(key.clone()),
                weight: 1.into(),
            })
            .collect(),
    }
}
fn raw_key(key: Option<&Bytes>) -> Result<Option<Bytes>, Error> {
    key.map(|encoded| {
        let raw =
            decode_base64(encoded).map_err(|_| Error::from("reward public key is invalid"))?;
        if raw.len() != 32 {
            return Err("reward public key length is invalid".into());
        }
        Ok(raw)
    })
    .transpose()
}
fn encoded_key(key: &Bytes) -> Bytes {
    STANDARD.encode(key).into_bytes()
}
pub fn to_source(attribution: &Attribution) -> Result<RewardSource, Error> {
    let proposer_key = raw_key(attribution.proposer_public_key.as_ref())?;
    let members = attribution
        .validators
        .iter()
        .map(|validator| {
            Ok(RewardMember {
                reward_address: validator.address.clone(),
                reward_public_key: raw_key(validator.public_key.as_ref())?,
                reward_weight: validator.weight.clone(),
            })
        })
        .collect::<Result<_, Error>>()?;
    reward::validate(&RewardSource {
        reward_proposer_addr: attribution.proposer.clone(),
        reward_proposer_public_key: proposer_key,
        reward_members: members,
    })
}
pub fn of_source(source: &RewardSource) -> Result<Attribution, Error> {
    let source = reward::validate(source)?;
    Ok(Attribution {
        proposer: source.reward_proposer_addr,
        proposer_public_key: source.reward_proposer_public_key.as_ref().map(encoded_key),
        validators: source
            .reward_members
            .into_iter()
            .map(|member| Validator {
                address: member.reward_address,
                public_key: member.reward_public_key.as_ref().map(encoded_key),
                weight: member.reward_weight,
            })
            .collect(),
    })
}
pub fn of_parent(parent: &ParentCommit) -> Result<Attribution, Error> {
    // Preserve native error precedence: proposer before participant lookup.
    let proposer = parent::proposer(parent)?;
    let participants = parent::participant_set(parent)?;
    Ok(Attribution {
        proposer: proposer.address,
        proposer_public_key: Some(encoded_key(&proposer.pubkey)),
        validators: participants
            .into_iter()
            .map(|v| Validator {
                address: v.address,
                public_key: Some(encoded_key(&v.pubkey)),
                weight: v.weight,
            })
            .collect(),
    })
}
pub fn standard_mode(chain: &[u8], epoch: i64) -> RuleMode {
    if !(0..(1_i64 << 62)).contains(&epoch) || (chain == policy::DEVNET && epoch >= 1_500_000) {
        RuleMode::Active
    } else {
        RuleMode::Prior
    }
}
fn legacy(set: &ValidatorSet, finalized: &Finalize) -> Result<Attribution, Error> {
    let keys = set
        .validators
        .iter()
        .map(|v| (v.address.clone(), STANDARD.encode(&v.pubkey).into_bytes()))
        .collect::<Vec<_>>();
    of_source(&to_source(&full_set(
        &finalized.header.creator_addr,
        &keys,
    ))?)
}
fn require(
    label: &str,
    expected: Attribution,
    supplied: &Attribution,
) -> Result<Attribution, Error> {
    if expected == *supplied {
        Ok(expected)
    } else {
        Err(format!("reward source does not match {label}").into())
    }
}
pub fn bind_finality(
    set: &ValidatorSet,
    finalized: &Finalize,
    supplied: &Attribution,
) -> Result<Attribution, Error> {
    match finalized.header.proto_version {
        LEGACY_VERSION => require("legacy finality", legacy(set, finalized)?, supplied),
        CURRENT_VERSION => match (
            standard_mode(&finalized.chain_id, finalized.epoch_id),
            finalized.epoch_id,
            &finalized.parent_commit,
        ) {
            (RuleMode::Prior, _, None) => Ok(supplied.clone()),
            (RuleMode::Active, 0, None) => {
                require("current genesis", legacy(set, finalized)?, supplied)
            }
            (RuleMode::Active, 0, Some(_)) => {
                Err("genesis reward parent commit is unexpected".into())
            }
            (RuleMode::Active, _, None) => Err("current reward parent commit is missing".into()),
            (_, _, Some(parent)) => require("parent commit", of_parent(parent)?, supplied),
        },
        _ => Err("reward finality protocol is unsupported".into()),
    }
}
pub fn resolve(
    chain: &[u8],
    epoch: i64,
    protocol: policy::Protocol,
    proposer: &[u8],
    keys: &[(Bytes, Bytes)],
    parent: Option<&ParentCommit>,
) -> Result<Attribution, Error> {
    match (protocol.version_at(epoch), epoch, parent) {
        (LEGACY_VERSION, _, None) | (CURRENT_VERSION, 0, None) => Ok(full_set(proposer, keys)),
        (LEGACY_VERSION, _, Some(_)) => Err("legacy reward parent commit is unexpected".into()),
        (CURRENT_VERSION, 0, Some(_)) => Err("genesis reward parent commit is unexpected".into()),
        (CURRENT_VERSION, _, Some(parent)) => of_parent(parent),
        (CURRENT_VERSION, _, None) if standard_mode(chain, epoch) == RuleMode::Prior => {
            Ok(full_set(proposer, keys))
        }
        (CURRENT_VERSION, _, None) => Err("current reward parent commit is missing".into()),
        _ => Err("reward protocol is unsupported".into()),
    }
}
