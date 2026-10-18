// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native `Consensus_reward_attribution.epoch_source` compatibility.
//!
//! These facts belong to a locally authenticated legacy epoch header. Historical
//! validator keys, activation and protocol come independently from its trusted
//! host. This converter does not authenticate a header, grant a peer certificate,
//! or repair missing reward evidence in a modern canonical record.
use super::{full_set, policy::Protocol, reward, to_source, Bytes, Error, RewardSource};
use crate::{
    epoch_rewards::{Attribution, Validator},
    transaction::Nonce,
};
use std::collections::BTreeSet;

mod header;
pub use header::DecodedHeader;

/// Historical policy and encoded validator keys selected by the local host,
/// independently of the exported header. No authority is inferred from rewards.
#[derive(Clone, Debug)]
pub struct Authority {
    pub protocol: Protocol,
    pub validator_activation_epoch: Option<Nonce>,
    pub validator_pubkeys: Vec<(Bytes, Bytes)>,
}

impl Authority {
    pub fn source(&self, header: &Header) -> Result<RewardSource, Error> {
        epoch_source(
            header,
            self.protocol,
            self.validator_activation_epoch,
            &self.validator_pubkeys,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    pub address: Bytes,
    pub role: Bytes,
}

/// Projection of an already decoded native `Epochlog.epoch_header`.
/// Recipient amounts are intentionally absent: the native converter never
/// consults them. `validator_reward_each` retains its exact string bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub epoch: Nonce,
    pub creator: Bytes,
    pub finalized_by: Bytes,
    pub validator_reward_each: Bytes,
    pub recipients: Vec<Recipient>,
    pub reward_source: Option<RewardSource>,
}

pub fn epoch_source(
    header: &Header,
    protocol: Protocol,
    validator_activation_epoch: Option<Nonce>,
    validator_pubkeys: &[(Bytes, Bytes)],
) -> Result<RewardSource, Error> {
    // Native validates explicit evidence before inspecting activation or keys.
    if let Some(source) = &header.reward_source {
        return reward::validate(source);
    }
    let epoch = header.epoch.get();
    let proposer = if header.creator.len() > 3 {
        &header.creator
    } else {
        &header.finalized_by
    };
    if validator_activation_epoch.is_some_and(|activation| epoch >= activation.get()) {
        return Err("weighted reward source is missing".into());
    }
    if protocol.version_at(epoch) == super::LEGACY_VERSION {
        return to_source(&full_set(proposer, validator_pubkeys));
    }
    let mut addresses = header
        .recipients
        .iter()
        .filter(|recipient| {
            recipient.role == b"validator" || recipient.role == b"proposer_validator"
        })
        .map(|recipient| recipient.address.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if addresses.is_empty() && header.validator_reward_each == b"0" {
        // Native's zero-reward fallback preserves key-list ordering and
        // duplicates; each member below still uses the first association.
        addresses = validator_pubkeys
            .iter()
            .map(|(address, _)| address.clone())
            .collect();
    }
    let validators = addresses
        .into_iter()
        .map(|address| {
            let key = validator_pubkeys
                .iter()
                .find(|(known, _)| *known == address)
                .map(|(_, key)| key.clone())
                .ok_or_else(|| {
                    Error::new(
                        [
                            b"legacy reward validator key is missing: ".as_slice(),
                            address.as_slice(),
                        ]
                        .concat(),
                    )
                })?;
            Ok(Validator {
                address,
                public_key: Some(key),
                weight: 1.into(),
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    to_source(&Attribution {
        proposer: proposer.clone(),
        proposer_public_key: validator_pubkeys
            .iter()
            .find(|(address, _)| address == proposer)
            .map(|(_, key)| key.clone()),
        validators,
    })
}
