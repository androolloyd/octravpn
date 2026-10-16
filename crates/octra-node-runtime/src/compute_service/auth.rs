// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Evidence, Head};
use crate::compute_record::verify_node;
use octra_node_protocol::{
    consensus::{hash::validator_set_hash, ValidatorSet},
    resource_compute::{
        capability::{self, Capability},
        message::{self, Offer},
        selection::{Commitment, Reveal},
        Error, Result,
    },
};
/// One actor turn's host view. Roots are raw 32-byte folded state commitments;
/// canonical snapshot authentication remains the host's responsibility.
pub struct View<'a> {
    pub chain: &'a [u8],
    pub validators: &'a ValidatorSet,
    pub head: Option<&'a Head>,
    pub state_root_at: &'a (dyn Fn(i64) -> Option<Vec<u8>> + Sync),
    pub evidence: Option<&'a Evidence>,
}
impl View<'_> {
    pub fn funding_matches(
        &self,
        call: &octra_node_protocol::resource_compute::call::Call,
        funds: &crate::compute_deposits::Funded,
    ) -> bool {
        match (self.current_head(), call.header()) {
            (Ok(head), Ok(header)) => {
                header == *funds.header()
                    && head.epoch == funds.epoch()
                    && hex::encode(&head.state_root).as_bytes() == funds.state_root()
                    && header.request().chain_id == self.chain
            }
            _ => false,
        }
    }
    pub fn current_head(&self) -> Result<&Head> {
        self.head
            .filter(|head| head.epoch >= 0 && head.state_root.len() == 32)
            .ok_or_else(|| Error::rejected(b"resource compute finalized head unavailable"))
    }
    /// Native checks these fields before consulting the historical model root.
    pub(in crate::compute_service) fn offer_preflight_checked(
        &self,
        offer: &Offer,
    ) -> Result<bool> {
        let root = validator_set_hash(self.validators)
            .map_err(|error| Error::Unavailable(error.to_string().into_bytes()))?;
        Ok(offer.shape()
            && offer.chain_id == self.chain
            && root.as_slice() == offer.validator_set_root)
    }
    pub fn offer_at(&self, epoch: i64, offer: &Offer) -> bool {
        self.offer_at_checked(epoch, offer).unwrap_or(false)
    }
    pub(in crate::compute_service) fn offer_at_checked(
        &self,
        epoch: i64,
        offer: &Offer,
    ) -> Result<bool> {
        if !self.offer_preflight_checked(offer)?
            || (self.state_root_at)(offer.model_epoch).as_deref()
                != Some(offer.model_state_root.as_slice())
            || offer.offered_epoch > epoch
            || epoch > offer.expires_epoch
            || offer.expires_epoch.wrapping_sub(offer.offered_epoch) > message::OFFER_TTL
            || !self.validators.is_validator(&offer.coordinator)
        {
            return Ok(false);
        }
        Ok(verify_node(
            self.validators,
            &offer.coordinator,
            &offer.sign_bytes()?,
            &offer.signature,
        ))
    }
    pub fn offer(&self, offer: &Offer) -> bool {
        self.current_head()
            .is_ok_and(|head| self.offer_at(head.epoch, offer))
    }
    pub fn capability_at(&self, epoch: i64, value: &Capability) -> bool {
        let Some(evidence) = self.evidence else {
            return false;
        };
        let Ok(root) = validator_set_hash(self.validators) else {
            return false;
        };
        capability::validate(
            self.chain,
            epoch,
            message::CAPACITY_TTL,
            value,
            |node| self.validators.is_validator(node),
            |value| {
                value.sign_bytes().is_ok_and(|bytes| {
                    verify_node(self.validators, &value.node_id, &bytes, &value.signature)
                })
            },
            |value| {
                value.validator_set_root == root
                    && value.executor_root == evidence.executor_root
                    && value.evidence_root == evidence.evidence_root
            },
        )
        .is_ok()
    }
    pub fn capability(&self, value: &Capability) -> bool {
        self.current_head()
            .is_ok_and(|head| self.capability_at(head.epoch, value))
    }
    pub fn commitment(&self, value: &Commitment) -> bool {
        value.signature.len() == 64
            && value.sign_bytes().is_ok_and(|bytes| {
                verify_node(self.validators, &value.node_id, &bytes, &value.signature)
            })
    }
    pub fn reveal(&self, commitment: &Commitment, value: &Reveal) -> bool {
        value.sign_bytes(commitment).is_ok_and(|bytes| {
            verify_node(self.validators, &value.node_id, &bytes, &value.signature)
        })
    }
}
impl Evidence {
    pub fn from_provider(
        value: &octra_node_protocol::resource_compute::provider::SelfTest,
    ) -> Result<Self> {
        let raw = |value: &[u8]| {
            if value.len() != 64 || !value.iter().all(u8::is_ascii_hexdigit) {
                return Err(Error::rejected(
                    b"resource compute hash must be lowercase hex64",
                ));
            }
            hex::decode(value)
                .map_err(|_| Error::rejected(b"resource compute hash must be lowercase hex64"))
        };
        Ok(Self {
            executor_root: raw(&value.executor_root)?,
            evidence_root: raw(&value.evidence_root)?,
            profile: value.profile.clone(),
        })
    }
}
