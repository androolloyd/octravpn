// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Canonical pending-set and legacy-readiness metadata.
use super::{admission::Member, Error};
use crate::{
    consensus::{codec::Wire, policy::QuorumPolicy, Eviction, ValidatorSet},
    control_payload::{weighted_fingerprint, LegacyReady, ValidatorEntry, ValidatorUpdate},
    transaction::json_string,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use std::collections::BTreeSet;
pub const PENDING_KEY: &[u8] = b"bft.validator_set.pending";
pub const ACTIVE_KEY: &[u8] = b"bft.validator_set.active";
pub fn snapshot_slot(epoch: i64, pending: Option<&ValidatorUpdate>) -> bool {
    pending.is_none_or(|p| p.activate_epoch <= epoch)
}
pub fn ready_key(fingerprint: &[u8], address: &[u8]) -> Vec<u8> {
    [b"bft.validator_set.ready.", fingerprint, b".", address].concat()
}
fn field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    if out.len() > 1 {
        out.push(b',');
    }
    json_string(out, name);
    out.push(b':');
    json_string(out, value);
}
impl ValidatorUpdate {
    pub fn make_weighted(source: i64, activate: i64, members: &[Member]) -> Result<Self, Error> {
        if source >= activate {
            return Err("weighted validator source epoch must precede activation".into());
        }
        let mut validators: Vec<_> = members
            .iter()
            .map(|m| ValidatorEntry {
                address: m.address.clone(),
                public_key: STANDARD.encode(&m.pubkey).into_bytes(),
                weight: m.weight.clone(),
            })
            .collect();
        validators.sort_by(|a, b| a.address.cmp(&b.address));
        let mut addresses = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for v in &validators {
            if !addresses.insert(&v.address) {
                return Err("duplicate validator address".into());
            }
            if !keys.insert(&v.public_key) {
                return Err("duplicate validator public key".into());
            }
        }
        if validators.is_empty() {
            return Err("validator set cannot be empty".into());
        }
        Ok(Self {
            activate_epoch: activate,
            source_epoch: Some(source),
            weighted: true,
            fingerprint: weighted_fingerprint(source, activate, &validators),
            validators,
            eviction: None,
        })
    }
    /// The update that removes `offenders` from `current` for the next
    /// epoch, with its witness, and the weight removed.
    pub fn make_eviction(
        source_epoch: i64,
        activate_epoch: i64,
        offenders: &[Vec<u8>],
        current: &ValidatorSet,
    ) -> Result<(Self, BigInt), Error> {
        if source_epoch < 0 || source_epoch == i64::MAX || activate_epoch != source_epoch + 1 {
            return Err("validator eviction must activate in the next epoch".into());
        }
        let mut source = current
            .validate_shape()
            .map_err(|e| Error(e.message().to_string()))?;
        source.authors = None;
        let (next, weight) = source.evict(offenders).map_err(|e| Error(e.to_string()))?;
        let members: Vec<_> = next
            .entries()
            .map_err(|e| Error(e.to_string()))?
            .into_iter()
            .map(|(member, weight)| Member {
                address: member.address,
                pubkey: member.pubkey,
                weight,
            })
            .collect();
        let mut update = Self::make_weighted(source_epoch, activate_epoch, &members)?;
        let mut offenders = offenders.to_vec();
        offenders.sort();
        update.eviction = Some(Eviction {
            epoch: source_epoch,
            source,
            offenders,
        });
        let update = Self::of_string(&update.to_bytes()).map_err(|e| Error(e.to_string()))?;
        Ok((update, weight))
    }
    /// Whether this update is exactly the removal of `offenders` from
    /// `current`; returns the resulting set and the weight removed.
    pub fn check_eviction(
        &self,
        source_epoch: i64,
        offenders: &[Vec<u8>],
        current: &ValidatorSet,
    ) -> Result<(ValidatorSet, BigInt), Error> {
        let (expected, weight) =
            Self::make_eviction(source_epoch, self.activate_epoch, offenders, current)?;
        if *self != expected {
            return Err("validator eviction differs from exact removal".into());
        }
        let next = expected.validator_set().map_err(|e| Error(e.to_string()))?;
        Ok((next, weight))
    }
    /// Native `check_eviction_state`: a stored eviction must be exactly the
    /// removal, from the current voting set, of the offenders the registry
    /// names at this epoch.
    pub fn check_eviction_state(
        &self,
        chain: &[u8],
        epoch: i64,
        registry: &super::registry::Registry,
        current: &ValidatorSet,
    ) -> Result<(ValidatorSet, BigInt), Error> {
        if epoch < 0 || epoch == (1 << 62) - 1 || !seatless_at(chain, epoch) {
            return Err("validator eviction state epoch is not active".into());
        }
        let Some(eviction) = &self.eviction else {
            return Err("validator eviction witness is missing".into());
        };
        if eviction.epoch != epoch || !current.same_voting_set(&eviction.source) {
            return Err("validator eviction source differs from current voting set".into());
        }
        let offenders = eviction_offenders(chain, epoch, registry, current)?;
        if eviction.offenders != offenders {
            return Err("validator eviction offenders differ from registry".into());
        }
        self.check_eviction(epoch, &offenders, current)
    }
    /// Whether the set this update schedules may vote at `epoch`.
    pub fn check_set_at(&self, chain: &[u8], epoch: i64) -> Result<(), Error> {
        let policy = QuorumPolicy::for_chain(chain);
        let seatless = policy.seatless(epoch);
        match &self.eviction {
            Some(eviction) => {
                if !seatless || epoch < eviction.epoch {
                    return Err("validator eviction requires active seatless voting".into());
                }
                let (set, _) = self.validate_eviction().map_err(|e| Error(e.to_string()))?;
                set.structural_for_policy(policy, epoch)
                    .map_err(|e| Error(e.message().to_string()))?;
            }
            None if !seatless => (),
            None => {
                self.validator_set()
                    .and_then(|set| set.checked_for_policy(policy, epoch))
                    .map_err(|e| Error(e.to_string()))?;
            }
        }
        Ok(())
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![b'{'];
        field(
            &mut out,
            b"activate_epoch",
            self.activate_epoch.to_string().as_bytes(),
        );
        field(&mut out, b"fingerprint", self.fingerprint.as_bytes());
        out.extend_from_slice(b",\"validators\":[");
        for (i, v) in self.validators.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            let mut entry = vec![b'{'];
            field(&mut entry, b"address", &v.address);
            field(&mut entry, b"pubkey", &v.public_key);
            if self.weighted {
                field(&mut entry, b"weight", v.weight.to_string().as_bytes());
            }
            entry.push(b'}');
            out.extend(entry);
        }
        out.push(b']');
        if self.weighted {
            field(&mut out, b"standard", b"bonded_stake");
            out.extend_from_slice(b",\"weighted\":true");
            field(
                &mut out,
                b"source_epoch",
                self.source_epoch
                    .expect("weighted source epoch")
                    .to_string()
                    .as_bytes(),
            );
        }
        if let Some(eviction) = &self.eviction {
            let mut witness = vec![b'{'];
            field(
                &mut witness,
                b"epoch",
                eviction.epoch.to_string().as_bytes(),
            );
            // A source that cannot be encoded cannot have been validated;
            // the empty string then fails every later check.
            let source = eviction.source.encode().unwrap_or_default();
            field(&mut witness, b"source", STANDARD.encode(source).as_bytes());
            witness.extend_from_slice(b",\"offenders\":[");
            for (index, offender) in eviction.offenders.iter().enumerate() {
                if index > 0 {
                    witness.push(b',');
                }
                json_string(&mut witness, offender);
            }
            witness.extend_from_slice(b"]}");
            out.extend_from_slice(b",\"eviction\":");
            out.extend(witness);
        }
        out.push(b'}');
        out
    }
}
impl LegacyReady {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![b'{'];
        // Native ready_ext reverses the base fields after prepending extras.
        field(&mut out, b"state_root", &self.state_root);
        field(
            &mut out,
            b"head_epoch",
            self.head_epoch.to_string().as_bytes(),
        );
        field(&mut out, b"fingerprint", &self.fingerprint);
        for (name, value) in [
            (b"chain_id".as_slice(), self.extra.chain_id.as_deref()),
            (b"binary_hash", self.extra.binary_hash.as_deref()),
            (b"config_hash", self.extra.config_hash.as_deref()),
        ] {
            if let Some(v) = value {
                field(&mut out, name, v);
            }
        }
        for (name, value) in [
            (
                b"catchup_head_epoch".as_slice(),
                self.extra.catchup_head_epoch,
            ),
            (b"shadow_epochs", self.extra.shadow_epochs),
        ] {
            if let Some(v) = value {
                field(&mut out, name, v.to_string().as_bytes());
            }
        }
        out.push(b'}');
        out
    }
}

/// Native `Rule_graph.seatless_at`: the activation alone, by chain.
pub fn seatless_at(chain: &[u8], epoch: i64) -> bool {
    crate::consensus::policy::seatless_epoch(chain).is_some_and(|first| epoch >= first)
}
/// Native `eviction_offenders`: current voters with a slash applied by this
/// epoch, ordered and unique; none before seatless.
pub fn eviction_offenders(
    chain: &[u8],
    epoch: i64,
    registry: &super::registry::Registry,
    current: &ValidatorSet,
) -> Result<Vec<Vec<u8>>, Error> {
    if !seatless_at(chain, epoch) {
        return Ok(vec![]);
    }
    let current = ValidatorSet {
        authors: None,
        ..current.clone()
    }
    .validate_shape()
    .map_err(|e| Error(e.message().to_string()))?;
    let mut offenders: Vec<Vec<u8>> = registry
        .slashes()
        .iter()
        .filter(|record| {
            record.applied_epoch <= epoch
                && current
                    .weights
                    .iter()
                    .any(|(address, _)| **address == *record.offender)
        })
        .map(|record| record.offender.clone())
        .collect();
    offenders.sort();
    offenders.dedup();
    Ok(offenders)
}
