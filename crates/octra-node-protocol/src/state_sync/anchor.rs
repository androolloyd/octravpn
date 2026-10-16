// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native finalized checkpoint authority and authenticated validator transitions.
use super::{checkpoint, lower_hex, require, Error, Result};
use crate::{
    consensus::{
        codec::Wire,
        hash,
        qc::{self, FinalityMode},
        Finalize, Validator, ValidatorSet,
    },
    control_payload::ValidatorUpdate,
    epoch_index, irmin, native_base64,
    oce1::{Reader, Writer},
    validator::update::{ACTIVE_KEY, PENDING_KEY},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MAX_STEPS: usize = 1024;
const MAX_FINALIZE: usize = 4_000_000;
const MAX_SET: usize = 1_000_000;
const MAX_UPDATE: usize = 1_000_000;
const MAX_PROOF: usize = 4_000_000;
const MAX_ROOT: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Pending,
    Active,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Step {
    pub source: Source,
    pub finalize: Finalize,
    pub ledger_state_root: Vec<u8>,
    pub epoch_index_root: Vec<u8>,
    pub update: Vec<u8>,
    pub proof: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Anchor {
    pub steps: Vec<Step>,
    pub finalize: Finalize,
    pub validator_set: ValidatorSet,
}
#[derive(Clone, Debug)]
pub struct VerifiedAnchor {
    anchor: Anchor,
}
impl VerifiedAnchor {
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }
}
/// Constructed only after authenticating an origin's finality and validator history.
#[derive(Clone, Debug)]
pub struct Origin {
    chain_id: Vec<u8>,
    epoch_id: i64,
    state_root: Vec<u8>,
    validators: ValidatorSet,
}
impl Origin {
    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }
    pub fn epoch_id(&self) -> i64 {
        self.epoch_id
    }
    pub fn state_root(&self) -> &[u8] {
        &self.state_root
    }
    pub fn validators(&self) -> &ValidatorSet {
        &self.validators
    }
    pub fn read_state(
        &self,
        max_bytes: usize,
        ledger_root: &[u8],
        index_root: &[u8],
        path: &[&[u8]],
        proof: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        require(
            max_bytes > 0 && proof.len() <= max_bytes,
            "state proof size exceeds limit",
        )?;
        require(
            (lower_hex(ledger_root, 64) || lower_hex(ledger_root, 128))
                && lower_hex(index_root, 64)
                && !path.is_empty()
                && path.iter().all(|v| !v.is_empty()),
            "state proof context is invalid",
        )?;
        require(
            fold(ledger_root, index_root)?.as_slice() == hex::encode(&self.state_root).as_bytes(),
            "state proof root differs",
        )?;
        irmin::proof::verify(ledger_root, path, proof)
    }
}
fn fold(ledger: &[u8], index: &[u8]) -> Result<Vec<u8>> {
    epoch_index::folded_state_root(ledger, index)
        .map(|v| hex::encode(v).into_bytes())
        .map_err(|e| e.to_string().into())
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn failure(error: Error) -> Error {
    format!("Failure(\"{error}\")").into()
}
fn put_step(w: &mut Writer, step: &Step) -> Result<()> {
    w.put_u8(match step.source {
        Source::Pending => 1,
        Source::Active => 2,
    })?;
    w.put_bytes(&step.finalize.encode()?)?;
    w.put_bytes(&step.ledger_state_root)?;
    w.put_bytes(&step.epoch_index_root)?;
    w.put_bytes(&step.update)?;
    w.put_bytes(&step.proof)
}
fn get_step(r: &mut Reader<'_>) -> Result<Step> {
    let source = match r.get_u8()? {
        1 => Source::Pending,
        2 => Source::Active,
        _ => return Err("validator transition source is invalid".into()),
    };
    Ok(Step {
        source,
        finalize: Finalize::decode(r.get_bytes_bounded(MAX_FINALIZE)?)?,
        ledger_state_root: r.get_bytes_bounded(MAX_ROOT)?.to_vec(),
        epoch_index_root: r.get_bytes_bounded(MAX_ROOT)?.to_vec(),
        update: r.get_bytes_bounded(MAX_UPDATE)?.to_vec(),
        proof: r.get_bytes_bounded(MAX_PROOF)?.to_vec(),
    })
}
pub fn raw_validator_set(set: &ValidatorSet) -> Result<ValidatorSet> {
    let entries = set
        .validators
        .iter()
        .map(|v| {
            let pubkey = checkpoint::raw_pubkey(&v.pubkey)?;
            let weight = set
                .weight(&v.address)
                .ok_or("trusted validator weight is missing")?
                .clone();
            Ok((
                Validator {
                    address: v.address.clone(),
                    pubkey,
                },
                weight,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    if set.weighted {
        ValidatorSet::weighted(entries)
    } else {
        Ok(ValidatorSet::unweighted(
            entries.into_iter().map(|(v, _)| v).collect(),
        ))
    }
}
pub fn encoded_validator_set(set: &ValidatorSet) -> Result<ValidatorSet> {
    let mut result = set.clone();
    for v in &mut result.validators {
        require(
            v.pubkey.len() == 32,
            "finality validator public key is invalid",
        )?;
        require(
            set.weight(&v.address).is_some(),
            "finality validator weight is missing",
        )?;
        v.pubkey = STANDARD.encode(&v.pubkey).into_bytes();
    }
    require(
        !result.validators.is_empty(),
        "finality validator set is empty",
    )?;
    Ok(result)
}
pub fn finalize_hash(finalize: &Finalize) -> Result<Vec<u8>> {
    Ok(hex::encode(Sha256::digest(finalize.encode()?)).into_bytes())
}
fn same_set(a: &ValidatorSet, b: &ValidatorSet) -> Result<bool> {
    Ok(hash::validator_set_hash(a)? == hash::validator_set_hash(b)?)
}
fn verify_finalize(chain: &[u8], set: &ValidatorSet, finalize: &Finalize) -> Result<()> {
    require(
        finalize.chain_id == chain && finalize.header.chain_id == chain,
        "finality chain mismatch",
    )?;
    require(
        finalize.epoch_id == finalize.header.epoch_id,
        "finality epoch mismatch",
    )?;
    qc::validate_finalize(chain, set, finalize, FinalityMode::StrictPersisted)
        .map_err(|e| Error::from(format!("finality qc {e}")))?;
    let vote_set = set.for_epoch(chain, finalize.epoch_id)?;
    let signers = finalize
        .precommits
        .iter()
        .map(|v| v.validator.clone())
        .collect::<Vec<_>>();
    require(vote_set.has_quorum(&signers), "finality qc signer quorum")
}
impl Step {
    fn verify(
        &self,
        chain: &[u8],
        prior: Option<i64>,
        set: &ValidatorSet,
    ) -> Result<(i64, ValidatorSet)> {
        let epoch = self.finalize.epoch_id;
        if let Some(prior) = prior.filter(|prior| epoch <= *prior) {
            return Err(format!(
                "validator transition order is invalid epoch = {epoch} prior_epoch = {prior}"
            )
            .into());
        }
        require(epoch != i64::MAX, "validator transition epoch overflows")?;
        require(
            lower_hex(&self.ledger_state_root, 64) || lower_hex(&self.ledger_state_root, 128),
            "validator transition ledger root is invalid",
        )?;
        require(
            lower_hex(&self.epoch_index_root, 64),
            "validator transition index root is invalid",
        )?;
        let update =
            ValidatorUpdate::parse(Some(&self.update)).map_err(|e| Error::from(e.to_string()))?;
        require(
            update.to_bytes() == self.update,
            "validator transition update is not exact",
        )?;
        require(
            update.weighted,
            "validator transition update is not weighted",
        )?;
        require(
            update.source_epoch.is_some(),
            "validator transition source epoch is missing",
        )?;
        let (path, active) = match self.source {
            Source::Pending => (PENDING_KEY, update.activate_epoch == epoch + 1),
            Source::Active => (ACTIVE_KEY, update.activate_epoch <= epoch),
        };
        require(active, "validator transition activation epoch mismatch")?;
        verify_finalize(chain, set, &self.finalize)?;
        require(
            hex::encode(&self.finalize.header.proposed_state_root).as_bytes()
                == fold(&self.ledger_state_root, &self.epoch_index_root)?,
            "validator transition folded root mismatch",
        )?;
        let value = irmin::proof::verify(&self.ledger_state_root, &[b"meta", path], &self.proof)?;
        require(
            value.as_deref() == Some(self.update.as_slice()),
            "validator transition state proof mismatch",
        )?;
        Ok((
            epoch,
            update
                .validator_set()?
                .for_epoch(chain, update.activate_epoch)?,
        ))
    }
}
impl Anchor {
    pub fn raw(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.put_list(&self.steps, put_step)?;
        w.put_bytes(&self.finalize.encode()?)?;
        w.put_bytes(&self.validator_set.encode()?)?;
        Ok(w.into_bytes())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(STANDARD.encode(self.raw()?).into_bytes())
    }
    pub fn decode(encoded: &[u8]) -> Result<Self> {
        let raw = native_base64::decode(encoded)
            .map_err(|e| Error::from(format!("Invalid_argument(\"{e}\")")))?;
        require(
            STANDARD.encode(&raw).as_bytes() == encoded,
            "finality encoding is not exact",
        )?;
        let value = (|| {
            let mut r = Reader::new(&raw);
            let value = Self {
                steps: r.get_list(MAX_STEPS, get_step)?,
                finalize: Finalize::decode(r.get_bytes_bounded(MAX_FINALIZE)?)?,
                validator_set: ValidatorSet::decode(r.get_bytes_bounded(MAX_SET)?)?,
            };
            r.finish()?;
            Ok(value)
        })()
        .map_err(failure)?;
        require(value.raw()? == raw, "finality encoding is not exact")?;
        Ok(value)
    }
    pub fn derive(&self, trusted: &ValidatorSet) -> Result<ValidatorSet> {
        let mut set = raw_validator_set(trusted)?;
        let mut prior = None;
        for step in &self.steps {
            require(
                step.finalize.epoch_id < self.finalize.epoch_id,
                "validator transition is not before checkpoint",
            )?;
            let (epoch, next) = step.verify(&self.finalize.chain_id, prior, &set)?;
            prior = Some(epoch);
            set = next;
        }
        require(
            same_set(&set, &self.validator_set)?,
            "finality validator transition is incomplete",
        )?;
        Ok(set)
    }
    fn verify_checkpoint(&self, checkpoint: &checkpoint::Body) -> Result<()> {
        checkpoint.validate()?;
        let finalize = &self.finalize;
        let header = &finalize.header;
        let set_hash = hex::encode(hash::validator_set_hash(&self.validator_set)?);
        let index = checkpoint
            .epoch_index_root
            .as_deref()
            .ok_or("finality checkpoint index root is missing")?;
        require(
            fold(&checkpoint.ledger_state_root, index)? == checkpoint.state_root,
            "finality checkpoint folded root mismatch",
        )?;
        require(
            set_hash.as_bytes() == checkpoint.validator_set_hash,
            "finality validator set mismatch",
        )?;
        require(
            finalize.chain_id == checkpoint.chain_id,
            "finality chain mismatch",
        )?;
        require(
            finalize.epoch_id == checkpoint.epoch && header.epoch_id == checkpoint.epoch,
            "finality epoch mismatch",
        )?;
        require(
            hex::encode(&header.proposed_state_root).as_bytes() == checkpoint.state_root,
            "finality state root mismatch",
        )?;
        require(
            header.txid_hi == checkpoint.txid_hi,
            "finality transaction high-water mismatch",
        )?;
        if let Some(expected) = &checkpoint.quorum_cert_hash {
            require(
                finalize_hash(finalize)? == *expected,
                "finality certificate hash mismatch",
            )?;
        }
        verify_finalize(&checkpoint.chain_id, &self.validator_set, finalize)
    }
    /// Remove redundant, already verified validator transitions while preserving
    /// the shortest authenticated path to the same final validator set.
    pub fn compact(&self, trusted: &ValidatorSet) -> Result<Self> {
        self.derive(trusted)?;
        let initial = hash::validator_set_hash(&raw_validator_set(trusted)?)?;
        let mut paths = BTreeMap::from([(initial, Vec::<usize>::new())]);
        let mut selected = Vec::new();
        for (index, step) in self.steps.iter().enumerate() {
            let update = ValidatorUpdate::parse(Some(&step.update))
                .map_err(|e| Error::from(e.to_string()))?;
            let next = update
                .validator_set()?
                .for_epoch(&self.finalize.chain_id, update.activate_epoch)?;
            let next = hash::validator_set_hash(&next)?;
            let mut extended = selected.clone();
            extended.push(index);
            selected = paths
                .get(&next)
                .filter(|p| p.len() <= extended.len())
                .cloned()
                .unwrap_or(extended);
            paths.insert(next, selected.clone());
        }
        let mut out = self.clone();
        out.steps = selected
            .into_iter()
            .map(|i| self.steps[i].clone())
            .collect();
        out.derive(trusted)?;
        Ok(out)
    }
}
pub fn verify(
    trusted: &ValidatorSet,
    checkpoint: &checkpoint::Body,
    encoded: &[u8],
) -> Result<VerifiedAnchor> {
    let anchor = Anchor::decode(encoded)?;
    let derived = anchor.derive(trusted)?;
    require(
        same_set(&derived, &anchor.validator_set)?,
        "finality validator transition mismatch",
    )?;
    anchor.verify_checkpoint(checkpoint)?;
    Ok(VerifiedAnchor { anchor })
}
pub fn verify_origin(
    max_bytes: usize,
    trusted: &ValidatorSet,
    chain: &[u8],
    epoch: i64,
    state_root: &[u8],
    set_root: &[u8],
    encoded: &[u8],
) -> Result<Origin> {
    require(
        max_bytes > 0 && encoded.len() <= max_bytes,
        "origin proof size exceeds limit",
    )?;
    require(
        !chain.is_empty()
            && chain.len() <= 128
            && epoch >= 0
            && state_root.len() == 32
            && set_root.len() == 32,
        "origin context is invalid",
    )?;
    let value = Anchor::decode(encoded)?;
    let validators = value.derive(trusted)?;
    let finalize = &value.finalize;
    require(
        finalize.chain_id == chain && finalize.header.chain_id == chain,
        "origin chain differs",
    )?;
    require(
        finalize.epoch_id == epoch && finalize.header.epoch_id == epoch,
        "origin epoch differs",
    )?;
    require(
        finalize.header.proposed_state_root == state_root,
        "origin state root differs",
    )?;
    require(
        hash::validator_set_hash(&validators)?.as_slice() == set_root,
        "origin validator set differs",
    )?;
    verify_finalize(chain, &validators, finalize)?;
    Ok(Origin {
        chain_id: chain.to_vec(),
        epoch_id: epoch,
        state_root: state_root.to_vec(),
        validators,
    })
}
