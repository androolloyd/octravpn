// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native finalized checkpoint authority and authenticated validator transitions.
use super::{checkpoint, lower_hex, require, Error, Result};
use crate::{
    consensus::{
        codec::Wire,
        hash,
        policy::{self, QuorumPolicy, Rule},
        qc::{self, FinalityMode},
        relief, relief_log, Finalize, Validator, ValidatorSet,
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
// An update that evicts validators also carries the set they were removed
// from, so it and its state proof get their own, larger limits.
const MAX_EVICTION_SET: usize = crate::control_payload::EVICTION_SOURCE_LIMIT;
const MAX_ADDRESS: usize = 128;
const MAX_VALIDATORS: usize = crate::consensus::codec::MAX_VALIDATORS;
const MAX_EVICTION_UPDATE: usize = concat!(
    r#"{"activate_epoch":"9223372036854775807","fingerprint":""#,
    "0000000000000000000000000000000000000000000000000000000000000000",
    r#"","validators":[],"standard":"bonded_stake","weighted":true,"#,
    r#""source_epoch":"9223372036854775807","eviction":{"epoch":"9223372036854775807","#,
    r#""source":"","offenders":[]}}"#
)
.len()
    + 4 * MAX_EVICTION_SET.div_ceil(3)
    + MAX_VALIDATORS
        * (r#"{"address":"","pubkey":"","weight":""}"#.len() + MAX_ADDRESS + 44 + 256 + 1)
    + MAX_VALIDATORS * (MAX_ADDRESS + 3);
const MAX_EVICTION_PROOF: usize = MAX_PROOF + 4 * MAX_EVICTION_UPDATE.div_ceil(3);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Pending,
    Active,
    Relief(relief::Mark),
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
    transition_epoch: i64,
    stake: ValidatorSet,
}
impl VerifiedAnchor {
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }
    pub fn transition_base(&self) -> (i64, &ValidatorSet) {
        (self.transition_epoch, &self.stake)
    }
    pub fn relief(&self) -> Option<&relief::Mark> {
        self.anchor.live_relief()
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
/// Whether `update` is a canonical eviction update that this step is in a
/// position to prove: the pending one for the next epoch, or an active one.
fn future_eviction(source: &Source, finalize: &Finalize, update: &[u8]) -> bool {
    let Ok(parsed) = ValidatorUpdate::of_string(update) else {
        return false;
    };
    let Some(witness) = &parsed.eviction else {
        return false;
    };
    parsed.to_bytes() == update
        && QuorumPolicy::for_chain(&finalize.chain_id).seatless(witness.epoch)
        && match source {
            Source::Pending => {
                witness.epoch == finalize.epoch_id
                    && finalize.epoch_id != i64::MAX
                    && parsed.activate_epoch == finalize.epoch_id + 1
            }
            Source::Active => parsed.activate_epoch <= finalize.epoch_id,
            Source::Relief(_) => false,
        }
}
fn proof_size_error(bytes: usize, max: usize) -> String {
    format!("validator transition proof exceeds size limit bytes = {bytes} limit = {max}")
}
fn check_step_size(step: &Step) -> Result<()> {
    let future = future_eviction(&step.source, &step.finalize, &step.update);
    let (max_update, max_proof) = if future {
        (MAX_EVICTION_UPDATE, MAX_EVICTION_PROOF)
    } else {
        (MAX_UPDATE, MAX_PROOF)
    };
    require(
        step.update.len() <= max_update,
        "validator transition update exceeds size limit",
    )?;
    if step.proof.len() > max_proof {
        return Err(proof_size_error(step.proof.len(), max_proof).into());
    }
    Ok(())
}
fn set_size_limit(steps: &[Step]) -> usize {
    if steps
        .iter()
        .any(|step| future_eviction(&step.source, &step.finalize, &step.update))
    {
        MAX_SET.max(MAX_EVICTION_SET)
    } else {
        MAX_SET
    }
}
fn put_step(w: &mut Writer, step: &Step) -> Result<()> {
    check_step_size(step)?;
    w.put_u8(match &step.source {
        Source::Pending => 1,
        Source::Active => 2,
        Source::Relief(_) => 3,
    })?;
    if let Source::Relief(mark) = &step.source {
        w.put_bytes(&relief_log::encode(mark)?)?;
    }
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
        3 => Source::Relief(relief_log::decode(
            r.get_bytes_bounded(relief_log::MAX_WIRE_BYTES as usize)?,
        )?),
        _ => return Err("validator transition source is invalid".into()),
    };
    let finalize = Finalize::decode(r.get_bytes_bounded(MAX_FINALIZE)?)?;
    let ledger_state_root = r.get_bytes_bounded(MAX_ROOT)?.to_vec();
    let epoch_index_root = r.get_bytes_bounded(MAX_ROOT)?.to_vec();
    let update = r
        .get_bytes_bounded(MAX_UPDATE.max(MAX_EVICTION_UPDATE))?
        .to_vec();
    let future = future_eviction(&source, &finalize, &update);
    if update.len() > MAX_UPDATE && !future {
        return Err("validator transition update exceeds legacy size limit".into());
    }
    let max_proof = if future {
        MAX_EVICTION_PROOF
    } else {
        MAX_PROOF
    };
    let bytes = r.get_u32()? as usize;
    if bytes > max_proof {
        return Err(proof_size_error(bytes, max_proof).into());
    }
    let proof = r.get_raw(bytes)?.to_vec();
    Ok(Step {
        source,
        finalize,
        ledger_state_root,
        epoch_index_root,
        update,
        proof,
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
    let validators: Vec<_> = entries.iter().map(|(member, _)| member.clone()).collect();
    let mut result = if set.weighted {
        ValidatorSet::weighted(entries)?
    } else {
        ValidatorSet::unweighted(validators.clone())
    };
    result.authors = set
        .authors
        .as_ref()
        .map(|(height, entries)| {
            entries
                .iter()
                .map(|(member, weight)| {
                    Ok((
                        Validator {
                            address: member.address.clone(),
                            pubkey: checkpoint::raw_pubkey(&member.pubkey)?,
                        },
                        weight.clone(),
                    ))
                })
                .collect::<Result<Vec<_>>>()
                .map(|entries| (*height, entries))
        })
        .transpose()?;
    if !set.weighted {
        return Ok(result);
    }
    // A declared-weight set must be exactly the set its own fields describe.
    ValidatorSet {
        validators,
        authors: result.authors,
        ..set.clone()
    }
    .validate_shape()
    .map_err(|error| error.message().into())
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
    if let Some((_, entries)) = &mut result.authors {
        for (member, _) in entries {
            member.pubkey = STANDARD.encode(&member.pubkey).into_bytes();
        }
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
fn same_voters(a: &ValidatorSet, b: &ValidatorSet) -> Result<bool> {
    let voters = |set: &ValidatorSet| ValidatorSet {
        authors: None,
        ..set.clone()
    };
    same_set(&voters(a), &voters(b))
}
fn structural_set(policy: QuorumPolicy, epoch: i64, set: &ValidatorSet) -> Result<ValidatorSet> {
    set.structural_for_policy(policy, epoch)
        .map_err(|error| error.message().into())
}
/// The set a pending eviction leaves, if its witness is the set that
/// voted at `epoch` and the update is exactly that removal.
fn eviction_set(
    policy: QuorumPolicy,
    epoch: i64,
    current: &ValidatorSet,
    update: &ValidatorUpdate,
    witness: &crate::consensus::Eviction,
) -> Result<ValidatorSet> {
    require(
        epoch >= 0 && epoch != i64::MAX && policy.seatless(epoch),
        "validator eviction source epoch is invalid",
    )?;
    require(
        witness.epoch == epoch
            && update.source_epoch == Some(epoch)
            && update.activate_epoch == epoch + 1,
        "validator eviction source epoch differs",
    )?;
    let current = structural_set(policy, epoch, current)?;
    let source = witness
        .source
        .validate_shape()
        .map_err(|error| Error::from(error.message()))?;
    require(
        same_voters(&source, &current)?,
        "validator eviction source set differs",
    )?;
    let (next, _) = update
        .check_eviction(epoch, &witness.offenders, &current)
        .map_err(|error| Error::from(error.0))?;
    structural_set(policy, update.activate_epoch, &next)
}
fn verify_finalize(
    policy: QuorumPolicy,
    chain: &[u8],
    set: &ValidatorSet,
    finalize: &Finalize,
) -> Result<()> {
    require(
        finalize.chain_id == chain && finalize.header.chain_id == chain,
        "finality chain mismatch",
    )?;
    require(
        finalize.epoch_id == finalize.header.epoch_id,
        "finality epoch mismatch",
    )?;
    let structural = set
        .structural_for_policy(policy, finalize.epoch_id)
        .map_err(|error| error.message())?;
    qc::validate_finalize_for_policy(
        policy,
        chain,
        &structural,
        finalize,
        FinalityMode::Persisted,
    )
    .map_err(|e| Error::from(format!("finality qc {e}")))?;
    let vote_set = set.for_policy(policy, finalize.epoch_id)?;
    let signers = finalize
        .precommits
        .iter()
        .map(|v| v.validator.clone())
        .collect::<Vec<_>>();
    require(
        vote_set.pair_for_policy(policy, finalize.epoch_id, &signers),
        "finality qc signer quorum",
    )
}
impl Step {
    fn verify(
        &self,
        policy: QuorumPolicy,
        chain: &[u8],
        prior: Option<i64>,
        set: &ValidatorSet,
    ) -> Result<(i64, ValidatorSet)> {
        check_step_size(self)?;
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
            ValidatorUpdate::of_string(&self.update).map_err(|e| Error::from(e.to_string()))?;
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
        let (path, active) = match &self.source {
            Source::Pending => (PENDING_KEY, update.activate_epoch == epoch + 1),
            Source::Active => (ACTIVE_KEY, update.activate_epoch <= epoch),
            Source::Relief(mark) => (
                PENDING_KEY,
                mark.height == epoch + 1
                    && mark.activate_epoch == update.activate_epoch
                    && mark.fingerprint == update.fingerprint.as_bytes()
                    && policy::quorum_rule(chain, mark.height) == Rule::Stake,
            ),
        };
        require(active, "validator transition activation epoch mismatch")?;
        verify_finalize(policy, chain, set, &self.finalize)?;
        require(
            hex::encode(&self.finalize.header.proposed_state_root).as_bytes()
                == fold(&self.ledger_state_root, &self.epoch_index_root)?,
            "validator transition folded root mismatch",
        )?;
        let next = update.validator_set()?;
        let use_epoch = match &self.source {
            Source::Pending => update.activate_epoch,
            Source::Active => epoch,
            Source::Relief(mark) => mark.height,
        };
        let next = match (&self.source, &update.eviction) {
            (Source::Pending, Some(witness)) => eviction_set(policy, epoch, set, &update, witness)?,
            (Source::Relief(_), Some(_)) => {
                return Err("validator eviction requires pending proof".into())
            }
            (Source::Active, eviction) => {
                let current = structural_set(policy, use_epoch, set)?;
                let checked = structural_set(policy, use_epoch, &next)?;
                if !same_voters(&checked, &current)? {
                    require(
                        eviction.is_none(),
                        "active validator eviction is not trusted",
                    )?;
                    next.checked_for_policy(policy, use_epoch)?;
                }
                next
            }
            (Source::Pending | Source::Relief(_), None) => {
                next.checked_for_policy(policy, use_epoch)?;
                next
            }
        };
        let next = match &self.source {
            Source::Pending | Source::Active => next,
            Source::Relief(mark) => {
                let current = set.checked_for_policy(policy, mark.height)?;
                let target = next.for_policy(policy, update.activate_epoch)?;
                relief::Plan {
                    chain_id: chain,
                    height: mark.height,
                    current: &current,
                    activate_epoch: update.activate_epoch,
                    target: &target,
                    fingerprint: update.fingerprint.as_bytes(),
                }
                .restore_with_authors_for_policy(Some(policy), mark)?
                .ok_or("validator relief step is expired")?
            }
        };
        // The state proof is checked last, after the set the update names
        // has been accepted, as upstream orders the two.
        let value = irmin::proof::verify(&self.ledger_state_root, &[b"meta", path], &self.proof)?;
        require(
            value.as_deref() == Some(self.update.as_slice()),
            "validator transition state proof mismatch",
        )?;
        Ok((epoch, next))
    }
}
impl Anchor {
    pub fn raw(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.put_list(&self.steps, put_step)?;
        w.put_bytes(&self.finalize.encode()?)?;
        let validator_set = self.validator_set.encode()?;
        require(
            validator_set.len() <= set_size_limit(&self.steps),
            "validator finality set exceeds size limit",
        )?;
        w.put_bytes(&validator_set)?;
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
            let steps = r.get_list(MAX_STEPS, get_step)?;
            let finalize = Finalize::decode(r.get_bytes_bounded(MAX_FINALIZE)?)?;
            let validator_set = ValidatorSet::decode(r.get_bytes_bounded(set_size_limit(&steps))?)?;
            let value = Self {
                steps,
                finalize,
                validator_set,
            };
            r.finish()?;
            Ok(value)
        })()
        .map_err(failure)?;
        require(value.raw()? == raw, "finality encoding is not exact")?;
        Ok(value)
    }
    pub fn live_relief(&self) -> Option<&relief::Mark> {
        self.steps.iter().rev().find_map(|step| match &step.source {
            Source::Relief(mark) if self.finalize.epoch_id < mark.activate_epoch => Some(mark),
            _ => None,
        })
    }
    pub fn path_epoch(&self) -> i64 {
        self.steps.last().map_or(-1, |step| step.finalize.epoch_id)
    }
    fn derived_set(&self, policy: QuorumPolicy, stake: &ValidatorSet) -> Result<ValidatorSet> {
        if policy.select(self.finalize.epoch_id) == Rule::Stake {
            structural_set(policy, self.finalize.epoch_id, stake)
        } else if let Some(step) = self.steps.last() {
            let update =
                ValidatorUpdate::of_string(&step.update).map_err(|e| Error::from(e.to_string()))?;
            Ok(stake.checked_for_policy(policy, update.activate_epoch)?)
        } else {
            Ok(stake.clone())
        }
    }
    fn derive_stake(&self, policy: QuorumPolicy, trusted: &ValidatorSet) -> Result<ValidatorSet> {
        let mut set = raw_validator_set(trusted)?;
        let mut prior = None;
        for step in &self.steps {
            require(
                step.finalize.epoch_id < self.finalize.epoch_id,
                "validator transition is not before checkpoint",
            )?;
            let (epoch, next) = step.verify(policy, &self.finalize.chain_id, prior, &set)?;
            prior = Some(epoch);
            set = next;
        }
        require(
            same_set(&self.derived_set(policy, &set)?, &self.validator_set)?,
            "finality validator transition is incomplete",
        )?;
        Ok(set)
    }
    pub fn derive(&self, trusted: &ValidatorSet) -> Result<ValidatorSet> {
        self.derive_with_policy(QuorumPolicy::for_chain(&self.finalize.chain_id), trusted)
    }
    pub fn derive_with_policy(
        &self,
        policy: QuorumPolicy,
        trusted: &ValidatorSet,
    ) -> Result<ValidatorSet> {
        self.derived_set(policy, &self.derive_stake(policy, trusted)?)
    }
    fn verify_checkpoint(&self, policy: QuorumPolicy, checkpoint: &checkpoint::Body) -> Result<()> {
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
        verify_finalize(policy, &checkpoint.chain_id, &self.validator_set, finalize)
    }
    /// Minimize encoded bytes over independently authenticated paths, preserving
    /// a live relief transition and the raw stake/effective-authority distinction.
    pub fn compact(&self, trusted: &ValidatorSet) -> Result<Self> {
        self.compact_with_policy(QuorumPolicy::for_chain(&self.finalize.chain_id), trusted)
    }
    pub fn compact_with_policy(
        &self,
        policy: QuorumPolicy,
        trusted: &ValidatorSet,
    ) -> Result<Self> {
        self.derive_stake(policy, trusted)?;
        #[derive(Clone)]
        struct Path {
            bytes: usize,
            prior: Option<i64>,
            validators: ValidatorSet,
            steps: Vec<Step>,
        }
        let key = |path: &Path| -> Result<_> {
            let mut ending = self.clone();
            ending.steps = path.steps.last().cloned().into_iter().collect();
            Ok((
                hash::validator_set_hash(&path.validators)?,
                ending
                    .derived_set(policy, &path.validators)
                    .ok()
                    .map(|set| hash::validator_set_hash(&set))
                    .transpose()?,
            ))
        };
        let initial = raw_validator_set(trusted)?;
        let empty = Path {
            bytes: 0,
            prior: None,
            validators: initial.clone(),
            steps: Vec::new(),
        };
        let mut paths = BTreeMap::from([(key(&empty)?, empty.clone())]);
        let mut selected = empty;
        let mut prior = None;
        let mut current = initial;
        for step in &self.steps {
            let (epoch, next) = step.verify(policy, &self.finalize.chain_id, prior, &current)?;
            let mut choices = Vec::new();
            for path in paths.values() {
                if !path.validators.is_author(
                    &step.finalize.chain_id,
                    step.finalize.epoch_id,
                    &step.finalize.header.creator_addr,
                ) {
                    continue;
                }
                let mut link = step.clone();
                link.finalize
                    .precommits
                    .retain(|vote| path.validators.public_key(&vote.validator).is_some());
                let Ok(voters) = path
                    .validators
                    .structural_for_policy(policy, step.finalize.epoch_id)
                else {
                    continue;
                };
                if !voters.pair_for_policy(
                    policy,
                    step.finalize.epoch_id,
                    &link
                        .finalize
                        .precommits
                        .iter()
                        .map(|vote| vote.validator.clone())
                        .collect::<Vec<_>>(),
                ) {
                    continue;
                }
                let mut wire = Writer::new();
                put_step(&mut wire, &link)?;
                choices.push((path.bytes + wire.into_bytes().len(), path, link));
            }
            choices.sort_by_key(|(bytes, _, _)| *bytes);
            let mut extended = None;
            for (bytes, path, link) in choices {
                if let Ok((_, reached)) = link.verify(
                    policy,
                    &self.finalize.chain_id,
                    path.prior,
                    &path.validators,
                ) {
                    if same_set(&reached, &next)? {
                        let mut steps = path.steps.clone();
                        steps.push(link);
                        extended = Some(Path {
                            bytes,
                            prior: Some(epoch),
                            validators: next.clone(),
                            steps,
                        });
                        break;
                    }
                }
            }
            let extended = extended.ok_or("validator path has no checked link")?;
            if matches!(&step.source, Source::Relief(mark) if Some(mark) == self.live_relief()) {
                paths.clear();
            }
            let id = key(&extended)?;
            selected = paths
                .get(&id)
                .filter(|old| old.bytes <= extended.bytes)
                .cloned()
                .unwrap_or(extended);
            paths.insert(id, selected.clone());
            prior = Some(epoch);
            current = next;
        }
        for path in paths.values() {
            let mut short = self.clone();
            short.steps.clone_from(&path.steps);
            let reaches = match short.derived_set(policy, &path.validators) {
                Ok(ending) => same_set(&ending, &self.validator_set)?,
                Err(_) => false,
            };
            if reaches
                && (path.bytes < selected.bytes
                    || (path.bytes == selected.bytes && path.prior < selected.prior))
            {
                selected = path.clone();
            }
        }
        let mut out = self.clone();
        out.steps = selected.steps;
        out.derive_stake(policy, trusted)?;
        if out.raw()?.len() < self.raw()?.len() {
            Ok(out)
        } else {
            Ok(self.clone())
        }
    }
}
pub fn verify(
    trusted: &ValidatorSet,
    checkpoint: &checkpoint::Body,
    encoded: &[u8],
) -> Result<VerifiedAnchor> {
    verify_with_policy(
        QuorumPolicy::for_chain(&checkpoint.chain_id),
        trusted,
        checkpoint,
        encoded,
    )
}
pub fn verify_with_policy(
    policy: QuorumPolicy,
    trusted: &ValidatorSet,
    checkpoint: &checkpoint::Body,
    encoded: &[u8],
) -> Result<VerifiedAnchor> {
    let anchor = Anchor::decode(encoded)?;
    let stake = anchor.derive_stake(policy, trusted)?;
    anchor.verify_checkpoint(policy, checkpoint)?;
    Ok(VerifiedAnchor {
        transition_epoch: anchor.path_epoch(),
        anchor,
        stake,
    })
}
pub fn verify_path(trusted: &ValidatorSet, encoded: &[u8]) -> Result<VerifiedAnchor> {
    let anchor = Anchor::decode(encoded)?;
    let policy = QuorumPolicy::for_chain(&anchor.finalize.chain_id);
    let stake = anchor.derive_stake(policy, trusted)?;
    verify_finalize(
        policy,
        &anchor.finalize.chain_id,
        &anchor.validator_set,
        &anchor.finalize,
    )?;
    Ok(VerifiedAnchor {
        transition_epoch: anchor.path_epoch(),
        anchor,
        stake,
    })
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
    verify_finalize(QuorumPolicy::for_chain(chain), chain, &validators, finalize)?;
    Ok(Origin {
        chain_id: chain.to_vec(),
        epoch_id: epoch,
        state_root: state_root.to_vec(),
        validators,
    })
}
