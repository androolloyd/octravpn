// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Authenticated pending-precommit recovery and the host durability callback.
//! Recovery never publishes canonical state or emits an ExEx commit. The driver
//! restores an authenticated lock or reconciles legacy records with peers;
//! canonical publication still requires execution and authenticated finality.
use crate::{consensus_bundle as bundle, consensus_votes::Precommit};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use octra_node_protocol::{
    consensus::{
        codec::Wire, engine::tx_list_hash_for_header, hash, journal::JournalOwner,
        pending_log::PendingCommit, policy::Protocol, Bytes, Error, Proposal, ValidatorSet, Vote,
        VoteType,
    },
    native_base64,
};

pub struct Context<'a> {
    pub chain_id: &'a [u8],
    pub validator_set: &'a ValidatorSet,
    pub protocol: Protocol,
    pub rules: &'a bundle::Rules,
}
pub struct Recovered {
    pub proposal: Proposal,
    pub vote: Vote,
    pub bundle: bundle::Accepted,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Restored {
    Lock,
    Legacy,
    Invalid(Error),
}

/// Preserve the native order: authenticate, cache the bundle, restore the lock.
/// Call while the driver is stopped and with the record's historical set.
pub fn restore(
    context: &Context<'_>,
    pending: &PendingCommit,
    running: bool,
    engine: &mut octra_node_protocol::consensus::engine::Engine,
    store_bundle: impl FnOnce(&Recovered) -> Result<(), Error>,
) -> Restored {
    if pending.proposal_b64.is_none() || pending.vote_b64.is_none() {
        return Restored::Legacy;
    }
    let result = (|| {
        let recovered = recover(context, pending)?;
        store_bundle(&recovered)?;
        if running {
            return Err("consensus driver is already running".into());
        }
        engine.restore_precommit_lock(recovered.proposal)
    })();
    match result {
        Ok(()) => Restored::Lock,
        Err(e) => Restored::Invalid(e),
    }
}
fn failure(e: impl std::fmt::Display) -> Error {
    format!("Failure(\"{e}\")").into()
}
fn base64_error(e: native_base64::Error) -> Error {
    format!("Invalid_argument(\"{e}\")").into()
}
pub fn recover(context: &Context<'_>, pending: &PendingCommit) -> Result<Recovered, Error> {
    let (Some(p), Some(v)) = (&pending.proposal_b64, &pending.vote_b64) else {
        return Err("legacy pending record".into());
    };
    let proposal =
        Proposal::decode(&native_base64::decode(p).map_err(base64_error)?).map_err(failure)?;
    let vote = Vote::decode(&native_base64::decode(v).map_err(base64_error)?).map_err(failure)?;
    let pid = hash::proposal_id(&proposal.header)?;
    let proposal_signature = match context.validator_set.public_key(&proposal.proposer) {
        Some(key) => hash::verify_proposal(key, &proposal)?,
        None => false,
    };
    let vote_signature = match context.validator_set.public_key(&vote.validator) {
        Some(key) => hash::verify_vote(key, &vote)?,
        None => false,
    };
    let reason = if proposal.epoch_id != pending.epoch_id {
        Some("pending proposal epoch mismatch")
    } else if proposal.round != pending.round {
        Some("pending proposal round mismatch")
    } else if !context.validator_set.proposal_well_formed(
        context.chain_id,
        context.protocol,
        &proposal,
    )? {
        Some("pending proposal envelope invalid")
    } else if bundle::hash_hex(&pid) != pending.proposal_id {
        Some("pending proposal id mismatch")
    } else if bundle::hash_hex(&proposal.header.proposed_state_root) != pending.proposed_state_root
    {
        Some("pending state root mismatch")
    } else if proposal.header.txid_hi != pending.txid_hi {
        Some("pending txid mismatch")
    } else if !proposal_signature {
        Some("pending proposal signature invalid")
    } else if vote.chain_id != context.chain_id {
        Some("pending vote chain mismatch")
    } else if vote.epoch_id != proposal.epoch_id {
        Some("pending vote epoch mismatch")
    } else if vote.round != proposal.round {
        Some("pending vote round mismatch")
    } else if vote.vote_type != VoteType::Precommit {
        Some("pending vote type mismatch")
    } else if vote.proposal_id != pid {
        Some("pending vote proposal mismatch")
    } else if vote.validator != pending.validator_addr {
        Some("pending vote validator mismatch")
    } else if !vote_signature {
        Some("pending vote signature invalid")
    } else if proposal
        .tx_hashes
        .iter()
        .map(|h| bundle::hash_hex(h))
        .collect::<Vec<_>>()
        != pending.tx_hashes
    {
        Some("pending proposal bundle mismatch")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(reason.into());
    }
    let raw = bundle::RawBundle {
        tx_hashes: pending.tx_hashes.clone(),
        txs_json: pending.txs_json.clone(),
        receipts_json: pending.receipts_json.clone(),
    };
    let bundle = bundle::finalized(&proposal.header, &raw, context.rules)
        .map_err(|e| Error::from(format!("pending bundle {e}")))?;
    Ok(Recovered {
        proposal,
        vote,
        bundle,
    })
}

/// Match the native live precommit host checks. Signatures are authenticated by
/// the engine before this callback; restart uses `recover`, which checks both.
pub fn matches(
    context: &Context<'_>,
    validator: &[u8],
    request: &Precommit,
    raw: &bundle::RawBundle,
) -> Result<(), Error> {
    let p = Proposal::decode(&request.proposal_wire).map_err(failure)?;
    let v = Vote::decode(&request.vote_wire).map_err(failure)?;
    let pid = hash::proposal_id(&p.header)?;
    let reason = if p.epoch_id != request.epoch_id {
        Some("proposal epoch mismatch")
    } else if p.round != request.round {
        Some("proposal round mismatch")
    } else if !context
        .validator_set
        .proposal_well_formed(context.chain_id, context.protocol, &p)?
    {
        Some("proposal envelope mismatch")
    } else if pid.as_slice() != request.proposal_id {
        Some("proposal id mismatch")
    } else if p.header.proposed_state_root != request.proposed_state_root {
        Some("proposal state root mismatch")
    } else if p.header.txid_hi != request.txid_hi {
        Some("proposal txid mismatch")
    } else if p
        .tx_hashes
        .iter()
        .map(|h| bundle::hash_hex(h))
        .collect::<Vec<_>>()
        != raw.tx_hashes
    {
        Some("proposal bundle mismatch")
    } else if tx_list_hash_for_header(&raw.tx_hashes).as_slice() != p.header.tx_list_hash {
        Some("proposal tx list root mismatch")
    } else if hash::receipt_root(&raw.receipts_json)?.as_slice() != p.header.receipt_root {
        Some("proposal receipt root mismatch")
    } else if hash::parent_commit_hash_opt(p.parent_commit.as_ref())?.as_slice()
        != p.header.parent_commit_hash
    {
        Some("proposal parent commit mismatch")
    } else if v.chain_id != p.chain_id {
        Some("vote chain mismatch")
    } else if v.epoch_id != request.epoch_id {
        Some("vote epoch mismatch")
    } else if v.round != request.round {
        Some("vote round mismatch")
    } else if v.vote_type != VoteType::Precommit {
        Some("vote type mismatch")
    } else if v.proposal_id != pid {
        Some("vote proposal mismatch")
    } else if v.validator != validator {
        Some("vote validator mismatch")
    } else {
        None
    };
    reason.map_or(Ok(()), |r| Err(r.into()))
}

/// Sync a decoded bundle when it differs from the host's current execution,
/// then fsync recovery data before returning success to the vote guard. The
/// caller marks itself unsynced on any error, matching the native host.
#[allow(clippy::too_many_arguments)] // Explicit native host callback inputs.
pub fn before_precommit(
    context: &Context<'_>,
    journal: &JournalOwner,
    validator: &[u8],
    request: &Precommit,
    raw: &bundle::RawBundle,
    current_tx_hashes: &[Bytes],
    now: f64,
    sync_bundle: impl FnOnce(&bundle::Accepted) -> Result<(), Error>,
) -> Result<(), Error> {
    let decoded = bundle::decode(raw, context.rules)?;
    matches(context, validator, request, raw)?;
    if current_tx_hashes != decoded.tx_hashes {
        sync_bundle(&decoded)?;
    }
    journal.keep_pending(&PendingCommit {
        epoch_id: request.epoch_id << 1 >> 1,
        round: request.round,
        proposal_id: bundle::hash_hex(&request.proposal_id),
        proposed_state_root: bundle::hash_hex(&request.proposed_state_root),
        txid_hi: request.txid_hi,
        ts: now,
        validator_addr: validator.to_vec(),
        proposal_b64: Some(STANDARD.encode(&request.proposal_wire).into_bytes()),
        vote_b64: Some(STANDARD.encode(&request.vote_wire).into_bytes()),
        tx_hashes: raw.tx_hashes.clone(),
        txs_json: raw.txs_json.clone(),
        receipts_json: raw.receipts_json.clone(),
    })
}
