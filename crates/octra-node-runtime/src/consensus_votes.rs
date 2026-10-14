// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native C_driver local-vote recovery and durability barrier. A driver must
//! broadcast only the vote returned by `save`, after peer/engine authentication.
use octra_node_protocol::consensus::{
    codec::{self, Wire},
    driver_policy,
    engine::Engine,
    hash,
    journal::JournalOwner,
    Bytes, Error, Proposal, Vote, VoteType, NIL,
};
use octra_node_protocol::network::{frame::Frame, swarm::Swarm};
use std::{collections::BTreeMap, future::Future};

pub const BOOTSTRAP_REQUIRED: &str = "vote log bootstrap required";
pub const FLOOR_WAIT: &str = "vote log floor is not behind current height";
#[derive(Clone, Copy)]
pub struct Readiness {
    pub role_can_vote: bool,
    pub can_vote: bool,
    pub finality_proof_needed: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    pub epoch_id: i64,
    pub round: i64,
    pub reason: &'static str,
}
/// Recovery data that the host must durably store before a non-nil precommit.
/// This is speculative recovery data, not a canonical commit or ExEx event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Precommit {
    pub epoch_id: i64,
    pub round: i64,
    pub proposal_id: Bytes,
    pub proposed_state_root: Bytes,
    pub txid_hi: i64,
    pub proposal_wire: Bytes,
    pub vote_wire: Bytes,
}
pub struct VoteGuard {
    chain: Bytes,
    address: Bytes,
    journal: JournalOwner,
    issue: Option<Error>,
    fault: Option<Fault>,
    durable: BTreeMap<Bytes, Vote>,
}
impl VoteGuard {
    pub fn new(chain: Bytes, address: Bytes, journal: JournalOwner) -> Self {
        Self {
            chain,
            address,
            journal,
            issue: None,
            fault: None,
            durable: BTreeMap::new(),
        }
    }
    pub fn issue(&self) -> Option<&Error> {
        self.issue.as_ref()
    }
    pub fn fault(&self) -> Option<&Fault> {
        self.fault.as_ref()
    }
    pub fn bootstrap_pending(&self) -> bool {
        self.issue
            .as_ref()
            .is_some_and(|e| e.as_bytes() == BOOTSTRAP_REQUIRED.as_bytes())
    }
    pub fn allowed(&self, readiness: Readiness) -> bool {
        self.issue.is_none() && readiness.can_vote && !readiness.finality_proof_needed
    }
    pub fn state(&self, engine: &Engine, readiness: Readiness) -> (bool, Option<&'static str>) {
        let reason = if let Some(issue) = &self.issue {
            Some(issue_label(issue))
        } else if let Some(fault) = self
            .fault
            .as_ref()
            .filter(|f| f.epoch_id == engine.state().height && f.round >= engine.state().round)
        {
            Some(fault.reason)
        } else if !readiness.role_can_vote {
            Some("role")
        } else if readiness.finality_proof_needed {
            Some("finality_proof")
        } else if !self.allowed(readiness) {
            Some("not_ready")
        } else if !engine.validators().is_validator(&self.address) {
            Some("not_member")
        } else {
            None
        };
        (reason.is_none(), reason)
    }
    fn restore_vote(&self, engine: &Engine, wire: &[u8]) -> Result<(), Error> {
        let vote = Vote::decode(wire)
            .map_err(|e| Error::from(format!("vote log wire decode failed: Failure(\"{e}\")")))?;
        if vote.encode()? != wire {
            return Err("vote log wire is not exact".into());
        }
        if vote.chain_id != self.chain {
            return Err("vote log record chain does not match".into());
        }
        if vote.validator != self.address {
            return Err("vote log record validator does not match".into());
        }
        if vote.epoch_id != engine.state().height {
            return Err("vote log record epoch does not match".into());
        }
        let public = engine
            .validators()
            .public_key(&vote.validator)
            .ok_or("vote log record validator is unavailable")?;
        if !hash::verify_vote(public, &vote)? {
            return Err("vote log record signature is invalid".into());
        }
        self.journal.keep_vote(vote)?;
        Ok(())
    }
    /// Restore signed recovery votes and move beyond the highest stored round
    /// before allowing startup. An existing floor cannot be silently reset.
    pub fn prepare(
        &mut self,
        running: bool,
        engine: &mut Engine,
        wires: Result<Vec<Bytes>, Error>,
    ) -> Result<(), Error> {
        if running {
            return Err("consensus driver is already running".into());
        }
        self.issue = None;
        let restored = (|| {
            for wire in wires? {
                self.restore_vote(engine, &wire)?;
            }
            if let Some(round) =
                self.journal
                    .max_round(&self.chain, &self.address, engine.state().height)?
            {
                if round >= codec::MAX_ROUND {
                    return Err("vote log reached round limit".into());
                }
                if round + 1 > engine.state().round {
                    engine.realign_round(round + 1)?;
                }
            }
            let height = engine.state().height;
            match self.journal.floor()? {
                Some(floor) if height > floor => Ok(()),
                Some(floor)
                    if !engine.validators().is_validator(&self.address) && height == floor =>
                {
                    Ok(())
                }
                Some(_) => Err(FLOOR_WAIT.into()),
                None if height <= 1 => self.journal.set_floor(height.wrapping_sub(1)),
                None => Err(BOOTSTRAP_REQUIRED.into()),
            }
        })();
        if let Err(reason) = &restored {
            self.issue = Some(reason.clone());
        }
        restored
    }
    fn hold(&mut self, vote: &Vote, reason: &'static str) {
        self.fault = Some(Fault {
            epoch_id: vote.epoch_id,
            round: vote.round,
            reason,
        });
    }
    pub async fn save<F: FnOnce(Precommit) -> R, R: Future<Output = bool>>(
        &mut self,
        engine: &Engine,
        vote: &Vote,
        proposal: Option<&Proposal>,
        finality_proof_needed: bool,
        before_precommit: F,
    ) -> Result<Option<Vote>, Error> {
        if vote.validator != self.address {
            return Ok(Some(vote.clone()));
        }
        if finality_proof_needed || self.issue.is_some() {
            return Ok(None);
        }
        if let Err(reason) = self.journal.check_vote(vote) {
            self.issue = Some(reason);
            return Ok(None);
        }
        if vote.vote_type == VoteType::Precommit && vote.proposal_id != NIL {
            let key = driver_policy::vote_key(vote);
            if !self.durable.contains_key(&key) {
                let Some(proposal) =
                    proposal.or_else(|| engine.find_proposal(&vote.proposal_id, vote.round))
                else {
                    self.hold(vote, "precommit_proposal_missing");
                    return Ok(None);
                };
                if !driver_policy::proposal_binds_vote(vote, proposal)? {
                    self.hold(vote, "precommit_proposal_mismatch");
                    return Ok(None);
                }
                let durable = before_precommit(Precommit {
                    epoch_id: vote.epoch_id,
                    round: vote.round,
                    proposal_id: vote.proposal_id.clone(),
                    proposed_state_root: proposal.header.proposed_state_root.clone(),
                    txid_hi: proposal.header.txid_hi,
                    proposal_wire: proposal.encode()?,
                    vote_wire: vote.encode()?,
                })
                .await;
                if !durable {
                    self.hold(vote, "precommit_not_durable");
                    return Ok(None);
                }
                self.durable.insert(key, vote.clone());
            }
            self.fault = None;
        }
        match self.journal.keep_vote(vote.clone()) {
            Ok(stored) => Ok(Some(stored)),
            Err(reason) => {
                self.issue = Some(reason);
                Ok(None)
            }
        }
    }
    /// Called after canonical finalization has durably advanced the vote floor.
    pub fn prune_durable(&mut self, finalized: i64) {
        self.durable.retain(|_, v| v.epoch_id > finalized);
    }

    /// Canonical publication has succeeded. Retain storage failures as a voting
    /// hold while allowing the node to follow certified chain progress.
    pub fn finalized(&mut self, epoch: i64, journal_result: Result<(), Error>) {
        self.prune_durable(epoch);
        self.fault = None;
        self.issue = journal_result.err();
    }

    /// Persist before handing a local vote to authenticated peer queues.
    #[allow(clippy::too_many_arguments)] // Keep the engine view and durability hook explicit.
    pub async fn broadcast<F: FnOnce(Precommit) -> R, R: Future<Output = bool>>(
        &mut self,
        engine: &Engine,
        swarm: &Swarm,
        vote: &Vote,
        proposal: Option<&Proposal>,
        finality_proof_needed: bool,
        before_precommit: F,
    ) -> Result<bool, Error> {
        let Some(stored) = self
            .save(
                engine,
                vote,
                proposal,
                finality_proof_needed,
                before_precommit,
            )
            .await?
        else {
            return Ok(false);
        };
        swarm
            .broadcast(
                Frame {
                    message: 0x31,
                    payload: stored.encode()?,
                },
                None,
                false,
            )
            .await?;
        Ok(true)
    }
}
pub fn issue_label(reason: &Error) -> &'static str {
    match reason.as_bytes() {
        b"local vote conflicts with stored vote" => "vote_log_conflict",
        b"vote log reached round limit" => "vote_log_limit",
        b"vote log bootstrap required" => "vote_log_bootstrap",
        b"vote log floor is not behind current height" => "vote_floor_wait",
        value
            if [
                b"vote log record".as_slice(),
                b"vote log wire",
                b"vote log epoch",
                b"vote log path",
                b"vote log floor",
            ]
            .iter()
            .any(|prefix| value.starts_with(prefix)) =>
        {
            "vote_log_corrupt"
        }
        _ => "vote_log_storage",
    }
}
