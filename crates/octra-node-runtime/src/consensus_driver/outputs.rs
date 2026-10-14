// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    driver_policy, hash, Driver, Duration, Error, Frame, Host, Instant, Output, Pace, Proposal,
    Publication, RoundStep, RoundSync, Timeout, Vote, Wire,
};
use octra_node_protocol::consensus::{policy, VoteType};
impl<H: Host, C: Publication> Driver<H, C> {
    pub(super) fn timer(&mut self, timeout: Timeout, delay: Duration) {
        self.timers.spawn(async move {
            tokio::time::sleep(delay).await;
            timeout
        });
    }
    pub(super) async fn round_sync(
        &mut self,
        round: i64,
        step: RoundStep,
        request: bool,
    ) -> Result<(), Error> {
        let Some(public) = self.engine.validators().public_key(&self.address) else {
            return Ok(());
        };
        if !request && !self.votes.allowed(self.host.readiness()) {
            return Ok(());
        }
        let mut sync = RoundSync {
            chain_id: self.chain.clone(),
            epoch_id: self.engine.state().height,
            round,
            step,
            request,
            validator: self.address.clone(),
            signature: vec![],
        };
        sync.signature = self.host.sign(&hash::round_sync_sign_bytes(&sync)?)?;
        let sync = if request {
            sync
        } else {
            match self.journal.keep_sync(sync, public) {
                Ok(sync) => sync,
                Err(reason) => {
                    self.host.warning(&reason.to_string());
                    return Ok(());
                }
            }
        };
        self.round_pool.add_local(sync.clone(), Self::wall_time());
        self.swarm
            .broadcast(
                Frame {
                    message: 0x3e,
                    payload: sync.encode()?,
                },
                None,
                false,
            )
            .await
    }
    async fn save_vote(
        &mut self,
        vote: &Vote,
        proposal: Option<&Proposal>,
        broadcast: bool,
    ) -> Result<(), Error> {
        let host = self.host.clone();
        let stored = self
            .votes
            .save(
                &self.engine,
                vote,
                proposal,
                self.host.readiness().finality_proof_needed,
                move |record| async move { host.before_precommit(record).await },
            )
            .await?;
        if let Some(stored) = stored {
            if broadcast {
                self.swarm
                    .broadcast(
                        Frame {
                            message: 0x31,
                            payload: stored.encode()?,
                        },
                        None,
                        false,
                    )
                    .await?;
            } else {
                self.pending_votes
                    .insert(driver_policy::vote_key(&stored), stored);
            }
        }
        Ok(())
    }
    pub(super) async fn drain(&mut self) -> Result<(), Error> {
        if self
            .active_work
            .is_some_and(|work| work.generation != self.engine.generation())
        {
            self.work.abort_all();
            self.active_work = None;
            self.build_retry = None;
        }
        self.relay.progress(self.engine.generation());
        self.refresh();
        if self.publish_retry.is_some() {
            return Ok(());
        }
        self.engine.on_ready(&mut |bytes| self.host.sign(bytes))?;
        self.replay_votes().await?;
        let height = self.engine.state().height;
        let round = self.engine.state().round;
        self.verified
            .retain(|&(e, r), _| e > height || e == height && r >= round);
        if let Some(proposal) = self.verified.remove(&(height, round)) {
            self.engine
                .on_proposal(proposal, &mut |_| Ok(true), &mut |bytes| {
                    self.host.sign(bytes)
                })?;
        }
        let outputs = self.engine.drain_outputs();
        if self.votes.allowed(self.host.readiness()) {
            let mut votes = std::mem::take(&mut self.pending_votes)
                .into_values()
                .filter(|v| {
                    v.epoch_id == self.engine.state().height
                        && v.epoch_id > self.engine.finalized_height()
                })
                .collect::<Vec<_>>();
            votes.sort_by_key(|v| (v.epoch_id, v.round, v.vote_type == VoteType::Prevote));
            for vote in votes {
                self.save_vote(&vote, None, true).await?;
            }
        }
        let mut advanced = false;
        for output in outputs {
            match output {
                Output::SendProposal(proposal) => {
                    self.swarm
                        .broadcast(
                            Frame {
                                message: 0x30,
                                payload: proposal.encode()?,
                            },
                            None,
                            false,
                        )
                        .await?;
                }
                Output::SendFinalize(finalize) => {
                    self.swarm
                        .broadcast(
                            Frame {
                                message: 0x32,
                                payload: finalize.encode()?,
                            },
                            None,
                            false,
                        )
                        .await?;
                }
                Output::SendVote(vote, proposal) => {
                    if driver_policy::finalized_vote(
                        self.engine.state().height,
                        &self.address,
                        self.engine.pending_finalized(),
                        &vote,
                    ) {
                        let host = self.host.clone();
                        self.votes
                            .save(
                                &self.engine,
                                &vote,
                                proposal.as_ref(),
                                self.host.readiness().finality_proof_needed,
                                move |r| async move { host.before_precommit(r).await },
                            )
                            .await?;
                    } else if vote.epoch_id == self.engine.state().height
                        && vote.epoch_id > self.engine.finalized_height()
                    {
                        let allowed = self.votes.allowed(self.host.readiness());
                        self.save_vote(
                            &vote,
                            if allowed { proposal.as_ref() } else { None },
                            allowed,
                        )
                        .await?;
                    }
                }
                Output::RequestRoundEvidence(round) => {
                    if self.votes.allowed(self.host.readiness()) {
                        self.round_sync(round, RoundStep::Prevote, true).await?;
                    }
                }
                Output::RequestProposal { round, proposal_id } => {
                    if self.engine.validators().is_validator(&self.address)
                        && self.votes.allowed(self.host.readiness())
                    {
                        let fetch = driver_policy::ProposalFetch {
                            height: self.engine.state().height,
                            round,
                            proposal_id: proposal_id.clone(),
                            generation: self.engine.generation(),
                        };
                        self.fetches.entry((round, proposal_id)).or_insert((
                            fetch,
                            4,
                            Instant::now(),
                        ));
                    }
                }
                Output::ScheduleTimeout {
                    step,
                    round,
                    delay_ms,
                    generation,
                } => {
                    let pace = if step == RoundStep::Propose {
                        Pace::remaining(
                            self.pace.as_ref(),
                            self.engine.state().height,
                            generation,
                            self.now(),
                        )
                    } else {
                        0
                    };
                    self.timer(
                        Timeout {
                            step,
                            round,
                            generation,
                        },
                        Duration::from_millis(delay_ms.max(0) as u64)
                            + Duration::from_nanos(pace.max(0) as u64),
                    );
                    self.round_sync(
                        self.engine.state().round,
                        self.engine.state().step,
                        step != RoundStep::Propose,
                    )
                    .await?;
                }
                Output::Finalized { epoch_id, finalize } => {
                    // Leave the engine's certificate pending on failure. It will
                    // emit this output again; no journal floor or next-height
                    // state may advance before durable publication succeeds.
                    if let Err(reason) = self
                        .publication
                        .finalized(self.engine.validators(), &finalize)
                        .await
                    {
                        self.host.warning(&reason.to_string());
                        self.publish_retry = Some(Instant::now() + Duration::from_millis(500));
                        return Ok(());
                    }
                    if !self.engine.ack_finalized(&finalize) {
                        return Err("finalized output is not pending".into());
                    }
                    let next = epoch_id.checked_add(1).ok_or("consensus epoch overflow")?;
                    if self.engine.state().height >= next {
                        continue;
                    }
                    let pruned = self.journal.prune_finalized(epoch_id)?;
                    self.votes.finalized(epoch_id, pruned.votes);
                    for result in [pruned.syncs, pruned.relief] {
                        if let Err(e) = result {
                            self.host.warning(&e.to_string());
                        }
                    }
                    let validators = self.host.activate(next).await?;
                    self.engine.replace_validator_set(validators);
                    self.engine.start_height(next);
                    self.work.abort_all();
                    self.active_work = None;
                    self.build_retry = None;
                    self.replies.clear();
                    self.round_replies.clear();
                    let now = self.now();
                    self.pace = Pace::new(
                        next,
                        self.engine.generation(),
                        now,
                        self.epoch_started,
                        10_000_000_000,
                        policy::next_delay_ms(Self::wall_time(), finalize.header.ts)
                            .saturating_mul(1_000_000),
                    );
                    if self.pace.is_none() {
                        self.epoch_started = now;
                    }
                    advanced = true;
                }
            }
        }
        // A new height has initial timeout outputs which must be drained before
        // sleeping, including for a non-leader with no subsequent peer traffic.
        if advanced {
            self.drain_again = true;
        }
        self.fetch().await?;
        self.start_work()?;
        self.refresh();
        Ok(())
    }
    async fn fetch(&mut self) -> Result<(), Error> {
        let mut ready = vec![];
        self.fetches.retain(|_, (fetch, left, deadline)| {
            if !fetch.should_send(
                true,
                self.engine.state().height,
                self.engine.state().round,
                self.engine.generation(),
                self.engine
                    .find_proposal(&fetch.proposal_id, fetch.round)
                    .is_some(),
                i64::from(*left),
            ) {
                return false;
            }
            if *deadline <= Instant::now() {
                ready.push(fetch.round);
                *left -= 1;
                *deadline = Instant::now() + Duration::from_millis(1050);
            }
            *left > 0
        });
        for round in ready {
            self.round_sync(round, RoundStep::Prevote, true).await?;
        }
        Ok(())
    }
}
