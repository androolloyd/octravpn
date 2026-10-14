// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    driver_policy, hash, Broadcast, Driver, Duration, Error, Frame, Host, Instant, Pace, Peer,
    Proposal, Publication, RoundStep, Verdict, Wire, Work,
};

pub(super) struct Check {
    pub peer: Peer,
    pub proposal: Proposal,
    pub attempt: u8,
    pub retry: Instant,
}
impl<H: Host, C: Publication> Driver<H, C> {
    pub(super) fn work_grace(&self) -> bool {
        self.active_work.is_some_and(|work| {
            work.current(
                self.engine.generation(),
                self.engine.state().height,
                self.engine.state().round,
                self.engine.state().step,
            ) && driver_policy::within_grace(
                self.now(),
                work.started_at,
                if self.checking {
                    self.work_grace_ms.1
                } else {
                    self.work_grace_ms.0
                },
            )
        })
    }
    pub(super) fn next_deadline(&self) -> Instant {
        // Work/fetch deadlines cannot be serviced while publication is held.
        // An expired proposal retry must not keep waking this actor until the
        // publication backoff expires.
        if let Some(retry) = self.publish_retry {
            return retry;
        }

        self.build_retry
            .into_iter()
            .chain(self.publish_retry)
            .chain(
                self.pending_checks
                    .values()
                    .filter(|c| self.work.is_empty() && self.current(&c.proposal))
                    .map(|c| c.retry),
            )
            .chain(self.fetches.values().map(|(_, _, deadline)| *deadline))
            .min()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(300))
    }
    pub(super) fn current(&self, p: &Proposal) -> bool {
        p.epoch_id == self.engine.state().height
            && p.epoch_id > self.publication.head_epoch()
            && driver_policy::proposal_verify_relevant(
                self.engine.state().round,
                self.engine.state().step,
                p.round,
            )
    }
    pub(super) fn queue_check(&mut self, peer: Peer, proposal: Proposal) {
        self.pending_checks
            .entry((proposal.epoch_id, proposal.round))
            .or_insert(Check {
                peer,
                proposal,
                attempt: 0,
                retry: Instant::now(),
            });
    }
    pub(super) fn start_work(&mut self) -> Result<(), Error> {
        if !self.work.is_empty() || self.engine.pending_finalized().is_some() {
            return Ok(());
        }
        let state = self.engine.state();
        let generation = self.engine.generation();
        let height = state.height;
        let round = state.round;
        let step = state.step;
        self.pending_checks
            .retain(|&(epoch, r), _| epoch > height || epoch == height && r >= round);
        let check = self
            .pending_checks
            .values()
            .find(|c| self.current(&c.proposal) && c.retry <= Instant::now());
        let active = driver_policy::ProposalBuild {
            generation,
            height,
            round,
            step,
            started_at: self.now(),
        };
        if let Some(check) = check {
            let peer = check.peer.clone();
            let proposal = check.proposal.clone();
            let host = self.host.clone();
            // Future messages are authenticated again against the activated set.
            if driver_policy::validate_proposal_frame(
                &self.chain,
                self.engine.validators(),
                self.engine.protocol(),
                &proposal,
            )?
            .is_some()
            {
                self.pending_checks
                    .remove(&(proposal.epoch_id, proposal.round));
                return Ok(());
            }
            if let Err(reason) = self
                .host
                .verify_parent(height, proposal.parent_commit.as_ref())
            {
                self.host.warning(&reason.to_string());
                self.pending_checks
                    .remove(&(proposal.epoch_id, proposal.round));
                return Ok(());
            }
            self.active_work = Some(active);
            self.checking = true;
            self.work.spawn(async move {
                let result = host.verify(&proposal).await;
                Work::Check {
                    generation,
                    proposal,
                    peer,
                    result,
                }
            });
        } else if self.votes.state(&self.engine, self.host.readiness()).0
            && self.engine.am_i_leader()?
            && step == RoundStep::Propose
            && self.build_retry.is_none()
            && Pace::remaining(self.pace.as_ref(), height, generation, self.now()) == 0
        {
            self.active_work = Some(active);
            self.checking = false;
            let host = self.host.clone();
            self.work.spawn(async move {
                Work::Build {
                    generation,
                    height,
                    round,
                    result: host.build(height).await,
                }
            });
        }
        Ok(())
    }
    pub(super) async fn finish(&mut self, work: Work) -> Result<(), Error> {
        self.active_work = None;
        self.refresh();
        match work {
            Work::Build {
                generation,
                height,
                round,
                result,
            } if generation == self.engine.generation()
                && height == self.engine.state().height
                && round == self.engine.state().round
                && self.engine.state().step == RoundStep::Propose =>
            {
                match result {
                    Ok(Some(plan))
                        if self.votes.allowed(self.host.readiness())
                            && self.engine.am_i_leader()? =>
                    {
                        self.host
                            .verify_parent(height, plan.parent_commit.as_ref())?;
                        self.engine.do_propose(
                            plan.header,
                            plan.tx_hashes,
                            plan.parent_commit,
                            &mut |bytes| self.host.sign(bytes),
                        )?;
                    }
                    Ok(Some(_)) => (),
                    result => {
                        if let Err(reason) = result {
                            self.host.warning(&reason.to_string());
                        }
                        self.build_retry = Some(Instant::now() + Duration::from_millis(500));
                    }
                }
            }
            Work::Check {
                generation,
                proposal,
                peer,
                result,
            } if generation == self.engine.generation() && self.current(&proposal) => {
                let verdict = result.unwrap_or_else(|reason| {
                    self.host.warning(&reason.to_string());
                    Verdict::Wait
                });
                if verdict == Verdict::Wait {
                    if let Some(check) = self
                        .pending_checks
                        .get_mut(&(proposal.epoch_id, proposal.round))
                    {
                        check.attempt = check.attempt.saturating_add(1).min(16);
                        let delay = match check.attempt {
                            0 | 1 => 0,
                            2 => 500,
                            3 => 1000,
                            4 => 2000,
                            _ => 4000,
                        };
                        check.retry = Instant::now() + Duration::from_millis(delay);
                    }
                } else {
                    self.pending_checks
                        .remove(&(proposal.epoch_id, proposal.round));
                    if verdict == Verdict::Accept && proposal.round > self.engine.state().round {
                        self.verified
                            .insert((proposal.epoch_id, proposal.round), proposal.clone());
                    }
                    self.engine.on_proposal(
                        proposal.clone(),
                        &mut |_| Ok(verdict == Verdict::Accept),
                        &mut |bytes| self.host.sign(bytes),
                    )?;
                    if verdict == Verdict::Accept {
                        self.relay.offer(
                            self.engine.generation(),
                            [
                                format!("{}:{}:", proposal.epoch_id, proposal.round).as_bytes(),
                                &hash::proposal_id(&proposal.header)?,
                            ]
                            .concat(),
                            Broadcast {
                                frame: Frame {
                                    message: 0x30,
                                    payload: proposal.encode()?,
                                },
                                except: Some(peer.hello().node_id.clone()),
                            },
                        );
                    }
                }
            }
            _ => (),
        }
        Ok(())
    }
}
