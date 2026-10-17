// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    driver_policy, hash, Driver, Duration, Error, Finalize, Frame, Host, Instant, Peer, Proposal,
    Publication, RoundSync, Vote, VoteConflict, Wire,
};
use octra_node_protocol::{
    consensus::{evidence, RoundFetch},
    network::handshake,
};
impl<H: Host, C: Publication> Driver<H, C> {
    pub(super) async fn receive(&mut self, peer: &Peer, frame: Frame) -> Result<(), Error> {
        if frame.message == 0x3c {
            // Native production wiring disables resource committees, but still
            // decodes gossip and charges well-formed rejected messages. A
            // malformed resource gossip is logged without charging the peer.
            match octra_node_protocol::consensus::resource_gossip::disabled_reason(
                &self.chain,
                &frame.payload,
            ) {
                Ok(reason) => self.swarm.report_peer(peer, reason),
                Err(reason) => self
                    .host
                    .warning(&format!("bad_resource_attestation error = {reason}")),
            }
            return Ok(());
        }
        // Decoding/authentication failures are peer input, not actor failures.
        if let Err(reason) = self.admit(peer, &frame).await {
            self.host.warning(&format!(
                "consensus frame {} rejected: {reason}",
                frame.message
            ));
            self.swarm.report_peer(
                peer,
                match frame.message {
                    0x30 => b"invalid_frame_propose",
                    0x31 => b"invalid_frame_vote",
                    0x32 => b"invalid_frame_finalize",
                    0x3d => b"invalid_frame_vote_evidence",
                    0x3e => b"invalid_frame_round_sync",
                    0x3f => b"invalid_frame_round_fetch",
                    _ => b"invalid_frame_consensus",
                },
            );
        }
        Ok(())
    }
    async fn admit(&mut self, peer: &Peer, frame: &Frame) -> Result<(), Error> {
        let id = driver_policy::frame_id(self.engine.generation(), frame.message, &frame.payload);
        let repeatable = frame.message == 0x3f
            || frame.message == 0x3e && RoundSync::decode(&frame.payload)?.request;
        if !repeatable && self.seen.known(&id) {
            let needed = match frame.message {
                0x31 => {
                    let vote = Vote::decode(&frame.payload)?;
                    vote.chain_id == self.chain
                        && vote.epoch_id == self.engine.state().height
                        && vote.vote_type == octra_node_protocol::consensus::VoteType::Prevote
                        && vote.round < self.engine.state().round
                        && self.engine.polc_request_pending(vote.round)
                        && !self
                            .engine
                            .historical_prevote_known(vote.round, &vote.validator)
                }
                0x32 => {
                    let f = Finalize::decode(&frame.payload)?;
                    f.chain_id == self.chain
                        && f.epoch_id == self.engine.state().height
                        && f.epoch_id > self.engine.finalized_height()
                }
                _ => false,
            };
            if !needed || !self.historical_replays.remember(&id) {
                return Ok(());
            }
        }
        let state = self.engine.state();
        let height = state.height;
        let round = state.round;
        match frame.message {
            0x30 => {
                let p = Proposal::decode(&frame.payload)?;
                if p.chain_id != self.chain
                    || p.epoch_id <= self.publication.head_epoch()
                    || p.epoch_id < height
                {
                    return Ok(());
                }
                if p.epoch_id > height
                    && !driver_policy::next_height_relay_relevant(height, p.epoch_id, p.round)
                {
                    return Ok(());
                }
                let validators = if p.epoch_id == height {
                    self.engine.validators().clone()
                } else {
                    self.host.validators(p.epoch_id).await?
                };
                if let Some(reason) = driver_policy::validate_proposal_frame(
                    &self.chain,
                    &validators,
                    self.engine.protocol(),
                    &p,
                )? {
                    // An unresolved future set is not evidence against its
                    // relay. Current authenticated errors retain native fault
                    // ownership: envelope faults belong to the signer.
                    if p.epoch_id == height {
                        self.host.warning(reason.label());
                        self.seen.remember(&id);
                        match reason.source() {
                            driver_policy::FaultSource::Unresolved => (),
                            driver_policy::FaultSource::Sender => {
                                self.swarm
                                    .report_peer(peer, reason.peer_reason().as_bytes());
                            }
                            driver_policy::FaultSource::Signer => {
                                self.report_validator(
                                    &validators,
                                    &p.proposer,
                                    reason.peer_reason().as_bytes(),
                                );
                            }
                        }
                    }
                    return Ok(());
                }
                if p.epoch_id == height {
                    if !self.current(&p) {
                        return Ok(());
                    }
                    if let Err(reason) = self.host.verify_parent(height, p.parent_commit.as_ref()) {
                        self.host.warning(&reason.to_string());
                        self.seen.remember(&id);
                        return Ok(());
                    }
                } else {
                    self.swarm
                        .broadcast(frame.clone(), Some(&peer.hello().node_id), false)
                        .await?;
                }
                self.queue_check(peer.clone(), p);
            }
            0x31 => {
                let vote = Vote::decode(&frame.payload)?;
                if vote.chain_id != self.chain || vote.epoch_id < height {
                    return Ok(());
                }
                if vote.epoch_id > height
                    && !driver_policy::future_vote_relay_relevant(height, &vote)
                {
                    return Ok(());
                }
                let validators = if vote.epoch_id == height {
                    self.engine.validators().clone()
                } else {
                    self.host.validators(vote.epoch_id).await?
                };
                let Some(public) = validators.public_key(&vote.validator) else {
                    if vote.epoch_id == height {
                        self.seen.remember(&id);
                    }
                    return Ok(());
                };
                if !hash::verify_vote(public, &vote)? {
                    self.host.warning("invalid vote signature");
                    self.swarm.report_peer(peer, b"bad_signature_vote");
                    self.seen.remember(&id);
                    return Ok(());
                }
                let conflict = if vote.epoch_id == height {
                    self.engine
                        .conflicting_vote(&vote)
                        .and_then(|prior| evidence::vote_conflict(prior, &vote))
                } else {
                    self.future_votes
                        .get(&driver_policy::future_vote_key(&vote))
                        .and_then(|prior| evidence::vote_conflict(prior, &vote))
                };
                if let Some(conflict) = conflict {
                    self.record_conflict(conflict, &validators).await?;
                } else if vote.epoch_id == height {
                    self.engine
                        .on_vote(vote.clone(), &mut |bytes| self.host.sign(bytes))?;
                    if driver_policy::vote_relay_relevant(height, round, &vote) {
                        self.swarm
                            .broadcast(frame.clone(), Some(&peer.hello().node_id), false)
                            .await?;
                    }
                } else {
                    self.future_votes
                        .entry(driver_policy::future_vote_key(&vote))
                        .or_insert(vote);
                    self.swarm
                        .broadcast(frame.clone(), Some(&peer.hello().node_id), false)
                        .await?;
                }
            }
            0x32 => {
                let f = Finalize::decode(&frame.payload)?;
                if f.chain_id != self.chain || f.epoch_id != height {
                    return Ok(());
                }
                if let Err(reason) = self.host.verify_parent(height, f.parent_commit.as_ref()) {
                    self.host.warning(&reason.to_string());
                    self.seen.remember(&id);
                    return Ok(());
                }
                let accepted = match self.engine.accept_finalize(f) {
                    Ok(accepted) => accepted,
                    Err(reason) => {
                        self.host.warning(&reason.to_string());
                        let reason = if reason.as_bytes() == b"signature" {
                            b"bad_signature_finalize".to_vec()
                        } else {
                            [b"invalid_frame_finalize_qc_".as_slice(), reason.as_bytes()].concat()
                        };
                        self.swarm.report_peer(peer, &reason);
                        self.seen.remember(&id);
                        return Ok(());
                    }
                };
                if accepted {
                    self.swarm
                        .broadcast(frame.clone(), Some(&peer.hello().node_id), false)
                        .await?;
                }
            }
            0x3d => {
                let conflict = VoteConflict::decode(&frame.payload)?;
                if conflict.second.chain_id != self.chain || !evidence::in_window(height, &conflict)
                {
                    self.swarm.report_peer(peer, b"invalid_vote_evidence");
                    self.seen.remember(&id);
                    return Ok(());
                }
                let set = self.host.validators(conflict.first.epoch_id).await?;
                let Some(public) = set.public_key(&conflict.first.validator) else {
                    if conflict.first.epoch_id <= height {
                        self.seen.remember(&id);
                    }
                    return Ok(());
                };
                if !conflict.verify(public)? {
                    self.swarm.report_peer(peer, b"invalid_vote_evidence");
                    self.seen.remember(&id);
                    return Ok(());
                }
                self.report_validator(&set, &conflict.first.validator, b"vote_equivocation");
                if self.evidence.remember(&conflict)? {
                    self.host.evidence(conflict).await?;
                    self.swarm
                        .broadcast(frame.clone(), Some(&peer.hello().node_id), false)
                        .await?;
                }
            }
            0x3e => {
                let sync = RoundSync::decode(&frame.payload)?;
                if sync.chain_id != self.chain || sync.epoch_id != height {
                    return Ok(());
                }
                let Some(public) = self.engine.validators().public_key(&sync.validator) else {
                    self.seen.remember(&id);
                    return Ok(());
                };
                if !hash::verify_round_sync(public, &sync)? {
                    self.host.warning("invalid round sync signature");
                    self.swarm.report_peer(peer, b"bad_signature_round_sync");
                    self.seen.remember(&id);
                    return Ok(());
                }
                self.remember_round_peer(&sync);
                if !driver_policy::round_sync_allowed(round, &sync) {
                    return Ok(());
                }
                self.round_pool
                    .add_at(round, sync.clone(), Self::wall_time());
                if driver_policy::round_sync_relay_relevant(height, round, &sync) {
                    self.swarm
                        .broadcast(frame.clone(), Some(&peer.hello().node_id), false)
                        .await?;
                }
                if self.engine.on_round_sync(&sync)? {
                    self.clear_round_sync_jump();
                    self.round_sync(self.engine.state().round, self.engine.state().step, true)
                        .await?;
                    self.schedule_sync_retry();
                }
                if sync.request
                    || sync.round < self.engine.state().round
                    || sync.round == self.engine.state().round
                        && (sync.step as u8) < self.engine.state().step as u8
                {
                    self.reply_sync(peer, &sync).await?;
                }
            }
            0x3f => {
                let fetch = RoundFetch::decode(&frame.payload)?;
                if !self.engine.validators().is_validator(&self.address)
                    || !driver_policy::round_fetch_valid(&self.chain, height, round, &fetch)
                    || !self
                        .engine
                        .validators()
                        .validators
                        .iter()
                        .any(|v| handshake::node_id(&v.pubkey).as_slice() == peer.hello().node_id)
                {
                    return Ok(());
                }
                let key = [b"fetch".as_slice(), &peer.hello().node_id].concat();
                if self
                    .replies
                    .get(&key)
                    .is_some_and(|time| time.elapsed() < Duration::from_secs(5))
                {
                    return Ok(());
                }
                self.replies.insert(key, Instant::now());
                for sync in
                    self.round_pool
                        .sent_range(height, fetch.after_round, fetch.through_round)
                {
                    Self::send(peer, 0x3e, &sync).await?;
                }
            }
            _ => return Ok(()),
        }
        if !repeatable {
            self.seen.remember(&id);
        }
        Ok(())
    }
    async fn send<T: Wire>(peer: &Peer, message: u8, value: &T) -> Result<(), Error> {
        peer.enqueue(
            Frame {
                message,
                payload: value.encode()?,
            },
            Duration::from_secs(2),
        )
        .await;
        Ok(())
    }
    async fn reply_sync(&mut self, peer: &Peer, sync: &RoundSync) -> Result<(), Error> {
        let prior = self.round_replies.get(&sync.validator);
        let progresses = prior.is_some_and(|(epoch, round, step, _)| {
            sync.epoch_id > *epoch
                || sync.epoch_id == *epoch
                    && sync.round == *round
                    && (sync.step as u8) > (*step as u8)
        });
        if !progresses
            && prior.is_some_and(|(_, _, _, time)| time.elapsed() < Duration::from_secs(1))
        {
            return Ok(());
        }
        let reply = match prior {
            Some((epoch, round, step, _)) if !progresses => (*epoch, *round, *step, Instant::now()),
            _ => (sync.epoch_id, sync.round, sync.step, Instant::now()),
        };
        self.round_replies.insert(sync.validator.clone(), reply);
        let height = self.engine.state().height;
        let mut current = None;
        if let Some(public) = self.engine.validators().public_key(&self.address) {
            if self.votes.allowed(self.host.readiness()) {
                let mut reply = RoundSync {
                    chain_id: self.chain.clone(),
                    epoch_id: height,
                    round: self.engine.state().round,
                    step: self.engine.state().step,
                    request: false,
                    validator: self.address.clone(),
                    signature: vec![],
                };
                reply.signature = self.host.sign(&hash::round_sync_sign_bytes(&reply)?)?;
                match self.journal.keep_sync(reply, public) {
                    Ok(reply) => {
                        self.round_pool.add_local(reply.clone(), Self::wall_time());
                        Self::send(peer, 0x3e, &reply).await?;
                        current = Some(reply);
                    }
                    Err(e) => self.host.warning(&e.to_string()),
                }
            }
        }
        if let Some(reply) = self
            .round_pool
            .sent_reply(height, sync.round, sync.round + 64)
        {
            if current.as_ref() != Some(reply) {
                Self::send(peer, 0x3e, reply).await?;
            }
        }
        if driver_policy::response_source_matches(
            self.engine.validators(),
            &peer.hello().node_id,
            &sync.validator,
        ) {
            for witness in self
                .round_pool
                .witness(
                    &self.chain,
                    height,
                    sync.round,
                    sync.round + 1024,
                    self.engine.validators(),
                )
                .into_iter()
                .filter(|s| s.validator != self.address)
            {
                Self::send(peer, 0x3e, &witness).await?;
            }
        }
        if let Some(proposal) = self.engine.current_proposal() {
            Self::send(peer, 0x30, proposal).await?;
        }
        let mut votes = self.engine.current_votes();
        if sync.round < self.engine.state().round {
            votes.extend(self.engine.polc_votes(sync.round));
        }
        for vote in votes {
            let host = self.host.clone();
            if let Some(stored) = self
                .votes
                .save(
                    &self.engine,
                    &vote,
                    None,
                    self.host.readiness().finality_proof_needed,
                    move |r| async move { host.before_precommit(r).await },
                )
                .await?
            {
                Self::send(peer, 0x31, &stored).await?;
            }
        }
        Ok(())
    }
    async fn record_conflict(
        &mut self,
        conflict: VoteConflict,
        validators: &octra_node_protocol::consensus::ValidatorSet,
    ) -> Result<(), Error> {
        self.report_validator(validators, &conflict.first.validator, b"vote_equivocation");
        if !self.evidence.remember(&conflict)? {
            return Ok(());
        }
        self.host.evidence(conflict.clone()).await?;
        self.swarm
            .broadcast(
                Frame {
                    message: 0x3d,
                    payload: conflict.encode()?,
                },
                None,
                false,
            )
            .await
    }
    fn report_validator(
        &self,
        validators: &octra_node_protocol::consensus::ValidatorSet,
        validator: &[u8],
        reason: &[u8],
    ) {
        if let Some(public) = validators.public_key(validator) {
            self.swarm.report_bad(&handshake::node_id(public), reason);
        }
    }
    pub(super) async fn replay_votes(&mut self) -> Result<(), Error> {
        let height = self.engine.state().height;
        let round = self.engine.state().round;
        let mut ready = vec![];
        self.future_votes.retain(|_, v| {
            if v.epoch_id == height && v.round == round {
                ready.push(v.clone());
                false
            } else {
                v.epoch_id >= height
            }
        });
        ready.sort_by(|a, b| {
            (a.vote_type as u8, a.round, &a.validator).cmp(&(
                b.vote_type as u8,
                b.round,
                &b.validator,
            ))
        });
        for vote in ready {
            let Some(public) = self.engine.validators().public_key(&vote.validator) else {
                continue;
            };
            if !hash::verify_vote(public, &vote)? {
                continue;
            }
            if let Some(conflict) = self
                .engine
                .conflicting_vote(&vote)
                .and_then(|prior| evidence::vote_conflict(prior, &vote))
            {
                let validators = self.engine.validators().clone();
                self.record_conflict(conflict, &validators).await?;
            } else {
                self.engine
                    .on_vote(vote, &mut |bytes| self.host.sign(bytes))?;
            }
        }
        Ok(())
    }
}
