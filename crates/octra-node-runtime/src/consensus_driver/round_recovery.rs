// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted driver round-history acquisition and generation transition cleanup.
use super::{driver_policy, Driver, Duration, Error, Frame, Host, Instant, Publication, Wire};
use octra_node_protocol::consensus::{engine, RoundFetch};

pub(super) struct ReplayRetry {
    height: i64,
    round: i64,
    pub deadline: Instant,
}

impl<H: Host, C: Publication> Driver<H, C> {
    pub(super) fn clear_round_sync_jump(&mut self) {
        let state = self.engine.state();
        let height = state.height;
        let round = state.round;
        self.work.abort_all();
        self.active_work = None;
        self.checking = false;
        self.build_retry = None;
        self.pace = None;
        self.past_round = None;
        self.pending_votes.clear();
        self.replies.clear();
        self.pending_checks.retain(|&(epoch, candidate), _| {
            epoch > height || epoch == height && candidate >= round
        });
        self.verified
            .retain(|&(epoch, candidate), _| epoch == height && candidate >= round);
        self.epoch_started = self.now();
    }

    pub(super) fn schedule_sync_retry(&mut self) {
        self.sync_retry = Some(ReplayRetry {
            height: self.engine.state().height,
            round: self.engine.state().round,
            deadline: Instant::now() + Duration::from_millis(1100),
        });
    }

    pub(super) async fn retry_round_sync(&mut self) -> Result<(), Error> {
        if self
            .sync_retry
            .as_ref()
            .is_none_or(|retry| retry.deadline > Instant::now())
        {
            return Ok(());
        }
        let retry = self.sync_retry.take().expect("due replay retry");
        if retry.height == self.engine.state().height && retry.round == self.engine.state().round {
            self.round_sync(self.engine.state().round, self.engine.state().step, true)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn ask_past(&mut self) -> Result<(), Error> {
        let state = self.engine.state();
        let height = state.height;
        let round = state.round;
        let now = Self::wall_time();
        let add = |a: i64, b: i64| (a.wrapping_add(b) << 1) >> 1;
        let ahead = self
            .round_peers
            .values()
            .filter(|peer| {
                let age = now - peer.last_seen;
                peer.state.epoch_id == height
                    && peer.state.round >= add(round, engine::ROUND_HISTORY_LIMIT / 2)
                    && (0. ..=30.).contains(&age)
            })
            .map(|peer| peer.state.round)
            .max();
        let Some(peer) = ahead else {
            return Ok(());
        };
        let sent_at = self.now();
        let limit = peer.min(add(round, engine::MAX_SYNC_AHEAD));
        let Some((target, tries)) =
            driver_policy::next_past_round(height, round, limit, self.past_round.as_ref(), sent_at)
        else {
            return Ok(());
        };
        let after = round.max(add(target, -engine::ROUND_HISTORY_LIMIT));
        if after >= target {
            return Ok(());
        }
        self.past_round = Some(driver_policy::PastRound {
            epoch_id: height,
            target,
            sent_at,
            tries,
        });
        if !self.engine.validators().is_validator(&self.address) {
            return Ok(());
        }
        self.swarm
            .broadcast(
                Frame {
                    message: 0x3f,
                    payload: RoundFetch {
                        chain_id: self.chain.clone(),
                        epoch_id: height,
                        after_round: after,
                        through_round: target,
                    }
                    .encode()?,
                },
                None,
                false,
            )
            .await
    }
}
