// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{respond, rpc, stopped, BTreeSet, Command, CommitteeLease, OfferState, Result, State};
impl State {
    async fn cancel(&mut self, value: rpc::Cancellation) -> Result<usize> {
        let cancel = self.service.wire_cancel(&value);
        let context = self.context(BTreeSet::new()).await?;
        let node = self.service.0.deps.node().to_vec();
        self.cancellations(&context.view(), &node)
            .cancel(&cancel, true, None)
            .await
    }
    async fn poll_cancel(
        &mut self,
        target: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Option<crate::compute_history::Notice>> {
        let context = self.context(BTreeSet::new()).await?;
        let epoch = context.view().current_head()?.epoch;
        // Native polling continues to refresh durable cancellation notices even
        // if pruning an unrelated expired job fails.
        let _ = self.prune_jobs(epoch).await;
        let node = self.service.0.deps.node().to_vec();
        self.cancellations(&context.view(), &node)
            .refresh(epoch)
            .await?;
        let deps = self.service.0.deps.clone();
        let rounds = deps.cancel_rounds().await;
        let clock = deps.clone();
        self.cancellations(&context.view(), &node)
            .poll_after_refresh_with_clock(target, move || clock.now(), rounds, &|bytes| {
                deps.sign(bytes)
            })
            .await
    }
    async fn read_cancels(
        &mut self,
        value: rpc::Cancellation,
    ) -> Result<Vec<octra_node_protocol::resource_compute::message::CancelAck>> {
        let cancel = self.service.wire_cancel(&value);
        let context = self.context(BTreeSet::new()).await?;
        let node = self.service.0.deps.node().to_vec();
        self.cancellations(&context.view(), &node)
            .read(&cancel)
            .await
    }
    async fn cancel_keys(
        &mut self,
        delivery: octra_node_protocol::resource_compute::message::CancelRound,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let context = self.context(BTreeSet::new()).await?;
        let node = self.service.0.deps.node().to_vec();
        let now = self.service.0.deps.now();
        self.cancellations(&context.view(), &node)
            .ack_keys(&delivery, now)
            .await
    }
    async fn remember_committee(&mut self, lease: CommitteeLease) -> Result<()> {
        let context = self.context(BTreeSet::new()).await?;
        self.committees.remember(&context.view(), lease)
    }
    pub(super) async fn dispatch(&mut self, command: Command) {
        match command {
            Command::Apply(input, reply) => respond(reply, self.apply(input)).await,
            Command::CheckFunding(call, reply) => respond(reply, self.check_funding(call)).await,
            Command::DropFunding(key, reply) => {
                respond(reply, async {
                    self.funding.drop_read(&key);
                    Ok(())
                })
                .await;
            }
            Command::FundCall((call, funds), reply) => {
                respond(reply, self.fund_call(call, funds)).await;
            }
            Command::Admit(input, reply) => respond(reply, self.admit(input)).await,
            Command::CompleteJob((id, caller), reply) => {
                respond(reply, async {
                    self.jobs.complete(&id, &caller);
                    Ok(())
                })
                .await;
            }
            Command::Cancel(value, reply) => respond(reply, self.cancel(value)).await,
            Command::PollCancel(target, reply) => respond(reply, self.poll_cancel(target)).await,
            Command::ReadCancels(value, reply) => respond(reply, self.read_cancels(value)).await,
            Command::CancelKeys(value, reply) => respond(reply, self.cancel_keys(value)).await,
            Command::CancelPath(value, reply) => {
                respond(reply, async {
                    self.routes.path(self.service.0.deps.node(), &value)
                })
                .await;
            }
            Command::WakeReveals((), reply) => respond(reply, self.wake_reveals()).await,
            Command::SentReveal((payload, sent), reply) => {
                respond(reply, self.sent_reveal(payload, sent)).await;
            }
            Command::SaveResult((call, result), reply) => {
                respond(reply, self.save_result(call, result)).await;
            }
            Command::IssueCall(call, reply) => respond(reply, self.issue_call(call)).await,
            Command::SaveJob((id, response), reply) => {
                respond(reply, self.save_job(id, response)).await;
            }
            Command::CompleteBackground(id, reply) => {
                respond(reply, async {
                    self.background.remove(&id);
                    Ok(())
                })
                .await;
            }
            Command::RememberCommittee(lease, reply) => {
                respond(reply, self.remember_committee(lease)).await;
            }
            Command::QueryStatus(read, reply) => respond(reply, self.query_status(read)).await,
            Command::ActiveJobs((), reply) => {
                respond(reply, async { Ok(self.jobs.active()) }).await;
            }
            Command::QueryOffer(key, reply) => {
                respond(reply, async {
                    Ok(self.offers.get(&key).map(OfferState::snapshot))
                })
                .await;
            }
            Command::QueryCertificate(key, reply) => {
                respond(reply, self.query_certificate(key)).await;
            }
            Command::RequestReplies(key, reply) => respond(reply, self.request_replies(key)).await,
            Command::Evidence((), reply) => respond(reply, self.evidence()).await,
            Command::Stop((), reply) => {
                let _ = reply.send(Err(stopped()));
            }
        }
    }
}
