// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{BTreeSet, Call, Error, Head, Result, State};
use crate::compute_service::funding::{FundCall, FundingCheck, IssueCall};
impl State {
    pub(super) async fn check_funding(&mut self, call: Call) -> Result<Option<Head>> {
        self.prune();
        let Some(check) = self.funding.begin(&self.requests, &call)? else {
            return Ok(None);
        };
        let read = check.clone();
        let pending = self
            .service
            .0
            .history
            .run(move |history| read.pending(history))
            .await?;
        let node = self.service.0.deps.node().to_vec();
        let prepared = match pending {
            Some(
                crate::compute_history::Work::Funding(body)
                | crate::compute_history::Work::Issued(body),
            ) => {
                let state = self
                    .restore(&call.request.caller, &call.intent_id()?, &body)
                    .await?;
                check.prepare_restored(state)?
            }
            pending => {
                let mut context = self.context(BTreeSet::new()).await?;
                self.offers.preflight_call(&context.view(), &call)?;
                let epoch = call.request.epoch_id;
                let root = self.service.0.deps.state_root_at(epoch).await?;
                context.root_at = Box::new(move |at| (at == epoch).then(|| root.clone()).flatten());
                check.prepare(
                    &context.view(),
                    &node,
                    &self.offers,
                    &self.requests,
                    pending,
                )?
            }
        };
        prepared.install_early(&mut self.requests)?;
        let check: FundingCheck = prepared.check().clone();
        let closed = self
            .service
            .0
            .history
            .run(move |history| check.closed(history))
            .await;
        let context = self.context(BTreeSet::new()).await?;
        prepared
            .commit(
                &context.view(),
                &mut self.funding,
                &mut self.requests,
                closed,
            )
            .map(Some)
    }
    pub(super) async fn fund_call(
        &mut self,
        call: Call,
        funds: crate::compute_deposits::Funded,
    ) -> Result<bool> {
        let context = self.context(BTreeSet::new()).await?;
        let Some(funding) = FundCall::begin(&context.view(), &self.requests, &call, funds)? else {
            return Ok(false);
        };
        let read = funding.clone();
        let pending = self
            .service
            .0
            .history
            .run(move |history| read.pending(history))
            .await?;
        let Some(
            crate::compute_history::Work::Funding(body)
            | crate::compute_history::Work::Issued(body),
        ) = pending
        else {
            return Err(Error::rejected(b"compute funded wait absent"));
        };
        let state = self
            .restore(&call.request.caller, &call.intent_id()?, &body)
            .await?;
        let context = self.context(BTreeSet::new()).await?;
        let Some(release) = funding.prepare_restored(&context.view(), state, body)? else {
            return Ok(false);
        };
        if !release.current(&context.view()) {
            return Ok(false);
        }
        let write = release.clone();
        let released = self
            .service
            .0
            .history
            .run(move |history| write.persist(history))
            .await?;
        release.install(&mut self.requests, released)
    }
    pub(super) async fn issue_call(&mut self, call: Call) -> Result<()> {
        self.prune();
        let mut context = self.context(BTreeSet::new()).await?;
        self.offers.preflight_call(&context.view(), &call)?;
        let epoch = call.request.epoch_id;
        let root = self.service.0.deps.state_root_at(epoch).await?;
        context.root_at = Box::new(move |at| (at == epoch).then(|| root.clone()).flatten());
        let issue = IssueCall::begin(
            &context.view(),
            &self.offers,
            &self.requests,
            &self.jobs,
            call,
        )?;
        let read = issue.clone();
        let pending = self
            .service
            .0
            .history
            .run(move |history| read.pending(history))
            .await?;
        let Some(plan) = issue.planned(pending)? else {
            return Ok(());
        };
        let (saved, _) = self
            .read_plan(plan.caller(), plan.id(), plan.before())
            .await?;
        let write = plan.prepare(saved)?;
        self.service
            .0
            .history
            .run(move |history| write.persist(history))
            .await?;
        Ok(())
    }
}
