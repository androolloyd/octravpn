// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Funding observations are separate from call acceptance. A read reservation
//! survives caller timeout until its owned observation completes and drops it.
use super::{Head, Jobs, OfferBook, Request, RequestBook, RequestState, View, MAX_REQUESTS};
use crate::{
    compute_deposits::Funded,
    compute_history::{History, Scope, Work},
};
use futures::FutureExt;
use octra_node_protocol::resource_compute::{call::Call, record, Error, Result};
use std::{
    collections::BTreeSet,
    future::Future,
    panic::AssertUnwindSafe,
    time::{Duration, Instant},
};

fn unavailable(error: crate::compute_history::Error) -> Error {
    Error::Unavailable(error.0)
}
#[derive(Default)]
pub struct FundingBook {
    reads: BTreeSet<Vec<u8>>,
}
#[derive(Clone, Debug)]
pub struct FundingCheck {
    call: Call,
    key: Vec<u8>,
    id: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct FundingPrepared {
    check: FundingCheck,
    state: RequestState,
    early: bool,
}
impl FundingBook {
    pub fn len(&self) -> usize {
        self.reads.len()
    }
    pub fn is_empty(&self) -> bool {
        self.reads.is_empty()
    }
    /// Prune offers, requests and cached cancellations before this gate.
    pub fn begin(&self, requests: &RequestBook, call: &Call) -> Result<Option<FundingCheck>> {
        let key = call.request.id()?.to_vec();
        if self.reads.len() >= MAX_REQUESTS
            || self.reads.contains(&key)
            || requests.len() >= MAX_REQUESTS && requests.get(&key).is_none()
        {
            return Ok(None);
        }
        Ok(Some(FundingCheck {
            call: call.clone(),
            key,
            id: call.intent_id()?.to_vec(),
        }))
    }
    pub fn drop_read(&mut self, key: &[u8]) {
        self.reads.remove(key);
    }
    pub fn clear(&mut self) {
        self.reads.clear();
    }
}
impl FundingCheck {
    pub fn key(&self) -> &[u8] {
        &self.key
    }
    pub fn call(&self) -> &Call {
        &self.call
    }
    pub fn pending(&self, history: &History) -> Result<Option<Work>> {
        history
            .work(&self.call.request.caller, &self.id)
            .map_err(unavailable)
    }
    pub fn closed(&self, history: &History) -> Result<bool> {
        let request = &self.call.request;
        history
            .cancelled(&request.caller, &request.session_id)
            .map_err(unavailable)
    }
    pub fn prepare_restored(self, state: RequestState) -> Result<FundingPrepared> {
        if state.call() != &self.call {
            return Err(Error::rejected(b"compute funding call differs"));
        }
        Ok(FundingPrepared {
            check: self,
            state,
            early: false,
        })
    }
    pub fn prepare(
        self,
        view: &View<'_>,
        node: &[u8],
        offers: &OfferBook,
        requests: &RequestBook,
        pending: Option<Work>,
    ) -> Result<FundingPrepared> {
        let (state, early) = if let Some(Work::Funding(body) | Work::Issued(body)) = pending {
            let state =
                RequestState::restore(view, node, &self.call.request.caller, &self.id, &body)?;
            if state.call() != &self.call {
                return Err(Error::rejected(b"compute funding call differs"));
            }
            (state, false)
        } else {
            let admission = offers.verify_call(view, &self.call)?;
            (requests.state_for_call(self.call.clone(), admission)?, true)
        };
        Ok(FundingPrepared {
            check: self,
            state,
            early,
        })
    }
}
impl FundingPrepared {
    /// Native request_state inserts newly verified remote calls before the
    /// subsequent durable cancellation read, including when that read refuses.
    pub fn install_early(&self, requests: &mut RequestBook) -> Result<()> {
        if self.early {
            requests.install_restored(self.state.clone())?;
        }
        Ok(())
    }
    pub fn check(&self) -> &FundingCheck {
        &self.check
    }
    pub fn commit(
        self,
        view: &View<'_>,
        book: &mut FundingBook,
        requests: &mut RequestBook,
        closed: Result<bool>,
    ) -> Result<Head> {
        // current_head is read even when the history read failed in native code;
        // history errors still take precedence over head unavailability.
        let head = view.current_head();
        let closed = closed?;
        let head = head?;
        if closed {
            return Err(Error::rejected(b"resource compute session cancelled"));
        }
        if head.epoch < self.check.call.request.epoch_id
            || head.epoch > self.check.call.request.expires_epoch
        {
            return Err(Error::rejected(b"compute funding epoch outside window"));
        }
        requests.install_restored(self.state)?;
        book.reads.insert(self.check.key);
        Ok(head.clone())
    }
}

#[derive(Clone, Debug)]
pub struct FundCall {
    call: Call,
    funds: Funded,
    id: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct FundRelease {
    call: FundCall,
    state: RequestState,
    body: Vec<u8>,
}
impl FundCall {
    /// None is a stale observation/capacity refusal, not durable absence.
    pub fn begin(
        view: &View<'_>,
        requests: &RequestBook,
        call: &Call,
        funds: Funded,
    ) -> Result<Option<Self>> {
        if !view.funding_matches(call, &funds) {
            return Ok(None);
        }
        let key = call.request.id()?;
        if requests.len() >= MAX_REQUESTS && requests.get(&key).is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            call: call.clone(),
            funds,
            id: call.intent_id()?.to_vec(),
        }))
    }
    pub fn pending(&self, history: &History) -> Result<Option<Work>> {
        history
            .work(&self.call.request.caller, &self.id)
            .map_err(unavailable)
    }
    pub fn prepare_restored(
        self,
        view: &View<'_>,
        state: RequestState,
        body: Vec<u8>,
    ) -> Result<Option<FundRelease>> {
        if state.call() != &self.call {
            return Err(Error::rejected(b"compute funded call differs"));
        }
        if !view.funding_matches(&self.call, &self.funds) {
            return Ok(None);
        }
        Ok(Some(FundRelease {
            call: self,
            state,
            body,
        }))
    }
    pub fn prepare(
        self,
        view: &View<'_>,
        node: &[u8],
        pending: Option<Work>,
    ) -> Result<Option<FundRelease>> {
        let Some(Work::Funding(body) | Work::Issued(body)) = pending else {
            return Err(Error::rejected(b"compute funded wait absent"));
        };
        let state = RequestState::restore(view, node, &self.call.request.caller, &self.id, &body)?;
        if state.call() != &self.call {
            return Err(Error::rejected(b"compute funded call differs"));
        }
        if !view.funding_matches(&self.call, &self.funds) {
            return Ok(None);
        }
        Ok(Some(FundRelease {
            call: self,
            state,
            body,
        }))
    }
}
impl FundRelease {
    /// Check again immediately before sending this transition to the worker if
    /// another actor turn or awaited operation occurred after prepare.
    pub fn current(&self, view: &View<'_>) -> bool {
        view.funding_matches(&self.call.call, &self.call.funds)
    }
    pub fn persist(&self, history: &History) -> Result<bool> {
        history
            .fund_job(
                self.call.funds.epoch(),
                self.call.funds.state_root(),
                &self.call.id,
                &self.body,
                &self.call.funds,
            )
            .map_err(unavailable)
    }
    pub fn install(self, requests: &mut RequestBook, released: bool) -> Result<bool> {
        if released {
            requests.install_restored(self.state)?;
        }
        Ok(released)
    }
}

/// A checked Issue_call reserves the complete funding/result room in one
/// durable transition. It does not admit the call into execution yet.
#[derive(Clone, Debug)]
pub struct IssueCall {
    call: Call,
    state: RequestState,
    id: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct WaitWrite {
    caller: Vec<u8>,
    session: Vec<u8>,
    id: Vec<u8>,
    before: Vec<u8>,
    body: Vec<u8>,
    scope: Scope,
    room: usize,
}
pub(crate) struct WaitPlan {
    issue: IssueCall,
    record: octra_node_protocol::resource_compute::record::Record,
    before: Vec<u8>,
    body: Vec<u8>,
}
impl IssueCall {
    pub fn begin(
        view: &View<'_>,
        offers: &OfferBook,
        requests: &RequestBook,
        jobs: &Jobs,
        call: Call,
    ) -> Result<Self> {
        let admission = offers.verify_call(view, &call)?;
        let id = call.intent_id()?.to_vec();
        if jobs.get(&id).is_none() {
            return Err(Error::rejected(b"compute local job absent"));
        }
        let key = call.request.id()?;
        if requests.len() >= MAX_REQUESTS && requests.get(&key).is_none() {
            return Err(Error::rejected(b"resource compute request table full"));
        }
        let state = RequestState::from_admission(call.clone(), admission);
        Ok(Self { call, state, id })
    }
    pub fn pending(&self, history: &History) -> Result<Option<Work>> {
        history
            .work(&self.call.request.caller, &self.id)
            .map_err(unavailable)
    }
    pub fn prepare(
        self,
        view: &View<'_>,
        node: &[u8],
        previous: Option<Work>,
    ) -> Result<Option<WaitWrite>> {
        let Some(plan) = self.planned(previous)? else {
            return Ok(None);
        };
        let request = &plan.issue.call.request;
        let (saved, _) =
            Request::read_plan(view, node, &request.caller, &plan.issue.id, &plan.before)?;
        plan.prepare(saved).map(Some)
    }
    /// Encode the target and classify the retained transition before any
    /// saved-plan decoding or historical root access.
    pub(crate) fn planned(self, previous: Option<Work>) -> Result<Option<WaitPlan>> {
        let record = self.state.record(Vec::new());
        let body = record.encode()?;
        let before = match previous {
            None => return Err(Error::rejected(b"compute local plan absent")),
            Some(Work::Funding(prior)) if prior == body => return Ok(None),
            Some(Work::Funding(_)) => return Err(Error::rejected(b"compute funding call differs")),
            Some(Work::Issued(prior)) if prior == body => return Ok(None),
            Some(Work::Issued(_)) => {
                return Err(Error::rejected(b"compute local call already issued"))
            }
            Some(Work::Planned(prior)) => prior,
        };
        Ok(Some(WaitPlan {
            issue: self,
            record,
            before,
            body,
        }))
    }
}
impl WaitPlan {
    pub(crate) fn caller(&self) -> &[u8] {
        &self.issue.call.request.caller
    }
    pub(crate) fn id(&self) -> &[u8] {
        &self.issue.id
    }
    pub(crate) fn before(&self) -> &[u8] {
        &self.before
    }
    // Preserve the native owned-input and typed diagnostic interface.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn prepare(self, saved: Request) -> Result<WaitWrite> {
        let request = &self.issue.call.request;
        if saved != Request::from_call(&self.issue.call) {
            return Err(Error::rejected(b"compute local intent differs"));
        }
        let members = self
            .issue
            .state
            .selection()
            .members
            .iter()
            .map(|member| member.node_id.clone())
            .collect::<Vec<_>>();
        let scope = Scope {
            sequence: request.sequence,
            request: request.id()?.to_vec(),
            body: record::encode_scope(&self.issue.call, self.issue.state.validators())?,
        };
        let room = self.record.job_space(&members)?;
        Ok(WaitWrite {
            caller: request.caller.clone(),
            session: request.session_id.clone(),
            id: self.issue.id,
            before: self.before,
            body: self.body,
            scope,
            room,
        })
    }
}
impl WaitWrite {
    pub fn persist(&self, history: &History) -> Result<()> {
        if history
            .wait_job(
                &self.caller,
                &self.session,
                &self.id,
                &self.before,
                &self.body,
                &self.scope,
                self.room,
            )
            .map_err(unavailable)?
        {
            Ok(())
        } else {
            Err(Error::rejected(b"compute local plan changed"))
        }
    }
}

/// Run a claimed read under an owned task. The timeout only abandons the reply;
/// it cannot cancel the observation or free its actor reservation prematurely.
/// Header construction errors remain explicit; errors from the host observation
/// itself are unavailable observations, matching native read_funding.
pub async fn read_observation<O, D, S>(
    observation: Result<O>,
    release: D,
    timeout: S,
) -> Result<Option<Funded>>
where
    O: Future<Output = Result<Option<Funded>>> + Send + 'static,
    D: Future<Output = ()> + Send + 'static,
    S: Future<Output = ()>,
{
    let owned = tokio::spawn(async move {
        let observed = match observation {
            Err(error) => Err(error),
            Ok(observation) => Ok(AssertUnwindSafe(observation)
                .catch_unwind()
                .await
                .ok()
                .and_then(std::result::Result::ok)
                .flatten()),
        };
        let _ = AssertUnwindSafe(release).catch_unwind().await;
        observed
    });
    tokio::select! {
        result = owned => result.map_err(|error| Error::Unavailable(error.to_string().into_bytes()))?,
        () = timeout => Ok(None),
    }
}

/// Native bounded funding polling uses both monotonic time and an attempt cap.
/// A released call whose local publish was refused returns to observation; it
/// cannot skip directly to certificate waiting on a stale funded observation.
pub struct FundingWait {
    started: Instant,
    ticks: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingStep {
    Retry(Duration),
    Certificate,
}
impl Default for FundingWait {
    fn default() -> Self {
        Self::new()
    }
}
impl FundingWait {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            ticks: 0,
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.ticks >= 3000 || self.started.elapsed() >= Duration::from_secs(300) {
            Err(Error::rejected(b"compute funding wait expired"))
        } else {
            Ok(())
        }
    }
    /// Pass published only after a successful Fund_call; the publish path must
    /// independently obtain a fresh sealed observation for local Call apply.
    pub fn advance(
        &mut self,
        call: &Call,
        released: Result<bool>,
        published: bool,
        head: Result<Head>,
    ) -> Result<FundingStep> {
        let released = released?;
        if released && published {
            return Ok(FundingStep::Certificate);
        }
        if released || head.is_ok_and(|head| head.epoch <= call.request.expires_epoch) {
            self.ticks += 1;
            Ok(FundingStep::Retry(Duration::from_millis(100)))
        } else {
            Err(Error::rejected(b"compute funding wait expired"))
        }
    }
}
