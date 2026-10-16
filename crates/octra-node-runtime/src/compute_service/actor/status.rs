// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    history_error, AssertUnwindSafe, BTreeSet, Call, CertificateProgress, Error, FutureExt,
    JobStatus, Result, State,
};
use crate::compute_service::{
    admission::{self, PendingStatus},
    command::Admit,
};
use octra_node_protocol::resource_compute::{
    message::{self, Fetch},
    read::Read,
};
// Preserve the native owned-input and typed diagnostic interface.
#[allow(clippy::needless_pass_by_value)]
fn refused(error: Error) -> JobStatus {
    JobStatus::Refused(error.as_bytes().to_vec())
}
impl State {
    async fn pending(
        &self,
        caller: Vec<u8>,
        id: Vec<u8>,
    ) -> Result<Option<crate::compute_history::Work>> {
        self.service
            .0
            .history
            .run(move |history| history.work(&caller, &id).map_err(history_error))
            .await
    }
    async fn closed(&self, call: &Call) -> Result<bool> {
        let request = call.request.clone();
        self.service
            .0
            .history
            .run(move |history| {
                history
                    .cancelled(&request.caller, &request.session_id)
                    .map_err(history_error)
            })
            .await
    }
    async fn job_status(&mut self, caller: &[u8], id: &[u8]) -> Result<Option<JobStatus>> {
        if let Some((owner, _, job)) = self.jobs.get(id) {
            if owner != caller {
                return Ok(None);
            }
            return Ok(Some(match job.status() {
                JobStatus::Waiting => {
                    admission::live_status(self.pending(caller.to_vec(), id.to_vec()).await)
                }
                status => status,
            }));
        }
        if let Some(response) = self.retained(caller.to_vec(), id.to_vec()).await? {
            return Ok(Some(JobStatus::Finished(response)));
        }
        let Some(work) = self.pending(caller.to_vec(), id.to_vec()).await? else {
            return Ok(None);
        };
        AssertUnwindSafe(async {
            match admission::pending_status(caller, id, work)? {
                PendingStatus::Funding(call) => {
                    let closed = self.closed(&call).await;
                    let context = self.context(BTreeSet::new()).await?;
                    Ok(Some(admission::funding_status(
                        &context.view(),
                        &call,
                        closed,
                    )))
                }
                PendingStatus::Resume(request) => {
                    let (saved, job) = self
                        .admit(Admit {
                            request,
                            resume: true,
                        })
                        .await?;
                    if saved != id {
                        return Err(Error::rejected(b"compute restored job differs"));
                    }
                    Ok(Some(job.status()))
                }
            }
        })
        .catch_unwind()
        .await
        .map_err(|_| Error::rejected(b"compute saved work unreadable"))?
    }
    async fn cancelled_overlay(
        &mut self,
        caller: &[u8],
        id: &[u8],
        status: Option<JobStatus>,
    ) -> Result<Option<JobStatus>> {
        if !matches!(status, Some(JobStatus::Refused(_))) {
            return Ok(status);
        }
        let Some(crate::compute_history::Work::Issued(body)) =
            self.pending(caller.to_vec(), id.to_vec()).await?
        else {
            return Ok(status);
        };
        let state = self.restore(caller, id, &body).await?;
        if !self.closed(state.call()).await? {
            return Ok(status);
        }
        let context = self.context(BTreeSet::new()).await?;
        let node = self.service.0.deps.node().to_vec();
        let cancelled = self
            .cancellations(&context.view(), &node)
            .status(&state)
            .await?;
        Ok(Some(JobStatus::Cancelled(cancelled)))
    }
    pub(super) async fn query_status(&mut self, read: Read) -> Result<Option<JobStatus>> {
        let context = self.context(BTreeSet::new()).await?;
        let head = context.view().current_head()?.epoch;
        if !read.verify(
            self.service.0.deps.chain(),
            self.service.0.deps.node(),
            head,
        ) {
            return Err(Error::rejected(b"compute read signature or scope refused"));
        }
        let status = match self.job_status(&read.caller, &read.job_id).await {
            Ok(status) => status,
            Err(error) => Some(refused(error)),
        };
        Ok(
            match self
                .cancelled_overlay(&read.caller, &read.job_id, status)
                .await
            {
                Ok(status) => status,
                Err(error) => Some(refused(error)),
            },
        )
    }
    pub(super) async fn query_certificate(&mut self, key: Vec<u8>) -> Result<CertificateProgress> {
        let context = self.context(BTreeSet::new()).await?;
        match self.requests.get(&key) {
            Some(state) => state.progress(&context.view()),
            None => Ok(CertificateProgress::Refused(
                b"resource compute request unavailable".to_vec(),
            )),
        }
    }
    pub(super) async fn request_replies(
        &mut self,
        key: Vec<u8>,
    ) -> Result<Option<(usize, Vec<Fetch>)>> {
        let context = self.context(BTreeSet::new()).await?;
        let view = context.view();
        let (Some(state), Ok(head)) = (self.requests.get(&key), view.current_head()) else {
            return Ok(None);
        };
        let call = state.call().clone();
        let request = &call.request;
        if call.coordinator != self.service.0.deps.node()
            || head.epoch < request.epoch_id
            || head.epoch > request.expires_epoch
        {
            return Ok(None);
        }
        let id = call.intent_id()?.to_vec();
        if self.jobs.get(&id).is_none_or(|(_, _, job)| !job.pending()) {
            return Ok(None);
        }
        let missing = state.missing();
        if missing.is_empty() {
            return Ok(None);
        }
        let caller = request.caller.clone();
        let session = request.session_id.clone();
        let Some(round) = self
            .service
            .0
            .history
            .run(move |history| {
                history
                    .claim_fetch(&caller, &session, &id, message::FETCH_ROUNDS as usize)
                    .map_err(history_error)
            })
            .await?
        else {
            return Ok(None);
        };
        let expires = if request.expires_epoch.wrapping_sub(head.epoch) <= message::FETCH_SPAN {
            request.expires_epoch
        } else {
            head.epoch.wrapping_add(message::FETCH_SPAN)
        };
        let mut fetches = Vec::new();
        for target in missing {
            let mut fetch = Fetch {
                call: call.clone(),
                target,
                epoch_id: head.epoch,
                expires_epoch: expires,
                round: round as i64,
                signature: vec![0; 64],
            };
            fetch.signature = self.service.0.deps.sign(&fetch.sign_bytes()?)?;
            fetches.push(fetch);
        }
        Ok(Some((round, fetches)))
    }
}
