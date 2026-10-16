// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Actor-owned caller leases and retained jobs. Background completion always
//! returns through the actor; observers cannot mutate registry ownership.
use super::{
    session_key, JobStatus, Request, Response, MAX_CALLER_SESSIONS, MAX_CANCELLED_SESSIONS,
    MAX_JOBS,
};
use async_trait::async_trait;
use futures::{
    future::{AbortHandle, Abortable},
    FutureExt,
};
use octra_node_protocol::resource_compute::{Error, Result};
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    panic::AssertUnwindSafe,
    sync::Arc,
};
use tokio::sync::watch;
#[async_trait]
pub trait JobHost: Send + Sync {
    async fn save_job(&self, id: Vec<u8>, response: Response) -> Result<()>;
    async fn complete_job(&self, id: Vec<u8>, caller: Vec<u8>) -> Result<()>;
}
#[derive(Clone)]
pub struct JobHandle {
    result: watch::Receiver<Option<Result<Response>>>,
    cancel: Option<AbortHandle>,
}
impl JobHandle {
    pub fn ready(result: Result<Response>) -> Self {
        let (_, result) = watch::channel(Some(result));
        Self {
            result,
            cancel: None,
        }
    }
    pub fn pending(&self) -> bool {
        self.result.borrow().is_none() && self.result.has_changed().is_ok()
    }
    pub fn status(&self) -> JobStatus {
        match self.result.borrow().clone() {
            Some(Ok(response)) => JobStatus::Finished(response),
            Some(Err(error)) => JobStatus::Refused(error.as_bytes().to_vec()),
            None if self.result.has_changed().is_err() => JobStatus::Refused(
                b"resource compute actor failed: completion channel closed".to_vec(),
            ),
            None => JobStatus::Waiting,
        }
    }
    pub async fn wait(mut self) -> Result<Response> {
        loop {
            let result = self.result.borrow().clone();
            if let Some(result) = result {
                return result;
            }
            self.result.changed().await.map_err(|_| {
                Error::Unavailable(
                    b"resource compute actor failed: completion channel closed".to_vec(),
                )
            })?;
        }
    }
    /// Native synchronous compute attaches its caller to the shared job. RPC
    /// submission/status observers instead use the cancellation-protected path.
    pub async fn wait_cancellable(self) -> Result<Response> {
        struct Guard(Option<AbortHandle>);
        impl Drop for Guard {
            fn drop(&mut self) {
                if let Some(cancel) = self.0.take() {
                    cancel.abort();
                }
            }
        }
        let mut guard = Guard(self.cancel.clone());
        let result = self.wait().await;
        guard.0 = None;
        result
    }
}
struct Job {
    caller: Vec<u8>,
    session: Vec<u8>,
    lease_active: bool,
    result: JobHandle,
    abort: AbortHandle,
}
fn release(counters: &mut BTreeMap<Vec<u8>, usize>, job: &mut Job) {
    if !job.lease_active {
        return;
    }
    job.lease_active = false;
    match counters.get_mut(&job.caller) {
        Some(count) if *count > 1 => *count -= 1,
        _ => {
            counters.remove(&job.caller);
        }
    }
}
#[derive(Default)]
pub struct Jobs {
    rows: BTreeMap<Vec<u8>, Job>,
    order: VecDeque<Vec<u8>>,
    callers: BTreeMap<Vec<u8>, usize>,
    cancelled: BTreeMap<[u8; 32], (Vec<u8>, i64)>,
}
impl Jobs {
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    pub fn active(&self) -> usize {
        self.callers.values().sum()
    }
    pub fn caller_admitted(&self, caller: &[u8]) -> bool {
        self.callers.get(caller).copied().unwrap_or(0) == 0
    }
    pub fn get(&self, id: &[u8]) -> Option<(&[u8], &[u8], JobHandle)> {
        self.rows.get(id).map(|job| {
            (
                job.caller.as_slice(),
                job.session.as_slice(),
                job.result.clone(),
            )
        })
    }
    pub fn complete(&mut self, id: &[u8], caller: &[u8]) {
        if let Some(job) = self.rows.get_mut(id) {
            if job.caller == caller {
                release(&mut self.callers, job);
            }
        }
    }
    pub fn prune_finished(&mut self) {
        let count = self.order.len();
        for _ in 0..count {
            if self.rows.len() < MAX_JOBS {
                break;
            }
            let Some(id) = self.order.pop_front() else {
                break;
            };
            match self.rows.get(&id) {
                Some(job) if job.result.pending() => self.order.push_back(id),
                Some(_) => {
                    self.rows.remove(&id);
                }
                None => {}
            }
        }
    }
    /// Called only after the actor's shape, history and cancellation admission.
    pub(crate) fn start(
        &mut self,
        host: Arc<dyn JobHost>,
        request: &Request,
        id: Vec<u8>,
        work: impl Future<Output = Result<Response>> + Send + 'static,
    ) -> Result<JobHandle> {
        if let Some(job) = self.rows.get(&id) {
            return Ok(job.result.clone());
        }
        if self.rows.len() >= MAX_JOBS {
            return Err(Error::rejected(b"resource compute job table full"));
        }
        if !self.caller_admitted(&request.caller) {
            return Err(Error::rejected(b"resource compute caller already active"));
        }
        let (reply, result) = watch::channel(None);
        let (abort, cancel) = AbortHandle::new_pair();
        let result = JobHandle {
            result,
            cancel: Some(abort.clone()),
        };
        let job_id = id.clone();
        let caller = request.caller.clone();
        let task_host = host.clone();
        tokio::spawn(async move {
            let computation = AssertUnwindSafe(async {
                let response = work.await?;
                task_host.save_job(job_id.clone(), response.clone()).await?;
                Ok(response)
            })
            .catch_unwind();
            let outcome = match Abortable::new(computation, cancel).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(Error::Unavailable(
                    b"resource compute actor failed: computation panicked".to_vec(),
                )),
                Err(_) => Err(Error::Unavailable(
                    b"resource compute actor failed: computation cancelled".to_vec(),
                )),
            };
            // Completion is idempotent and outside the abortable computation.
            // Aborting work therefore cannot skip the actor's lease release.
            let _ = AssertUnwindSafe(host.complete_job(job_id, caller))
                .catch_unwind()
                .await;
            reply.send_replace(Some(outcome));
        });
        *self.callers.entry(request.caller.clone()).or_default() += 1;
        self.rows.insert(
            id.clone(),
            Job {
                caller: request.caller.clone(),
                session: request.session_id.clone(),
                lease_active: true,
                result: result.clone(),
                abort,
            },
        );
        self.order.push_back(id);
        Ok(result)
    }
    pub fn prune_cancelled(&mut self, epoch: i64) {
        self.cancelled.retain(|_, (_, expires)| *expires >= epoch);
    }
    pub fn session_cancelled(&self, caller: &[u8], session: &[u8]) -> Result<bool> {
        Ok(self.cancelled.contains_key(&session_key(caller, session)?))
    }
    pub fn cancel_expiry(&self, caller: &[u8], session: &[u8]) -> Result<Option<i64>> {
        Ok(self
            .cancelled
            .get(&session_key(caller, session)?)
            .map(|(_, expires)| *expires))
    }
    pub fn cancel_available(&self, caller: &[u8], session: &[u8]) -> Result<bool> {
        let mut count = self.cancelled.len();
        let mut own = self
            .cancelled
            .values()
            .filter(|(owner, _)| owner == caller)
            .count();
        let mut reserved = false;
        for job in self.rows.values() {
            if job.lease_active && !self.session_cancelled(&job.caller, &job.session)? {
                count += 1;
                own += usize::from(job.caller == caller);
                reserved |= job.caller == caller && job.session == session;
            }
        }
        Ok(self.session_cancelled(caller, session)?
            || reserved
            || count < MAX_CANCELLED_SESSIONS && own < MAX_CALLER_SESSIONS)
    }
    pub fn remember_cancelled(
        &mut self,
        caller: &[u8],
        session: &[u8],
        expires: i64,
    ) -> Result<()> {
        self.cancelled
            .insert(session_key(caller, session)?, (caller.to_vec(), expires));
        Ok(())
    }
    pub fn cancel_session(&mut self, caller: &[u8], session: &[u8]) -> usize {
        let mut count = 0;
        for job in self.rows.values_mut() {
            if job.caller == caller && job.session == session && job.result.pending() {
                release(&mut self.callers, job);
                job.abort.abort();
                count += 1;
            }
        }
        count
    }
    pub fn stop(&mut self) {
        for job in self.rows.values_mut() {
            release(&mut self.callers, job);
            if job.result.pending() {
                job.abort.abort();
            }
        }
    }
}
impl Drop for Jobs {
    fn drop(&mut self) {
        self.stop();
    }
}
