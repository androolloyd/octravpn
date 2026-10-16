// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! A single owner serializes compute policy. Control traffic has bounded priority;
//! durable transactions leave the async executor through the history owner.
use super::{
    cancellation,
    command::{Command, Envelope, Reply},
    reads, rpc,
    service::{stopped, Status},
    CertificateProgress, CommitteeBook, CommitteeLease, Evidence, Execution, Head, JobHandle,
    JobHost, JobStatus, Jobs, OfferBook, OfferState, Request, RequestBook, RequestState, Response,
    Service, View,
};
use futures::{
    future::{AbortHandle, Abortable},
    FutureExt,
};
use octra_node_protocol::{
    consensus::{seen::Seen, ValidatorSet},
    network::domain_hash,
    resource_compute::{call::Call, record::Record, Error, Result},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    panic::AssertUnwindSafe,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
mod dispatch;
mod funding;
mod jobs;
mod protocol;
mod status;
struct Background {
    abort: AbortHandle,
    task: JoinHandle<()>,
}
struct State {
    service: Service,
    offers: OfferBook,
    requests: RequestBook,
    jobs: Jobs,
    committees: CommitteeBook,
    funding: super::funding::FundingBook,
    reads: reads::ReadBudget,
    seen: Seen,
    routes: cancellation::Routes,
    evidence: Option<Evidence>,
    relay_pending: Option<Vec<u8>>,
    relay_retry: BTreeMap<[u8; 32], i64>,
    background: BTreeMap<u64, Background>,
    next_background: u64,
}
struct Context {
    chain: Vec<u8>,
    validators: ValidatorSet,
    head: Option<Head>,
    evidence: Option<Evidence>,
    root_at: Box<dyn Fn(i64) -> Option<Vec<u8>> + Send + Sync>,
}
impl Context {
    fn view(&self) -> View<'_> {
        View {
            chain: &self.chain,
            validators: &self.validators,
            head: self.head.as_ref(),
            state_root_at: self.root_at.as_ref(),
            evidence: self.evidence.as_ref(),
        }
    }
}
fn history_error(error: crate::compute_history::Error) -> Error {
    Error::Unavailable(error.0)
}
// Box the unchanged owned coroutine so the actor frame stays bounded.
fn respond<T>(reply: Reply<T>, work: impl Future<Output = Result<T>>) -> impl Future<Output = ()> {
    Box::pin(respond_owned(reply, work))
}
async fn respond_owned<T>(reply: Reply<T>, work: impl Future<Output = Result<T>>) {
    let result = AssertUnwindSafe(work)
        .catch_unwind()
        .await
        .unwrap_or_else(|_| {
            Err(Error::Unavailable(
                b"resource compute actor failed".to_vec(),
            ))
        });
    let _ = reply.send(result);
}
impl State {
    fn new(service: Service) -> Self {
        Self {
            service,
            offers: OfferBook::default(),
            requests: RequestBook::default(),
            jobs: Jobs::default(),
            committees: CommitteeBook::default(),
            funding: super::funding::FundingBook::default(),
            reads: reads::ReadBudget::default(),
            seen: Seen::new(8192).expect("fixed positive seen capacity"),
            routes: cancellation::Routes::default(),
            evidence: None,
            relay_pending: None,
            relay_retry: BTreeMap::new(),
            background: BTreeMap::new(),
            next_background: 0,
        }
    }
    fn prune(&mut self) {
        if let Some(head) = self
            .service
            .0
            .deps
            .head()
            .filter(|head| head.epoch >= 0 && head.state_root.len() == 32)
        {
            self.jobs.prune_cancelled(head.epoch);
            self.offers.prune(head.epoch);
            self.requests.prune(head.epoch);
        }
    }
    async fn evidence(&mut self) -> Result<Evidence> {
        if let Some(evidence) = &self.evidence {
            return Ok(evidence.clone());
        }
        let evidence = Evidence::from_provider(&self.service.0.deps.self_test().await?)?;
        self.evidence = Some(evidence.clone());
        Ok(evidence)
    }
    // Keep the operation on the exclusive native execution/actor interface.
    #[allow(clippy::needless_pass_by_ref_mut)]
    async fn context(&mut self, required: BTreeSet<i64>) -> Result<Context> {
        let mut roots = BTreeMap::new();
        for epoch in required.into_iter().filter(|epoch| *epoch >= 0) {
            if let Some(root) = self.service.0.deps.state_root_at(epoch).await? {
                roots.insert(epoch, root);
            }
        }
        Ok(Context {
            chain: self.service.0.deps.chain().to_vec(),
            validators: self.service.0.deps.validators(),
            head: self.service.0.deps.head(),
            evidence: self.evidence.clone(),
            root_at: Box::new(move |epoch| roots.get(&epoch).cloned()),
        })
    }
    fn cancellations<'a, 'view>(
        &'a mut self,
        context: &'a View<'view>,
        node: &'a [u8],
    ) -> cancellation::Coordinator<'a, 'view> {
        cancellation::Coordinator {
            view: context,
            node,
            requests: &self.requests,
            jobs: &mut self.jobs,
            committees: &mut self.committees,
            history: &self.service.0.history,
            seen: &mut self.seen,
        }
    }
    fn spawn_background(&mut self, work: impl Future<Output = Result<()>> + Send + 'static) {
        while self.background.contains_key(&self.next_background) {
            self.next_background = self.next_background.wrapping_add(1);
        }
        let id = self.next_background;
        self.next_background = self.next_background.wrapping_add(1);
        let (abort, cancel) = AbortHandle::new_pair();
        let service = self.service.clone();
        let task = tokio::spawn(async move {
            let _ = Abortable::new(AssertUnwindSafe(work).catch_unwind(), cancel).await;
            let _ = service
                .call(|reply| Command::CompleteBackground(id, reply), false)
                .await;
        });
        self.background.insert(id, Background { abort, task });
    }
    async fn finish(&mut self) -> Result<()> {
        self.jobs.stop();
        self.funding.clear();
        let background = std::mem::take(&mut self.background);
        for task in background.values() {
            task.abort.abort();
        }
        for (_, task) in background {
            let _ = task.task.await;
        }
        let provider = AssertUnwindSafe(async {
            match &self.service.0.provider {
                Some(provider) => provider.stop().await,
                None => Ok(()),
            }
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| {
            Err(Error::Unavailable(
                b"resource compute provider shutdown failed".to_vec(),
            ))
        });
        // Preserve native finalize semantics: an engine shutdown failure cannot
        // bypass closing the owned history lane.
        self.service.0.history.shutdown().await?;
        provider
    }
}
pub(super) fn spawn(
    service: Service,
    mut data: mpsc::Receiver<Envelope>,
    mut control: mpsc::Receiver<Envelope>,
    status: watch::Sender<Status>,
) {
    tokio::spawn(async move {
        let mut state = State::new(service.clone());
        let timer = service.clone();
        state.spawn_background(async move {
            loop {
                timer.0.deps.sleep(Duration::from_secs(3)).await;
                if !timer.open() {
                    return Ok(());
                }
                let _ = timer.send_cancel(None).await;
                let _ = timer.forward_reveals().await;
            }
        });
        loop {
            let envelope = tokio::select! {biased;Some(envelope)=control.recv()=>envelope,Some(envelope)=data.recv()=>envelope,else=>break};
            if envelope.generation != service.generation() {
                envelope.command.reject(Error::Unavailable(
                    b"resource compute actor generation changed".to_vec(),
                ));
                continue;
            }
            if let Command::Stop((), reply) = envelope.command {
                status.send_replace(Status::Closing);
                service.0.generation.fetch_add(1, Ordering::AcqRel);
                data.close();
                control.close();
                state.jobs.stop();
                while let Ok(envelope) = control.try_recv() {
                    envelope.command.reject(stopped());
                }
                while let Ok(envelope) = data.try_recv() {
                    envelope.command.reject(stopped());
                }
                let result = AssertUnwindSafe(state.finish())
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|_| Err(stopped()));
                status.send_replace(Status::Stopped(result.clone()));
                let _ = reply.send(result);
                return;
            }
            state.dispatch(envelope.command).await;
        }
        status.send_replace(Status::Closing);
        let result = state.finish().await;
        status.send_replace(Status::Stopped(result));
    });
}

#[cfg(test)]
mod tests;
