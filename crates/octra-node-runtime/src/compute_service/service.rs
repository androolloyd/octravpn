// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Public service handle and bounded typed actor channels.
use super::{
    command::{Admit, Command, Envelope, Reply},
    rpc, CertificateProgress, CommitteeLease, Evidence, Head, HistoryWorker, JobHost, JobStatus,
    OfferSnapshot, Request, Response, View, CONTROL_CHANNEL_LIMIT, DATA_CHANNEL_LIMIT,
};
use crate::{compute_deposits::Funded, compute_provider::Provider};
use async_trait::async_trait;
use octra_node_protocol::{
    consensus::ValidatorSet,
    resource_compute::{
        call::Header, message::Cancellation, provider::SelfTest, read::Read, Error, Result,
    },
};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, watch};
mod flows;
mod network;
#[async_trait]
pub trait Dependencies: Send + Sync + 'static {
    fn chain(&self) -> &[u8];
    fn node(&self) -> &[u8];
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>>;
    fn validators(&self) -> ValidatorSet;
    fn head(&self) -> Option<Head>;
    async fn state_root_at(&self, epoch: i64) -> Result<Option<Vec<u8>>>;
    async fn funding(&self, head: Head, header: Header) -> Result<Option<Funded>>;
    async fn self_test(&self) -> Result<SelfTest>;
    fn nonce(&self) -> Vec<u8>;
    async fn broadcast(&self, payload: Vec<u8>) -> Result<()>;
    async fn send(&self, peer: Vec<u8>, payload: Vec<u8>) -> Result<()>;
    async fn cancel_rounds(&self) -> bool;
    fn now(&self) -> i64;
    async fn relay(&self, source: Vec<u8>, payload: Vec<u8>) -> Result<()>;
    async fn sleep(&self, duration: Duration);
}
#[derive(Clone)]
pub(super) enum Status {
    Open,
    Closing,
    Stopped(Result<()>),
}
pub(super) struct Inner {
    pub deps: Arc<dyn Dependencies>,
    pub provider: Option<Provider>,
    pub history: HistoryWorker,
    pub data: mpsc::Sender<Envelope>,
    pub control: mpsc::Sender<Envelope>,
    pub generation: AtomicU64,
    pub status: watch::Receiver<Status>,
}
#[derive(Clone)]
pub struct Service(pub(super) Arc<Inner>);
pub(super) fn stopping() -> Error {
    Error::Unavailable(b"resource compute actor is stopping".to_vec())
}
pub(super) fn stopped() -> Error {
    Error::Unavailable(b"resource compute actor stopped".to_vec())
}
impl Service {
    pub fn new(
        deps: Arc<dyn Dependencies>,
        provider: Option<Provider>,
        history: HistoryWorker,
    ) -> Self {
        let (data, data_rx) = mpsc::channel(DATA_CHANNEL_LIMIT);
        let (control, control_rx) = mpsc::channel(CONTROL_CHANNEL_LIMIT);
        let (status, status_rx) = watch::channel(Status::Open);
        let service = Self(Arc::new(Inner {
            deps,
            provider,
            history,
            data,
            control,
            generation: AtomicU64::new(0),
            status: status_rx,
        }));
        super::actor::spawn(service.clone(), data_rx, control_rx, status);
        service
    }
    pub fn provider_enabled(&self) -> bool {
        self.0.provider.is_some()
    }
    pub(super) fn open(&self) -> bool {
        matches!(*self.0.status.borrow(), Status::Open)
    }
    pub(super) fn generation(&self) -> u64 {
        self.0.generation.load(Ordering::Acquire)
    }
    pub(super) async fn call<T>(
        &self,
        build: impl FnOnce(Reply<T>) -> Command,
        try_only: bool,
    ) -> Result<T> {
        if !self.open() {
            return Err(stopping());
        }
        let (reply, read) = oneshot::channel();
        let command = build(reply);
        let channel = if command.control() {
            &self.0.control
        } else {
            &self.0.data
        };
        let envelope = Envelope {
            generation: self.generation(),
            command,
        };
        if try_only {
            channel.try_send(envelope).map_err(|_| stopping())?;
        } else {
            channel.send(envelope).await.map_err(|_| stopping())?;
        }
        read.await.map_err(|_| stopped())?
    }
    pub(super) fn wire_cancel(&self, value: &rpc::Cancellation) -> Cancellation {
        Cancellation {
            chain_id: self.0.deps.chain().to_vec(),
            caller: value.caller.clone(),
            caller_public_key: value.caller_public_key.clone(),
            caller_signature: value.caller_signature.clone(),
            session_id: value.session_id.clone(),
            until: value.until,
        }
    }
    pub async fn submit(&self, request: Request) -> Result<(Vec<u8>, Vec<u8>)> {
        let (id, _) = self
            .call(
                |reply| {
                    Command::Admit(
                        Admit {
                            request,
                            resume: false,
                        },
                        reply,
                    )
                },
                false,
            )
            .await?;
        Ok((hex::encode(id).into_bytes(), self.0.deps.node().to_vec()))
    }
    pub async fn compute(&self, request: Request) -> Result<Response> {
        let (_, job) = self
            .call(
                |reply| {
                    Command::Admit(
                        Admit {
                            request,
                            resume: false,
                        },
                        reply,
                    )
                },
                false,
            )
            .await?;
        job.wait_cancellable().await
    }
    pub async fn status(&self, read: Read) -> Result<Option<JobStatus>> {
        self.call(|reply| Command::QueryStatus(read, reply), false)
            .await
    }
    pub async fn cancel(&self, cancel: rpc::Cancellation) -> Result<usize> {
        let target = Some((cancel.caller.clone(), cancel.session_id.clone()));
        let cancelled = self
            .call(|reply| Command::Cancel(cancel, reply), false)
            .await?;
        let _ = self.send_cancel(target).await;
        Ok(cancelled)
    }
    pub async fn cancel_receipts(
        &self,
        cancel: rpc::Cancellation,
    ) -> Result<Vec<octra_node_protocol::resource_compute::message::CancelAck>> {
        self.call(|reply| Command::ReadCancels(cancel, reply), false)
            .await
    }
    pub async fn active_jobs(&self) -> Result<usize> {
        self.call(|reply| Command::ActiveJobs((), reply), false)
            .await
    }
    pub async fn shutdown(&self) -> Result<()> {
        if self.open() {
            let _ = self.call(|reply| Command::Stop((), reply), false).await;
        }
        let mut status = self.0.status.clone();
        loop {
            let state = status.borrow().clone();
            if let Status::Stopped(result) = state {
                return result;
            }
            status.changed().await.map_err(|_| stopped())?;
        }
    }
}
#[async_trait]
impl rpc::Gateway for Service {
    async fn submit(&self, request: Request) -> std::result::Result<(Vec<u8>, Vec<u8>), Vec<u8>> {
        Self::submit(self, request)
            .await
            .map_err(|error| error.as_bytes().to_vec())
    }
    async fn status(&self, read: Read) -> std::result::Result<Option<JobStatus>, Vec<u8>> {
        Self::status(self, read)
            .await
            .map_err(|error| error.as_bytes().to_vec())
    }
    async fn cancel(&self, value: rpc::Cancellation) -> std::result::Result<usize, Vec<u8>> {
        Self::cancel(self, value)
            .await
            .map_err(|error| error.as_bytes().to_vec())
    }
    async fn cancel_receipts(
        &self,
        value: rpc::Cancellation,
    ) -> std::result::Result<Vec<octra_node_protocol::resource_compute::message::CancelAck>, Vec<u8>>
    {
        Self::cancel_receipts(self, value)
            .await
            .map_err(|error| error.as_bytes().to_vec())
    }
}
