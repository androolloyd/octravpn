// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native provider model ownership and bounded execution service.
mod actor;
mod native;
mod operations;
pub use native::Native;
pub mod owner;
use async_trait::async_trait;
use octra_node_protocol::resource_compute::{
    provider::{Execute, Executed, Limits, Prepare, Prepared, SelfTest},
    Error, Result,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, watch};

pub type CacheLease = Box<dyn Send>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub circle_id: Vec<u8>,
    pub code_b64: Vec<u8>,
    pub code_hash: Vec<u8>,
    pub runtime: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub output_json: Vec<u8>,
    pub trace_root: Vec<u8>,
    pub steps: i64,
    pub operations: i64,
    pub effort_used: i64,
}
#[async_trait]
pub trait Dependencies: Send + Sync + 'static {
    async fn program(&self, epoch: i64, state_root: Vec<u8>, circle: Vec<u8>) -> Result<Program>;
    async fn storage(
        &self,
        epoch: i64,
        state_root: Vec<u8>,
        circle: Vec<u8>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;
    async fn load_model(&self, cancel: Cancellation, request: Prepare) -> Result<owner::Model>;
    async fn drop_model(&self, key: Vec<u8>) -> Result<()>;
    fn hold_model(&self, model: &owner::Model) -> Result<CacheLease>;
    async fn self_test(&self) -> Result<SelfTest>;
    async fn execute(
        &self,
        model: owner::Model,
        program: Program,
        storage: Vec<(Vec<u8>, Vec<u8>)>,
        request: Execute,
    ) -> Result<Observation>;
}
#[derive(Clone)]
enum Status {
    Open,
    Closing,
    Stopped(Result<()>),
}
struct Inner {
    limits: Limits,
    deps: Arc<dyn Dependencies>,
    data: mpsc::Sender<actor::Data>,
    control: mpsc::Sender<actor::Control>,
    status: watch::Receiver<Status>,
}
#[derive(Clone)]
pub struct Provider(Arc<Inner>);
#[derive(Clone)]
pub struct Cancellation {
    aborted: watch::Receiver<Option<Vec<u8>>>,
    status: watch::Receiver<Status>,
}
impl Cancellation {
    pub fn reason(&self) -> Option<Vec<u8>> {
        if matches!(*self.status.borrow(), Status::Open) {
            self.aborted.borrow().clone()
        } else {
            Some(b"resource compute provider stopped".to_vec())
        }
    }
    pub async fn cancelled(&self) -> Vec<u8> {
        let mut signal = self.clone();
        loop {
            if let Some(reason) = signal.reason() {
                return reason;
            }
            tokio::select! {
                changed=signal.aborted.changed()=>if changed.is_err() {return b"resource compute request cancelled".to_vec();},
                changed=signal.status.changed()=>if changed.is_err() {return b"resource compute provider stopped".to_vec();},
            }
        }
    }
}
fn refused(reason: &[u8]) -> Error {
    Error::rejected(reason)
}
fn stopped() -> Error {
    refused(b"resource compute provider stopped")
}
fn unavailable(error: impl std::fmt::Display) -> Error {
    Error::Unavailable(error.to_string().into_bytes())
}
impl Provider {
    pub fn new(limits: Limits, deps: Arc<dyn Dependencies>) -> Self {
        let (data, data_rx) = mpsc::channel(32);
        let (control, control_rx) = mpsc::channel(16);
        let (status, status_rx) = watch::channel(Status::Open);
        tokio::spawn(actor::run(
            owner::State::new(limits.lanes),
            deps.clone(),
            data_rx,
            control_rx,
            status,
        ));
        Self(Arc::new(Inner {
            limits,
            deps,
            data,
            control,
            status: status_rx,
        }))
    }
    pub fn limits(&self) -> &Limits {
        &self.0.limits
    }
    pub async fn self_test(&self) -> Result<SelfTest> {
        if !matches!(*self.0.status.borrow(), Status::Open) {
            return Err(stopped());
        }
        self.0.deps.self_test().await
    }
    pub async fn prepare(&self, request: Prepare) -> Result<Prepared> {
        let provider = self.clone();
        self.owned(move |cancel| async move { provider.prepare_owned(cancel, request).await })
            .await
    }
    pub async fn execute(&self, request: Execute) -> Result<Executed> {
        let limits = &self.0.limits;
        if request.memory_bytes <= 0
            || request.memory_bytes > octra_node_protocol::resource_compute::request::MAX_MEMORY
            || request.memory_bytes > limits.memory_bytes
        {
            return Err(refused(b"resource compute memory refused"));
        }
        if !(65_536..=67_108_864).contains(&request.guest_bytes)
            || request.guest_bytes % 65_536 != 0
        {
            return Err(refused(b"resource compute pages refused"));
        }
        if !(1..=2_000_000_000).contains(&request.fuel_limit) {
            return Err(refused(b"resource compute fuel refused"));
        }
        if request.params_json.len() as i64 > limits.max_request_bytes {
            return Err(refused(b"resource compute input exceeds provider limit"));
        }
        let mut request = request;
        request.program_b64.clear();
        request.storage.clear();
        let provider = self.clone();
        self.owned(move |cancel| async move { provider.execute_owned(cancel, request).await })
            .await
    }
    pub async fn stop(&self) -> Result<()> {
        if matches!(*self.0.status.borrow(), Status::Open) {
            self.command(actor::ControlKind::Close).await?;
        }
        let mut status = self.0.status.clone();
        loop {
            if let Status::Stopped(result) = status.borrow().clone() {
                return result;
            }
            status.changed().await.map_err(|_| stopped())?;
        }
    }
    async fn command(&self, kind: actor::ControlKind) -> Result<actor::Reply> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.0
            .control
            .send(actor::Control { kind, reply })
            .await
            .map_err(|_| stopped())?;
        response.await.map_err(|_| stopped())?
    }
    async fn reserve(&self, request: Prepare) -> Result<owner::Preparation> {
        let (reply, response) = tokio::sync::oneshot::channel();
        let command = actor::Data::Reserve {
            request,
            reply,
            deadline: tokio::time::Instant::now()
                + Duration::from_secs(self.0.limits.timeout_seconds.max(0) as u64),
        };
        self.0.data.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => refused(b"resource compute provider busy"),
            mpsc::error::TrySendError::Closed(_) => stopped(),
        })?;
        response.await.map_err(|_| stopped())?
    }
    async fn select(&self, request: Execute) -> Result<actor::Selected> {
        let (reply, response) = tokio::sync::oneshot::channel();
        let command = actor::Data::Select {
            request,
            reply,
            deadline: tokio::time::Instant::now()
                + Duration::from_secs(self.0.limits.timeout_seconds.max(0) as u64),
        };
        self.0.data.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => refused(b"resource compute provider busy"),
            mpsc::error::TrySendError::Closed(_) => stopped(),
        })?;
        response.await.map_err(|_| stopped())?
    }
}
