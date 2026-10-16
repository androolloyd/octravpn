// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! History work is owned after submission. Dropping an RPC or actor reply cannot
//! cancel a queued transaction or release its lane while LMDB is still running.
use crate::compute_history::History;
use octra_node_protocol::resource_compute::{Error, Result};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::{mpsc, oneshot, watch};
type Source = Result<Arc<History>>;
type Job = Box<dyn FnOnce(&Source) + Send + 'static>;
enum Command {
    Run(Job),
    Close,
}
#[derive(Clone)]
enum Status {
    Open,
    Closing,
    Closed(Result<()>),
}
struct Inner {
    data: mpsc::Sender<Command>,
    closing: AtomicBool,
    status: watch::Receiver<Status>,
}
#[derive(Clone)]
pub struct HistoryWorker(Arc<Inner>);
fn stopped() -> Error {
    Error::Unavailable(b"compute history worker stopped".to_vec())
}
fn failed(error: impl std::fmt::Display) -> Error {
    Error::Unavailable(error.to_string().into_bytes())
}
impl HistoryWorker {
    /// Opening/identity errors remain explicit and are returned by every job;
    /// there is no empty in-memory replacement for unavailable durable history.
    pub fn new(history: Source) -> Self {
        let (data, receiver) = mpsc::channel(super::DATA_CHANNEL_LIMIT);
        let (status, status_rx) = watch::channel(Status::Open);
        tokio::spawn(dispatch(history, receiver, status));
        Self(Arc::new(Inner {
            data,
            closing: AtomicBool::new(false),
            status: status_rx,
        }))
    }
    pub async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce(&History) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let inner = self.0.clone();
        // The detached owner survives cancellation during queue admission too.
        tokio::spawn(async move {
            if inner.closing.load(Ordering::Acquire) {
                return Err(stopped());
            }
            let (reply, read) = oneshot::channel();
            let job: Job = Box::new(move |history| {
                let result = match history {
                    Ok(history) => work(history),
                    Err(error) => Err(error.clone()),
                };
                let _ = reply.send(result);
            });
            inner
                .data
                .send(Command::Run(job))
                .await
                .map_err(|_| stopped())?;
            read.await.map_err(|_| stopped())?
        })
        .await
        .map_err(failed)?
    }
    pub async fn shutdown(&self) -> Result<()> {
        let inner = self.0.clone();
        tokio::spawn(async move {
            if !inner.closing.swap(true, Ordering::AcqRel) {
                // Once shutdown starts, its close command must survive caller
                // cancellation even if the bounded queue is currently full.
                let _ = inner.data.send(Command::Close).await;
            }
            let mut status = inner.status.clone();
            loop {
                let state = status.borrow().clone();
                if let Status::Closed(result) = state {
                    return result;
                }
                status.changed().await.map_err(|_| stopped())?;
            }
        })
        .await
        .map_err(failed)?
    }
}
async fn dispatch(
    history: Source,
    mut receiver: mpsc::Receiver<Command>,
    status: watch::Sender<Status>,
) {
    while let Some(command) = receiver.recv().await {
        match command {
            Command::Run(job) => {
                let source = history.clone();
                // The actor keeps the lane until the blocking task has actually
                // returned, including unwind, even when its reply is abandoned.
                let _ = tokio::task::spawn_blocking(move || job(&source)).await;
            }
            Command::Close => break,
        }
    }
    status.send_replace(Status::Closing);
    receiver.close();
    // Jobs queued after the close boundary are refused by dropping their reply.
    while receiver.try_recv().is_ok() {}
    let result = tokio::task::spawn_blocking(move || match history {
        Ok(history) => history.close().map_err(|error| Error::Unavailable(error.0)),
        Err(_) => Ok(()),
    })
    .await
    .map_err(failed)
    .and_then(|result| result);
    status.send_replace(Status::Closed(result));
}
