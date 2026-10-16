// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    mpsc, owner, refused, stopped, unavailable, watch, Arc, CacheLease, Dependencies, Error,
    Execute, Prepare, Result, Status,
};
use futures::FutureExt;
use std::{collections::BTreeMap, panic::AssertUnwindSafe};
use tokio::{sync::oneshot, time::Instant};
pub(super) struct Selected {
    pub token: owner::Token,
    pub model: owner::Model,
    pub lease: CacheLease,
}
// Keep native owned command/result records inline without changing their API.
#[allow(clippy::large_enum_variant)]
pub(super) enum Data {
    Reserve {
        request: Prepare,
        reply: oneshot::Sender<Result<owner::Preparation>>,
        deadline: Instant,
    },
    Select {
        request: Execute,
        reply: oneshot::Sender<Result<Selected>>,
        deadline: Instant,
    },
}
impl Data {
    fn reject(self, error: Error) {
        match self {
            Self::Reserve { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Select { reply, .. } => {
                let _ = reply.send(Err(error));
            }
        }
    }
}
// Keep native owned command/result records inline without changing their API.
#[allow(clippy::large_enum_variant)]
pub(super) enum ControlKind {
    Dropped(owner::Token),
    Remember(owner::Token, owner::Model),
    Check(owner::Token),
    Finish(owner::Token),
    Release(owner::Token, bool),
    Close,
}
pub(super) enum Reply {
    Unit,
    Dropped(bool),
}
pub(super) struct Control {
    pub kind: ControlKind,
    pub reply: oneshot::Sender<Result<Reply>>,
}
fn stale(error: &Error) -> bool {
    matches!(
        error.as_bytes(),
        b"compute storage cache missing" | b"compute storage cache identity differs"
    )
}
fn hold(deps: &dyn Dependencies, model: &owner::Model) -> Result<CacheLease> {
    std::panic::catch_unwind(AssertUnwindSafe(|| deps.hold_model(model)))
        .unwrap_or_else(|_| Err(unavailable("resource compute cache hold failed: panic")))
}
fn reserve(
    state: &mut owner::State,
    deps: &dyn Dependencies,
    request: &Prepare,
) -> Result<owner::Preparation> {
    let response = state.reserve(request)?;
    match &response {
        owner::Preparation::Ready(model) => match hold(deps, model) {
            Ok(lease) => {
                drop(lease);
                Ok(response)
            }
            Err(error) if stale(&error) => {
                state.lost(model);
                match state.reserve(request) {
                    Ok(owner::Preparation::Ready(_)) => Err(error),
                    other => other,
                }
            }
            Err(error) => Err(error),
        },
        owner::Preparation::Build(_) => Ok(response),
    }
}
fn select(
    state: &mut owner::State,
    deps: &dyn Dependencies,
    request: &Execute,
) -> Result<Selected> {
    let (token, model) = state.acquire(request)?;
    match hold(deps, &model) {
        Ok(lease) => Ok(Selected {
            token,
            model,
            lease,
        }),
        Err(error) => {
            if stale(&error) {
                state.forget(&token);
            }
            state.release(&token, false);
            Err(error)
        }
    }
}
fn control(state: &mut owner::State, deps: &dyn Dependencies, kind: ControlKind) -> Result<Reply> {
    match kind {
        ControlKind::Remember(token, model) => {
            let mut next = state.clone();
            next.remember(&token, model.clone())?;
            let lease = hold(deps, &model)?;
            *state = next;
            drop(lease);
            Ok(Reply::Unit)
        }
        ControlKind::Dropped(token) => Ok(Reply::Dropped(state.dropped(&token))),
        ControlKind::Check(token) => {
            state.check(&token)?;
            Ok(Reply::Unit)
        }
        ControlKind::Finish(token) => {
            state.finish(&token);
            Ok(Reply::Unit)
        }
        ControlKind::Release(token, spent) => {
            state.release(&token, spent);
            Ok(Reply::Unit)
        }
        ControlKind::Close => {
            state.close();
            Ok(Reply::Unit)
        }
    }
}
async fn own(
    mut state: owner::State,
    deps: Arc<dyn Dependencies>,
    data: &mut mpsc::Receiver<Data>,
    commands: &mut mpsc::Receiver<Control>,
    status: &watch::Sender<Status>,
) -> Result<()> {
    let mut data_open = true;
    let mut control_open = true;
    loop {
        if state.closed() && matches!(*status.borrow(), Status::Open) {
            status.send_replace(Status::Closing);
        }
        if state.drained() {
            data.close();
            commands.close();
            while let Ok(command) = data.try_recv() {
                command.reject(stopped());
            }
            while let Ok(command) = commands.try_recv() {
                let _ = command.reply.send(Err(stopped()));
            }
            let mut models = BTreeMap::new();
            for model in state.models() {
                models.entry(model.cache_key.clone()).or_insert(model);
            }
            for key in models.into_keys() {
                deps.drop_model(key).await?;
            }
            return Ok(());
        }
        tokio::select! {biased;
            command=commands.recv(),if control_open=>if let Some(command) = command {
                let result=control(&mut state,deps.as_ref(),command.kind);
                if state.closed() && matches!(*status.borrow(),Status::Open) {status.send_replace(Status::Closing);}
                let _=command.reply.send(result);
            } else {control_open=false;state.close();},
            command=data.recv(),if data_open=>match command {
                Some(Data::Reserve {request,reply,deadline})=>if !reply.is_closed() {
                    let result=if Instant::now()>=deadline {Err(refused(b"resource compute request expired"))} else {reserve(&mut state,deps.as_ref(),&request)};
                    // A cancellation racing delivery must retire a build
                    // token that the caller can no longer finish.
                    if let Err(Ok(owner::Preparation::Build(plan)))=reply.send(result) {
                        state.finish(&plan.token);
                    }
                },
                Some(Data::Select {request,reply,deadline})=>if !reply.is_closed() {
                    let result=if Instant::now()>=deadline {Err(refused(b"resource compute request expired"))} else {select(&mut state,deps.as_ref(),&request)};
                    if let Err(Ok(selected))=reply.send(result) {drop(selected.lease);state.release(&selected.token,false);}
                },
                None=>{data_open=false;state.close();},
            },
            else=>return Err(unavailable("resource compute provider channel closed with active work")),
        }
        tokio::task::yield_now().await;
    }
}
pub(super) async fn run(
    state: owner::State,
    deps: Arc<dyn Dependencies>,
    mut data: mpsc::Receiver<Data>,
    mut commands: mpsc::Receiver<Control>,
    status: watch::Sender<Status>,
) {
    let result = AssertUnwindSafe(own(state, deps, &mut data, &mut commands, &status))
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(unavailable("resource compute provider owner failed")));
    data.close();
    commands.close();
    let error = result.as_ref().err().cloned().unwrap_or_else(stopped);
    while let Ok(command) = data.try_recv() {
        command.reject(error.clone());
    }
    while let Ok(command) = commands.try_recv() {
        let _ = command.reply.send(Err(error.clone()));
    }
    status.send_replace(Status::Stopped(result));
}
