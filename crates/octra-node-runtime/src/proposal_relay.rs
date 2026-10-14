// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Bounded, cancellable proposal broadcast, matching native `C_relay`.
use futures::{future::BoxFuture, FutureExt};
use octra_node_protocol::{
    consensus::driver_work::{
        Relay, RelayEffect, RelayItem, RelayMessage, RelayOutcome, RELAY_LIFETIME,
    },
    network::{frame::Frame, swarm::Swarm},
};
use std::{
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{runtime::Handle, task::AbortHandle};

/// Local I/O policy; neither clock nor failure strings enter consensus data.
/// Send and wait futures must release their resources when dropped.
pub trait RelayIo<T>: Send + Sync + 'static {
    fn now(&self) -> f64;
    fn send(&self, value: T) -> BoxFuture<'static, Result<(), Vec<u8>>>;
    fn wait(&self, seconds: f64) -> BoxFuture<'static, ()>;
    fn warn(&self, reason: &[u8]);
}

struct State<T> {
    relay: Relay<T>,
    task: Option<AbortHandle>,
}
struct Inner<T> {
    state: Mutex<State<T>>,
    io: Arc<dyn RelayIo<T>>,
    runtime: Handle,
}
impl<T> Drop for Inner<T> {
    fn drop(&mut self) {
        if let Some(task) = self.state.get_mut().expect("relay lock").task.take() {
            task.abort();
        }
    }
}

/// One active send and at most four queued proposals. New generations, close,
/// open and dropping the last owner cancel pending I/O. Already-sent network
/// bytes cannot be recalled; stale completions cannot change the new queue.
pub struct ProposalRelay<T>(Arc<Inner<T>>);
impl<T> Clone for ProposalRelay<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T: Clone + Send + Sync + 'static> ProposalRelay<T> {
    /// Construct within the runtime that will own the relay's worker tasks.
    pub fn new(io: Arc<dyn RelayIo<T>>) -> Self {
        Self(Arc::new(Inner {
            state: Mutex::new(State {
                relay: Relay::default(),
                task: None,
            }),
            io,
            runtime: Handle::current(),
        }))
    }
    pub fn offer(&self, generation: i64, key: Vec<u8>, value: T) {
        let now = self.0.io.now();
        self.0.dispatch(RelayMessage::Offer {
            generation,
            now,
            item: RelayItem {
                key,
                value,
                expires: now + RELAY_LIFETIME,
            },
        });
    }
    pub fn progress(&self, generation: i64) {
        self.0.dispatch(RelayMessage::Advance {
            generation,
            now: self.0.io.now(),
        });
    }
    pub fn close(&self) {
        self.0.dispatch(RelayMessage::Close);
    }
    pub fn open(&self, generation: i64) {
        self.0.dispatch(RelayMessage::Open(generation));
    }
}
impl<T: Clone + Send + Sync + 'static> Inner<T> {
    fn dispatch(self: &Arc<Self>, message: RelayMessage<T>) {
        let warnings = {
            let mut state = self.state.lock().expect("relay lock");
            if let RelayMessage::Finished { serial, .. } = &message {
                if state
                    .relay
                    .active
                    .as_ref()
                    .is_some_and(|(current, _)| current == serial)
                {
                    state.task = None;
                }
            }
            let mut warnings = vec![];
            for effect in state.relay.step(message) {
                match effect {
                    RelayEffect::Cancel => {
                        if let Some(task) = state.task.take() {
                            task.abort();
                        }
                    }
                    RelayEffect::Dropped(reason) => warnings.push(reason),
                    RelayEffect::Send(serial, item) => {
                        let owner = Arc::downgrade(self);
                        let io = self.io.clone();
                        // No worker owns Inner while waiting on a peer. Dropping
                        // the last service handle therefore cancels this task.
                        let task = self.runtime.spawn(async move {
                            let outcome = AssertUnwindSafe(async {
                                tokio::task::yield_now().await;
                                let remaining = item.expires - io.now();
                                if remaining <= 0. {
                                    return RelayOutcome::Expired;
                                }
                                let wait = io.wait(remaining);
                                let send = io.send(item.value);
                                tokio::select! {
                                    biased;
                                    result = send => match result {
                                        Ok(()) => RelayOutcome::Sent,
                                        Err(reason) => RelayOutcome::Failed(reason),
                                    },
                                    () = wait => RelayOutcome::Expired,
                                }
                            })
                            .catch_unwind()
                            .await
                            .unwrap_or_else(|_| {
                                RelayOutcome::Failed(b"relay I/O panicked".to_vec())
                            });
                            if let Some(owner) = owner.upgrade() {
                                owner.dispatch(RelayMessage::Finished {
                                    serial,
                                    now: io.now(),
                                    outcome,
                                });
                            }
                        });
                        state.task = Some(task.abort_handle());
                    }
                }
            }
            warnings
        };
        // Host logging may reenter the relay; never invoke it under the lock.
        for reason in warnings {
            self.io.warn(&reason);
        }
    }
}

#[derive(Clone)]
pub struct Broadcast {
    pub frame: Frame,
    pub except: Option<Vec<u8>>,
}
type Warning = Box<dyn Fn(&[u8]) + Send + Sync>;
struct SwarmIo {
    swarm: Swarm,
    started: Instant,
    warn: Warning,
}
impl RelayIo<Broadcast> for SwarmIo {
    fn now(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }
    fn send(&self, value: Broadcast) -> BoxFuture<'static, Result<(), Vec<u8>>> {
        let swarm = self.swarm.clone();
        Box::pin(async move {
            swarm
                .broadcast(value.frame, value.except.as_deref(), false)
                .await
                .map_err(|error| error.to_string().into_bytes())
        })
    }
    fn wait(&self, seconds: f64) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(Duration::from_secs_f64(seconds)))
    }
    fn warn(&self, reason: &[u8]) {
        (self.warn)(reason);
    }
}
impl ProposalRelay<Broadcast> {
    pub fn for_swarm(swarm: Swarm, warn: impl Fn(&[u8]) + Send + Sync + 'static) -> Self {
        Self::new(Arc::new(SwarmIo {
            swarm,
            started: Instant::now(),
            warn: Box::new(warn),
        }))
    }
}
