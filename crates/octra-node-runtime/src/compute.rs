// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native bounded compute scheduling. Cancelling queued work releases its slot;
//! cancelling a caller after work starts does not release capacity prematurely.
use octra_node_protocol::resource_lanes;
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    sync::{Arc, Condvar, Mutex, MutexGuard},
};
use tokio::{runtime::Handle, sync::Notify, task::JoinError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Required,
    Speculative,
}
#[derive(Clone, Copy)]
pub struct Limits {
    pub capacity: usize,
    pub required: usize,
    pub speculative: usize,
    pub required_burst: usize,
}
impl Limits {
    pub fn proof(capacity: usize) -> Self {
        Self {
            capacity,
            required: resource_lanes::PREVERIFY_REQUIRED_QUEUE as usize,
            speculative: resource_lanes::PREVERIFY_SPECULATIVE_QUEUE as usize,
            required_burst: resource_lanes::PREVERIFY_REQUIRED_BURST as usize,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub active: usize,
    pub required_waiting: usize,
    pub speculative_waiting: usize,
    pub required_streak: usize,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Waiting,
    Granted,
    Claimed,
}
struct Waiter {
    priority: Priority,
    status: Status,
    ready: Arc<Notify>,
}
#[derive(Default)]
struct State {
    active: usize,
    streak: usize,
    next: u64,
    required: VecDeque<u64>,
    speculative: VecDeque<u64>,
    waiters: BTreeMap<u64, Waiter>,
}
impl State {
    fn queue(&mut self, priority: Priority) -> &mut VecDeque<u64> {
        match priority {
            Priority::Required => &mut self.required,
            Priority::Speculative => &mut self.speculative,
        }
    }
}
struct Inner {
    limits: Limits,
    state: Mutex<State>,
    changed: Condvar,
    runtime: Option<Handle>,
}
#[derive(Clone)]
pub struct Pool(Arc<Inner>);
pub(crate) struct Permit {
    pool: Pool,
    id: u64,
    ready: Arc<Notify>,
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.pool.state();
        if let Some(waiter) = state.waiters.remove(&self.id) {
            if waiter.status == Status::Waiting {
                state.queue(waiter.priority).retain(|id| *id != self.id);
            } else {
                state.active -= 1;
            }
            self.pool.dispatch(&mut state);
        }
    }
}
impl Pool {
    pub fn new(limits: Limits, runtime: Handle) -> Result<Self, &'static str> {
        Self::with_runtime(limits, Some(runtime))
    }
    /// Synchronous users share the exact scheduler without creating a runtime
    /// or an extra set of OS workers.
    pub(crate) fn new_sync(limits: Limits) -> Result<Self, &'static str> {
        Self::with_runtime(limits, None)
    }
    fn with_runtime(limits: Limits, runtime: Option<Handle>) -> Result<Self, &'static str> {
        if limits.capacity == 0
            || limits.required == 0
            || limits.speculative == 0
            || limits.required_burst == 0
        {
            return Err("compute limits must be positive");
        }
        Ok(Self(Arc::new(Inner {
            limits,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            runtime,
        })))
    }
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.state.lock().expect("compute state poisoned")
    }
    pub fn capacity(&self) -> usize {
        self.0.limits.capacity
    }
    fn dispatch(&self, state: &mut State) {
        while state.active < self.0.limits.capacity {
            let priority = match (state.required.is_empty(), state.speculative.is_empty()) {
                (true, true) => break,
                (true, false) => Priority::Speculative,
                (false, false) if state.streak >= self.0.limits.required_burst => {
                    Priority::Speculative
                }
                _ => Priority::Required,
            };
            let id = state.queue(priority).pop_front().expect("nonempty queue");
            let waiter = state.waiters.get_mut(&id).expect("queued waiter");
            waiter.status = Status::Granted;
            waiter.ready.notify_one();
            state.active += 1;
            state.streak = if priority == Priority::Required && !state.speculative.is_empty() {
                state.streak + 1
            } else {
                0
            };
        }
        self.0.changed.notify_all();
    }
    fn enqueue(&self, priority: Priority) -> Option<Permit> {
        let mut state = self.state();
        let limit = match priority {
            Priority::Required => self.0.limits.required,
            Priority::Speculative => self.0.limits.speculative,
        };
        if state.queue(priority).len() >= limit {
            return None;
        }
        while state.waiters.contains_key(&state.next) {
            state.next = state.next.wrapping_add(1);
        }
        let id = state.next;
        state.next = state.next.wrapping_add(1);
        let ready = Arc::new(Notify::new());
        state.waiters.insert(
            id,
            Waiter {
                priority,
                status: Status::Waiting,
                ready: ready.clone(),
            },
        );
        state.queue(priority).push_back(id);
        self.dispatch(&mut state);
        Some(Permit {
            pool: self.clone(),
            id,
            ready,
        })
    }
    fn claim(state: &mut State, permit: &Permit) -> bool {
        let waiter = state.waiters.get_mut(&permit.id).expect("owned waiter");
        if waiter.status == Status::Granted {
            waiter.status = Status::Claimed;
            true
        } else {
            false
        }
    }
    async fn acquire(&self, priority: Priority) -> Option<Permit> {
        let permit = self.enqueue(priority)?;
        loop {
            if Self::claim(&mut self.state(), &permit) {
                return Some(permit);
            }
            permit.ready.notified().await;
        }
    }
    pub(crate) fn acquire_sync(&self, priority: Priority, wait: bool) -> Option<Permit> {
        let permit = self.enqueue(priority)?;
        let mut state = self.state();
        loop {
            if Self::claim(&mut state, &permit) {
                drop(state);
                return Some(permit);
            }
            if !wait {
                drop(state);
                return None;
            }
            state = self.0.changed.wait(state).expect("compute state poisoned");
        }
    }
    pub async fn run_async<F, Fut, T>(
        &self,
        priority: Priority,
        task: F,
    ) -> Result<Option<T>, JoinError>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let Some(permit) = self.acquire(priority).await else {
            return Ok(None);
        };
        // The task owns capacity until it finishes, even if the caller disappears.
        self.0
            .runtime
            .as_ref()
            .expect("synchronous compute pool used asynchronously")
            .spawn(async move {
                let _permit = permit;
                task().await
            })
            .await
            .map(Some)
    }
    pub async fn run_threaded<F, T>(
        &self,
        priority: Priority,
        task: F,
    ) -> Result<Option<T>, JoinError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let Some(permit) = self.acquire(priority).await else {
            return Ok(None);
        };
        self.0
            .runtime
            .as_ref()
            .expect("synchronous compute pool used asynchronously")
            .spawn_blocking(move || {
                let _permit = permit;
                task()
            })
            .await
            .map(Some)
    }
    /// Blocking acquisition for callers already running on a worker thread.
    pub fn run_sync<F, T>(&self, priority: Priority, task: F) -> Option<T>
    where
        F: FnOnce() -> T,
    {
        let _permit = self.acquire_sync(priority, true)?;
        Some(task())
    }
    pub fn try_run_sync<F, T>(&self, priority: Priority, task: F) -> Option<T>
    where
        F: FnOnce() -> T,
    {
        let _permit = self.acquire_sync(priority, false)?;
        Some(task())
    }
    pub fn stats(&self) -> Stats {
        let state = self.state();
        Stats {
            active: state.active,
            required_waiting: state.required.len(),
            speculative_waiting: state.speculative.len(),
            required_streak: state.streak,
        }
    }
}
