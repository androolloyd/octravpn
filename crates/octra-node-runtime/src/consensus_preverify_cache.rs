// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native consensus item-cache lifecycle, separate from speculative proof pools.
//! No crypto workers are spawned here. The caller's existing blocking worker
//! owns proof execution and its resource deadline; waiters share its result.
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Condvar, Mutex, Weak},
};

use crate::{
    execution::Error,
    preverify_batch::{Checked, Kind},
};
use octra_node_protocol::{native_integer, network::domain_hash, transaction::Transaction};

type Result<T> = std::result::Result<T, Error>;
type Key = [u8; 32];
mod shared;
pub use shared::Shared;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Build,
    Validate,
}

impl Purpose {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Build => b"build",
            Self::Validate => b"validate",
        }
    }
}

/// Native startup bound, captured once by the owning execution host.
pub fn configured_capacity(value: Option<&[u8]>) -> usize {
    value
        .and_then(native_integer::parse_int63)
        .filter(|value| (64..=65_536).contains(value))
        .map_or(4096, |value| value as usize)
}

pub fn item_key(epoch: i64, purpose: Purpose, root: &[u8], hash: &[u8]) -> Key {
    fn part(buffer: &mut Vec<u8>, bytes: &[u8]) {
        buffer.extend_from_slice(bytes.len().to_string().as_bytes());
        buffer.push(b':');
        buffer.extend_from_slice(bytes);
    }
    let mut bytes = Vec::new();
    part(&mut bytes, purpose.tag());
    part(&mut bytes, root);
    part(&mut bytes, hash);
    if epoch != 0 {
        part(&mut bytes, epoch.to_string().as_bytes());
    }
    domain_hash(b"octra:consensus_preverify_item_cache:v1", &bytes)
}

struct Context<B> {
    root: Vec<u8>,
    binding: B,
}
pub struct Scope<B>(Arc<Context<B>>);
impl<B> Clone for Scope<B> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
struct Job {
    result: Mutex<Option<Result<Checked>>>,
    ready: Condvar,
}
impl Job {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
        }
    }
    fn pending(&self) -> bool {
        self.result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none()
    }
    fn wait(&self) -> Result<Checked> {
        let mut result = self
            .result
            .lock()
            .map_err(|_| Error("consensus preverify result poisoned".into()))?;
        loop {
            if let Some(result) = &*result {
                return result.clone();
            }
            result = self
                .ready
                .wait(result)
                .map_err(|_| Error("consensus preverify result poisoned".into()))?;
        }
    }
    fn finish(&self, result: Result<Checked>) {
        *self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
        self.ready.notify_all();
    }
}
struct Entry {
    job: Arc<Job>,
    bytes: usize,
}
struct State<B> {
    scope: Option<Arc<Context<B>>>,
    entries: BTreeMap<Key, Entry>,
    fifo: VecDeque<(Key, Weak<Job>)>,
    bytes: usize,
}
struct Inner<B> {
    state: Mutex<State<B>>,
    capacity: usize,
    byte_limit: usize,
    shared: Shared,
}
pub struct Cache<B>(Arc<Inner<B>>);
impl<B> Clone for Cache<B> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<B> Default for Cache<B> {
    fn default() -> Self {
        Self::new(4096, 32 * 1024 * 1024)
    }
}
impl<B> Cache<B> {
    pub fn new(capacity: usize, byte_limit: usize) -> Self {
        Self(Arc::new(Inner {
            state: Mutex::new(State {
                scope: None,
                entries: BTreeMap::new(),
                fifo: VecDeque::new(),
                bytes: 0,
            }),
            capacity,
            byte_limit,
            shared: Shared::default(),
        }))
    }
    /// Independent native transaction relay lifetime: root changes only clear
    /// proof results, never the bounded transactions served to gossip peers.
    pub fn shared(&self) -> &Shared {
        &self.0.shared
    }
    fn forget(state: &mut State<B>, key: &Key, job: &Arc<Job>) {
        if state
            .entries
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(&current.job, job))
        {
            let entry = state.entries.remove(key).expect("matching preverify job");
            state.bytes -= entry.bytes;
        }
    }
    fn evict(&self, state: &mut State<B>) {
        // Native visits at most the queue length observed on entry. Sleeping
        // jobs rotate only for byte pressure, but count pressure may evict them.
        for _ in 0..state.fifo.len() {
            let over_count = state.fifo.len() > self.0.capacity;
            if !over_count && state.bytes <= self.0.byte_limit {
                break;
            }
            let Some((key, ticket)) = state.fifo.pop_front() else {
                break;
            };
            let Some(job) = ticket.upgrade() else {
                continue;
            };
            if state
                .entries
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(&current.job, &job))
                && !over_count
                && job.pending()
            {
                state.fifo.push_back((key, ticket));
            } else {
                Self::forget(state, &key, &job);
            }
        }
    }
}
impl<B: PartialEq> Cache<B> {
    /// The immutable binding contains every trusted policy/authority input not
    /// represented by the native root/epoch key. A policy change clears reuse.
    pub fn select(&self, root: &[u8], binding: B) -> Result<Scope<B>> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| Error("consensus preverify cache poisoned".into()))?;
        if let Some(scope) = state
            .scope
            .as_ref()
            .filter(|scope| scope.root == root && scope.binding == binding)
        {
            return Ok(Scope(scope.clone()));
        }
        let scope = Arc::new(Context {
            root: root.to_vec(),
            binding,
        });
        state.scope = Some(scope.clone());
        state.entries.clear();
        state.fifo.clear();
        state.bytes = 0;
        Ok(Scope(scope))
    }
    /// Seed an already-computed speculative result without installing a pending
    /// ticket or waiting for required work. Neither a stale scope nor an
    /// existing authoritative ticket may be replaced by a late warmup.
    pub fn remember(
        &self,
        scope: &Scope<B>,
        epoch: i64,
        purpose: Purpose,
        tx: &Transaction,
        checked: Checked,
    ) -> Result<bool> {
        if !cacheable(&checked) {
            return Ok(false);
        }
        let hash = tx.hash().map_err(|error| Error(error.to_string()))?;
        let key = item_key(epoch, purpose, &scope.0.root, hex::encode(hash).as_bytes());
        let bytes = checked_bytes(tx, &checked)?;
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| Error("consensus preverify cache poisoned".into()))?;
        if !state
            .scope
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &scope.0))
            || state.entries.contains_key(&key)
        {
            return Ok(false);
        }
        let total = state
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| Error("consensus preverify cache size overflow".into()))?;
        let job = Arc::new(Job::new());
        job.finish(Ok(checked));
        state.entries.insert(
            key,
            Entry {
                job: job.clone(),
                bytes,
            },
        );
        state.fifo.push_back((key, Arc::downgrade(&job)));
        state.bytes = total;
        self.evict(&mut state);
        Ok(true)
    }
    /// The proof factory runs without any cache lock. A dropped async caller
    /// does not cancel the blocking owner; a panic wakes joined callers and
    /// forgets only its own ticket. Late old-root completion cannot repopulate.
    pub fn run(
        &self,
        scope: &Scope<B>,
        epoch: i64,
        purpose: Purpose,
        tx: &Transaction,
        verify: impl FnOnce() -> Result<Checked>,
    ) -> Result<Checked> {
        let hash = tx.hash().map_err(|error| Error(error.to_string()))?;
        let key = item_key(epoch, purpose, &scope.0.root, hex::encode(hash).as_bytes());
        let (job, owner) = {
            let mut state = self
                .0
                .state
                .lock()
                .map_err(|_| Error("consensus preverify cache poisoned".into()))?;
            if !state
                .scope
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &scope.0))
            {
                drop(state);
                return verify();
            }
            if let Some(entry) = state.entries.get(&key) {
                (entry.job.clone(), false)
            } else {
                let job = Arc::new(Job::new());
                state.entries.insert(
                    key,
                    Entry {
                        job: job.clone(),
                        bytes: 0,
                    },
                );
                state.fifo.push_back((key, Arc::downgrade(&job)));
                self.evict(&mut state);
                (job, true)
            }
        };
        if !owner {
            return job.wait();
        }
        let mut completion = Completion {
            cache: self.clone(),
            key,
            job,
            finished: false,
        };
        let result = verify();
        let bytes = result
            .as_ref()
            .ok()
            .filter(|result| cacheable(result))
            .map(|result| checked_bytes(tx, result))
            .transpose();
        let mut result = match &bytes {
            Ok(_) => result,
            Err(error) => Err(error.clone()),
        };
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| Error("consensus preverify cache poisoned".into()))?;
        if state
            .entries
            .get(&key)
            .is_some_and(|entry| Arc::ptr_eq(&entry.job, &completion.job))
        {
            if let (Ok(checked), Ok(Some(bytes))) = (&result, &bytes) {
                debug_assert!(cacheable(checked));
                let old = state
                    .entries
                    .get(&key)
                    .expect("matching preverify job")
                    .bytes;
                let total = state
                    .bytes
                    .checked_sub(old)
                    .and_then(|total| total.checked_add(*bytes));
                if let Some(total) = total {
                    state.bytes = total;
                    state
                        .entries
                        .get_mut(&key)
                        .expect("matching preverify job")
                        .bytes = *bytes;
                } else {
                    Self::forget(&mut state, &key, &completion.job);
                    result = Err(Error("consensus preverify cache size overflow".into()));
                }
            } else {
                Self::forget(&mut state, &key, &completion.job);
            }
        }
        completion.job.finish(result.clone());
        self.evict(&mut state);
        completion.finished = true;
        result
    }
}
struct Completion<B> {
    cache: Cache<B>,
    key: Key,
    job: Arc<Job>,
    finished: bool,
}
impl<B> Drop for Completion<B> {
    fn drop(&mut self) {
        if !self.finished {
            self.job
                .finish(Err(Error("consensus preverify worker stopped".into())));
            let mut state = self
                .cache
                .0
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Cache::forget(&mut state, &self.key, &self.job);
        }
    }
}
fn cacheable(result: &Checked) -> bool {
    matches!(
        result,
        Checked::Ready(_)
            | Checked::Skip {
                kind: Kind::Invalid,
                ..
            }
    )
}
fn checked_bytes(tx: &Transaction, result: &Checked) -> Result<usize> {
    let tx = tx
        .to_json_bytes()
        .map_err(|error| Error(error.to_string()))?
        .len();
    let output = match result {
        Checked::Ready(receipt) => receipt
            .as_ref()
            .map_or(0, |receipt| receipt.canonical().len()),
        Checked::Skip { reason, .. } => reason.len(),
    };
    tx.checked_add(output)
        .ok_or_else(|| Error("consensus preverify item size overflow".into()))
}

#[cfg(test)]
mod tests;
