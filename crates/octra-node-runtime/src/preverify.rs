//! Shared native preverification jobs. Required work can displace queued
//! speculative work; cancellation of a waiter does not cancel a shared job.
pub use crate::compute::Priority;
use async_trait::async_trait;
use futures::{future::try_join_all, FutureExt};
use octra_node_protocol::transaction::Transaction;
use std::{
    collections::BTreeMap,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::{
    runtime::Handle,
    sync::watch,
    task::{AbortHandle, JoinHandle},
};

pub enum Verification<A> {
    Ready(Arc<A>),
    Rejected(Arc<A>, String),
    Stale,
}
impl<A> Clone for Verification<A> {
    fn clone(&self) -> Self {
        match self {
            Self::Ready(a) => Self::Ready(a.clone()),
            Self::Rejected(a, e) => Self::Rejected(a.clone(), e.clone()),
            Self::Stale => Self::Stale,
        }
    }
}
pub enum Binding<P> {
    Bound(P),
    SourceChanged,
    Invalid(String),
}
#[derive(Debug, PartialEq, Eq)]
pub enum Availability<P> {
    /// Run the host's synchronous verification path. This is not acceptance.
    Unmanaged,
    Pending,
    Ready(P),
    Invalid(String),
}
#[async_trait]
pub trait Worker: Send + Sync + 'static {
    type Artifact: Send + Sync + 'static;
    type Prepared: Send + 'static;
    fn eligible(&self, tx: &Transaction) -> bool;
    async fn verify(
        &self,
        priority: Priority,
        tx: &Transaction,
    ) -> Result<Verification<Self::Artifact>, String>;
    async fn bind(
        &self,
        tx: &Transaction,
        artifact: &Self::Artifact,
    ) -> Result<Binding<Self::Prepared>, String>;
}
#[derive(Clone, Copy)]
pub struct Limits {
    pub running: usize,
    pub queued: usize,
    pub complete: usize,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub pending: usize,
    pub queued: usize,
    pub running: usize,
    pub ready: usize,
    pub invalid: usize,
}
struct Queued {
    tx: Arc<Transaction>,
    hash: Vec<u8>,
    order: i64,
    priority: Priority,
    activated: watch::Sender<bool>,
}
struct Job<A> {
    id: u64,
    result: watch::Sender<Option<Result<Verification<A>, String>>>,
}
struct Complete<A> {
    artifact: Arc<A>,
    invalid: Option<String>,
    time: f64,
}
impl<A> Clone for Complete<A> {
    fn clone(&self) -> Self {
        Self {
            artifact: self.artifact.clone(),
            invalid: self.invalid.clone(),
            time: self.time,
        }
    }
}
enum Entry<A> {
    Queued(Arc<Queued>),
    Running(Arc<Job<A>>),
    Complete(Complete<A>),
}
impl<A> Clone for Entry<A> {
    fn clone(&self) -> Self {
        match self {
            Self::Queued(q) => Self::Queued(q.clone()),
            Self::Running(j) => Self::Running(j.clone()),
            Self::Complete(c) => Self::Complete(c.clone()),
        }
    }
}
struct State<A> {
    entries: BTreeMap<Vec<u8>, Entry<A>>,
    tasks: BTreeMap<u64, AbortHandle>,
    next_order: i64,
    next_job: u64,
    closed: bool,
}
struct Inner<W: Worker> {
    worker: Arc<W>,
    clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    runtime: Handle,
    limits: Limits,
    state: Mutex<State<W::Artifact>>,
}
pub struct Pool<W: Worker>(Arc<Inner<W>>);
impl<W: Worker> Clone for Pool<W> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
fn hash(tx: &Transaction) -> Result<Vec<u8>, String> {
    tx.hash()
        .map(|h| hex::encode(h).into_bytes())
        .map_err(|e| e.to_string())
}
fn float_order(a: f64, b: f64) -> std::cmp::Ordering {
    match (a.is_nan(), b.is_nan()) {
        (true, true) => std::cmp::Ordering::Equal,
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.partial_cmp(&b).expect("ordered floats"),
    }
}
// A supervisor owns its worker task even if the pool shuts down during an await.
struct OwnedTask<T>(JoinHandle<T>);
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl<W: Worker> Drop for Inner<W> {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for task in state.tasks.values() {
            task.abort();
        }
    }
}
impl<W: Worker> Pool<W> {
    pub fn new(
        worker: W,
        limits: Limits,
        clock: Arc<dyn Fn() -> f64 + Send + Sync>,
        runtime: Handle,
    ) -> Result<Self, String> {
        if limits.running == 0 || limits.queued == 0 || limits.complete == 0 {
            return Err("preverify limits must be positive".into());
        }
        Ok(Self(Arc::new(Inner {
            worker: Arc::new(worker),
            limits,
            clock,
            runtime,
            state: Mutex::new(State {
                entries: BTreeMap::new(),
                tasks: BTreeMap::new(),
                next_order: 0,
                next_job: 0,
                closed: false,
            }),
        })))
    }
    fn state(&self) -> MutexGuard<'_, State<W::Artifact>> {
        self.0.state.lock().expect("preverify state poisoned")
    }
    fn view(&self, hash: &[u8]) -> Result<Option<Entry<W::Artifact>>, String> {
        let state = self.state();
        if state.closed {
            Err("preverification pool closed".into())
        } else {
            Ok(state.entries.get(hash).cloned())
        }
    }
    fn check_open(&self) -> Result<(), String> {
        if self.state().closed {
            Err("preverification pool closed".into())
        } else {
            Ok(())
        }
    }
    fn remove(state: &mut State<W::Artifact>, hash: &[u8]) {
        if let Some(Entry::Queued(q)) = state.entries.remove(hash) {
            q.activated.send_replace(true);
        }
    }
    fn trim(&self, state: &mut State<W::Artifact>) {
        let mut complete: Vec<_> = state
            .entries
            .iter()
            .filter_map(|(h, e)| match e {
                Entry::Complete(c) => Some((h.clone(), c.time)),
                _ => None,
            })
            .collect();
        complete.sort_by(|a, b| float_order(a.1, b.1).then_with(|| a.0.cmp(&b.0)));
        let excess = complete.len().saturating_sub(self.0.limits.complete);
        for (hash, _) in complete.into_iter().take(excess) {
            Self::remove(state, &hash);
        }
    }
    fn schedule(&self, state: &mut State<W::Artifact>) {
        while !state.closed
            && state
                .entries
                .values()
                .filter(|e| matches!(e, Entry::Running(_)))
                .count()
                < self.0.limits.running
        {
            let next = state
                .entries
                .values()
                .filter_map(|e| {
                    if let Entry::Queued(q) = e {
                        Some(q.clone())
                    } else {
                        None
                    }
                })
                .min_by(|a, b| (a.priority, a.order, &a.hash).cmp(&(b.priority, b.order, &b.hash)));
            let Some(queued) = next else {
                break;
            };
            while state.tasks.contains_key(&state.next_job) {
                state.next_job = state.next_job.wrapping_add(1);
            }
            let (result, _) = watch::channel(None);
            let job = Arc::new(Job {
                id: state.next_job,
                result,
            });
            state.next_job = state.next_job.wrapping_add(1);
            state
                .entries
                .insert(queued.hash.clone(), Entry::Running(job.clone()));
            queued.activated.send_replace(true);
            let inner = Arc::downgrade(&self.0);
            let worker = self.0.worker.clone();
            let runtime = self.0.runtime.clone();
            let completed_job = job.clone();
            let task = self.0.runtime.spawn(async move {
                let tx = queued.tx.clone();
                let priority = queued.priority;
                let mut task = OwnedTask(runtime.spawn(async move {
                    tokio::task::yield_now().await;
                    worker.verify(priority, &tx).await
                }));
                let result = match (&mut task.0).await {
                    Ok(result) => result,
                    Err(_) => Err("preverification worker failed".into()),
                };
                if let Some(inner) = inner.upgrade() {
                    Self(inner).complete(&queued.hash, &completed_job, &result);
                }
                completed_job.result.send_replace(Some(result));
            });
            state.tasks.insert(job.id, task.abort_handle());
        }
    }
    fn complete(
        &self,
        hash: &[u8],
        job: &Arc<Job<W::Artifact>>,
        result: &Result<Verification<W::Artifact>, String>,
    ) {
        let mut state = self.state();
        state.tasks.remove(&job.id);
        if state
            .entries
            .get(hash)
            .is_some_and(|e| matches!(e,Entry::Running(current) if Arc::ptr_eq(current,job)))
        {
            match result {
                Ok(Verification::Ready(artifact) | Verification::Rejected(artifact, _)) => {
                    let invalid = if let Ok(Verification::Rejected(_, reason)) = result {
                        Some(reason.clone())
                    } else {
                        None
                    };
                    state.entries.insert(
                        hash.to_vec(),
                        Entry::Complete(Complete {
                            artifact: artifact.clone(),
                            invalid,
                            time: (self.0.clock)(),
                        }),
                    );
                }
                Ok(Verification::Stale) | Err(_) => Self::remove(&mut state, hash),
            }
            self.trim(&mut state);
        }
        self.schedule(&mut state);
    }
    fn enqueue(
        &self,
        tx: &Transaction,
        priority: Priority,
    ) -> Result<Availability<W::Prepared>, String> {
        self.check_open()?;
        if !self.0.worker.eligible(tx) {
            return Ok(Availability::Unmanaged);
        }
        let hash = hash(tx)?;
        let mut state = self.state();
        if state.closed {
            return Err("preverification pool closed".into());
        }
        if state.entries.contains_key(&hash) {
            return Ok(Availability::Pending);
        }
        let count = state
            .entries
            .values()
            .filter(|e| matches!(e, Entry::Queued(_)))
            .count();
        if count >= self.0.limits.queued {
            if priority == Priority::Speculative {
                return Ok(Availability::Pending);
            }
            let oldest = state
                .entries
                .values()
                .filter_map(|e| match e {
                    Entry::Queued(q) if q.priority == Priority::Speculative => Some(q.clone()),
                    _ => None,
                })
                .min_by_key(|q| q.order);
            let Some(oldest) = oldest else {
                return Ok(Availability::Pending);
            };
            Self::remove(&mut state, &oldest.hash);
        }
        let (activated, _) = watch::channel(false);
        let order = state.next_order;
        state.next_order = (order.wrapping_add(1) << 1) >> 1;
        state.entries.insert(
            hash.clone(),
            Entry::Queued(Arc::new(Queued {
                tx: Arc::new(tx.clone()),
                hash,
                order,
                priority,
                activated,
            })),
        );
        self.schedule(&mut state);
        Ok(Availability::Pending)
    }
    pub fn admit(&self, tx: &Transaction) -> Result<Availability<W::Prepared>, String> {
        self.enqueue(tx, Priority::Speculative)
    }
    fn restart(&self, tx: &Transaction, priority: Priority) -> Result<(), String> {
        Self::remove(&mut self.state(), &hash(tx)?);
        self.enqueue(tx, priority)?;
        Ok(())
    }
    fn promote(state: &mut State<W::Artifact>, queued: &Arc<Queued>) {
        if state.entries.get(&queued.hash).is_some_and(
            |e| matches!(e,Entry::Queued(q) if q.activated.same_channel(&queued.activated)),
        ) {
            state.entries.insert(
                queued.hash.clone(),
                Entry::Queued(Arc::new(Queued {
                    tx: queued.tx.clone(),
                    hash: queued.hash.clone(),
                    order: queued.order,
                    priority: Priority::Required,
                    activated: queued.activated.clone(),
                })),
            );
        }
    }
    async fn activated(queued: &Queued) -> Result<(), String> {
        let mut channel = queued.activated.subscribe();
        loop {
            if *channel.borrow_and_update() {
                return Ok(());
            }
            channel
                .changed()
                .await
                .map_err(|_| "preverification queue closed".to_owned())?;
        }
    }
    async fn result(job: &Job<W::Artifact>) -> Result<Verification<W::Artifact>, String> {
        let mut channel = job.result.subscribe();
        loop {
            if let Some(result) = channel.borrow_and_update().clone() {
                return result;
            }
            channel
                .changed()
                .await
                .map_err(|_| "preverification job closed".to_owned())?;
        }
    }
    async fn bind(
        &self,
        tx: &Transaction,
        artifact: Arc<W::Artifact>,
    ) -> Result<Binding<W::Prepared>, String> {
        let binding = AssertUnwindSafe(self.0.worker.bind(tx, &artifact))
            .catch_unwind()
            .await
            .map_err(|_| "preverification binding failed".to_owned())??;
        self.check_open()?;
        if let Binding::Invalid(reason) = &binding {
            let mut state = self.state();
            if state.closed {
                return Err("preverification pool closed".into());
            }
            state.entries.insert(
                hash(tx)?,
                Entry::Complete(Complete {
                    artifact,
                    invalid: Some(reason.clone()),
                    time: (self.0.clock)(),
                }),
            );
            self.trim(&mut state);
        }
        Ok(binding)
    }
    pub async fn observe(&self, tx: &Transaction) -> Result<Availability<W::Prepared>, String> {
        self.check_open()?;
        if !self.0.worker.eligible(tx) {
            return Ok(Availability::Unmanaged);
        }
        match self.view(&hash(tx)?)? {
            None => {
                self.admit(tx)?;
                Ok(Availability::Pending)
            }
            Some(Entry::Queued(_) | Entry::Running(_)) => Ok(Availability::Pending),
            Some(Entry::Complete(c)) => match self.bind(tx, c.artifact).await? {
                Binding::Bound(value) => Ok(Availability::Ready(value)),
                Binding::Invalid(reason) => Ok(Availability::Invalid(reason)),
                Binding::SourceChanged => {
                    self.restart(tx, Priority::Speculative)?;
                    Ok(Availability::Pending)
                }
            },
        }
    }
    pub async fn wait(&self, tx: &Transaction) -> Result<Availability<W::Prepared>, String> {
        let mut restarts = 0;
        loop {
            self.check_open()?;
            if !self.0.worker.eligible(tx) {
                return Ok(Availability::Unmanaged);
            }
            let hash = hash(tx)?;
            let binding = match self.view(&hash)? {
                None => {
                    self.enqueue(tx, Priority::Required)?;
                    if self.view(&hash)?.is_none() {
                        return Ok(Availability::Unmanaged);
                    }
                    continue;
                }
                Some(Entry::Queued(q)) => {
                    {
                        let mut state = self.state();
                        Self::promote(&mut state, &q);
                        self.schedule(&mut state);
                    }
                    Self::activated(&q).await?;
                    continue;
                }
                Some(Entry::Complete(c)) => self.bind(tx, c.artifact).await?,
                Some(Entry::Running(job)) => {
                    let result = Self::result(&job).await;
                    self.check_open()?;
                    self.complete(&hash, &job, &result);
                    match result {
                        Err(_) => return Ok(Availability::Unmanaged),
                        Ok(Verification::Stale) => Binding::SourceChanged,
                        Ok(Verification::Ready(a) | Verification::Rejected(a, _)) => {
                            if let Ok(binding) = self.bind(tx, a).await {
                                binding
                            } else {
                                self.check_open()?;
                                return Ok(Availability::Unmanaged);
                            }
                        }
                    }
                }
            };
            match binding {
                Binding::Bound(value) => return Ok(Availability::Ready(value)),
                Binding::Invalid(reason) => return Ok(Availability::Invalid(reason)),
                Binding::SourceChanged if restarts == 0 => {
                    self.restart(tx, Priority::Required)?;
                    restarts += 1;
                }
                Binding::SourceChanged => {
                    Self::remove(&mut self.state(), &hash);
                    return Ok(Availability::Unmanaged);
                }
            }
        }
    }
    pub fn artifact(&self, tx: &Transaction) -> Result<Option<Arc<W::Artifact>>, String> {
        Ok(match self.view(&hash(tx)?)? {
            Some(Entry::Complete(c)) if c.invalid.is_none() => Some(c.artifact),
            _ => None,
        })
    }
    async fn join(&self, tx: &Transaction) -> Result<Option<Arc<W::Artifact>>, String> {
        loop {
            match self.view(&hash(tx)?)? {
                None => return Ok(None),
                Some(Entry::Complete(c)) => return Ok(c.invalid.is_none().then_some(c.artifact)),
                Some(Entry::Queued(q)) => {
                    {
                        let mut state = self.state();
                        Self::promote(&mut state, &q);
                        self.schedule(&mut state);
                    }
                    Self::activated(&q).await?;
                }
                Some(Entry::Running(job)) => {
                    let result = Self::result(&job).await;
                    self.check_open()?;
                    self.complete(&hash(tx)?, &job, &result);
                    return Ok(if let Ok(Verification::Ready(a)) = result {
                        Some(a)
                    } else {
                        None
                    });
                }
            }
        }
    }
    pub async fn collect(
        &self,
        txs: &[Transaction],
    ) -> Result<Vec<(Vec<u8>, Arc<W::Artifact>)>, String> {
        {
            let mut state = self.state();
            if state.closed {
                return Err("preverification pool closed".into());
            }
            for tx in txs {
                if let Some(Entry::Queued(q)) = state.entries.get(&hash(tx)?).cloned() {
                    Self::promote(&mut state, &q);
                }
            }
            self.schedule(&mut state);
        }
        // Join the whole batch before yielding: a later result can leave the
        // bounded cache while an earlier job is still running.
        let results = try_join_all(
            txs.iter()
                .map(|tx| async { Ok::<_, String>(self.join(tx).await?.map(|a| (hash(tx), a))) }),
        )
        .await?;
        results
            .into_iter()
            .flatten()
            .map(|(h, a)| Ok((h?, a)))
            .collect()
    }
    pub fn retain(&self, keep: impl Fn(&[u8]) -> bool) {
        let mut state = self.state();
        let removed: Vec<_> = state
            .entries
            .iter()
            .filter_map(|(hash, entry)| {
                let protected = matches!(entry, Entry::Running(_))
                    || matches!(entry,Entry::Queued(q) if q.priority==Priority::Required);
                (!protected && !keep(hash)).then_some(hash.clone())
            })
            .collect();
        for hash in removed {
            Self::remove(&mut state, &hash);
        }
    }
    pub fn stats(&self) -> Stats {
        let mut stats = Stats::default();
        for entry in self.state().entries.values() {
            match entry {
                Entry::Queued(_) => {
                    stats.pending += 1;
                    stats.queued += 1;
                }
                Entry::Running(_) => {
                    stats.pending += 1;
                    stats.running += 1;
                }
                Entry::Complete(c) if c.invalid.is_none() => stats.ready += 1,
                Entry::Complete(_) => stats.invalid += 1,
            }
        }
        stats
    }
    pub fn shutdown(&self) {
        let mut state = self.state();
        state.closed = true;
        for entry in state.entries.values() {
            match entry {
                Entry::Queued(q) => {
                    q.activated.send_replace(true);
                }
                Entry::Running(j) => {
                    j.result
                        .send_replace(Some(Err("preverification pool closed".into())));
                }
                Entry::Complete(_) => {}
            }
        }
        state.entries.clear();
        for (_, task) in std::mem::take(&mut state.tasks) {
            task.abort();
        }
    }
}
