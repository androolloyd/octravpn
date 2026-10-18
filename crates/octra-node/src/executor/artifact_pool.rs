//! Local, tx-hash proof jobs. Receipts and canonical authority never enter here.
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::JoinHandle,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Lane {
    Private,
    Key,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Priority {
    Required,
    Speculative,
}
pub(super) type Work<A> = Box<dyn FnOnce(Priority, Arc<AtomicBool>) -> Result<A, String> + Send>;
struct Job<A> {
    result: Mutex<Option<Result<Arc<A>, String>>>,
    wake: Condvar,
}
impl<A> Job<A> {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            wake: Condvar::new(),
        }
    }
    fn finish(&self, result: Result<Arc<A>, String>) {
        *self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
        self.wake.notify_all();
    }
    fn wait(&self) -> Result<Arc<A>, String> {
        let mut value = self
            .result
            .lock()
            .map_err(|_| "private artifact result poisoned")?;
        loop {
            if let Some(result) = &*value {
                return result.clone();
            }
            value = self
                .wake
                .wait(value)
                .map_err(|_| "private artifact result poisoned")?;
        }
    }
}
struct Queued<A> {
    hash: Vec<u8>,
    lane: Lane,
    priority: Priority,
    ticket: Arc<Job<A>>,
    work: Work<A>,
}
struct Running<A> {
    lane: Lane,
    cancelled: Arc<AtomicBool>,
    ticket: Arc<Job<A>>,
}
struct Completed<A> {
    hash: Vec<u8>,
    lane: Lane,
    artifact: Arc<A>,
}
struct State<A> {
    closed: bool,
    queue: VecDeque<Queued<A>>,
    running: BTreeMap<Vec<u8>, Running<A>>,
    complete: VecDeque<Completed<A>>,
}
impl<A> Default for State<A> {
    fn default() -> Self {
        Self {
            closed: false,
            queue: VecDeque::new(),
            running: BTreeMap::new(),
            complete: VecDeque::new(),
        }
    }
}
struct Inner<A> {
    capacity: usize,
    state: Mutex<State<A>>,
    wake: Condvar,
}
/// Native independent private/KeySwitch lane bounds: six queued and six
/// completed, with captured one/two running jobs per lane. Worker threads own
/// only Inner; their closures must not retain this manager through Native.
pub(super) struct Pool<A> {
    inner: Arc<Inner<A>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    stopping: Mutex<()>,
}
impl<A: Send + Sync + 'static> Pool<A> {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                capacity: capacity.clamp(1, 2),
                state: Mutex::new(State::default()),
                wake: Condvar::new(),
            }),
            threads: Mutex::new(Vec::new()),
            stopping: Mutex::new(()),
        }
    }
    fn enqueue(
        &self,
        hash: Vec<u8>,
        lane: Lane,
        priority: Priority,
        work: Work<A>,
    ) -> Result<Option<Arc<Job<A>>>, String> {
        let mut threads = self
            .threads
            .lock()
            .map_err(|_| "private artifact worker handles poisoned")?;
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "private artifact pool poisoned")?;
        if state.closed {
            return Err("private artifact pool closed".into());
        }
        if let Some(job) = state.running.get(&hash) {
            return Ok(Some(job.ticket.clone()));
        }
        if let Some(job) = state.queue.iter_mut().find(|job| job.hash == hash) {
            if priority == Priority::Required {
                job.priority = priority;
            }
            self.inner.wake.notify_all();
            return Ok(Some(job.ticket.clone()));
        }
        if let Some(done) = state.complete.iter().find(|job| job.hash == hash) {
            let job = Arc::new(Job::new());
            job.finish(Ok(done.artifact.clone()));
            return Ok(Some(job));
        }
        let limit = octra_node_protocol::resource_lanes::PREVERIFY_SPECULATIVE_QUEUE as usize;
        if state.queue.iter().filter(|job| job.lane == lane).count() >= limit {
            if priority == Priority::Speculative {
                return Ok(None);
            }
            let Some(index) = state
                .queue
                .iter()
                .position(|job| job.lane == lane && job.priority == Priority::Speculative)
            else {
                return Ok(None);
            };
            let displaced = state.queue.remove(index).expect("selected speculative job");
            displaced
                .ticket
                .finish(Err("private artifact speculative job displaced".into()));
        }
        while threads.len() < self.inner.capacity * 2 {
            let inner = self.inner.clone();
            let thread = std::thread::Builder::new()
                .name("octra-private-proof".into())
                .spawn(move || run(&inner))
                .map_err(|error| error.to_string())?;
            threads.push(thread);
        }
        let ticket = Arc::new(Job::new());
        state.queue.push_back(Queued {
            hash,
            lane,
            priority,
            ticket: ticket.clone(),
            work,
        });
        self.inner.wake.notify_all();
        Ok(Some(ticket))
    }
    pub(super) fn offer(&self, hash: Vec<u8>, lane: Lane, work: Work<A>) {
        let _ = self.enqueue(hash, lane, Priority::Speculative, work);
    }
    /// Called only inside the existing owned blocking execution worker. The
    /// pool lock is released before joining; cancellation of its async waiter
    /// cannot release that owner, cancel public proof work or publish a result.
    pub(super) fn required(
        &self,
        hash: Vec<u8>,
        lane: Lane,
        work: Work<A>,
    ) -> Result<Option<Arc<A>>, String> {
        self.enqueue(hash, lane, Priority::Required, work)?
            .map(|job| job.wait())
            .transpose()
    }
    pub(super) fn completed(&self, hash: &[u8]) -> Option<Arc<A>> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .complete
            .iter()
            .find(|entry| entry.hash == hash)
            .map(|entry| entry.artifact.clone())
    }
    pub(super) fn closed(&self) -> bool {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed
    }
    /// A stale completion cannot delete a newer attempt for the same hash.
    pub(super) fn forget(&self, hash: &[u8], artifact: &Arc<A>) {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .complete
            .retain(|entry| entry.hash != hash || !Arc::ptr_eq(&entry.artifact, artifact));
    }
    pub(super) fn retain(&self, keep: impl Fn(&[u8]) -> bool) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Required queued jobs and all running jobs are protected owners.
        state.queue.retain(|job| {
            let live = job.priority == Priority::Required || keep(&job.hash);
            if !live {
                job.ticket
                    .finish(Err("private artifact speculative job retired".into()));
            }
            live
        });
        state.complete.retain(|job| keep(&job.hash));
    }
}
impl<A> Pool<A> {
    pub(super) fn shutdown(&self) {
        let _stopping = self
            .stopping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.closed = true;
            for job in state.queue.drain(..) {
                job.ticket
                    .finish(Err("private artifact pool closed".into()));
            }
            state.complete.clear();
            for job in state.running.values() {
                job.cancelled.store(true, Ordering::Release);
            }
            self.inner.wake.notify_all();
        }
        let threads = std::mem::take(
            &mut *self
                .threads
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for thread in threads {
            let _ = thread.join();
        }
    }
}
impl<A> Drop for Pool<A> {
    fn drop(&mut self) {
        self.shutdown();
    }
}
fn run<A: Send + Sync + 'static>(inner: &Inner<A>) {
    loop {
        let (job, cancelled) = {
            let mut state = inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            loop {
                if state.closed {
                    return;
                }
                let eligible = |job: &&Queued<A>| {
                    state
                        .running
                        .values()
                        .filter(|running| running.lane == job.lane)
                        .count()
                        < inner.capacity
                };
                let ready = state
                    .queue
                    .iter()
                    .enumerate()
                    .filter(|(_, job)| eligible(job))
                    .min_by_key(|(index, job)| (job.priority != Priority::Required, *index))
                    .map(|(index, _)| index);
                if let Some(index) = ready {
                    let job = state.queue.remove(index).expect("selected artifact job");
                    let cancelled = Arc::new(AtomicBool::new(false));
                    state.running.insert(
                        job.hash.clone(),
                        Running {
                            lane: job.lane,
                            cancelled: cancelled.clone(),
                            ticket: job.ticket.clone(),
                        },
                    );
                    break (job, cancelled);
                }
                state = inner
                    .wake
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (job.work)(job.priority, cancelled.clone()).map(Arc::new)
        }))
        .unwrap_or_else(|_| Err("private artifact worker panicked".into()));
        let mut state = inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.running.remove(&job.hash);
        if !state.closed && !cancelled.load(Ordering::Acquire) {
            if let Ok(artifact) = &result {
                state.complete.push_back(Completed {
                    hash: job.hash,
                    lane: job.lane,
                    artifact: artifact.clone(),
                });
                let limit =
                    octra_node_protocol::resource_lanes::PREVERIFY_SPECULATIVE_QUEUE as usize;
                while state
                    .complete
                    .iter()
                    .filter(|entry| entry.lane == job.lane)
                    .count()
                    > limit
                {
                    let index = state
                        .complete
                        .iter()
                        .position(|entry| entry.lane == job.lane)
                        .expect("completed lane entry");
                    state.complete.remove(index);
                }
            }
        }
        job.ticket
            .finish(if state.closed || cancelled.load(Ordering::Acquire) {
                Err("private artifact job cancelled".into())
            } else {
                result
            });
        inner.wake.notify_all();
    }
}

#[cfg(test)]
mod tests;
