//! Host-owned, cancellable native crypto process service shared by Circle and
//! OCTB. VM registers retain serialized images, never expanded untrusted keys.
//! Embedders explicitly supply the trusted worker executable; this service does
//! not assume that their current executable implements a hidden CLI command.
use crate::single_private::worker::{bounded_read, Watchdog, Worker};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::VecDeque,
    io::{Read, Write},
    marker::PhantomData,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
#[cfg(feature = "test-helpers")]
mod faults;
#[cfg(feature = "test-helpers")]
pub use faults::Fault;
mod image;
pub(crate) mod private;
mod sessions;
pub(crate) mod tasks;
pub use crate::single_private::worker::Limits;
pub use image::{Cipher, Key};
pub(crate) use tasks::{Operation, Request, Response};
const MAX_BYTES: usize = 1024 * 1024 * 1024;
const DOMAIN: &[u8] = b"octra:crypto-worker:v1\0";

/// Reusable process admission. Clones of this service and Single workers can
/// share one `Worker`, including its captured native capacity/RSS policy.
pub struct Pool {
    worker: Arc<Worker>,
    queue: Mutex<Queue>,
    sessions: Arc<Mutex<sessions::Sessions>>,
    reaper: OnceLock<Result<sessions::Reaper, String>>,
}
impl Pool {
    pub fn new(worker: Arc<Worker>) -> Arc<Self> {
        Arc::new(Self {
            worker,
            queue: Mutex::new(Queue::default()),
            sessions: Arc::new(Mutex::new(sessions::Sessions::default())),
            reaper: OnceLock::new(),
        })
    }
    pub fn open(executable: &std::path::Path, limits: Limits) -> Result<Arc<Self>, String> {
        Worker::open(executable, limits).map(Self::new)
    }
    pub fn worker(&self) -> &Arc<Worker> {
        &self.worker
    }
    pub fn scope(self: &Arc<Self>, view: bool, cancelled: Arc<AtomicBool>) -> Scope {
        Scope::enter(self.clone(), view, cancelled)
    }
    /// Admission warmups may use spare proof capacity, never the required lane.
    /// Nested proof scopes inherit this restriction and parent cancellation.
    pub fn speculative_scope(self: &Arc<Self>, cancelled: Arc<AtomicBool>) -> Scope {
        let scope = self.scope(false, cancelled);
        CURRENT.with(|cell| {
            if let Some(context) = cell.borrow_mut().as_mut() {
                context.speculative = true;
            }
        });
        scope
    }
    pub fn scope_until(
        self: &Arc<Self>,
        view: bool,
        cancelled: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Scope {
        let scope = self.scope(view, cancelled);
        CURRENT.with(|cell| {
            if let Some(context) = cell.borrow_mut().as_mut() {
                context.deadline = Some(
                    context
                        .deadline
                        .map_or(deadline, |outer| outer.min(deadline)),
                );
            }
        });
        scope
    }
    /// Explicit synthetic process failure probe, excluded from production builds.
    #[cfg(feature = "test-helpers")]
    pub fn test_fault(&self, fault: Fault) -> Result<u32, String> {
        let context = CURRENT
            .with(|cell| cell.borrow().clone())
            .ok_or("crypto scope missing")?;
        match self.call(Request::Fault(fault), &context) {
            Ok(Response::Fault(pid)) => Ok(pid),
            Err(Error::Unavailable(reason)) => Err(reason),
            _ => Err("worker fault probe refused".into()),
        }
    }
    /// Synthetic proof-lane probe; never enabled in production builds.
    #[cfg(feature = "test-helpers")]
    pub fn test_proof_fault(&self, required: bool, fault: Fault) -> Result<u32, String> {
        let context = CURRENT
            .with(|cell| cell.borrow().clone())
            .ok_or("crypto scope missing")?;
        match self.call(Request::ProofFault { required, fault }, &context) {
            Ok(Response::Fault(pid)) => Ok(pid),
            Err(Error::Unavailable(reason)) => Err(reason),
            _ => Err("worker proof probe refused".into()),
        }
    }
    #[cfg(feature = "test-helpers")]
    pub fn proof_stats(&self) -> crate::compute::Stats {
        self.worker.proofs().stats()
    }
    fn call(&self, request: Request, context: &Context) -> Result<Response, Error> {
        if !std::ptr::eq(self, context.pool.as_ref()) {
            return Err(Error::Unavailable(
                "crypto invocation belongs to another service".into(),
            ));
        }
        if context.is_cancelled()
            || context
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(Error::Unavailable(
                "crypto invocation cancelled or expired".into(),
            ));
        }
        use private::admission::{self, Kind};
        let kind = match admission::kind(&request) {
            Kind::Required if context.speculative => Kind::Speculative,
            kind => kind,
        };
        let result = match kind {
            Kind::Required => self
                .worker
                .proofs()
                .run_sync(crate::compute::Priority::Required, || {
                    self.process(&request, context, self.deadline(context))
                })
                .unwrap_or_else(|| Err(Error::Unavailable("proof queue full".into()))),
            Kind::Speculative => self
                .worker
                .proofs()
                .try_run_sync(crate::compute::Priority::Speculative, || {
                    self.process(&request, context, self.deadline(context))
                })
                .unwrap_or_else(|| Err(Error::Unavailable("proof worker busy".into()))),
            Kind::Fhe => {
                let deadline = self.deadline(context);
                let _admission = self.admit(context, deadline)?;
                self.process(&request, context, deadline)
            }
        };
        // The invocation owns its request, including any zeroizing callback
        // material; release it before returning the detached response.
        drop(request);
        result
    }
    fn deadline(&self, context: &Context) -> Instant {
        // ContractVM allocates a fresh update-worker deadline for each FHE
        // suspension. A view and wasm_keys batch additionally share their
        // outer deadline, so repeated operations cannot extend those bounds.
        context.deadline.unwrap_or_else(|| {
            Instant::now() + Duration::from_secs_f64(self.worker.limits().timeout_seconds)
        })
    }
    fn process(
        &self,
        request: &Request,
        context: &Context,
        deadline: Instant,
    ) -> Result<Response, Error> {
        if context.is_cancelled() || Instant::now() >= deadline {
            return Err(Error::Unavailable(
                "crypto invocation cancelled or expired".into(),
            ));
        }
        let session = matches!(
            request,
            Request::Key { .. } | Request::Cipher { .. } | Request::Calculate { .. }
        );
        #[cfg(feature = "test-helpers")]
        let session = session || matches!(request, Request::Fault(_));
        let body = zeroize::Zeroizing::new(
            serde_json::to_vec(request)
                .map_err(|_| Error::Unavailable("crypto request encoding failed".into()))?,
        );
        if body.len() > MAX_BYTES {
            return Err(Error::Unavailable(
                "crypto request exceeds local transport limit".into(),
            ));
        }
        let digest: [u8; 32] = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&*body)
            .finalize()
            .into();
        let envelope = Envelope {
            digest,
            body: body.to_vec(),
        };
        let bytes = zeroize::Zeroizing::new(
            serde_json::to_vec(&envelope)
                .map_err(|_| Error::Unavailable("crypto envelope encoding failed".into()))?,
        );
        // The base64 envelope is larger than the task. Both
        // sides use the same finite limit, before any child is launched.
        if bytes.len() > MAX_BYTES {
            return Err(Error::Unavailable(
                "crypto request exceeds local transport limit".into(),
            ));
        }
        let output = zeroize::Zeroizing::new(if session {
            self.session_exchange(context.view, &bytes, deadline, || context.is_cancelled())?
        } else {
            self.worker
                .exchange("crypto-worker", &bytes, MAX_BYTES, deadline, || {
                    context.is_cancelled()
                })
                .map_err(|e| Error::Unavailable(e.to_string()))?
        });
        let reply: Reply = if let Ok(reply) = serde_json::from_slice(&output) {
            reply
        } else {
            if session {
                self.retire_session(context.view);
            }
            return Err(Error::Unavailable("crypto response malformed".into()));
        };
        if reply.digest != digest {
            if session {
                self.retire_session(context.view);
            }
            return Err(Error::Unavailable("crypto response binding differs".into()));
        }
        if context.is_cancelled() || Instant::now() >= deadline {
            if session {
                self.retire_session(context.view);
            }
            return Err(Error::Unavailable(
                "crypto invocation cancelled or expired".into(),
            ));
        }
        if session && matches!(&reply.outcome, Err(Error::Unavailable(_))) {
            self.retire_session(context.view);
        }
        reply.outcome
    }
}
// Fhe_queue native scheduling: one active FHE task, eight pending tasks,
// at most two pending views. Updates precede views and abandon an active view;
// the next task starts only after its owned process has been reaped.
#[derive(Default)]
struct Queue {
    next: u64,
    active: Option<Entry>,
    pending: VecDeque<Entry>,
}
struct Entry {
    id: u64,
    view: bool,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}
struct Admission<'a> {
    pool: &'a Pool,
    id: u64,
}
impl Drop for Admission<'_> {
    fn drop(&mut self) {
        let mut queue = self
            .pool
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if queue
            .active
            .as_ref()
            .is_some_and(|entry| entry.id == self.id)
        {
            queue.active = None;
        }
        queue.pending.retain(|entry| entry.id != self.id);
    }
}
impl Pool {
    fn admit(&self, context: &Context, deadline: Instant) -> Result<Admission<'_>, Error> {
        let id = {
            let mut queue = self
                .queue
                .lock()
                .map_err(|_| Error::Unavailable("crypto queue poisoned".into()))?;
            // Native Fhe_queue.delta expires pending work on every Submit,
            // before checking capacity. Do not depend on the old waiter's next
            // polling turn to release its expired slot.
            let now = Instant::now();
            queue
                .pending
                .retain(|entry| entry.deadline > now && !entry.cancelled.load(Ordering::Acquire));
            if let Some(active) = &queue.active {
                if active.deadline <= now {
                    active.cancelled.store(true, Ordering::Release);
                }
            }
            if queue.pending.len() >= 8
                || (context.view && queue.pending.iter().filter(|entry| entry.view).count() >= 2)
            {
                return Err(Error::Unavailable("crypto queue full".into()));
            }
            let id = queue
                .next
                .checked_add(1)
                .ok_or_else(|| Error::Unavailable("crypto queue ticket exhausted".into()))?;
            queue.next = id;
            let entry = Entry {
                id,
                view: context.view,
                cancelled: context.cancelled.clone(),
                deadline,
            };
            if context.view {
                queue.pending.push_back(entry);
            } else {
                if let Some(active) = &queue.active {
                    if active.view {
                        active.cancelled.store(true, Ordering::Release);
                    }
                }
                let index = queue
                    .pending
                    .iter()
                    .position(|entry| entry.view)
                    .unwrap_or(queue.pending.len());
                queue.pending.insert(index, entry);
            }
            id
        };
        let admission = Admission { pool: self, id };
        loop {
            if context.is_cancelled() || Instant::now() >= deadline {
                return Err(Error::Unavailable(
                    "crypto invocation cancelled or expired".into(),
                ));
            }
            {
                let mut queue = self
                    .queue
                    .lock()
                    .map_err(|_| Error::Unavailable("crypto queue poisoned".into()))?;
                if queue.active.is_none()
                    && queue.pending.front().is_some_and(|entry| entry.id == id)
                {
                    queue.active = queue.pending.pop_front();
                    return Ok(admission);
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
#[derive(Clone)]
struct Context {
    pool: Arc<Pool>,
    deadline: Option<Instant>,
    cancelled: Arc<AtomicBool>,
    parents: Vec<Arc<AtomicBool>>,
    active: Arc<AtomicBool>,
    ancestors: Vec<Arc<AtomicBool>>,
    view: bool,
    speculative: bool,
}
impl Context {
    fn is_cancelled(&self) -> bool {
        !self.active.load(Ordering::Acquire)
            || self
                .ancestors
                .iter()
                .any(|flag| !flag.load(Ordering::Acquire))
            || self.cancelled.load(Ordering::Acquire)
            || self.parents.iter().any(|flag| flag.load(Ordering::Acquire))
    }
}
thread_local! { static CURRENT: RefCell<Option<Context>> = const { RefCell::new(None) }; }
/// Synchronous invocation lifetime. The owner of the asynchronous job must set
/// `cancelled` on cancellation, then await/reap its blocking worker. This guard
/// cannot move between threads or extend a nested view/batch deadline.
pub struct Scope {
    previous: Option<Context>,
    active: Arc<AtomicBool>,
    _thread: PhantomData<Rc<()>>,
}
impl Scope {
    pub fn enter(pool: Arc<Pool>, view: bool, cancelled: Arc<AtomicBool>) -> Self {
        let deadline = view.then(|| Instant::now() + Duration::from_secs(10));
        let active = Arc::new(AtomicBool::new(true));
        let mut context = Context {
            pool,
            deadline,
            cancelled,
            parents: vec![],
            active: active.clone(),
            ancestors: vec![],
            view,
            speculative: false,
        };
        let previous = CURRENT.with(|cell| {
            let previous = cell.borrow_mut().take();
            if let Some(outer) = &previous {
                context.deadline = match (context.deadline, outer.deadline) {
                    (Some(inner), Some(outer)) => Some(inner.min(outer)),
                    (inner, outer) => inner.or(outer),
                };
                context.view |= outer.view;
                context.speculative |= outer.speculative;
                // Preserve both parent cancellation and the inner view clock.
                // Neither invocation can detach work owned by the other.
                context.ancestors.clone_from(&outer.ancestors);
                context.ancestors.push(outer.active.clone());
                context.parents.clone_from(&outer.parents);
                if !Arc::ptr_eq(&context.cancelled, &outer.cancelled) {
                    context.parents.push(outer.cancelled.clone());
                }
            }
            *cell.borrow_mut() = Some(context);
            previous
        });
        Self {
            previous,
            active,
            _thread: PhantomData,
        }
    }
    /// Native wasm_keys preparation shares one deadline across all key tasks.
    pub(crate) fn batch() -> Result<Self, Error> {
        CURRENT.with(|cell| {
            let previous = cell.borrow().clone().ok_or_else(|| {
                Error::Unavailable(
                    "crypto process service is not configured for this invocation".into(),
                )
            })?;
            let active = Arc::new(AtomicBool::new(true));
            let mut context = previous.clone();
            context.ancestors.push(previous.active.clone());
            context.active = active.clone();
            let deadline = Instant::now()
                + Duration::from_secs_f64(context.pool.worker.limits().timeout_seconds);
            context.deadline = Some(
                context
                    .deadline
                    .map_or(deadline, |outer| outer.min(deadline)),
            );
            *cell.borrow_mut() = Some(context);
            Ok(Self {
                previous: Some(previous),
                active,
                _thread: PhantomData,
            })
        })
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        CURRENT.with(|cell| {
            let mut current = cell.borrow_mut();
            // Trusted embedders may drop guards out of order. Never restore a
            // stale guard over a newer invocation or resurrect its authority.
            if current
                .as_ref()
                .is_some_and(|context| Arc::ptr_eq(&context.active, &self.active))
            {
                *current = self
                    .previous
                    .take()
                    .filter(|context| context.active.load(Ordering::Acquire));
            }
        });
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum Error {
    Invalid,
    Unavailable(String),
}
pub(crate) fn has_scope() -> bool {
    CURRENT.with(|cell| cell.borrow().is_some())
}
pub(crate) fn call(request: Request) -> Result<Response, Error> {
    let context = CURRENT.with(|cell| cell.borrow().clone()).ok_or_else(|| {
        Error::Unavailable("crypto process service is not configured for this invocation".into())
    })?;
    context.pool.call(request, &context)
}
pub(crate) fn circle(
    pool: &Arc<Pool>,
    input: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    use crate::circle_hfhe::preflight::{self, Step};
    let context = CURRENT
        .with(|cell| cell.borrow().clone())
        .ok_or_else(|| "crypto process service is not configured for this invocation".to_owned())?;
    let result = || -> Result<serde_json::Value, Error> {
        let request = SensitiveJson(input.clone());
        if !matches!(
            input.get("action").and_then(serde_json::Value::as_str),
            Some("verify_zero" | "verify_range" | "verify_bound")
        ) {
            return match pool.call(Request::Circle(request), &context)? {
                Response::Circle(value) => Ok(value),
                _ => Err(Error::Unavailable("crypto response kind differs".into())),
            };
        }
        let parameters = match pool.call(Request::CircleParameters(request), &context)? {
            Response::CircleParameters(Step::Ready(parameters)) => parameters,
            Response::CircleParameters(Step::Final(value)) => return Ok(value),
            _ => {
                return Err(Error::Unavailable(
                    "crypto proof parameters response differs".into(),
                ))
            }
        };
        let _lane =
            preflight::lane().map_err(|_| Error::Unavailable("hfhe verifier busy".into()))?;
        let prepared = match pool.call(Request::CirclePrepare(parameters), &context)? {
            Response::CirclePrepare(Step::Ready(prepared)) => prepared,
            Response::CirclePrepare(Step::Final(value)) => return Ok(value),
            _ => {
                return Err(Error::Unavailable(
                    "crypto proof preflight response differs".into(),
                ))
            }
        };
        match pool.call(Request::CircleVerify(prepared), &context)? {
            Response::Circle(value) => Ok(value),
            _ => Err(Error::Unavailable("crypto proof response differs".into())),
        }
    };
    match result() {
        Ok(value) => Ok(value),
        Err(Error::Unavailable(reason)) => Err(reason),
        Err(Error::Invalid) => Err("crypto proof worker response differs".into()),
    }
}

/// Owned callback request guard. IPC buffers and this clone can contain the
/// scoped secret-key field. This bounds their lifetime; it does not claim to
/// wipe the caller's original Value or every allocator/compiler temporary.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct SensitiveJson(serde_json::Value);
impl std::ops::Deref for SensitiveJson {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        fn wipe(value: &mut serde_json::Value) {
            use zeroize::Zeroize;
            match value {
                serde_json::Value::String(text) => text.zeroize(),
                serde_json::Value::Array(values) => values.iter_mut().for_each(wipe),
                serde_json::Value::Object(values) => values.values_mut().for_each(wipe),
                _ => (),
            }
        }
        wipe(&mut self.0);
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    digest: [u8; 32],
    #[serde(with = "tasks::bytes")]
    body: Vec<u8>,
}
impl Drop for Envelope {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.body.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    digest: [u8; 32],
    outcome: Result<Response, Error>,
}
/// Packaged hidden worker entrypoint: no ledger, wallet, RPC or network opens.
/// The parent owns the child and kills/reaps on every resource failure. The
/// independent watchdog also ends it if the hosting process disappears.
pub fn helper(parent_pid: u32) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .map_err(|e| e.to_string())?;
    let _watchdog = Watchdog::start(parent_pid)?;
    let raw = zeroize::Zeroizing::new(bounded_read(
        std::io::stdin().lock(),
        MAX_BYTES,
        &AtomicBool::new(false),
    )?);
    let output = reply(&raw, &mut tasks::Local::default())?;
    std::io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|e| e.to_string())
}

/// Persistent native FHE calculation session. Frames are private parent/helper
/// messages, bounded before allocation; EOF ends it without retaining a child.
pub fn helper_session(parent_pid: u32) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .map_err(|e| e.to_string())?;
    let _watchdog = Watchdog::start_session(parent_pid)?;
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut local = tasks::Local::default();
    loop {
        let mut header = [0_u8; 8];
        let mut read = 0;
        while read < header.len() {
            match input.read(&mut header[read..]) {
                Ok(0) if read == 0 => return Ok(()),
                Ok(0) => return Err("crypto session frame truncated".into()),
                Ok(n) => read += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
                Err(_) => return Err("crypto session read failed".into()),
            }
        }
        let length = usize::try_from(u64::from_be_bytes(header))
            .map_err(|_| "crypto frame length overflow")?;
        if length == 0 || length > MAX_BYTES {
            return Err("crypto frame exceeds local transport limit".into());
        }
        let mut raw = zeroize::Zeroizing::new(Vec::new());
        raw.try_reserve_exact(length)
            .map_err(|_| "crypto frame memory unavailable")?;
        raw.resize(length, 0);
        input
            .read_exact(&mut raw)
            .map_err(|_| "crypto session frame truncated")?;
        let response = reply(&raw, &mut local)?;
        output
            .write_all(&(response.len() as u64).to_be_bytes())
            .and_then(|()| output.write_all(&response))
            .and_then(|()| output.flush())
            .map_err(|_| "crypto session reply failed")?;
    }
}
fn reply(raw: &[u8], local: &mut tasks::Local) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let envelope: Envelope = serde_json::from_slice(raw).map_err(|_| "crypto request malformed")?;
    let digest: [u8; 32] = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(&envelope.body)
        .finalize()
        .into();
    if digest != envelope.digest {
        return Err("crypto request binding differs".into());
    }
    let request: Request =
        serde_json::from_slice(&envelope.body).map_err(|_| "crypto task malformed")?;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| local.execute(request)))
        .unwrap_or_else(|_| Err(Error::Unavailable("crypto worker exception".into())));
    let output = zeroize::Zeroizing::new(
        serde_json::to_vec(&Reply { digest, outcome })
            .map_err(|_| "crypto response encoding failed")?,
    );
    if output.len() > MAX_BYTES {
        return Err("crypto response exceeds local transport limit".into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
