//! Native local validator duty orchestration. Only committed receipts choose
//! pulses or appeals; proofs come from the operator's durable vote journal.
pub mod control;
pub mod post;
use octra_node_protocol::{
    consensus::hash,
    duty::Proof,
    validator::set_fold::{Config, Receipt},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{oneshot, Notify};

pub const STREAM_CAPACITY: usize = 16;
pub const CONTROL_CAPACITY: usize = 2;
pub const APPEAL_CAPACITY: usize = 32;
const LIFETIME: f64 = 120.;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Accepted,
    Busy,
    Stopped,
}
#[derive(Clone, Debug)]
// Keep native owned command/result records inline without changing their API.
#[allow(clippy::large_enum_variant)]
pub enum Action {
    Pulse,
    Appeal(Proof),
}
pub struct Sample {
    pub epoch: i64,
    pub active: bool,
    pub bonded: Result<bool, String>,
}
pub struct Point {
    pub epoch: i64,
    pub head: Option<i64>,
    pub finalized: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Moved,
    Uncommitted,
    Finalized,
}
impl Refusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Moved => "validator duty epoch changed",
            Self::Uncommitted => "validator duty head is not committed",
            Self::Finalized => "validator duty epoch is already finalized",
        }
    }
}
// Preserve the native owned-input and typed diagnostic interface.
#[allow(clippy::needless_pass_by_value)]
pub fn plan(epoch: i64, point: Point) -> Result<i64, Refusal> {
    if epoch != point.epoch {
        Err(Refusal::Moved)
    } else if epoch <= 0 || point.head != Some(epoch - 1) {
        Err(Refusal::Uncommitted)
    } else if point.finalized {
        Err(Refusal::Finalized)
    } else {
        Ok(epoch - 1)
    }
}
#[derive(Clone, Copy, Debug)]
pub enum Fault {
    Control,
    Receipt,
    Transport,
    Send,
    Internal,
}
impl Fault {
    pub fn event(self) -> &'static str {
        match self {
            Self::Control => "set_actor_control_failed",
            Self::Receipt => "set_actor_read_failed",
            Self::Transport => "set_actor_transport_failed",
            Self::Send => "set_actor_send_failed",
            Self::Internal => "set_actor_internal_failed",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum Stage {
    Available,
    Attempt,
    Marked,
    Expired,
    Unread,
    Capacity,
    Overload,
    Closed,
}
impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Attempt => "attempt",
            Self::Marked => "marked",
            Self::Expired => "expired_unobserved",
            Self::Unread => "receipt_unavailable",
            Self::Capacity => "capacity",
            Self::Overload => "overload",
            Self::Closed => "closed",
        }
    }
}
pub fn proof_key(proof: &Proof) -> Result<String, String> {
    let mut raw = hash::vote_sign_bytes(&proof.vote)
        .map_err(|e| e.to_string())?
        .to_vec();
    raw.extend_from_slice(&proof.vote.signature);
    Ok(hex::encode(Sha256::digest(raw)))
}
#[async_trait::async_trait]
pub trait Host: Send + Sync + 'static {
    fn sample(&self) -> Sample;
    async fn read(&self, epoch: i64) -> Result<Receipt, String>;
    fn peers(&self) -> usize;
    async fn send(&self, epoch: i64, action: Action) -> Result<(), (Fault, String)>;
    fn warn(&self, fault: Fault, reason: &str);
    fn observe(&self, _stage: Stage, _epoch: i64, _proof: &Proof) {}
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub queued: usize,
    pub appeals: usize,
    pub generation: i64,
    pub sent: i64,
}
struct Appeal {
    proof: Proof,
    ready: i64,
    expires: i64,
}
impl Appeal {
    fn new(proof: Proof) -> Self {
        Self {
            ready: proof.vote.epoch_id.wrapping_add(2),
            expires: proof
                .vote
                .epoch_id
                .wrapping_add(Config::default().challenge),
            proof,
        }
    }
}
#[derive(Default)]
struct State {
    appeals: BTreeMap<String, Appeal>,
    last_send: Option<i64>,
    sent: i64,
    sample_error: Option<String>,
}
struct Notice {
    proof: Option<Proof>,
    accepted_at: f64,
    generation: i64,
}
enum Control {
    Stats(oneshot::Sender<Stats>),
}
struct Queues {
    open: bool,
    generation: i64,
    stream: VecDeque<Notice>,
    control: VecDeque<Control>,
    stats: Stats,
}
struct Shared<H: Host> {
    host: Arc<H>,
    queue: Mutex<Queues>,
    ready: Notify,
    ended: Notify,
    closed: std::sync::atomic::AtomicBool,
}
pub struct Actor<H: Host>(Arc<Shared<H>>);
impl<H: Host> Clone for Actor<H> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0., |v| v.as_secs_f64())
}
impl<H: Host> Actor<H> {
    fn report(&self, fault: Fault, reason: &str) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.0.host.warn(fault, reason);
        }));
    }
    fn observe(&self, stage: Stage, epoch: i64, proof: &Proof) {
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.0.host.observe(stage, epoch, proof);
        }))
        .is_err()
        {
            self.report(Fault::Internal, "validator duty observation panicked");
        }
    }
    pub fn new(host: Arc<H>) -> Self {
        let this = Self(Arc::new(Shared {
            host,
            queue: Mutex::new(Queues {
                open: true,
                generation: 0,
                stream: VecDeque::new(),
                control: VecDeque::new(),
                stats: Stats::default(),
            }),
            ready: Notify::new(),
            ended: Notify::new(),
            closed: std::sync::atomic::AtomicBool::new(false),
        }));
        let worker = this.clone();
        tokio::spawn(async move {
            worker.run().await;
        });
        this
    }
    pub fn notify(&self, epoch: i64, proof: Option<Proof>) -> Admission {
        if let Some(proof) = &proof {
            self.observe(Stage::Available, epoch, proof);
        }
        let mut queue = self
            .0
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stage = if !queue.open {
            Some((Stage::Closed, Admission::Stopped))
        } else if proof.is_none()
            && queue
                .stream
                .iter()
                .any(|n| n.proof.is_none() && now() - n.accepted_at <= LIFETIME)
        {
            return Admission::Accepted;
        } else if queue.stream.len() >= STREAM_CAPACITY {
            Some((Stage::Overload, Admission::Busy))
        } else {
            None
        };
        if let Some((stage, admission)) = stage {
            drop(queue);
            if let Some(proof) = &proof {
                self.observe(stage, epoch, proof);
            }
            return admission;
        }
        let generation = queue.generation;
        queue.stream.push_back(Notice {
            proof,
            generation,
            accepted_at: now(),
        });
        drop(queue);
        self.0.ready.notify_one();
        Admission::Accepted
    }
    pub fn wake(&self, head: i64) -> Admission {
        self.notify(head.wrapping_add(1), None)
    }
    pub fn stop(&self) {
        let mut queue = self
            .0
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if queue.open {
            queue.open = false;
            queue.generation = queue.generation.wrapping_add(1);
            queue.stream.clear();
            queue.control.clear();
            queue.stats = Stats {
                generation: queue.generation,
                ..Stats::default()
            };
        }
        drop(queue);
        self.0.ready.notify_one();
    }
    pub async fn stats(&self) -> Stats {
        let (send, receive) = oneshot::channel();
        {
            let mut queue = self
                .0
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !queue.open || queue.control.len() >= CONTROL_CAPACITY {
                return queue.stats;
            }
            queue.control.push_back(Control::Stats(send));
        }
        self.0.ready.notify_one();
        receive.await.unwrap_or_else(|_| {
            self.0
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .stats
        })
    }
    pub async fn shutdown(&self) {
        self.stop();
        loop {
            let ended = self.0.ended.notified();
            if self.0.closed.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            ended.await;
        }
    }
    fn permitted(&self, state: &mut State, sample: &Sample) -> bool {
        let error = sample.bonded.as_ref().err().cloned();
        if error != state.sample_error {
            if let Some(reason) = &error {
                self.report(Fault::Control, reason);
            }
            state.sample_error = error;
        }
        sample.bonded == Ok(true)
    }
    async fn notice(&self, state: &mut State, notice: Notice) -> Result<(), String> {
        let sample = self.0.host.sample();
        let mut before = state
            .appeals
            .iter()
            .map(|(k, a)| (k.clone(), (a.proof.clone(), a.expires)))
            .collect::<BTreeMap<_, _>>();
        if let Some(proof) = notice.proof {
            let key = proof_key(&proof)?;
            let appeal = Appeal::new(proof);
            before.insert(key.clone(), (appeal.proof.clone(), appeal.expires));
            if sample.epoch <= appeal.expires {
                state.appeals.insert(key, appeal);
            }
        }
        state.appeals.retain(|_, a| sample.epoch <= a.expires);
        if state.appeals.len() > APPEAL_CAPACITY {
            if let Some(key) = state
                .appeals
                .iter()
                .min_by(|(lk, l), (rk, r)| l.expires.cmp(&r.expires).then(lk.cmp(rk)))
                .map(|(key, _)| key.clone())
            {
                state.appeals.remove(&key);
            }
        }
        let allowed = self.permitted(state, &sample);
        if !allowed && before.is_empty() {
            return Ok(());
        }
        let receipt = self.0.host.read(sample.epoch).await;
        let current = self.0.host.sample();
        let allowed = self.permitted(state, &current);
        state.appeals.retain(|_, a| {
            current.epoch <= a.expires
                && receipt
                    .as_ref()
                    .map_or(true, |r| !r.marked.contains(&a.proof.vote.epoch_id))
        });
        for (key, (proof, expires)) in before {
            if !state.appeals.contains_key(&key) {
                let stage = if receipt
                    .as_ref()
                    .is_ok_and(|r| r.marked.contains(&proof.vote.epoch_id))
                {
                    Stage::Marked
                } else if current.epoch > expires && receipt.is_ok() && sample.epoch > expires {
                    Stage::Expired
                } else if current.epoch > expires {
                    Stage::Unread
                } else {
                    Stage::Capacity
                };
                self.observe(stage, current.epoch, &proof);
            }
        }
        let receipt = match receipt {
            Ok(v) => v,
            Err(reason) => {
                self.report(Fault::Receipt, &reason);
                return Ok(());
            }
        };
        if current.epoch != sample.epoch || !allowed || state.last_send == Some(current.epoch) {
            return Ok(());
        }
        let action = if current.active {
            state
                .appeals
                .iter()
                .filter(|(_, a)| current.epoch >= a.ready && current.epoch <= a.expires)
                .min_by(|(lk, l), (rk, r)| l.expires.cmp(&r.expires).then(lk.cmp(rk)))
                .map(|(_, a)| Action::Appeal(a.proof.clone()))
        } else {
            let step = (Config::default().pulse_gap / 2).max(1);
            receipt
                .pulse
                .is_none_or(|prior| current.epoch.wrapping_sub(prior) >= step)
                .then_some(Action::Pulse)
        };
        let Some(action) = action else {
            return Ok(());
        };
        if self.0.host.peers() == 0 {
            self.report(
                Fault::Transport,
                "validator set fold transport has no peers",
            );
            return Ok(());
        }
        if let Action::Appeal(proof) = &action {
            self.observe(Stage::Attempt, current.epoch, proof);
        }
        match self.0.host.send(current.epoch, action).await {
            Ok(()) => {
                state.sent = state.sent.wrapping_add(1);
                state.last_send = Some(current.epoch);
            }
            Err((fault, reason)) => self.report(fault, &reason),
        }
        Ok(())
    }
    async fn run(&self) {
        let mut state = State::default();
        loop {
            let notified = self.0.ready.notified();
            let next = {
                let mut queue = self
                    .0
                    .queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !queue.open {
                    queue.stats = Stats {
                        generation: queue.generation,
                        ..Stats::default()
                    };
                    break;
                }
                queue.stats = Stats {
                    queued: queue.stream.len(),
                    appeals: state.appeals.len(),
                    generation: queue.generation,
                    sent: state.sent,
                };
                if let Some(control) = queue.control.pop_front() {
                    match control {
                        Control::Stats(reply) => {
                            let _ = reply.send(queue.stats);
                        }
                    }
                    None
                } else {
                    queue.stream.pop_front().filter(|n| {
                        n.generation == queue.generation && now() - n.accepted_at <= LIFETIME
                    })
                }
            };
            if let Some(notice) = next {
                use futures::FutureExt;
                let work =
                    std::panic::AssertUnwindSafe(self.notice(&mut state, notice)).catch_unwind();
                match work.await {
                    Ok(Ok(())) => (),
                    Ok(Err(reason)) => self.report(Fault::Internal, &reason),
                    Err(_) => self.report(Fault::Internal, "validator duty worker panicked"),
                }
                continue;
            }
            let wait = {
                let q = self
                    .0
                    .queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                q.open && q.stream.is_empty() && q.control.is_empty()
            };
            if wait {
                notified.await;
            }
        }
        self.0
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.0.ended.notify_waiters();
    }
}
