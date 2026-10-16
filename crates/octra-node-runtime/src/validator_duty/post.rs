//! One native duty delivery slot with retry, retention and generation guards.
use octra_node_protocol::{
    native_json::{Document, Value},
    transaction::Transaction,
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{watch, Notify},
    task::JoinSet,
};
pub const PERIOD: f64 = 30.;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    Retry(String),
    Wait(String),
    Refused(String),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eligibility {
    Eligible,
    Paused,
    Expired,
}
pub fn http_failure(status: u16) -> Failure {
    let reason = format!("validator duty RPC returned HTTP {status}");
    if matches!(status, 408 | 429 | 500..=599) {
        Failure::Retry(reason)
    } else {
        Failure::Refused(reason)
    }
}
pub fn rpc_failure(doc: &Document, error: &Value) -> Failure {
    let reason = format!(
        "validator duty RPC refused transaction: {}",
        String::from_utf8_lossy(&doc.write(error, false).unwrap_or_else(|_| b"null".to_vec()))
    );
    let code = match doc.field(error, b"code") {
        Some(Value::Int(n)) => Some(n.get()),
        _ => None,
    };
    let data = match doc.field(error, b"data") {
        Some(Value::String(v)) => Some(v.as_slice()),
        _ => None,
    };
    match (code, data) {
        (Some(104 | 107 | 110 | 113 | 118 | -32005), _) => Failure::Retry(reason),
        (Some(100 | 103 | 106), _)
        | (Some(105), Some(b"duplicate nonce (fee rate bump < 10%)")) => Failure::Wait(reason),
        (Some(105), Some(raw))
            if [b"pre_verify_busy".as_slice(), b"pre_verify_unavailable"]
                .iter()
                .any(|prefix| {
                    raw == *prefix
                        || raw
                            .strip_prefix(*prefix)
                            .is_some_and(|suffix| suffix.starts_with(b" "))
                }) =>
        {
            Failure::Retry(reason)
        }
        _ => Failure::Refused(reason),
    }
}
#[async_trait::async_trait]
pub trait Host: Send + Sync + 'static {
    fn staged(&self, hash: &[u8]) -> bool;
    fn landed(&self, tx: &Transaction) -> bool;
    fn eligible(&self, tx: &Transaction, bonded_epoch: Option<i64>) -> Eligibility;
    async fn post(
        &self,
        tx: Transaction,
        bonded_epoch: Option<i64>,
        current: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<(), Failure>;
    fn warn(&self, reason: &str);
}
#[derive(Clone)]
pub struct Retry {
    pub bonded_epoch: i64,
    pub retain: bool,
}
#[derive(Clone)]
struct Item {
    hash: Vec<u8>,
    tx: Transaction,
    attempts: u8,
    retry: Option<Retry>,
    rejected: bool,
    generation: i64,
}
struct State {
    item: Option<Item>,
    due: f64,
    busy: bool,
    open: bool,
    generation: i64,
}
struct Shared<H: Host> {
    host: Arc<H>,
    state: Mutex<State>,
    ready: Notify,
    ended: watch::Receiver<bool>,
    finished: watch::Sender<bool>,
}
pub struct Post<H: Host>(Arc<Shared<H>>);
impl<H: Host> Clone for Post<H> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0., |v| v.as_secs_f64())
}
fn retained(item: &Item) -> bool {
    item.retry.as_ref().is_some_and(|r| r.retain)
}
impl<H: Host> Post<H> {
    pub fn new(host: Arc<H>) -> Self {
        let (finished, ended) = watch::channel(false);
        let this = Self(Arc::new(Shared {
            host,
            state: Mutex::new(State {
                item: None,
                due: 0.,
                busy: false,
                open: true,
                generation: 0,
            }),
            ready: Notify::new(),
            ended,
            finished,
        }));
        let worker = this.clone();
        tokio::spawn(async move {
            worker.run().await;
        });
        this
    }
    fn eligibility(&self, item: &Item) -> Eligibility {
        if self.0.host.landed(&item.tx) || !retained(item) && !self.0.host.staged(&item.hash) {
            Eligibility::Expired
        } else {
            self.0
                .host
                .eligible(&item.tx, item.retry.as_ref().map(|r| r.bonded_epoch))
        }
    }
    pub fn pending(&self) -> bool {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state
            .item
            .as_ref()
            .is_some_and(|item| self.eligibility(item) == Eligibility::Expired)
        {
            state.item = None;
            state.due = 0.;
            self.0.ready.notify_one();
        }
        state.busy || state.item.is_some()
    }
    pub fn put(&self, hash: Vec<u8>, tx: Transaction, retry: Option<Retry>) {
        let _ = self.pending();
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.open {
            return;
        }
        if !state
            .item
            .as_ref()
            .is_some_and(|item| item.hash == hash || retained(item))
        {
            state.generation = state.generation.wrapping_add(1);
            state.item = Some(Item {
                hash,
                tx,
                attempts: 0,
                retry,
                rejected: false,
                generation: state.generation,
            });
            state.due = now();
        }
        drop(state);
        self.tick();
    }
    pub fn tick(&self) {
        self.0.ready.notify_one();
    }
    pub fn stop(&self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.open = false;
        state.item = None;
        state.due = 0.;
        drop(state);
        self.tick();
    }
    pub async fn shutdown(&self) {
        self.stop();
        let mut ended = self.0.ended.clone();
        let _ = ended.wait_for(|v| *v).await;
    }
    fn complete(&self, item: &Item, result: Result<(), Failure>) {
        let mut warning = None;
        {
            let mut state = self
                .0
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.busy = false;
            if let Some(current) = state
                .item
                .as_ref()
                .filter(|v| v.generation == item.generation)
                .cloned()
            {
                if self.eligibility(&current) == Eligibility::Expired {
                    state.item = None;
                    state.due = 0.;
                } else {
                    match result {
                        Ok(()) if retained(&current) => state.due = now() + PERIOD,
                        Ok(()) => {
                            state.item = None;
                            state.due = 0.;
                        }
                        Err(Failure::Refused(reason)) => {
                            warning = Some(reason);
                            if retained(&current) {
                                state.item.as_mut().expect("current delivery").rejected = true;
                                state.due = now() + PERIOD;
                            } else {
                                state.item = None;
                                state.due = 0.;
                            }
                        }
                        Err(Failure::Wait(reason)) => {
                            warning = Some(reason);
                            state.item.as_mut().expect("current delivery").attempts = 3;
                            state.due = now() + PERIOD;
                        }
                        Err(Failure::Retry(reason)) => warning = Some(reason),
                    }
                }
            }
        }
        if let Some(reason) = warning {
            self.0.host.warn(&reason);
        }
    }
    async fn run(&self) {
        let mut jobs = JoinSet::new();
        loop {
            let notified = self.0.ready.notified();
            let (send, delay, open) = {
                let mut state = self
                    .0
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !state.open {
                    (None, None, false)
                } else if state.busy {
                    (None, None, true)
                } else if let Some(item) = state.item.clone() {
                    match self.eligibility(&item) {
                        Eligibility::Expired => {
                            state.item = None;
                            state.due = 0.;
                            (None, None, true)
                        }
                        Eligibility::Paused => {
                            state.due = now() + PERIOD;
                            (None, Some(PERIOD), true)
                        }
                        Eligibility::Eligible if now() < state.due => {
                            (None, Some(state.due - now()), true)
                        }
                        Eligibility::Eligible if item.rejected => {
                            state.due = now() + PERIOD;
                            (None, Some(PERIOD), true)
                        }
                        Eligibility::Eligible => {
                            let attempts = (item.attempts + 1).min(3);
                            state.item.as_mut().expect("current delivery").attempts = attempts;
                            state.busy = true;
                            state.due = now()
                                + match attempts {
                                    1 => 1.,
                                    2 => 2.,
                                    _ => PERIOD,
                                };
                            (Some(item), None, true)
                        }
                    }
                } else {
                    (None, None, true)
                }
            };
            if !open {
                jobs.abort_all();
                while jobs.join_next().await.is_some() {}
                break;
            }
            if let Some(item) = send {
                let shared = self.0.clone();
                let checked = shared.clone();
                let generation = item.generation;
                let current: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
                    let state = checked
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    state.open
                        && state
                            .item
                            .as_ref()
                            .is_some_and(|v| v.generation == generation)
                });
                jobs.spawn(async move {
                    use futures::FutureExt;
                    let result = std::panic::AssertUnwindSafe(shared.host.post(
                        item.tx.clone(),
                        item.retry.as_ref().map(|r| r.bonded_epoch),
                        current,
                    ))
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|_| {
                        Err(Failure::Retry("validator duty delivery panicked".into()))
                    });
                    (item, result)
                });
            }
            tokio::select! {
                () = notified => (),
                result = jobs.join_next(), if !jobs.is_empty() => { match result { Some(Ok((item, result))) => self.complete(&item, result), Some(Err(error)) => { self.0.host.warn(&error.to_string()); self.0.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).busy = false; }, None => () } },
                () = async { if let Some(delay) = delay { tokio::time::sleep(Duration::from_secs_f64(delay.max(0.))).await } else { std::future::pending::<()>().await } } => (),
            }
        }
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .busy = false;
        self.0.finished.send_replace(true);
    }
}
