//! Native migration classifier actor. Public-key classes are cached only within
//! the caller's authenticated chain/root scope; ciphertext classes are fresh.
use crate::{execution, private_account_rpc::Classified, private_key::classify};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot};

const REQUEST_CAPACITY: usize = 4;
const CONTROL_CAPACITY: usize = 2;
const HASH_CAPACITY: usize = 4096;
const ADDRESS_CAPACITY: usize = 1024;
const REQUEST_LIFETIME: f64 = 5.;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    Stopped,
    ReadFailed,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub cache_entries: usize,
    pub queued: usize,
    pub generation: i64,
}
pub struct Query {
    pub scope: Vec<u8>,
    pub address: Vec<u8>,
    pub key_hash: Option<Vec<u8>>,
    pub cipher: Arc<[u8]>,
}
pub type Load = Box<dyn FnOnce() -> Result<Option<Vec<u8>>, execution::Error> + Send + 'static>;
struct Command {
    query: Query,
    load: Load,
    accepted: f64,
    reply: oneshot::Sender<Result<Classified, Error>>,
}
enum Control {
    Stats(oneshot::Sender<Stats>),
    Stop(oneshot::Sender<()>),
}
#[derive(Clone)]
struct Handle {
    requests: mpsc::Sender<Command>,
    control: mpsc::Sender<Control>,
    open: Arc<Mutex<bool>>,
}
#[derive(Clone, Default)]
pub struct Service(Arc<Mutex<Lifecycle>>);
#[derive(Default)]
struct Lifecycle {
    handle: Option<Handle>,
    stopped: bool,
}
#[derive(Clone)]
struct KeyClass {
    kind: classify::Key,
    reason: Vec<u8>,
}
struct Entry {
    class: KeyClass,
    touched: i64,
}
#[derive(Default)]
struct Cache {
    keys: BTreeMap<Vec<u8>, Entry>,
    clock: i64,
}
fn now() -> f64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => value.as_secs_f64(),
        Err(error) => -error.duration().as_secs_f64(),
    }
}
fn key(scope: &[u8], hash: bool, value: &[u8]) -> Vec<u8> {
    let mut key = if hash { b"h:".to_vec() } else { b"a:".to_vec() };
    key.extend_from_slice(scope.len().to_string().as_bytes());
    key.push(b':');
    key.extend_from_slice(scope);
    key.extend_from_slice(value);
    key
}
fn query_key(query: &Query) -> Vec<u8> {
    match &query.key_hash {
        Some(hash) => key(&query.scope, true, hash),
        None => key(&query.scope, false, &query.address),
    }
}
impl Cache {
    fn find(&mut self, key: &[u8]) -> Option<KeyClass> {
        self.clock = self.clock.wrapping_add(1);
        let entry = self.keys.get_mut(key)?;
        entry.touched = self.clock;
        Some(entry.class.clone())
    }
    fn insert(&mut self, key: Vec<u8>, class: KeyClass) {
        self.clock = self.clock.wrapping_add(1);
        self.keys.remove(&key);
        let space = key[0];
        let capacity = if space == b'h' {
            HASH_CAPACITY
        } else {
            ADDRESS_CAPACITY
        };
        if self.keys.keys().filter(|key| key[0] == space).count() >= capacity {
            let oldest = self
                .keys
                .iter()
                .filter(|(key, _)| key[0] == space)
                .min_by(|(left_key, left), (right_key, right)| {
                    left.touched
                        .cmp(&right.touched)
                        .then(left_key.cmp(right_key))
                })
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.keys.remove(&oldest);
            }
        }
        self.keys.insert(
            key,
            Entry {
                class,
                touched: self.clock,
            },
        );
    }
}
struct Loaded {
    status: Classified,
    class: KeyClass,
    hash: Option<Vec<u8>>,
}
fn classify(query: &Query, load: Load, cached: Option<KeyClass>) -> Result<Loaded, Error> {
    let (class, hash, cipher, reason) = if let Some(class) = cached {
        let (cipher, reason) =
            classify::cipher(&query.cipher, true).map_err(|_| Error::ReadFailed)?;
        (class, None, cipher, reason)
    } else {
        let public = load().map_err(|_| Error::ReadFailed)?;
        let hash = public
            .as_ref()
            .map(|raw| hex::encode(Sha256::digest(raw)).into_bytes());
        if let Some(expected) = &query.key_hash {
            if hash.as_ref() != Some(expected) {
                return Err(Error::ReadFailed);
            }
        }
        let (cipher, reason) =
            classify::cipher(&query.cipher, true).map_err(|_| Error::ReadFailed)?;
        let (kind, key_reason) = classify::key(public.as_deref()).map_err(|_| Error::ReadFailed)?;
        (
            KeyClass {
                kind,
                reason: key_reason,
            },
            hash,
            cipher,
            reason,
        )
    };
    Ok(Loaded {
        status: Classified(classify::of_classes(
            cipher,
            reason,
            class.kind,
            class.reason.clone(),
        )),
        class,
        hash,
    })
}
async fn actor(
    mut requests: mpsc::Receiver<Command>,
    mut control: mpsc::Receiver<Control>,
    open: Arc<Mutex<bool>>,
) {
    let mut cache = Cache::default();
    let generation = AtomicI64::new(0);
    enum Next {
        Control(Option<Control>),
        Request(Option<Command>),
    }
    loop {
        let next = tokio::select! {biased;
            command=control.recv()=>Next::Control(command),
            command=requests.recv()=>Next::Request(command),
        };
        match next {
            Next::Control(Some(Control::Stats(reply))) => {
                let _ = reply.send(Stats {
                    cache_entries: cache.keys.len(),
                    queued: requests.len(),
                    generation: generation.load(Ordering::Relaxed),
                });
            }
            Next::Control(Some(Control::Stop(reply))) => {
                // Enqueue and stop/drain share this short gate. A concurrent
                // request cannot slip in after the stopped queue was drained.
                let mut opened = open
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *opened = false;
                generation.fetch_add(1, Ordering::Relaxed);
                cache.keys.clear();
                while let Ok(command) = requests.try_recv() {
                    let _ = command.reply.send(Err(Error::Stopped));
                }
                while let Ok(command) = control.try_recv() {
                    match command {
                        Control::Stats(reply) => {
                            let _ = reply.send(Stats::default());
                        }
                        Control::Stop(reply) => {
                            let _ = reply.send(());
                        }
                    }
                }
                let _ = reply.send(());
                break;
            }
            Next::Request(Some(command)) => {
                if now() - command.accepted > REQUEST_LIFETIME {
                    let _ = command.reply.send(Err(Error::Busy));
                    continue;
                }
                let query_key = query_key(&command.query);
                let cached = cache.find(&query_key);
                let was_cached = cached.is_some();
                let hash_scope = command.query.scope.clone();
                let reply = command.reply;
                let result = tokio::task::spawn_blocking(move || {
                    classify(&command.query, command.load, cached)
                })
                .await;
                let result = match result {
                    Ok(Ok(loaded)) => {
                        if !was_cached {
                            if let Some(hash) = loaded.hash {
                                cache.insert(query_key.clone(), loaded.class.clone());
                                let hash_key = key(&hash_scope, true, &hash);
                                if query_key != hash_key {
                                    cache.insert(hash_key, loaded.class);
                                }
                            }
                        }
                        Ok(loaded.status)
                    }
                    _ => Err(Error::ReadFailed),
                };
                let _ = reply.send(result);
            }
            Next::Control(None) | Next::Request(None) => break,
        }
    }
    *open
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
}
impl Service {
    fn handle(&self) -> Result<Handle, Error> {
        let mut current = self.0.lock().map_err(|_| Error::ReadFailed)?;
        if current.stopped {
            return Err(Error::Busy);
        }
        if let Some(handle) = current.handle.as_ref() {
            return Ok(handle.clone());
        }
        let (requests, request_rx) = mpsc::channel(REQUEST_CAPACITY);
        let (control, control_rx) = mpsc::channel(CONTROL_CAPACITY);
        let open = Arc::new(Mutex::new(true));
        tokio::spawn(actor(request_rx, control_rx, open.clone()));
        let handle = Handle {
            requests,
            control,
            open,
        };
        current.handle = Some(handle.clone());
        Ok(handle)
    }
    pub async fn query(&self, query: Query, load: Load) -> Result<Classified, Error> {
        let handle = self.handle()?;
        let (reply, response) = oneshot::channel();
        {
            let opened = handle.open.lock().map_err(|_| Error::ReadFailed)?;
            if !*opened {
                return Err(Error::Busy);
            }
            handle
                .requests
                .try_send(Command {
                    query,
                    load,
                    accepted: now(),
                    reply,
                })
                .map_err(|_| Error::Busy)?;
        }
        response.await.unwrap_or(Err(Error::ReadFailed))
    }
    pub async fn stats(&self) -> Stats {
        let fallback = Stats {
            queued: REQUEST_CAPACITY,
            ..Stats::default()
        };
        let Ok(handle) = self.handle() else {
            return fallback;
        };
        let (reply, response) = oneshot::channel();
        {
            let Ok(opened) = handle.open.lock() else {
                return fallback;
            };
            if !*opened {
                return fallback;
            }
            if handle.control.try_send(Control::Stats(reply)).is_err() {
                return fallback;
            }
        }
        response.await.unwrap_or_default()
    }
    pub async fn shutdown(&self) {
        let handle = self.0.lock().ok().and_then(|mut current| {
            if current.handle.is_none() {
                current.stopped = true;
            }
            current.handle.clone()
        });
        let Some(handle) = handle else {
            return;
        };
        let (reply, response) = oneshot::channel();
        {
            let Ok(opened) = handle.open.lock() else {
                return;
            };
            if !*opened {
                return;
            }
            if handle.control.try_send(Control::Stop(reply)).is_err() {
                return;
            }
        }
        let _ = response.await;
    }
}
