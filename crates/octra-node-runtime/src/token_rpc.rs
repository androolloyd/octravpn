//! Native token-query actor with bounded queues, deadlines and byte-accounted
//! caches. Each uncached query reads one immutable canonical snapshot.
use crate::{program::store, state_batch::Snapshot};
use octra_node_protocol::{token_rpc as policy, transaction::is_valid_address};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        Arc,
    },
};
use tokio::sync::{mpsc, oneshot};
pub const CACHE_BYTE_LIMIT: usize = 4 * 1024 * 1024;
pub const CACHE_ENTRY_LIMIT: usize = 128;
pub const DATA_CHANNEL_LIMIT: usize = 16;
pub const CONTROL_CHANNEL_LIMIT: usize = 2;
pub fn data_admitted(queued: i64) -> bool {
    queued >= 0 && queued < DATA_CHANNEL_LIMIT as i64
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    Stopped,
    ReadFailed,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub cache_entries: usize,
    pub cache_bytes: usize,
    pub queued: usize,
    pub generation: i64,
}
struct Query {
    holder: Vec<u8>,
    offset: usize,
    limit: usize,
    snapshot: Snapshot,
}
enum Message {
    Query(Query),
    Stats,
    Stop,
}
enum Reply {
    Query(Result<Vec<u8>, Error>),
    Stats(Stats),
    Stop,
}
struct Command {
    generation: i64,
    key: Vec<u8>,
    accepted: f64,
    message: Message,
    reply: oneshot::Sender<Reply>,
}
struct Inner {
    data: mpsc::Sender<Command>,
    control: mpsc::Sender<Command>,
    open: AtomicBool,
    generation: AtomicI64,
}
#[derive(Clone)]
pub struct Actor(Arc<Inner>);
struct Page {
    expires: f64,
    touched: f64,
    bytes: Vec<u8>,
}
struct Metadata {
    expires: f64,
    programs: Vec<policy::Meta>,
    limited: bool,
}
#[derive(Default)]
struct State {
    meta: Option<Metadata>,
    pages: BTreeMap<Vec<u8>, Page>,
    bytes: usize,
}
fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs_f64())
        .unwrap_or_default()
}
fn cache_key(query: &Query) -> Vec<u8> {
    [
        query.holder.as_slice(),
        b":",
        query.offset.to_string().as_bytes(),
        b":",
        query.limit.to_string().as_bytes(),
    ]
    .concat()
}
fn key(generation: i64, message: &Message) -> Vec<u8> {
    let kind = match message {
        Message::Query(q) => cache_key(q),
        Message::Stats => b"stats".to_vec(),
        Message::Stop => b"stop".to_vec(),
    };
    [generation.to_string().as_bytes(), b":", &kind].concat()
}
impl State {
    fn prune(&mut self, time: f64) {
        self.pages.retain(|_, p| p.expires > time);
        self.bytes = self.pages.values().map(|p| p.bytes.len()).sum();
    }
    fn insert(&mut self, time: f64, key: Vec<u8>, bytes: Vec<u8>) {
        self.prune(time);
        if let Some(old) = self.pages.remove(&key) {
            self.bytes = self.bytes.saturating_sub(old.bytes.len());
        }
        if bytes.len() > policy::MAX_PAGE_BYTES || bytes.len() > CACHE_BYTE_LIMIT {
            return;
        }
        while self.pages.len() >= CACHE_ENTRY_LIMIT || self.bytes + bytes.len() > CACHE_BYTE_LIMIT {
            let Some(old) = self
                .pages
                .iter()
                .min_by(|(ka, a), (kb, b)| a.touched.total_cmp(&b.touched).then_with(|| ka.cmp(kb)))
                .map(|(k, _)| k.clone())
            else {
                self.bytes = 0;
                break;
            };
            if let Some(old) = self.pages.remove(&old) {
                self.bytes = self.bytes.saturating_sub(old.bytes.len());
            }
        }
        self.bytes += bytes.len();
        self.pages.insert(
            key,
            Page {
                expires: time + 10.,
                touched: time,
                bytes,
            },
        );
    }
    // Preserve the native owned-input and typed diagnostic interface.
    #[allow(clippy::needless_pass_by_value)]
    fn query(&mut self, query: Query) -> Result<Vec<u8>, Error> {
        let time = now();
        let key = cache_key(&query);
        self.prune(time);
        if let Some(page) = self.pages.get_mut(&key) {
            page.touched = time;
            return Ok(page.bytes.clone());
        }
        if self.meta.as_ref().is_none_or(|m| m.expires <= time) {
            let addresses = query
                .snapshot
                .child_names(&[b"contracts"])
                .collect::<Vec<_>>();
            let limited = addresses.len() > policy::MAX_SCAN_PROGRAMS;
            let mut programs = Vec::new();
            for address in addresses.into_iter().take(policy::MAX_SCAN_PROGRAMS) {
                let read = |name: &[u8]| {
                    query
                        .snapshot
                        .get(&[b"contracts", address, b"storage", name])
                };
                let Some(symbol) = read(b"symbol") else {
                    continue;
                };
                let decimals = read(b"decimals");
                let supply = read(b"total_supply");
                if decimals.is_some_and(|v| v.len() > 2) || supply.is_some_and(|v| v.len() > 39) {
                    continue;
                }
                let owner = store::meta(&query.snapshot, address)
                    .map_err(|_| Error::ReadFailed)?
                    .map(|v| v.owner)
                    .unwrap_or_default();
                if let Some(meta) =
                    policy::Meta::new(address, &owner, symbol, read(b"name"), decimals, supply)
                {
                    programs.push(meta);
                }
            }
            self.meta = Some(Metadata {
                expires: time + 60.,
                programs,
                limited,
            });
        }
        let meta = self.meta.as_ref().ok_or(Error::ReadFailed)?;
        let mut page = policy::Page::new(query.holder.clone(), query.offset, query.limit);
        let name = [b"balances:".as_slice(), &query.holder].concat();
        let mut full = false;
        for token in &meta.programs {
            let Some(balance) =
                query
                    .snapshot
                    .get(&[b"contracts", &token.address, b"storage", &name])
            else {
                continue;
            };
            if let Some(row) = token.row(balance) {
                if matches!(page.add(row), policy::Added::Complete) {
                    full = true;
                    break;
                }
            }
        }
        let payload = page.finish(meta.limited || full);
        self.insert(now(), key, payload.clone());
        Ok(payload)
    }
}
impl Actor {
    pub fn new() -> Self {
        let (data, mut receiver) = mpsc::channel::<Command>(DATA_CHANNEL_LIMIT);
        let (control, mut commands) = mpsc::channel::<Command>(CONTROL_CHANNEL_LIMIT);
        let inner = Arc::new(Inner {
            data,
            control,
            open: AtomicBool::new(true),
            generation: AtomicI64::new(0),
        });
        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move {
            let mut state = State::default();
            loop {
                let command = tokio::select! {biased;value=commands.recv()=>value,value=receiver.recv()=>value};
                let Some(command) = command else { break };
                let Some(inner) = weak.upgrade() else { break };
                if command.generation != inner.generation.load(Ordering::Acquire)
                    || command.key != key(command.generation, &command.message)
                {
                    let _ = command.reply.send(match command.message {
                        Message::Query(_) => Reply::Query(Err(Error::Stopped)),
                        Message::Stats => Reply::Stats(Stats::default()),
                        Message::Stop => Reply::Stop,
                    });
                    continue;
                }
                let result = match command.message {
                    Message::Stop => {
                        inner.open.store(false, Ordering::Release);
                        inner.generation.fetch_add(1, Ordering::AcqRel);
                        drop(state);
                        receiver.close();
                        commands.close();
                        while let Ok(command) = receiver.try_recv() {
                            let _ = command.reply.send(match command.message {
                                Message::Query(_) => Reply::Query(Err(Error::Stopped)),
                                Message::Stats => Reply::Stats(Stats::default()),
                                Message::Stop => Reply::Stop,
                            });
                        }
                        let _ = command.reply.send(Reply::Stop);
                        break;
                    }
                    Message::Stats => Reply::Stats(Stats {
                        cache_entries: state.pages.len(),
                        cache_bytes: state.bytes,
                        queued: receiver.len(),
                        generation: inner.generation.load(Ordering::Acquire),
                    }),
                    Message::Query(query) => {
                        if now() - command.accepted > 5. {
                            Reply::Query(Err(Error::Busy))
                        } else {
                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    state.query(query)
                                }))
                                .unwrap_or(Err(Error::ReadFailed));
                            Reply::Query(result)
                        }
                    }
                };
                let _ = command.reply.send(result);
            }
        });
        Self(inner)
    }
    async fn send(&self, message: Message, control: bool) -> Result<Reply, Error> {
        if !self.0.open.load(Ordering::Acquire) {
            return Err(Error::Busy);
        }
        let generation = self.0.generation.load(Ordering::Acquire);
        let (reply, response) = oneshot::channel();
        let command = Command {
            generation,
            key: key(generation, &message),
            accepted: now(),
            message,
            reply,
        };
        let sender = if control {
            &self.0.control
        } else {
            &self.0.data
        };
        sender.try_send(command).map_err(|_| Error::Busy)?;
        response.await.map_err(|_| Error::Stopped)
    }
    pub async fn query(
        &self,
        snapshot: Snapshot,
        holder: Vec<u8>,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<u8>, Error> {
        if !is_valid_address(&holder)
            || offset < 0
            || offset > policy::MAX_SCAN_PROGRAMS as i64
            || limit <= 0
            || limit > policy::MAX_PAGE_ROWS as i64
        {
            return Err(Error::ReadFailed);
        }
        match self
            .send(
                Message::Query(Query {
                    holder,
                    offset: offset as usize,
                    limit: limit as usize,
                    snapshot,
                }),
                false,
            )
            .await?
        {
            Reply::Query(result) => result,
            _ => Err(Error::ReadFailed),
        }
    }
    pub async fn stats(&self) -> Stats {
        match self.send(Message::Stats, false).await {
            Ok(Reply::Stats(stats)) => stats,
            Err(Error::Busy) => Stats {
                queued: DATA_CHANNEL_LIMIT,
                ..Stats::default()
            },
            _ => Stats::default(),
        }
    }
    pub async fn shutdown(&self) {
        if self.0.open.load(Ordering::Acquire) {
            let _ = self.send(Message::Stop, true).await;
        }
    }
}
impl Default for Actor {
    fn default() -> Self {
        Self::new()
    }
}
