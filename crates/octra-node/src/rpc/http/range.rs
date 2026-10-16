//! Native four-slot range service, one active read and retained multipart bytes.
use octra_node_protocol::state_sync::{http::RangeQuery, range_part::Encoded};
use octra_node_runtime::canonical::Head;
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, Mutex as AsyncMutex, Notify};

#[derive(Clone, Debug)]
pub(super) enum Error {
    Busy,
    Expired,
    Stopped,
    Changed,
    Missing,
    Invalid(String),
}
impl Error {
    pub(super) fn reason(&self) -> &str {
        match self {
            Self::Busy => "range read busy",
            Self::Expired => "range read expired",
            Self::Stopped => "range read stopped",
            Self::Changed => "range head changed",
            Self::Missing => "range response unavailable",
            Self::Invalid(reason) => reason,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Key {
    pub head: Head,
    pub query: RangeQuery,
}
struct Cache {
    from: i64,
    max: i64,
    encoded: Arc<Encoded>,
    expires: Instant,
}
struct State {
    open: bool,
    next: u64,
    jobs: BTreeMap<u64, Key>,
    cache: Option<Cache>,
}
pub(super) struct Service {
    state: Mutex<State>,
    serial: Arc<AsyncMutex<()>>,
    stop: Notify,
}
pub(super) type Read = Pin<Box<dyn Future<Output = Result<Encoded, Error>> + Send + 'static>>;
impl Default for Service {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                open: true,
                next: 0,
                jobs: BTreeMap::new(),
                cache: None,
            }),
            serial: Arc::new(AsyncMutex::new(())),
            stop: Notify::new(),
        }
    }
}
struct Ticket {
    service: Arc<Service>,
    id: u64,
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if let Ok(mut state) = self.service.state.lock() {
            state.jobs.remove(&self.id);
        }
    }
}
impl Service {
    pub(super) fn shutdown(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.open = false;
            state.cache = None;
        }
        self.stop.notify_waiters();
    }
    fn cached(&self, key: &Key) -> Result<Option<Arc<Encoded>>, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Stopped)?;
        if !state.open {
            return Err(Error::Stopped);
        }
        if state
            .cache
            .as_ref()
            .is_some_and(|c| Instant::now() >= c.expires)
        {
            state.cache = None;
        }
        Ok(state
            .cache
            .as_ref()
            .filter(|c| {
                key.query.part.is_some()
                    && c.from == key.query.from_epoch
                    && c.max == key.query.max_epochs
                    && key
                        .query
                        .hash
                        .as_ref()
                        .is_none_or(|h| Some(h.as_slice()) == c.encoded.digest())
            })
            .map(|c| c.encoded.clone()))
    }
    pub(super) async fn load(
        self: &Arc<Self>,
        key: Key,
        read: impl FnOnce(Arc<AtomicBool>) -> Read + Send + 'static,
    ) -> Result<Vec<u8>, Error> {
        let id = {
            let mut state = self.state.lock().map_err(|_| Error::Stopped)?;
            if !state.open {
                return Err(Error::Stopped);
            }
            if state.jobs.len() >= 4 || state.jobs.values().any(|q| q == &key) {
                return Err(Error::Busy);
            }
            state.next = state.next.checked_add(1).ok_or(Error::Stopped)?;
            let id = state.next;
            state.jobs.insert(id, key.clone());
            id
        };
        let ticket = Ticket {
            service: self.clone(),
            id,
        };
        let service = self.clone();
        let (mut reply, result) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        tokio::spawn(async move {
            let _ticket = ticket;
            let stopped = service.stop.notified();
            tokio::pin!(stopped);
            stopped.as_mut().enable();
            if service.state.lock().map_or(true, |state| !state.open) {
                let _ = reply.send(Err(Error::Stopped));
                return;
            }
            let _guard = tokio::select! {
                guard=service.serial.clone().lock_owned()=>guard,
                ()=reply.closed()=>return,
                ()=tokio::time::sleep_until(deadline)=>{let _=reply.send(Err(Error::Expired));return;},
                ()=&mut stopped=>{let _=reply.send(Err(Error::Stopped));return;},
            };
            if tokio::time::Instant::now() >= deadline {
                let _ = reply.send(Err(Error::Expired));
                return;
            }
            let cached = match service.cached(&key) {
                Ok(value) => value,
                Err(error) => {
                    let _ = reply.send(Err(error));
                    return;
                }
            };
            let encoded = if let Some(cached) = cached {
                cached
            } else {
                let cancelled = Arc::new(AtomicBool::new(false));
                // The owned read retains the active slot through its current
                // physical SQL/worker operation, even after its listener leaves.
                let mut worker = tokio::spawn(read(cancelled.clone()));
                let loaded = tokio::select! {
                    value=&mut worker=>value.unwrap_or(Err(Error::Missing)),
                    ()=reply.closed()=>{cancelled.store(true,Ordering::Release);let _=worker.await;return;},
                    ()=tokio::time::sleep_until(deadline)=>{cancelled.store(true,Ordering::Release);let _=reply.send(Err(Error::Expired));let _=worker.await;return;},
                    ()=&mut stopped=>{cancelled.store(true,Ordering::Release);let _=reply.send(Err(Error::Stopped));let _=worker.await;return;},
                };
                match loaded {
                    Ok(value) => Arc::new(value),
                    Err(error) => {
                        let _ = reply.send(Err(error));
                        return;
                    }
                }
            };
            let rendered = encoded
                .render(key.query.part)
                .map_err(|e| Error::Invalid(e.to_string()));
            if tokio::time::Instant::now() >= deadline {
                let _ = reply.send(Err(Error::Expired));
                return;
            }
            // Failed part selection never replaces the previous native cache.
            match service.state.lock() {
                Ok(mut state) => {
                    if !state.open {
                        let _ = reply.send(Err(Error::Stopped));
                        return;
                    }
                    if rendered.is_ok() && !reply.is_closed() && encoded.digest().is_some() {
                        state.cache = Some(Cache {
                            from: key.query.from_epoch,
                            max: key.query.max_epochs,
                            encoded,
                            expires: Instant::now() + Duration::from_secs(60),
                        });
                    }
                    let _ = reply.send(rendered);
                }
                Err(_) => {
                    let _ = reply.send(Err(Error::Stopped));
                }
            };
        });
        result.await.unwrap_or(Err(Error::Stopped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octra_exex::{Cursor, EpochId, Sequence, StateRoot};
    fn key(from: i64) -> Key {
        Key {
            head: Head {
                cursor: Cursor {
                    sequence: Sequence(1),
                    epoch: EpochId(1),
                    state_root: StateRoot([1; 32]),
                },
                ledger_root: "ledger".into(),
                irmin_commit: "commit".into(),
                parent_commit: None,
                index_root: "index".into(),
                index_hash: None,
                txid_hi: -1,
                date: 1,
                message: vec![],
            },
            query: RangeQuery {
                from_epoch: from,
                max_epochs: 16,
                part: None,
                hash: None,
            },
        }
    }
    #[tokio::test]
    async fn cancelled_listener_does_not_release_physical_slot_or_unbound_queue() {
        let service = Arc::new(Service::default());
        let release = Arc::new(Notify::new());
        let read_release = release.clone();
        let (started, ready) = oneshot::channel();
        let first = tokio::spawn({
            let service = service.clone();
            async move {
                service
                    .load(key(1), move |cancelled| {
                        Box::pin(async move {
                            let _ = started.send(cancelled.clone());
                            read_release.notified().await;
                            assert!(cancelled.load(Ordering::Acquire));
                            Err(Error::Stopped)
                        })
                    })
                    .await
            }
        });
        let cancelled = ready.await.unwrap();
        first.abort();
        let _ = first.await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cancelled.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut queued = vec![];
        for from in 2..=4 {
            queued.push(tokio::spawn({
                let service = service.clone();
                async move {
                    service
                        .load(key(from), move |_| {
                            Box::pin(async {
                                Encoded::encode(b"{}".to_vec())
                                    .map_err(|e| Error::Invalid(e.to_string()))
                            })
                        })
                        .await
                }
            }));
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while service.state.lock().unwrap().jobs.len() != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            service
                .load(key(5), |_| panic!("full queue started work"))
                .await,
            Err(Error::Busy)
        ));
        assert!(matches!(
            service
                .load(key(2), |_| panic!("duplicate started work"))
                .await,
            Err(Error::Busy)
        ));
        release.notify_one();
        for request in queued {
            assert_eq!(request.await.unwrap().unwrap(), b"{}");
        }
    }
    #[tokio::test]
    async fn shutdown_replies_to_active_and_queued_and_never_restarts() {
        let service = Arc::new(Service::default());
        let release = Arc::new(Notify::new());
        let (started, ready) = oneshot::channel();
        let read_release = release.clone();
        let active = tokio::spawn({
            let service = service.clone();
            async move {
                service
                    .load(key(1), move |cancelled| {
                        Box::pin(async move {
                            let _ = started.send(());
                            read_release.notified().await;
                            assert!(cancelled.load(Ordering::Acquire));
                            Err(Error::Stopped)
                        })
                    })
                    .await
            }
        });
        ready.await.unwrap();
        let queued = tokio::spawn({
            let service = service.clone();
            async move {
                service
                    .load(key(2), |_| panic!("stopped queue executed work"))
                    .await
            }
        });
        tokio::task::yield_now().await;
        service.shutdown();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), active)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::Stopped)
        ));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), queued)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::Stopped)
        ));
        assert!(matches!(
            service
                .load(key(3), |_| panic!("closed actor restarted"))
                .await,
            Err(Error::Stopped)
        ));
        release.notify_one();
    }
}
