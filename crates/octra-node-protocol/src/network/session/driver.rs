// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Full-duplex native connection loops with a one-frame outgoing mailbox.
use super::{frame, Action, Connection, Error, Frame, Hello, PeerClass, Verdict};
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot, watch, Notify},
};

struct Control {
    closed: AtomicBool,
    close: watch::Sender<bool>,
    validator: AtomicBool,
    received: AtomicU64,
    sent: AtomicU64,
    writes: Mutex<Writes>,
    changed: Notify,
    batch_gate: tokio::sync::Mutex<()>,
    remote_addr: Mutex<Option<std::net::SocketAddr>>,
}
const TX_LIMIT: usize = 8 * 1024 * 1024;
const WRITE_WAIT: Duration = Duration::from_secs(10);
#[derive(Default)]
struct Writes {
    pending: usize,
    transactions: usize,
    bytes: usize,
    service: bool,
    batches: usize,
}
struct Pending {
    control: Arc<Control>,
    transaction_bytes: Option<usize>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        let mut writes = self.control.writes.lock().expect("peer writes");
        writes.pending -= 1;
        if let Some(bytes) = self.transaction_bytes {
            writes.transactions -= 1;
            writes.bytes -= bytes;
        }
        drop(writes);
        self.control.changed.notify_waiters();
    }
}
struct Outgoing {
    frame: Frame,
    written: Option<oneshot::Sender<()>>,
    _pending: Pending,
    _retained: Option<Box<dyn Send>>,
}
/// Owns the sole optional-service lane through reply construction and writing.
pub struct ServicePermit {
    peer: Peer,
    _service: Service,
}
impl ServicePermit {
    pub async fn send(self, frame: Frame) -> bool {
        self.send_retained(frame, ()).await
    }
    /// Move resource accounting into the writer; cancelling the caller cannot
    /// release an allocation that still occupies the outgoing queue.
    pub async fn send_retained(self, frame: Frame, retained: impl Send + 'static) -> bool {
        let Some(pending) = self.peer.pending(None) else {
            return false;
        };
        let (sent, written) = oneshot::channel();
        self.peer
            .queue(Outgoing {
                frame,
                written: Some(sent),
                _pending: pending,
                _retained: Some(Box::new(retained)),
            })
            .await
            && self.peer.written(written).await
    }
}
struct Service(Arc<Control>);
impl Drop for Service {
    fn drop(&mut self) {
        self.0.writes.lock().expect("peer writes").service = false;
        self.0.changed.notify_waiters();
    }
}
struct Batch(Arc<Control>);
impl Drop for Batch {
    fn drop(&mut self) {
        self.0.writes.lock().expect("peer writes").batches -= 1;
    }
}
/// Clones address one authenticated connection, never a replacement connection.
#[derive(Clone)]
pub struct Peer {
    hello: Arc<Hello>,
    control: Arc<Control>,
    queue: mpsc::Sender<Outgoing>,
}
impl Peer {
    pub fn hello(&self) -> &Hello {
        &self.hello
    }
    pub fn is_connected(&self) -> bool {
        !self.control.closed.load(Ordering::Acquire)
    }
    pub fn close(&self) {
        self.control.closed.store(true, Ordering::Release);
        self.control.close.send_replace(true);
    }
    /// Role changes come only from the host's authenticated validator registry.
    pub fn set_peer_class(&self, class: PeerClass) {
        self.control
            .validator
            .store(class == PeerClass::Validator, Ordering::Release);
    }
    pub fn peer_class(&self) -> PeerClass {
        if self.control.validator.load(Ordering::Acquire) {
            PeerClass::Validator
        } else {
            PeerClass::Observer
        }
    }
    pub fn message_counts(&self) -> (u64, u64) {
        (
            self.control.received.load(Ordering::Relaxed),
            self.control.sent.load(Ordering::Relaxed),
        )
    }
    /// Reports queue acceptance, not remote delivery. Cancellation discards only
    /// this not-yet-enqueued frame and does not interrupt a frame being written.
    pub async fn enqueue(&self, frame: Frame, deadline: Duration) -> bool {
        tokio::time::timeout(deadline, self.enqueue_wait(frame))
            .await
            .unwrap_or(false)
    }
    fn pending(&self, transaction_bytes: Option<usize>) -> Option<Pending> {
        if !self.is_connected() {
            return None;
        }
        let mut writes = self.control.writes.lock().expect("peer writes");
        if let Some(bytes) = transaction_bytes {
            if writes.transactions >= 64 || bytes > TX_LIMIT - writes.bytes {
                return None;
            }
            writes.transactions += 1;
            writes.bytes += bytes;
        }
        writes.pending += 1;
        Some(Pending {
            control: self.control.clone(),
            transaction_bytes,
        })
    }
    async fn queue(&self, frame: Outgoing) -> bool {
        let mut close = self.control.close.subscribe();
        if *close.borrow_and_update() {
            return false;
        }
        tokio::select! {
            biased;
            _ = close.changed() => false,
            result = self.queue.send(frame) => result.is_ok(),
        }
    }
    /// Native P2p_conn.send semantics: wait for the single mailbox or closure.
    pub async fn enqueue_wait(&self, frame: Frame) -> bool {
        let Some(pending) = self.pending(None) else {
            return false;
        };
        self.queue(Outgoing {
            frame,
            written: None,
            _pending: pending,
            _retained: None,
        })
        .await
    }
    async fn idle(&self, transactions_only: bool) -> bool {
        let mut close = self.control.close.subscribe();
        loop {
            let changed = self.control.changed.notified();
            // Register before inspecting the state to avoid a lost completion.
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self.is_connected() || *close.borrow_and_update() {
                return false;
            }
            let ready = {
                let writes = self.control.writes.lock().expect("peer writes");
                if transactions_only {
                    writes.transactions == 0
                } else {
                    writes.pending == 0
                }
            };
            if ready {
                return true;
            }
            tokio::select! { () = changed => {}, _ = close.changed() => return false }
        }
    }
    async fn written(&self, written: oneshot::Receiver<()>) -> bool {
        let mut close = self.control.close.subscribe();
        if *close.borrow_and_update() {
            return false;
        }
        tokio::select! { biased; _ = close.changed() => false, result = written => result.is_ok() }
    }
    pub fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        *self.control.remote_addr.lock().expect("peer address")
    }
    pub(crate) fn set_remote_addr(&self, address: Option<std::net::SocketAddr>) {
        *self.control.remote_addr.lock().expect("peer address") = address;
    }
    /// Reserve before preparing a reply; cancellation always releases the lane.
    pub async fn service(&self) -> Option<ServicePermit> {
        {
            let mut writes = self.control.writes.lock().expect("peer writes");
            if writes.service || !self.is_connected() {
                return None;
            }
            writes.service = true;
        }
        let service = Service(self.control.clone());
        if !tokio::time::timeout(WRITE_WAIT, self.idle(false))
            .await
            .unwrap_or(false)
        {
            return None;
        }
        Some(ServicePermit {
            peer: self.clone(),
            _service: service,
        })
    }
    pub async fn send_service(&self, frame: Frame) -> bool {
        match self.service().await {
            Some(permit) => permit.send(frame).await,
            None => false,
        }
    }
    /// Retain bounded transaction bytes until the writer finishes, even if the
    /// requesting task is cancelled after enqueueing.
    pub async fn send_tx(&self, frame: Frame) -> bool {
        let Some(pending) = self.pending(Some(frame.payload.len())) else {
            return false;
        };
        self.write_tx(frame, pending).await
    }
    /// Reserve before detaching: stalled peers cannot create unbounded jobs or
    /// hold the shared transaction admission loop behind their socket writer.
    pub fn queue_tx(&self, frame: Frame) -> bool {
        let Some(pending) = self.pending(Some(frame.payload.len())) else {
            return false;
        };
        let peer = self.clone();
        tokio::spawn(async move {
            peer.write_tx(frame, pending).await;
        });
        true
    }
    async fn write_tx(&self, frame: Frame, pending: Pending) -> bool {
        let (sent, written) = oneshot::channel();
        let outgoing = Outgoing {
            frame,
            written: Some(sent),
            _pending: pending,
            _retained: None,
        };
        tokio::time::timeout(WRITE_WAIT, self.queue(outgoing))
            .await
            .unwrap_or(false)
            && self.written(written).await
    }
    fn reserve_batch(&self, count: usize) -> Option<Batch> {
        let mut writes = self.control.writes.lock().expect("peer writes");
        if !self.is_connected() || writes.batches >= 4 || count > 64 {
            return None;
        }
        writes.batches += 1;
        Some(Batch(self.control.clone()))
    }
    /// Build each payload only after the preceding transaction writes drain.
    pub async fn send_batch<F>(&self, message: u8, builders: Vec<F>)
    where
        F: FnOnce() -> Option<Vec<u8>>,
    {
        let Some(batch) = self.reserve_batch(builders.len()) else {
            return;
        };
        self.write_batch(message, builders, batch).await;
    }
    /// Bounded asynchronous lazy service, matching native transaction gossip.
    pub fn queue_batch<F>(&self, message: u8, builders: Vec<F>) -> bool
    where
        F: FnOnce() -> Option<Vec<u8>> + Send + 'static,
    {
        let Some(batch) = self.reserve_batch(builders.len()) else {
            return false;
        };
        let peer = self.clone();
        tokio::spawn(async move {
            peer.write_batch(message, builders, batch).await;
        });
        true
    }
    async fn write_batch<F>(&self, message: u8, builders: Vec<F>, _batch: Batch)
    where
        F: FnOnce() -> Option<Vec<u8>>,
    {
        let mut close = self.control.close.subscribe();
        if *close.borrow_and_update() {
            return;
        }
        let _gate = tokio::select! {
            biased;
            _ = close.changed() => return,
            gate = self.control.batch_gate.lock() => gate,
        };
        for build in builders {
            if !tokio::time::timeout(WRITE_WAIT, self.idle(true))
                .await
                .unwrap_or(false)
            {
                return;
            }
            if let Some(payload) = build() {
                if !self.send_tx(Frame { message, payload }).await {
                    return;
                }
            }
        }
    }
}
pub struct Driver<S> {
    peer: Peer,
    connection: Option<Connection<S>>,
    queue: Option<mpsc::Receiver<Outgoing>>,
    close: watch::Receiver<bool>,
}
pub(super) fn create<S>(connection: Connection<S>) -> Result<(Peer, Driver<S>), Error> {
    if connection.closed {
        return Err("connection_closed".into());
    }
    let (queue, receiver) = mpsc::channel(1);
    let (close, closed) = watch::channel(false);
    let peer = Peer {
        hello: Arc::new(connection.peer.clone()),
        control: Arc::new(Control {
            closed: AtomicBool::new(false),
            close,
            validator: AtomicBool::new(connection.budget.peer_class() == PeerClass::Validator),
            received: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            writes: Mutex::new(Writes::default()),
            changed: Notify::new(),
            batch_gate: tokio::sync::Mutex::new(()),
            remote_addr: Mutex::new(None),
        }),
        queue,
    };
    Ok((
        peer.clone(),
        Driver {
            peer,
            connection: Some(connection),
            queue: Some(receiver),
            close: closed,
        },
    ))
}
impl<S> Drop for Driver<S> {
    fn drop(&mut self) {
        self.peer.close();
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> Driver<S> {
    /// Runs until closed, failed, or cancelled. Each inbound callback completes
    /// before the next frame is read; the outgoing loop remains independent.
    pub async fn run<F, Fut>(mut self, mut on_message: F) -> Result<(), Error>
    where
        F: FnMut(Peer, Frame) -> Fut,
        Fut: Future<Output = Result<(), Error>>,
    {
        if !self.peer.is_connected() {
            return Ok(());
        }
        let connection = self.connection.take().expect("driver owns connection");
        let mut queue = self.queue.take().expect("driver owns receiver");
        let (mut reader, mut writer) = tokio::io::split(connection.stream);
        let mut budget = connection.budget;
        let peer = &self.peer;
        let read = async {
            loop {
                let frame = frame::read_frame(
                    &mut reader,
                    connection.timeouts.read_idle,
                    frame::MAX_FRAME_SIZE - 1,
                )
                .await?;
                budget.set_peer_class(peer.peer_class());
                match budget.admit(
                    connection.created.elapsed().as_secs_f64(),
                    frame.message,
                    frame.payload.len() as i64,
                ) {
                    Verdict::Accept => {
                        peer.control.received.fetch_add(1, Ordering::Relaxed);
                        on_message(peer.clone(), frame).await?;
                    }
                    Verdict::Drop(r) if r.action == Action::Discard => {}
                    Verdict::Drop(r) => return Err(Error::from(r.reason)),
                }
                tokio::task::yield_now().await;
            }
        };
        let write = async {
            while let Some(mut outgoing) = queue.recv().await {
                frame::write_frame(&mut writer, &outgoing.frame, connection.timeouts.write_idle)
                    .await?;
                if let Some(sent) = outgoing.written.take() {
                    let _ = sent.send(());
                }
                drop(outgoing);
                peer.control.sent.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
            Ok(())
        };
        // Losing loops are dropped together with both stream halves. No read or
        // write future is repeatedly cancelled while the connection stays alive.
        tokio::select! { biased; _=self.close.changed()=>Ok(()), result=read=>result, result=write=>result }
    }
}
