// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Full-duplex native connection loops with a one-frame outgoing mailbox.
use super::{frame, Action, Connection, Error, Frame, Hello, PeerClass, Verdict};
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch},
};

struct Control {
    closed: AtomicBool,
    close: watch::Sender<bool>,
    validator: AtomicBool,
    received: AtomicU64,
    sent: AtomicU64,
}
/// Clones address one authenticated connection, never a replacement connection.
#[derive(Clone)]
pub struct Peer {
    hello: Arc<Hello>,
    control: Arc<Control>,
    queue: mpsc::Sender<Frame>,
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
    /// Native P2p_conn.send semantics: wait for the single mailbox or closure.
    pub async fn enqueue_wait(&self, frame: Frame) -> bool {
        if !self.is_connected() {
            return false;
        }
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
}
pub struct Driver<S> {
    peer: Peer,
    connection: Option<Connection<S>>,
    queue: Option<mpsc::Receiver<Frame>>,
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
            while let Some(frame) = queue.recv().await {
                frame::write_frame(&mut writer, &frame, connection.timeouts.write_idle).await?;
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
