//! Cancellation and reply ownership for the boxed command-response boundary.
use super::respond;
use octra_node_protocol::resource_compute::{Error, Result};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::oneshot;

struct Guard(Arc<AtomicUsize>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn receiver_close_does_not_abandon_owned_command() {
    let (reply, receiver) = oneshot::channel::<Result<u8>>();
    drop(receiver);
    let mut effects = Vec::new();
    respond(reply, async {
        tokio::task::yield_now().await;
        effects.push(17);
        Ok(4)
    })
    .await;
    assert_eq!(effects, [17]);
}

#[tokio::test]
async fn pending_response_cancellation_drops_guard_and_reply_once() {
    let drops = Arc::new(AtomicUsize::new(0));
    let guard = Guard(drops.clone());
    let (reply, mut receiver) = oneshot::channel::<Result<usize>>();
    let (_release, wait) = oneshot::channel::<()>();
    let mut response = Box::pin(respond(reply, async move {
        let _guard = guard;
        let _ = wait.await;
        Ok(7)
    }));
    assert!(futures::poll!(response.as_mut()).is_pending());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    drop(response);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    ));
}

#[tokio::test]
async fn command_panic_preserves_unavailable_reply_and_guard_cleanup() {
    let drops = Arc::new(AtomicUsize::new(0));
    let guard = Guard(drops.clone());
    let (reply, receiver) = oneshot::channel::<Result<()>>();
    respond(reply, async move {
        let _guard = guard;
        panic!("controlled compute command panic");
    })
    .await;
    let Err(Error::Unavailable(reason)) = receiver.await.unwrap() else {
        panic!("command panic must produce Unavailable");
    };
    assert_eq!(reason, b"resource compute actor failed");
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unpolled_response_owns_guard_without_starting_work() {
    let drops = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(AtomicUsize::new(0));
    let guard = Guard(drops.clone());
    let work_started = started.clone();
    let (reply, mut receiver) = oneshot::channel::<Result<()>>();
    let response = respond(reply, async move {
        let _guard = guard;
        work_started.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(response);
    assert_eq!(started.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    ));
}
