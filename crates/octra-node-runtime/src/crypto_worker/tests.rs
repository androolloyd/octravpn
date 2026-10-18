use super::*;
fn pool() -> Arc<Pool> {
    // Scope-only tests never execute this image; the path is an explicit local
    // capability rather than an implicit current_exe worker fallback.
    Pool::open(
        &std::env::current_exe().unwrap(),
        Limits {
            capacity: 1,
            timeout_seconds: 600.,
            rss_mb: 9216,
        },
    )
    .unwrap()
}
#[test]
fn nested_views_and_batches_cannot_extend_deadlines_or_detach_either_owner() {
    let pool = pool();
    let parent = Arc::new(AtomicBool::new(false));
    let inner = Arc::new(AtomicBool::new(false));
    let until = Instant::now() + Duration::from_secs(1);
    let outer = pool.scope_until(true, parent.clone(), until);
    let nested = pool.scope(false, inner.clone());
    let current = CURRENT.with(|cell| cell.borrow().clone().unwrap());
    assert!(current.view);
    assert_eq!(current.deadline, Some(until));
    assert!(!current.is_cancelled());
    inner.store(true, Ordering::Release);
    assert!(current.is_cancelled());
    inner.store(false, Ordering::Release);
    parent.store(true, Ordering::Release);
    assert!(current.is_cancelled());
    parent.store(false, Ordering::Release);
    let batch = Scope::batch().unwrap();
    assert_eq!(
        CURRENT.with(|cell| cell.borrow().as_ref().unwrap().deadline),
        Some(until)
    );
    drop(batch);
    drop(outer);
    assert!(
        CURRENT.with(|cell| cell.borrow().as_ref().unwrap().is_cancelled()),
        "out-of-order guard drop invalidates descendants"
    );
    drop(nested);
    assert!(
        !has_scope(),
        "finished scope must not resurrect stale authority"
    );
}

#[test]
fn expired_pending_entries_do_not_consume_native_queue_or_view_capacity() {
    let pool = pool();
    let _scope = pool.scope(true, Arc::new(AtomicBool::new(false)));
    let context = CURRENT.with(|cell| cell.borrow().clone().unwrap());
    let expired = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .unwrap();
    {
        let mut queue = pool.queue.lock().unwrap();
        queue.next = 8;
        for id in 1..=8 {
            queue.pending.push_back(Entry {
                id,
                view: true,
                cancelled: Arc::new(AtomicBool::new(false)),
                deadline: expired,
            });
        }
    }
    let admission = pool
        .admit(&context, Instant::now() + Duration::from_secs(10))
        .unwrap();
    let queue = pool.queue.lock().unwrap();
    assert!(queue.pending.is_empty());
    assert_eq!(queue.active.as_ref().unwrap().id, 9);
    drop(queue);
    drop(admission);
}

#[test]
fn speculative_scope_inherits_nested_deadline_cancellation_and_restores_required_context() {
    let pool = pool();
    let normal = pool.scope(false, Arc::new(AtomicBool::new(false)));
    assert!(!CURRENT.with(|cell| cell.borrow().as_ref().unwrap().speculative));
    let cancel = Arc::new(AtomicBool::new(false));
    let speculative = pool.speculative_scope(cancel.clone());
    let inner_cancel = Arc::new(AtomicBool::new(false));
    let until = Instant::now() + Duration::from_secs(1);
    let inner = pool.scope_until(false, inner_cancel.clone(), until);
    let context = CURRENT.with(|cell| cell.borrow().clone().unwrap());
    assert!(context.speculative);
    assert_eq!(context.deadline, Some(until));
    assert!(!context.is_cancelled());
    cancel.store(true, Ordering::Release);
    assert!(context.is_cancelled());
    cancel.store(false, Ordering::Release);
    inner_cancel.store(true, Ordering::Release);
    assert!(context.is_cancelled());
    drop(inner);
    drop(speculative);
    assert!(!CURRENT.with(|cell| cell.borrow().as_ref().unwrap().speculative));
    assert!(!CURRENT.with(|cell| cell.borrow().as_ref().unwrap().is_cancelled()));
    drop(normal);
    assert!(!has_scope());
}

fn amount() -> Request {
    Request::Private(private::Request::Amount {
        public: private::Key {
            raw: vec![],
            alias: false,
        },
        amount: "1".into(),
        cipher: vec![],
        proof: vec![],
        commitment: vec![],
        blinding: vec![],
        strict: true,
        math: true,
    })
}

#[test]
fn nested_warmup_request_uses_speculative_busy_instead_of_waiting_for_required_capacity() {
    use crate::compute::Priority;
    use std::{sync::mpsc, thread};
    let pool = pool();
    let occupied = pool
        .worker
        .proofs()
        .acquire_sync(Priority::Required, true)
        .unwrap();
    assert_eq!(pool.worker.proofs().stats().active, 1);
    let cancelled = Arc::new(AtomicBool::new(false));
    let (send, receive) = mpsc::channel();
    let job = {
        let pool = pool.clone();
        let cancelled = cancelled.clone();
        thread::spawn(move || {
            let _speculative = pool.speculative_scope(cancelled);
            // This is the normal nested scope installed by Native::prove.
            let _proof = pool.scope(false, Arc::new(AtomicBool::new(false)));
            let context = CURRENT.with(|cell| cell.borrow().clone().unwrap());
            send.send(pool.call(amount(), &context)).unwrap();
        })
    };
    let early = receive.recv_timeout(Duration::from_secs(3));
    let waiting = pool.worker.proofs().stats().required_waiting;
    // If the classification regresses, cancel before releasing the permit so
    // even that failing path cannot execute this unit-test image as a helper.
    cancelled.store(true, Ordering::Release);
    drop(occupied);
    job.join().unwrap();
    assert_eq!(waiting, 0);
    assert!(
        matches!(early.unwrap(), Err(Error::Unavailable(reason)) if reason == "proof worker busy")
    );
    assert_eq!(pool.worker.proofs().stats().active, 0);
}

#[test]
fn cancelled_speculative_parent_refuses_before_admission_and_cannot_be_detached() {
    let pool = pool();
    let cancelled = Arc::new(AtomicBool::new(false));
    let outer = pool.speculative_scope(cancelled.clone());
    let inner = pool.scope(false, Arc::new(AtomicBool::new(false)));
    let context = CURRENT.with(|cell| cell.borrow().clone().unwrap());
    cancelled.store(true, Ordering::Release);
    assert!(
        matches!(pool.call(amount(), &context), Err(Error::Unavailable(reason)) if reason == "crypto invocation cancelled or expired")
    );
    assert_eq!(pool.worker.proofs().stats().active, 0);
    assert_eq!(pool.worker.proofs().stats().required_waiting, 0);
    drop(outer);
    assert!(CURRENT.with(|cell| cell.borrow().as_ref().unwrap().is_cancelled()));
    drop(inner);
    assert!(!has_scope());
}
