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
