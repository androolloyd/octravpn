//! Scheduling/ownership controls use integer results, never fake proof authority.
use super::*;
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

fn until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(Instant::now() < deadline, "artifact pool control timed out");
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn blocked(id: u8, entered: mpsc::Sender<(u8, bool)>, release: Arc<AtomicBool>) -> Work<u8> {
    Box::new(move |priority, cancelled| {
        entered.send((id, priority == Priority::Required)).unwrap();
        until(|| release.load(Ordering::Acquire) || cancelled.load(Ordering::Acquire));
        Ok(id)
    })
}

#[test]
fn required_joins_running_work_and_other_lane_progresses_without_pool_lock() {
    let pool = Arc::new(Pool::new(1));
    let (entered, events) = mpsc::channel();
    let release = Arc::new(AtomicBool::new(false));
    pool.offer(vec![1], Lane::Private, blocked(1, entered, release.clone()));
    assert_eq!(
        events.recv_timeout(Duration::from_secs(5)).unwrap(),
        (1, false)
    );
    let waiting = pool.clone();
    let waiter = std::thread::spawn(move || {
        waiting.required(
            vec![1],
            Lane::Private,
            Box::new(|_, _| panic!("running proof repeated")),
        )
    });
    pool.offer(vec![2], Lane::Key, Box::new(|_, _| Ok(2)));
    until(|| pool.completed(&[2]).is_some());
    // Neither retain nor an unrelated head's work retires the running owner.
    pool.retain(|hash| hash == [1] || hash == [2]);
    assert!(!waiter.is_finished());
    release.store(true, Ordering::Release);
    assert_eq!(*waiter.join().unwrap().unwrap().unwrap(), 1);
    let before = pool.completed(&[1]).unwrap();
    for _ in 0..3 {
        pool.retain(|_| true);
        let reused = pool
            .required(
                vec![1],
                Lane::Private,
                Box::new(|_, _| panic!("completed artifact repeated")),
            )
            .unwrap()
            .unwrap();
        assert!(Arc::ptr_eq(&before, &reused));
    }
    pool.shutdown();
}

#[test]
fn required_promotes_queue_and_displaces_only_an_old_speculative_job() {
    let pool = Arc::new(Pool::new(1));
    let (entered, events) = mpsc::channel();
    let release = Arc::new(AtomicBool::new(false));
    pool.offer(
        vec![0],
        Lane::Private,
        blocked(0, entered.clone(), release.clone()),
    );
    assert_eq!(
        events.recv_timeout(Duration::from_secs(5)).unwrap(),
        (0, false)
    );
    for id in 1..=6 {
        pool.offer(
            vec![id],
            Lane::Private,
            blocked(id, entered.clone(), release.clone()),
        );
    }
    pool.offer(
        vec![7],
        Lane::Private,
        Box::new(|_, _| panic!("seventh queued job ran")),
    );
    assert_eq!(pool.inner.state.lock().unwrap().queue.len(), 6);
    let waiting = pool.clone();
    let notify = entered;
    let gate = release.clone();
    let waiter = std::thread::spawn(move || {
        waiting.required(vec![9], Lane::Private, blocked(9, notify, gate))
    });
    until(|| {
        pool.inner
            .state
            .lock()
            .unwrap()
            .queue
            .iter()
            .any(|job| job.hash == [9])
    });
    {
        let state = pool.inner.state.lock().unwrap();
        assert_eq!(state.queue.len(), 6);
        assert!(!state.queue.iter().any(|job| job.hash == [1]));
        assert!(state
            .queue
            .iter()
            .any(|job| job.hash == [9] && job.priority == Priority::Required));
    }
    release.store(true, Ordering::Release);
    assert_eq!(
        events.recv_timeout(Duration::from_secs(5)).unwrap(),
        (9, true)
    );
    assert_eq!(*waiter.join().unwrap().unwrap().unwrap(), 9);
    until(|| {
        let state = pool.inner.state.lock().unwrap();
        state.running.is_empty() && state.queue.is_empty()
    });
    assert_eq!(pool.inner.state.lock().unwrap().complete.len(), 6);
    assert!(pool.completed(&[7]).is_none());
    pool.shutdown();
}

#[test]
fn per_lane_running_limits_and_retention_preserve_protected_required_work() {
    for capacity in [1, 2] {
        let pool = Arc::new(Pool::new(capacity));
        let (entered, events) = mpsc::channel();
        let release = Arc::new(AtomicBool::new(false));
        for (lane, base) in [(Lane::Private, 0_u8), (Lane::Key, 32)] {
            for offset in 0..capacity {
                let id = base + u8::try_from(offset).unwrap();
                pool.offer(
                    vec![id],
                    lane,
                    blocked(id, entered.clone(), release.clone()),
                );
                assert_eq!(
                    events.recv_timeout(Duration::from_secs(5)).unwrap(),
                    (id, false)
                );
            }
        }
        assert_eq!(pool.inner.state.lock().unwrap().running.len(), capacity * 2);
        let waiting = pool.clone();
        let gate = release.clone();
        let notify = entered.clone();
        let waiter = std::thread::spawn(move || {
            waiting.required(vec![99], Lane::Private, blocked(99, notify, gate))
        });
        until(|| {
            pool.inner
                .state
                .lock()
                .unwrap()
                .queue
                .iter()
                .any(|job| job.hash == [99])
        });
        pool.retain(|_| false);
        {
            let state = pool.inner.state.lock().unwrap();
            assert_eq!(state.queue.len(), 1);
            assert_eq!(state.running.len(), capacity * 2);
            assert!(state
                .running
                .values()
                .all(|job| !job.cancelled.load(Ordering::Acquire)));
        }
        release.store(true, Ordering::Release);
        assert_eq!(*waiter.join().unwrap().unwrap().unwrap(), 99);
        pool.shutdown();
    }
}

#[test]
fn failed_or_panicking_jobs_are_not_cached_and_old_completion_cannot_forget_new() {
    let pool = Pool::new(1);
    assert!(pool
        .required(
            vec![1],
            Lane::Private,
            Box::new(|_, _| Err("unavailable".into()))
        )
        .is_err());
    assert!(pool.completed(&[1]).is_none());
    assert!(pool
        .required(
            vec![1],
            Lane::Private,
            Box::new(|_, _| panic!("test worker panic"))
        )
        .is_err());
    assert!(pool.completed(&[1]).is_none());
    let old = pool
        .required(vec![1], Lane::Private, Box::new(|_, _| Ok(1)))
        .unwrap()
        .unwrap();
    pool.forget(&[1], &old);
    let new = pool
        .required(vec![1], Lane::Private, Box::new(|_, _| Ok(2)))
        .unwrap()
        .unwrap();
    pool.forget(&[1], &old);
    assert!(Arc::ptr_eq(&new, &pool.completed(&[1]).unwrap()));
    pool.retain(|_| false);
    assert!(pool.completed(&[1]).is_none());
    pool.shutdown();
}

#[tokio::test]
async fn cancelled_required_waiter_keeps_owned_execution_until_joined_proof_finishes() {
    let pool = Arc::new(Pool::new(1));
    let (entered, events) = mpsc::channel();
    let release = Arc::new(AtomicBool::new(false));
    pool.offer(vec![1], Lane::Private, blocked(1, entered, release.clone()));
    assert_eq!(
        events.recv_timeout(Duration::from_secs(5)).unwrap(),
        (1, false)
    );
    let owner = Arc::new(tokio::sync::Semaphore::new(1));
    let worker_owner = owner.clone();
    let worker_pool = pool.clone();
    let waiter = tokio::spawn(async move {
        super::super::run_worker(worker_owner, move || {
            let artifact = worker_pool
                .required(
                    vec![1],
                    Lane::Private,
                    Box::new(|_, _| panic!("joined work replayed")),
                )
                .map_err(anyhow::Error::msg)?;
            Ok(artifact)
        })
        .await
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while owner.available_permits() != 0 {
        assert!(Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert_eq!(owner.available_permits(), 0);
    release.store(true, Ordering::Release);
    let permit = tokio::time::timeout(Duration::from_secs(5), owner.acquire())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*pool.completed(&[1]).unwrap(), 1);
    drop(permit);
    pool.shutdown();
}

#[test]
fn shutdown_and_last_owner_drop_cancel_join_and_never_dispatch_retired_queue() {
    let pool = Arc::new(Pool::new(1));
    let weak = Arc::downgrade(&pool);
    let (entered, events) = mpsc::channel();
    for (lane, id) in [(Lane::Private, 1), (Lane::Key, 2)] {
        pool.offer(
            vec![id],
            lane,
            blocked(id, entered.clone(), Arc::new(AtomicBool::new(false))),
        );
        assert_eq!(
            events.recv_timeout(Duration::from_secs(5)).unwrap(),
            (id, false)
        );
        pool.offer(
            vec![id + 10],
            lane,
            Box::new(|_, _| panic!("shutdown dispatched queued work")),
        );
    }
    let stopping = pool.clone();
    let joined = std::thread::spawn(move || stopping.shutdown());
    pool.shutdown();
    joined.join().unwrap();
    assert!(pool.inner.state.lock().unwrap().running.is_empty());
    assert!(pool.inner.state.lock().unwrap().queue.is_empty());
    assert!(pool.threads.lock().unwrap().is_empty());
    assert!(pool
        .required(
            vec![9],
            Lane::Private,
            Box::new(|_, _| panic!("closed job ran"))
        )
        .is_err());
    drop(pool);
    assert!(weak.upgrade().is_none());

    // Exercise Drop itself while a real OS worker is still running, rather
    // than relying only on the explicit shutdown path above.
    let pool = Arc::new(Pool::new(1));
    let weak = Arc::downgrade(&pool);
    let (entered, events) = mpsc::channel();
    pool.offer(
        vec![1],
        Lane::Private,
        blocked(1, entered, Arc::new(AtomicBool::new(false))),
    );
    assert_eq!(
        events.recv_timeout(Duration::from_secs(5)).unwrap(),
        (1, false)
    );
    drop(pool);
    assert!(weak.upgrade().is_none());
}
