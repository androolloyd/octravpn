use super::*;
use octra_node_protocol::transaction::{Nonce, OpType};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

pub(super) fn tx(nonce: i64) -> Transaction {
    Transaction {
        from: b"octFrom".to_vec(),
        to: b"octFrom".to_vec(),
        amount: 0.into(),
        nonce: Nonce::new(nonce).unwrap(),
        ou: 3000.into(),
        timestamp: 1.,
        signature: b"sig".to_vec(),
        public_key: Some(b"pub".to_vec()),
        message: None,
        op_type: OpType::KeySwitch,
        encrypted_data: Some(b"payload".to_vec()),
    }
}
fn ready() -> Checked {
    Checked::Ready(None)
}
fn skipped(kind: Kind) -> Checked {
    Checked::Skip {
        kind,
        reason: b"fixture reason".to_vec(),
    }
}
fn stats<B>(cache: &Cache<B>) -> (usize, usize, usize) {
    let state = cache.0.state.lock().unwrap();
    (state.entries.len(), state.fifo.len(), state.bytes)
}
fn wait_for_join<B>(cache: &Cache<B>) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if cache
            .0
            .state
            .lock()
            .unwrap()
            .entries
            .values()
            .any(|entry| Arc::strong_count(&entry.job) >= 3)
        {
            return;
        }
        assert!(Instant::now() < deadline, "proof waiter did not join");
        thread::yield_now();
    }
}
#[test]
fn root_epoch_purpose_transaction_and_trusted_policy_are_separate() {
    let cache = Cache::new(32, usize::MAX);
    let calls = AtomicUsize::new(0);
    let invoke = |scope: &Scope<u64>, epoch, purpose, tx: &Transaction| {
        cache
            .run(scope, epoch, purpose, tx, || {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(ready())
            })
            .unwrap();
    };
    let original = cache.select(b"root", 1).unwrap();
    invoke(&original, 7, Purpose::Build, &tx(1));
    invoke(
        &cache.select(b"root", 1).unwrap(),
        7,
        Purpose::Build,
        &tx(1),
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    invoke(&original, 7, Purpose::Validate, &tx(1));
    invoke(&original, 8, Purpose::Build, &tx(1));
    invoke(&original, 7, Purpose::Build, &tx(2));
    let policy = cache.select(b"root", 2).unwrap();
    invoke(&policy, 7, Purpose::Build, &tx(1));
    let next = cache.select(b"next", 2).unwrap();
    invoke(&next, 7, Purpose::Build, &tx(1));
    // An old execution may finish, but cannot select the current root back.
    invoke(&original, 7, Purpose::Build, &tx(1));
    invoke(&original, 7, Purpose::Build, &tx(1));
    invoke(&next, 7, Purpose::Build, &tx(1));
    assert_eq!(calls.load(Ordering::Relaxed), 8);
    assert_eq!(stats(&cache).0, 1);
}

#[test]
fn only_ready_and_invalid_results_are_reused() {
    for kind in [
        None,
        Some(Kind::Invalid),
        Some(Kind::Unavailable),
        Some(Kind::Deferred),
    ] {
        let cache = Cache::new(8, usize::MAX);
        let scope = cache.select(b"root", ()).unwrap();
        let mut calls = 0;
        for _ in 0..2 {
            cache
                .run(&scope, 1, Purpose::Build, &tx(1), || {
                    calls += 1;
                    Ok(kind.map_or_else(ready, skipped))
                })
                .unwrap();
        }
        assert_eq!(
            calls,
            if kind.is_none() || kind == Some(Kind::Invalid) {
                1
            } else {
                2
            }
        );
    }
    let cache = Cache::new(8, usize::MAX);
    let scope = cache.select(b"root", ()).unwrap();
    for _ in 0..2 {
        assert!(cache
            .run(&scope, 1, Purpose::Build, &tx(1), || Err(Error(
                "offline".into()
            )))
            .is_err());
    }
    assert_eq!(stats(&cache), (0, 2, 0));
    cache
        .run(&scope, 1, Purpose::Build, &tx(1), || Ok(ready()))
        .unwrap();
    assert_eq!(stats(&cache).0, 1);
}

#[test]
fn fifo_and_bytes_are_bounded_without_refreshing_hits() {
    let cache = Cache::new(2, usize::MAX);
    let scope = cache.select(b"root", ()).unwrap();
    let mut calls = Vec::new();
    for i in [1, 2, 1, 3, 2, 1] {
        cache
            .run(&scope, 1, Purpose::Build, &tx(i), || {
                calls.push(i);
                Ok(ready())
            })
            .unwrap();
    }
    assert_eq!(calls, [1, 2, 3, 1]);
    assert_eq!(stats(&cache).0, 2);
    assert_eq!(stats(&cache).1, 2);
    let bytes = checked_bytes(&tx(1), &Checked::Ready(None)).unwrap();
    let cache = Cache::new(8, bytes);
    let scope = cache.select(b"root", ()).unwrap();
    cache
        .run(&scope, 1, Purpose::Build, &tx(1), || Ok(ready()))
        .unwrap();
    assert_eq!(stats(&cache), (1, 1, bytes));
    cache
        .run(&scope, 1, Purpose::Build, &tx(2), || Ok(ready()))
        .unwrap();
    assert_eq!(stats(&cache), (1, 1, bytes));
    let disabled = Cache::new(0, usize::MAX);
    let scope = disabled.select(b"root", ()).unwrap();
    disabled
        .run(&scope, 1, Purpose::Build, &tx(1), || Ok(ready()))
        .unwrap();
    assert_eq!(stats(&disabled), (0, 0, 0));
}

#[test]
fn concurrent_items_join_one_owner_and_root_change_keeps_new_ticket() {
    let cache = Cache::new(8, usize::MAX);
    let scope = cache.select(b"root", ()).unwrap();
    let (started, begun) = mpsc::sync_channel(0);
    let (release, finish) = mpsc::sync_channel(0);
    let owner = {
        let cache = cache.clone();
        let scope = scope.clone();
        thread::spawn(move || {
            cache.run(&scope, 1, Purpose::Build, &tx(1), || {
                started.send(()).unwrap();
                finish.recv().unwrap();
                Ok(ready())
            })
        })
    };
    begun.recv_timeout(Duration::from_secs(3)).unwrap();
    let waiter = {
        let cache = cache.clone();
        thread::spawn(move || {
            cache.run(&scope, 1, Purpose::Build, &tx(1), || {
                panic!("duplicate proof")
            })
        })
    };
    wait_for_join(&cache);
    // Two root changes restore the same logical item key with a new ticket.
    cache.select(b"other", ()).unwrap();
    let current = cache.select(b"root", ()).unwrap();
    cache
        .run(&current, 1, Purpose::Build, &tx(1), || {
            Ok(skipped(Kind::Invalid))
        })
        .unwrap();
    release.send(()).unwrap();
    assert!(matches!(
        owner.join().unwrap().unwrap(),
        Checked::Ready(None)
    ));
    assert!(matches!(
        waiter.join().unwrap().unwrap(),
        Checked::Ready(None)
    ));
    assert!(matches!(
        cache
            .run(&current, 1, Purpose::Build, &tx(1), || panic!(
                "lost new ticket"
            ))
            .unwrap(),
        Checked::Skip {
            kind: Kind::Invalid,
            ..
        }
    ));
    assert_eq!(stats(&cache).0, 1);
}

#[test]
fn failed_owner_wakes_waiters_and_later_proof_can_retry() {
    let cache = Cache::new(8, usize::MAX);
    let scope = cache.select(b"root", ()).unwrap();
    let (started, begun) = mpsc::sync_channel(0);
    let (release, finish) = mpsc::sync_channel(0);
    let owner = {
        let cache = cache.clone();
        let scope = scope.clone();
        thread::spawn(move || {
            cache.run(&scope, 1, Purpose::Build, &tx(1), || {
                started.send(()).unwrap();
                finish.recv().unwrap();
                panic!("proof worker panicked")
            })
        })
    };
    begun.recv_timeout(Duration::from_secs(3)).unwrap();
    let waiter = {
        let cache = cache.clone();
        let scope = scope.clone();
        thread::spawn(move || {
            cache.run(&scope, 1, Purpose::Build, &tx(1), || {
                panic!("duplicate proof")
            })
        })
    };
    wait_for_join(&cache);
    release.send(()).unwrap();
    assert!(owner.join().is_err());
    assert!(waiter.join().unwrap().is_err());
    assert_eq!(stats(&cache).0, 0);
    cache
        .run(&scope, 1, Purpose::Build, &tx(1), || Ok(ready()))
        .unwrap();
}

#[tokio::test]
async fn abandoning_async_waiter_keeps_protected_blocking_proof_alive() {
    let cache = Cache::new(8, usize::MAX);
    let scope = cache.select(b"root", ()).unwrap();
    let (started, begun) = tokio::sync::oneshot::channel();
    let (release, finish) = mpsc::sync_channel(0);
    let owner = {
        let cache = cache.clone();
        let scope = scope.clone();
        tokio::task::spawn_blocking(move || {
            cache.run(&scope, 1, Purpose::Build, &tx(1), || {
                started.send(()).unwrap();
                finish.recv().unwrap();
                Ok(ready())
            })
        })
    };
    begun.await.unwrap();
    owner.abort();
    let waiter = {
        let cache = cache.clone();
        let scope = scope.clone();
        tokio::task::spawn_blocking(move || {
            cache.run(&scope, 1, Purpose::Build, &tx(1), || {
                panic!("aborted owner was restarted")
            })
        })
    };
    wait_for_join(&cache);
    release.send(()).unwrap();
    assert!(matches!(
        waiter.await.unwrap().unwrap(),
        Checked::Ready(None)
    ));
    let _ = owner.await;
    assert!(matches!(
        cache
            .run(&scope, 1, Purpose::Build, &tx(1), || panic!("result lost"))
            .unwrap(),
        Checked::Ready(None)
    ));
}

#[test]
fn startup_capacity_matches_native_int63_bounds() {
    assert_eq!(configured_capacity(None), 4096);
    for value in [
        b"63".as_slice(),
        b"65537",
        b"garbage",
        b"4611686018427387904",
    ] {
        assert_eq!(configured_capacity(Some(value)), 4096);
    }
    assert_eq!(configured_capacity(Some(b"64")), 64);
    assert_eq!(configured_capacity(Some(b"0x10000")), 65536);
}

mod parity;

#[test]
fn remember_reuses_only_completed_ready_and_invalid_for_the_exact_item() {
    let cache = Cache::new(16, usize::MAX);
    let scope = cache.select(b"root", ()).unwrap();
    assert!(cache
        .remember(&scope, 7, Purpose::Build, &tx(1), ready())
        .unwrap());
    assert!(matches!(
        cache
            .run(&scope, 7, Purpose::Build, &tx(1), || panic!(
                "completed warmup not reused"
            ))
            .unwrap(),
        Checked::Ready(None)
    ));
    for (epoch, purpose, transaction) in [
        (8, Purpose::Build, tx(1)),
        (7, Purpose::Validate, tx(1)),
        (7, Purpose::Build, tx(2)),
    ] {
        let mut calls = 0;
        let result = cache
            .run(&scope, epoch, purpose, &transaction, || {
                calls += 1;
                Ok(skipped(Kind::Invalid))
            })
            .unwrap();
        assert_eq!(calls, 1, "warmup crossed an item binding");
        assert!(matches!(
            result,
            Checked::Skip {
                kind: Kind::Invalid,
                ..
            }
        ));
    }
    assert!(cache
        .remember(&scope, 7, Purpose::Build, &tx(3), skipped(Kind::Invalid))
        .unwrap());
    assert!(matches!(
        cache
            .run(&scope, 7, Purpose::Build, &tx(3), || panic!(
                "completed rejection not reused"
            ))
            .unwrap(),
        Checked::Skip {
            kind: Kind::Invalid,
            ..
        }
    ));
    for kind in [Kind::Unavailable, Kind::Deferred] {
        assert!(!cache
            .remember(&scope, 7, Purpose::Build, &tx(4), skipped(kind))
            .unwrap());
    }
    assert!(cache
        .run(&scope, 7, Purpose::Build, &tx(4), || Ok(ready()))
        .is_ok());
    assert!(!cache
        .remember(&scope, 7, Purpose::Build, &tx(1), skipped(Kind::Invalid))
        .unwrap());
    assert!(matches!(
        cache
            .run(&scope, 7, Purpose::Build, &tx(1), || panic!(
                "late seed replaced completion"
            ))
            .unwrap(),
        Checked::Ready(None)
    ));
}

#[test]
fn remember_rejects_old_scope_even_when_the_same_root_returns() {
    let cache = Cache::new(8, usize::MAX);
    let old = cache.select(b"root", 1).unwrap();
    cache.select(b"other", 1).unwrap();
    let current = cache.select(b"root", 1).unwrap();
    assert!(!cache
        .remember(&old, 1, Purpose::Build, &tx(1), ready())
        .unwrap());
    assert_eq!(stats(&cache), (0, 0, 0));
    assert!(cache
        .remember(&current, 1, Purpose::Build, &tx(1), skipped(Kind::Invalid))
        .unwrap());
    assert!(!cache
        .remember(&old, 1, Purpose::Build, &tx(1), ready())
        .unwrap());
    assert!(matches!(
        cache
            .run(&current, 1, Purpose::Build, &tx(1), || panic!(
                "stale seed replaced current scope"
            ))
            .unwrap(),
        Checked::Skip {
            kind: Kind::Invalid,
            ..
        }
    ));
}

#[test]
fn remember_neither_waits_for_nor_replaces_an_active_required_ticket() {
    let cache = Cache::new(8, usize::MAX);
    let scope = cache.select(b"root", ()).unwrap();
    let (started, begun) = mpsc::channel();
    let (release, finish) = mpsc::channel();
    let owner = {
        let cache = cache.clone();
        let scope = scope.clone();
        thread::spawn(move || {
            cache.run(&scope, 1, Purpose::Build, &tx(1), || {
                started.send(()).unwrap();
                finish.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok(ready())
            })
        })
    };
    begun.recv_timeout(Duration::from_secs(3)).unwrap();
    let key = item_key(
        1,
        Purpose::Build,
        b"root",
        hex::encode(tx(1).hash().unwrap()).as_bytes(),
    );
    let original = cache
        .0
        .state
        .lock()
        .unwrap()
        .entries
        .get(&key)
        .unwrap()
        .job
        .clone();
    assert!(original.pending());
    let (seeded, seed) = mpsc::channel();
    let seeder = {
        let cache = cache.clone();
        let scope = scope.clone();
        thread::spawn(move || {
            let result = cache.remember(&scope, 1, Purpose::Build, &tx(1), skipped(Kind::Invalid));
            seeded.send(result).unwrap();
        })
    };
    // Capture the observation before releasing the real owner, but always
    // release/join before asserting so a failed regression leaves no waiter.
    let early = seed.recv_timeout(Duration::from_secs(3));
    let unchanged = cache.0.state.try_lock().is_ok_and(|state| {
        state
            .entries
            .get(&key)
            .is_some_and(|entry| Arc::ptr_eq(&entry.job, &original))
    });
    let still_pending = original
        .result
        .try_lock()
        .is_ok_and(|result| result.is_none());
    release.send(()).unwrap();
    seeder.join().unwrap();
    let result = owner.join().unwrap().unwrap();
    assert!(
        !early.unwrap().unwrap(),
        "seed waited or replaced required work"
    );
    assert!(unchanged && still_pending);
    assert!(matches!(result, Checked::Ready(None)));
    assert!(matches!(
        cache
            .run(&scope, 1, Purpose::Build, &tx(1), || panic!(
                "required result was lost"
            ))
            .unwrap(),
        Checked::Ready(None)
    ));
}

#[test]
fn remember_obeys_existing_fifo_count_and_byte_limits() {
    let bytes = checked_bytes(&tx(1), &ready()).unwrap();
    let cache = Cache::new(2, bytes * 2);
    let scope = cache.select(b"root", ()).unwrap();
    for nonce in 1..=3 {
        assert!(cache
            .remember(&scope, 1, Purpose::Build, &tx(nonce), ready())
            .unwrap());
        assert!(stats(&cache).0 <= 2 && stats(&cache).2 <= bytes * 2);
    }
    let mut calls = 0;
    cache
        .run(&scope, 1, Purpose::Build, &tx(1), || {
            calls += 1;
            Ok(ready())
        })
        .unwrap();
    assert_eq!(calls, 1, "oldest seeded result was not evicted");
    let tiny = Cache::new(8, bytes - 1);
    let scope = tiny.select(b"root", ()).unwrap();
    tiny.remember(&scope, 1, Purpose::Build, &tx(1), ready())
        .unwrap();
    assert_eq!(stats(&tiny).0, 0);
    assert_eq!(stats(&tiny).2, 0);
}
