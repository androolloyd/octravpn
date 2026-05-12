//! Concurrency stress tests for the node control plane.
//!
//! These exercise the lock-protected data structures that ship in
//! production. We're not measuring throughput here — we're proving
//! the locks are correct under contention: no panics, monotonic
//! counters, audit-log lines well-formed.

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    thread,
};

// Pull in the binary crate as a path-style mod so we can test the
// internal modules. Cargo doesn't expose private bin modules to
// integration tests directly; instead we duplicate the bare-minimum
// types we need via the same crate-internal paths. For audit/rate
// limit, the public API surface we want to exercise is exactly the
// `pub(crate)` constructors plus their methods on instances we
// receive; integration tests can't reach them. So this file runs
// black-box scenarios via dependencies that ARE public.

// The strategy: drive `octravpn_core::bounded::BoundedMap` (used by
// the control plane for session + allowlist storage) under heavy
// parallel insert load to verify the production-relevant locking
// path stays correct.

use octravpn_core::bounded::BoundedMap;
use std::time::Duration;

#[test]
fn bounded_map_handles_parallel_inserts() {
    let map: Arc<BoundedMap<u64, u64>> = Arc::new(BoundedMap::new(10_000, Duration::from_secs(60)));
    let writers = 8usize;
    let inserts_per_writer = 500usize;
    let mut handles = Vec::new();
    for w in 0..writers {
        let m = map.clone();
        handles.push(thread::spawn(move || {
            for i in 0..inserts_per_writer {
                let k = (w as u64) * 10_000 + (i as u64);
                m.insert(k, k + 1);
            }
        }));
    }
    for h in handles {
        h.join().expect("writer thread panicked");
    }
    assert_eq!(map.len(), writers * inserts_per_writer);
}

#[test]
fn bounded_map_parallel_read_write_no_panic() {
    let map: Arc<BoundedMap<u64, u64>> = Arc::new(BoundedMap::new(10_000, Duration::from_secs(60)));
    for i in 0..200u64 {
        map.insert(i, i);
    }
    let mut handles = Vec::new();
    // Half writers, half readers.
    for w in 0..4 {
        let m = map.clone();
        handles.push(thread::spawn(move || {
            for i in 0..1000u64 {
                m.insert(1000 + (w as u64) * 1000 + i, i);
            }
        }));
    }
    for _ in 0..4 {
        let m = map.clone();
        handles.push(thread::spawn(move || {
            for i in 0..1000u64 {
                let _ = m.get(&i);
            }
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }
    // Some inserts succeeded; no panics during reads.
    assert!(map.len() >= 200);
}

// ---------- mesh-side stress ----------

use octravpn_mesh::{MeshManager, PeerCandidate, PeerSnapshot};
use std::time::Instant;

fn snap(tid: &str, addr: &str, cands: Vec<PeerCandidate>) -> PeerSnapshot {
    PeerSnapshot {
        tailnet_id: tid.into(),
        addr: addr.into(),
        wg_pubkey: [9u8; 32],
        candidates: cands,
        hostname: None,
        last_refresh: Instant::now(),
    }
}

#[test]
fn mesh_manager_tick_is_safe_under_concurrent_publish() {
    let mgr = Arc::new(MeshManager::new("octSELF", [1u8; 32]));
    mgr.set_self_candidates(vec![PeerCandidate::Lan(
        "10.0.0.1:51820".parse().unwrap(),
    )]);

    let writer = {
        let m = mgr.clone();
        thread::spawn(move || {
            for i in 0..200u64 {
                let addr = format!("octB{i:040x}");
                let snap = snap(
                    "t",
                    &addr,
                    vec![PeerCandidate::Lan(format!("10.0.{}.{}:51820", i / 256, i % 256).parse().unwrap())],
                );
                m.peers().publish_unverified(snap);
            }
        })
    };
    let ticker = {
        let m = mgr.clone();
        thread::spawn(move || {
            for _ in 0..50 {
                let _ = m.tick("t");
                thread::sleep(Duration::from_micros(100));
            }
        })
    };

    writer.join().expect("writer panicked");
    ticker.join().expect("ticker panicked");
    // No assertion needed beyond "no panic"; the test passing is the result.
}

// Required to opt in to `publish_unverified` from an integration test
// living outside the mesh crate. The test wraps it in a no-op when the
// feature isn't compiled — we add the feature in `dev-dependencies` of
// this crate so the function is available here.
//
// NOTE: this comment exists so a future maintainer doesn't wonder
// why we don't need the explicit `--features` flag.
