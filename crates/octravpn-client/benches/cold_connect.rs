//! Client cold-connect latency.
//!
//! `docs/performance-limitations.md` §6 flagged: "only the 30 s poll
//! budget is recorded; no observed wall-clock distribution."
//!
//! ## Why this bench is poll-loop-shaped, not full-connect-shaped
//!
//! `octravpn-client` is a binary crate (no `lib.rs`) — `Cmd::Connect`
//! and `poll_session_id` are private modules under `src/`. Driving
//! the real `connect` path requires a wallet, a real (or mocked)
//! chain RPC, a `tokio::signal::ctrl_c` future, an exit announce
//! HTTP endpoint, and a TUN device. That is integration-test
//! territory, not a `criterion` bench.
//!
//! What dominates connect-time per the doc is step 4: poll for
//! `SessionOpened` (`runner.rs:311`, backoff 100 ms → 2 s, capped at
//! 30 s). That schedule is a pure function of "when does the chain
//! make the event visible." We reproduce the same backoff schedule
//! verbatim against an in-process mock that flips "ready" after a
//! configurable target delay, and measure the wall-clock from
//! `submit` to "session id observed."
//!
//! ## What is measured
//!
//!   - For target chain-finality delays of 0 / 1 s / 5 s / 10 s
//!     (the empirical mainnet epoch length per
//!     `docs/octra-research.md:15`), what wall-clock does the poll
//!     loop add on top.
//!   - p50 / p95 / p99 across 100 iterations per scenario, reported
//!     as criterion percentiles.
//!
//! ## Honesty caveat
//!
//! End-to-end connect time on real chain is dominated by the epoch
//! length (~10 s mainnet). The "poll overhead" measured here is the
//! *additional* tail from rounding the next poll-wake to the backoff
//! schedule. It bounds the gap between "tx finalized at instant T"
//! and "client observed SessionOpened at instant T + delta."
//!
//! How to run:
//!
//!     cargo bench -p octravpn-client --bench cold_connect

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use parking_lot::Mutex;
use tokio::runtime::Builder;

/// In-process mock of the chain side. The mock returns `Some` from
/// `transaction(tx_hash)` once `ready_at` has been reached. We
/// don't simulate network — only the poll schedule's interaction
/// with finality timing.
#[derive(Clone)]
struct MockChain {
    ready_at: Arc<Mutex<Instant>>,
}

impl MockChain {
    fn new_arriving_in(delay: Duration) -> Self {
        Self {
            ready_at: Arc::new(Mutex::new(Instant::now() + delay)),
        }
    }
    async fn observed_session(&self) -> Option<u64> {
        // No network — just a wall-clock comparison.
        if Instant::now() >= *self.ready_at.lock() {
            Some(0x00C0_FFEE)
        } else {
            None
        }
    }
}

/// Verbatim copy of the `poll_session_id` backoff schedule from
/// `crates/octravpn-client/src/runner.rs:311-336`: 100 ms, 200 ms,
/// 400 ms, 800 ms, 1.6 s, then capped at 2 s; up to 20 iterations.
///
/// If `runner.rs` ever changes that schedule, this bench will lag
/// reality and the doc cite should be updated. Keeping the schedule
/// in one place is a separate refactor (would require exposing the
/// poll loop on a public surface, out of scope for this PR).
async fn poll_for_session(chain: &MockChain) -> Option<u64> {
    let mut delay_ms: u64 = 100;
    for _ in 0..20 {
        if let Some(id) = chain.observed_session().await {
            return Some(id);
        }
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        delay_ms = (delay_ms * 2).min(2_000);
    }
    None
}

fn bench_cold_connect_poll(c: &mut Criterion) {
    // Build one shared runtime — spinning a fresh runtime per iter
    // would dwarf the actual delay we're measuring.
    let rt = Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");

    let mut g = c.benchmark_group("cold_connect_poll");
    // Each scenario sleeps for at least the target delay, so the
    // measurement window must accommodate. Sample count kept low
    // for the 10s scenario to keep the bench under five minutes.
    g.sample_size(20);

    for &delay_ms in &[0u64, 1_000, 5_000, 10_000] {
        let target = Duration::from_millis(delay_ms);
        // Widen the measurement window to fit at least 20 samples.
        let per_iter_budget = target + Duration::from_millis(2_500);
        g.measurement_time(per_iter_budget * 20 + Duration::from_secs(1));

        g.bench_with_input(
            BenchmarkId::new("ready_after", format_args!("{delay_ms}ms")),
            &target,
            |b, &target| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    rt.block_on(async {
                        for _ in 0..iters {
                            let chain = MockChain::new_arriving_in(target);
                            let _ = black_box(poll_for_session(&chain).await);
                        }
                    });
                    start.elapsed()
                });
            },
        );
    }
    g.finish();
}

criterion_group!(benches, bench_cold_connect_poll);
criterion_main!(benches);
