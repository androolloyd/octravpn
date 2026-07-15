//! Step 8b: the permissionless keeper sweeper.
//!
//! `relay_sweep` (program/main-v4.aml) rescues a PERMANENTLY-offline funder: for
//! a session still `RELAY_ARMED` that neither the operator claimed (Step 6) nor
//! the funder refunded (Step 8a), once `epoch >= deadline + session_grace *
//! sweep_multiplier`, ANY caller may sweep it — the deposit goes back to the
//! funder and the caller earns a bounty. This actor is that keeper.
//!
//! Unlike the claimer (which scans the node's OWN receipt vault), the sweeper
//! rescues OTHER funders' sessions, which the node does not hold — so it scans
//! the chain session-id range `[0, session_count)` with a **cursor-bounded**
//! batch per tick (a large chain never blows up one tick; the cursor covers the
//! whole range over many ticks). It has no vault to drain: a session leaves the
//! candidate set simply by no longer being `RELAY_ARMED` on chain.
//!
//! Safety: the on-chain sweep guard (`epoch >= deadline + sweep_grace`, plus the
//! off-chain `margin` buffer here) opens strictly LATER than both the operator
//! claim guard (`epoch < deadline`) and the on-chain funder refund guard
//! (`epoch >= deadline` — the client watcher layers its own off-chain margin k_r
//! on top, but the chain itself allows refund from the deadline). So a live
//! operator/funder always resolves the session first; a keeper only ever rescues
//! the truly-abandoned. Default-off behind `[control.relay].auto_sweep`; the
//! actor parks otherwise.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tracing::{debug, info};

use crate::chain_v3::SESSION_RELAY_ARMED;
use crate::hub::Hub;
use crate::relay_claimer::within_grace;

/// The chain surface the sweeper needs, as a trait so the scan/gate logic is
/// testable with a mock backend.
#[async_trait]
pub(crate) trait SweeperBackend: Send + Sync {
    async fn session_count(&self) -> Result<u64>;
    async fn sweep_grace(&self) -> Result<u64>;
    async fn current_epoch(&self) -> Result<u64>;
    /// STRICT status read (Err => skip this sid, never a phantom 0).
    async fn session_status(&self, session_id: u64) -> Result<u64>;
    async fn relay_deadline(&self, session_id: u64) -> Result<u64>;
    async fn submit_sweep(&self, session_id: u64) -> Result<String>;
}

#[async_trait]
impl SweeperBackend for Hub {
    async fn session_count(&self) -> Result<u64> {
        self.chain_v3.get_session_count().await
    }
    async fn sweep_grace(&self) -> Result<u64> {
        self.chain_v3.get_sweep_grace().await
    }
    async fn current_epoch(&self) -> Result<u64> {
        self.chain_v3.current_epoch().await
    }
    async fn session_status(&self, session_id: u64) -> Result<u64> {
        self.chain_v3.get_session_status_strict(session_id).await
    }
    async fn relay_deadline(&self, session_id: u64) -> Result<u64> {
        self.chain_v3.get_relay_deadline(session_id).await
    }
    async fn submit_sweep(&self, session_id: u64) -> Result<String> {
        let fee = self.chain_v3.fee_or_fallback("contract_call").await;
        let call = self.chain_v3.build_relay_sweep_call(session_id, fee, 0);
        self.chain_v3.submit_call(call).await
    }
}

/// One sweeper tick: read the chain-wide `session_count`/`sweep_grace`/`epoch`
/// once, then scan a bounded `batch` of session ids from the cursor (wrapping),
/// submitting `relay_sweep` for any that are still `RELAY_ARMED` and past
/// `deadline + sweep_grace + margin` and not already in-flight.
#[allow(clippy::too_many_arguments)]
async fn run_tick<B: SweeperBackend + ?Sized>(
    backend: &B,
    inflight: &mut HashMap<u64, u64>,
    cursor: &mut u64,
    tick: u64,
    margin: u64,
    quiesce: u64,
    batch: u64,
) {
    let count = match backend.session_count().await {
        Ok(c) => c,
        Err(e) => {
            debug!(error = %e, "sweeper: session_count read failed; skip tick");
            return;
        }
    };
    if count == 0 {
        return;
    }
    let grace = match backend.sweep_grace().await {
        Ok(g) => g,
        Err(e) => {
            debug!(error = %e, "sweeper: sweep_grace read failed; skip tick");
            return;
        }
    };
    let epoch = match backend.current_epoch().await {
        Ok(e) => e,
        Err(e) => {
            debug!(error = %e, "sweeper: epoch read failed; skip tick");
            return;
        }
    };

    let scan = batch.min(count);
    for _ in 0..scan {
        let sid = *cursor % count;
        *cursor = (*cursor + 1) % count;

        let status = match backend.session_status(sid).await {
            Ok(s) => s,
            Err(_) => continue, // strict read failed for this sid; skip
        };
        if status != SESSION_RELAY_ARMED {
            // Resolved (open / claimed / refunded / already swept) -> forget any
            // in-flight reservation so the map does not grow unbounded.
            inflight.remove(&sid);
            continue;
        }
        // Still armed. In-flight grace: don't re-submit a sweep whose tx may still
        // be in the mempool.
        if let Some(t) = inflight.get(&sid) {
            if within_grace(tick, *t, quiesce) {
                continue;
            }
        }
        let deadline = match backend.relay_deadline(sid).await {
            Ok(d) if d > 0 => d,
            // A RELAY_ARMED session always has a non-zero deadline; 0 (or an error)
            // means a bad read -> skip (fail-closed, never sweep early).
            _ => continue,
        };
        // Sweep only strictly after the on-chain threshold (deadline + sweep_grace)
        // plus the margin buffer, so a live funder's refund window closes first.
        // epoch is a LOWER bound, so a conservative read only ever delays a sweep.
        if epoch < deadline.saturating_add(grace).saturating_add(margin) {
            continue;
        }
        // Reserve before submit so a submit error still holds the grace window.
        inflight.insert(sid, tick);
        match backend.submit_sweep(sid).await {
            Ok(tx) => {
                info!(session = sid, tx = %tx, "relay_sweep submitted (offline-funder rescue)")
            }
            Err(e) => debug!(
                session = sid,
                error = %e,
                "relay_sweep not submitted this tick (window/status gate)"
            ),
        }
    }
}

pub(crate) async fn run(hub: Arc<Hub>) -> Result<()> {
    let relay = &hub.cfg.control.relay;
    if !relay.enabled || !relay.auto_sweep {
        // Park (never return): like the claimer, this is one arm of the daemon's
        // top-level select! of infinite loops; returning would shut the node down.
        debug!("relay auto-sweep disabled; sweeper idle");
        std::future::pending::<()>().await;
        unreachable!("std::future::pending never resolves");
    }
    let period = relay.resolved_sweep_period();
    let margin = relay.resolved_sweep_margin_epochs();
    let quiesce = u64::from(relay.resolved_quiescent_ticks());
    let batch = relay.resolved_sweep_batch();
    info!(
        period_secs = period.as_secs(),
        sweep_margin_epochs = margin,
        sweep_batch = batch,
        "relay auto-sweeper started"
    );

    let mut inflight: HashMap<u64, u64> = HashMap::new();
    let mut cursor: u64 = 0;
    let mut tick: u64 = 0;

    loop {
        tokio::time::sleep(period).await;
        tick += 1;
        run_tick(
            hub.as_ref(),
            &mut inflight,
            &mut cursor,
            tick,
            margin,
            quiesce,
            batch,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::collections::HashMap;

    /// Backend with a fixed chain-wide (count, grace, epoch) and a per-session
    /// status/deadline map; records sweep submissions.
    struct MockSweep {
        count: u64,
        grace: u64,
        epoch: u64,
        status: HashMap<u64, u64>,
        deadline: HashMap<u64, u64>,
        swept: Mutex<Vec<u64>>,
    }

    #[async_trait]
    impl SweeperBackend for MockSweep {
        async fn session_count(&self) -> Result<u64> {
            Ok(self.count)
        }
        async fn sweep_grace(&self) -> Result<u64> {
            Ok(self.grace)
        }
        async fn current_epoch(&self) -> Result<u64> {
            Ok(self.epoch)
        }
        async fn session_status(&self, sid: u64) -> Result<u64> {
            Ok(*self.status.get(&sid).unwrap_or(&0))
        }
        async fn relay_deadline(&self, sid: u64) -> Result<u64> {
            Ok(*self.deadline.get(&sid).unwrap_or(&0))
        }
        async fn submit_sweep(&self, sid: u64) -> Result<String> {
            self.swept.lock().push(sid);
            Ok(format!("sweep-{sid}"))
        }
    }

    fn one_session(status: u64, deadline: u64, grace: u64, epoch: u64) -> MockSweep {
        MockSweep {
            count: 1,
            grace,
            epoch,
            status: HashMap::from([(0u64, status)]),
            deadline: HashMap::from([(0u64, deadline)]),
            swept: Mutex::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn sweeps_armed_session_past_grace_plus_margin() {
        // deadline 100, grace 20, margin 3 -> threshold 123; epoch 123 -> sweep.
        let b = one_session(SESSION_RELAY_ARMED, 100, 20, 123);
        let mut inflight = HashMap::new();
        let mut cursor = 0;
        run_tick(&b, &mut inflight, &mut cursor, 1, 3, 1, 256).await;
        assert_eq!(*b.swept.lock(), vec![0]);
    }

    #[tokio::test]
    async fn skips_before_threshold() {
        // epoch 122 < threshold 123 -> no sweep.
        let b = one_session(SESSION_RELAY_ARMED, 100, 20, 122);
        let mut inflight = HashMap::new();
        let mut cursor = 0;
        run_tick(&b, &mut inflight, &mut cursor, 1, 3, 1, 256).await;
        assert!(b.swept.lock().is_empty());
    }

    #[tokio::test]
    async fn skips_non_armed_session() {
        // Claimed already (status 4) -> not sweepable even long past the window.
        let b = one_session(4, 100, 20, 9999);
        let mut inflight = HashMap::new();
        let mut cursor = 0;
        run_tick(&b, &mut inflight, &mut cursor, 1, 3, 1, 256).await;
        assert!(b.swept.lock().is_empty());
    }

    #[tokio::test]
    async fn skips_armed_with_zero_deadline_fail_closed() {
        // A 0 deadline for an armed session = bad read -> never sweep early.
        let b = one_session(SESSION_RELAY_ARMED, 0, 20, 9999);
        let mut inflight = HashMap::new();
        let mut cursor = 0;
        run_tick(&b, &mut inflight, &mut cursor, 1, 3, 1, 256).await;
        assert!(b.swept.lock().is_empty());
    }

    #[tokio::test]
    async fn in_flight_grace_skips_resubmit_then_forgets_when_resolved() {
        let mut b = one_session(SESSION_RELAY_ARMED, 100, 20, 200);
        let mut inflight = HashMap::new();
        let mut cursor = 0;
        run_tick(&b, &mut inflight, &mut cursor, 1, 3, 1, 256).await; // sweep at tick 1
        run_tick(&b, &mut inflight, &mut cursor, 2, 3, 1, 256).await; // tick 2 within grace -> skip
        assert_eq!(*b.swept.lock(), vec![0], "no re-submit within grace");
        // The sweep confirmed on chain (status -> REFUNDED); re-scan forgets it.
        b.status.insert(0, 5);
        run_tick(&b, &mut inflight, &mut cursor, 10, 3, 1, 256).await;
        assert_eq!(*b.swept.lock(), vec![0]);
        assert!(
            inflight.is_empty(),
            "resolved session dropped from in-flight"
        );
    }

    #[tokio::test]
    async fn cursor_batches_bound_the_scan() {
        // 5 sessions, batch 2 -> only 2 status reads per tick; cursor advances.
        let b = MockSweep {
            count: 5,
            grace: 0,
            epoch: 0,
            status: HashMap::new(),
            deadline: HashMap::new(),
            swept: Mutex::new(Vec::new()),
        };
        let mut inflight = HashMap::new();
        let mut cursor = 0;
        run_tick(&b, &mut inflight, &mut cursor, 1, 3, 1, 2).await;
        assert_eq!(cursor, 2, "scanned 2, cursor advanced by batch");
        run_tick(&b, &mut inflight, &mut cursor, 2, 3, 1, 2).await;
        assert_eq!(cursor, 4);
        run_tick(&b, &mut inflight, &mut cursor, 3, 3, 1, 2).await;
        assert_eq!(cursor, 1, "wrapped around count=5");
    }
}
