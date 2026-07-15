//! Step 6: the in-daemon autonomous relay-claimer.
//!
//! A single boot-spawned actor (mirrors `control::run_sweeper`) that makes the
//! daemon the SOLE relay-claim nonce owner + vault writer — retiring the CLI
//! claim path (which was a second nonce owner + a second cross-process vault
//! writer). Each tick it runs two ordered passes:
//!
//!   1. **DRAIN** — over `armed_unclaimed()` ({Armed, ClaimSubmitted}), promote
//!      entries to a terminal vault state purely from an EXACT positive on-chain
//!      status match (`RELAY_CLAIMED` -> Claimed, `RELAY_REFUNDED` -> Refunded).
//!      A hostile/failed status read is an `Err` (via `get_session_status_strict`)
//!      that leaves the entry, so a bad read never phantom-drains a live session.
//!   2. **SUBMIT** — over `claimable()` ({Proposed, Armed, ClaimSubmitted}; the
//!      canonical POST->ACK->arm order leaves the operator's entry Proposed, so
//!      the normal case IS Proposed and the claim path promotes it from chain
//!      truth). Reveal only when the margin gate passes (enforced inside
//!      `submit_relay_claim_from_vault`) and the entry is not already in-flight
//!      within the grace window.
//!
//! The actor holds `Arc<Hub>` and routes every submission through `hub.chain_v3`
//! (the boot-built shared `ChainTxQueue`) so I4 (nonce single-owner) holds.
//! Default-off: it parks unless `[control.relay].enabled = true` AND
//! `auto_claim = true`, so an operator who has not opted in sees zero change.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::hub::{DrainOutcome, Hub};
use crate::relay_settlement::RelayClaimSubmission;

/// Compact the vault every N ticks (defense-in-depth GC of terminal entries).
const COMPACT_EVERY: u64 = 60;

/// Whether a claim submitted at tick `submitted_at` is still inside its in-flight
/// grace window at tick `now`: don't re-submit for `quiesce` ticks after submit.
/// With `quiesce = 1` (the default), a claim submitted at tick T is skipped on
/// T+1 and re-eligible at T+2. The `<=` is load-bearing: a plain `<` makes
/// `quiesce = 1` a no-op (the T+1 gap of 1 fails `1 < 1`, re-submitting a
/// duplicate claim tx while the first is still in the mempool).
fn within_grace(now: u64, submitted_at: u64, quiesce: u64) -> bool {
    now.saturating_sub(submitted_at) <= quiesce
}

/// The slice of `Hub` the claimer needs, extracted as a trait so the per-tick
/// money-path logic (which candidate set is scanned, the drain/submit ordering,
/// the in-flight grace) is testable with a mock backend — a full `Hub` is not
/// constructible in a unit test.
#[async_trait]
pub(crate) trait ClaimerBackend: Send + Sync {
    /// Drain-pass candidates: {Armed, ClaimSubmitted} (u64 session ids).
    fn armed_unclaimed_ids(&self) -> Vec<u64>;
    /// Submit-pass candidates: {Proposed, Armed, ClaimSubmitted} (u64 ids).
    fn claimable_ids(&self) -> Vec<u64>;
    async fn confirm_and_drain(&self, session_id: u64) -> Result<DrainOutcome>;
    async fn claim(&self, session_id: u64) -> Result<RelayClaimSubmission>;
    fn compact(&self);
}

#[async_trait]
impl ClaimerBackend for Hub {
    fn armed_unclaimed_ids(&self) -> Vec<u64> {
        self.receipt_vault
            .armed_unclaimed()
            .into_iter()
            .filter_map(|(id, _)| id.as_u64())
            .collect()
    }
    fn claimable_ids(&self) -> Vec<u64> {
        self.receipt_vault
            .claimable()
            .into_iter()
            .filter_map(|(id, _)| id.as_u64())
            .collect()
    }
    async fn confirm_and_drain(&self, session_id: u64) -> Result<DrainOutcome> {
        Hub::relay_confirm_and_drain(self, session_id).await
    }
    async fn claim(&self, session_id: u64) -> Result<RelayClaimSubmission> {
        self.relay_claim_session(session_id).await
    }
    fn compact(&self) {
        if let Err(e) = self.receipt_vault.compact() {
            warn!(error = %e, "relay vault compaction failed");
        }
    }
}

/// One claimer tick: drain confirmed entries, then submit for still-claimable
/// ones (respecting the in-flight grace), then optionally compact.
async fn run_tick<B: ClaimerBackend + ?Sized>(
    backend: &B,
    inflight: &mut HashMap<u64, u64>,
    tick: u64,
    quiesce: u64,
    compact: bool,
) {
    // ---- PASS 1: DRAIN (terminal only from a strict positive chain read) ----
    for sid in backend.armed_unclaimed_ids() {
        match backend.confirm_and_drain(sid).await {
            Ok(DrainOutcome::Claimed) => {
                inflight.remove(&sid);
                debug!(
                    session = sid,
                    "relay claim confirmed on chain; drained to Claimed"
                );
            }
            Ok(DrainOutcome::Refunded) => {
                inflight.remove(&sid);
                debug!(
                    session = sid,
                    "relay session refunded on chain; drained to Refunded"
                );
            }
            Ok(DrainOutcome::Pending) => {}
            Err(e) => {
                debug!(session = sid, error = %e, "relay confirm-drain read failed; retry next tick");
            }
        }
    }

    // ---- PASS 2: SUBMIT (claimable = {Proposed, Armed, ClaimSubmitted}) ----
    for sid in backend.claimable_ids() {
        // In-flight grace: leave a just-submitted (still-unconfirmed) claim alone
        // for `quiesce` ticks so we don't spam re-reveals while a claim tx is in
        // the mempool.
        if let Some(t) = inflight.get(&sid) {
            if within_grace(tick, *t, quiesce) {
                continue;
            }
        }
        // Reserve BEFORE submitting so a submit error still holds the grace window
        // (no tight re-submit loop). `submit_relay_claim_from_vault` is the
        // authoritative gate (status==ARMED, margin, on-chain-hash match, and the
        // Proposed->Armed promotion for canonical entries).
        inflight.insert(sid, tick);
        match backend.claim(sid).await {
            Ok(sub) => info!(
                session = sub.session_id,
                tx = %sub.tx_hash,
                settlement_hash = %sub.settlement_hash,
                receipt_seq = sub.receipt_seq,
                epoch = sub.current_epoch,
                deadline = sub.relay_deadline,
                "relay claim submitted"
            ),
            Err(e) => debug!(
                session = sid,
                error = %e,
                "relay claim not submitted this tick (window/hash/status gate)"
            ),
        }
    }

    if compact {
        backend.compact();
    }
}

pub(crate) async fn run(hub: Arc<Hub>) -> Result<()> {
    let relay = &hub.cfg.control.relay;
    if !relay.enabled || !relay.auto_claim {
        // Park forever instead of returning: `run()` is awaited as one arm of the
        // daemon's top-level `tokio::select!`, whose arms are all infinite loops.
        // Returning `Ok(())` here would complete that arm and shut the whole node
        // down at startup for the DEFAULT (auto_claim = false) config. Idle
        // parking keeps the arm pending; the task is dropped on shutdown.
        debug!("relay auto-claim disabled; claimer idle");
        std::future::pending::<()>().await;
        unreachable!("std::future::pending never resolves");
    }
    let period = relay.resolved_scan_period();
    let quiesce = u64::from(relay.resolved_quiescent_ticks());
    info!(
        period_secs = period.as_secs(),
        margin_epochs = relay.resolved_margin_epochs(),
        quiescent_ticks = quiesce,
        "relay auto-claimer started"
    );

    // session -> tick at which we last submitted a claim (in-flight grace).
    // Seeded empty on boot: a durable `ClaimSubmitted` survives restart, so pass
    // 1 re-confirms a landed claim (draining it) rather than pass 2 blindly
    // re-revealing; a still-armed dropped claim is legitimately re-submitted.
    let mut inflight: HashMap<u64, u64> = HashMap::new();
    let mut tick: u64 = 0;

    loop {
        tokio::time::sleep(period).await;
        tick += 1;
        run_tick(
            hub.as_ref(),
            &mut inflight,
            tick,
            quiesce,
            tick % COMPACT_EVERY == 0,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    #[test]
    fn grace_skips_exactly_quiesce_ticks() {
        // Submitted at tick 10, quiesce = 1 (default): the same tick and the very
        // next tick are inside the grace (skip), re-eligible at T+2. This is the
        // off-by-one the review caught: a plain `<` would re-submit at T+1.
        assert!(within_grace(10, 10, 1));
        assert!(within_grace(11, 10, 1));
        assert!(!within_grace(12, 10, 1));

        // quiesce = 3: skip 11,12,13; re-eligible 14.
        assert!(within_grace(13, 10, 3));
        assert!(!within_grace(14, 10, 3));
    }

    /// Backend that records claim/drain calls; `claimable`/`armed_unclaimed` are
    /// the scripted candidate sets.
    struct MockBackend {
        claimable: Vec<u64>,
        armed_unclaimed: Vec<u64>,
        claims: Mutex<Vec<u64>>,
        drains: Mutex<Vec<u64>>,
    }

    #[async_trait]
    impl ClaimerBackend for MockBackend {
        fn armed_unclaimed_ids(&self) -> Vec<u64> {
            self.armed_unclaimed.clone()
        }
        fn claimable_ids(&self) -> Vec<u64> {
            self.claimable.clone()
        }
        async fn confirm_and_drain(&self, session_id: u64) -> Result<DrainOutcome> {
            self.drains.lock().push(session_id);
            Ok(DrainOutcome::Pending)
        }
        async fn claim(&self, session_id: u64) -> Result<RelayClaimSubmission> {
            self.claims.lock().push(session_id);
            Ok(RelayClaimSubmission {
                session_id,
                tx_hash: "tx".to_string(),
                settlement_hash: "h".to_string(),
                receipt_seq: 1,
                current_epoch: 1,
                relay_deadline: 100,
            })
        }
        fn compact(&self) {}
    }

    fn mock(claimable: Vec<u64>, armed_unclaimed: Vec<u64>) -> MockBackend {
        MockBackend {
            claimable,
            armed_unclaimed,
            claims: Mutex::new(vec![]),
            drains: Mutex::new(vec![]),
        }
    }

    #[tokio::test]
    async fn claimer_submits_for_a_proposed_session() {
        // The critical Step-6 regression: a canonical session is `Proposed` in the
        // operator's vault (POST landed while OPEN) but RELAY_ARMED on chain. It is
        // in `claimable` but NOT `armed_unclaimed`; the submit pass MUST still claim
        // it. If pass 2 scanned armed_unclaimed the operator would never be paid.
        let backend = mock(vec![42], vec![]);
        let mut inflight = HashMap::new();
        run_tick(&backend, &mut inflight, 1, 1, false).await;
        assert_eq!(
            *backend.claims.lock(),
            vec![42],
            "claimer must submit a claim for the Proposed session"
        );
        assert!(backend.drains.lock().is_empty());
    }

    #[tokio::test]
    async fn claimer_grace_skips_resubmit_then_retries() {
        let backend = mock(vec![42], vec![]);
        let mut inflight = HashMap::new();
        run_tick(&backend, &mut inflight, 1, 1, false).await; // submit at tick 1
        run_tick(&backend, &mut inflight, 2, 1, false).await; // tick 2 within grace -> skip
        assert_eq!(
            *backend.claims.lock(),
            vec![42],
            "no re-submit within grace"
        );
        run_tick(&backend, &mut inflight, 3, 1, false).await; // tick 3 -> re-eligible
        assert_eq!(
            *backend.claims.lock(),
            vec![42, 42],
            "re-submit once past the grace window"
        );
    }
}
