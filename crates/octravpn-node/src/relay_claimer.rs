//! Step 6: the in-daemon autonomous relay-claimer.
//!
//! A single boot-spawned actor (mirrors `control::run_sweeper`) that makes the
//! daemon the SOLE relay-claim nonce owner + vault writer — retiring the CLI
//! claim path (which was a second nonce owner + a second cross-process vault
//! writer). Each tick it scans `ReceiptVault::armed_unclaimed()` and runs two
//! ordered passes:
//!
//!   1. **DRAIN** — promote entries to a terminal vault state purely from an
//!      EXACT positive on-chain status match (`RELAY_CLAIMED` -> Claimed,
//!      `RELAY_REFUNDED` -> Refunded). A hostile/failed status read is an `Err`
//!      (via `get_session_status_strict`) that leaves the entry untouched, so a
//!      bad read never phantom-drains a live session.
//!   2. **SUBMIT** — reveal a preimage for a still-armed entry only when the
//!      margin gate passes (`epoch + margin <= deadline`, enforced inside
//!      `submit_relay_claim_from_vault`) and the entry is not already in-flight
//!      within the grace window.
//!
//! The actor holds `Arc<Hub>` and routes every submission through
//! `hub.chain_v3` (the boot-built shared `ChainTxQueue`) so I4 (nonce
//! single-owner) holds. Default-off: it returns immediately unless
//! `[control.relay].enabled = true` AND `auto_claim = true`, so an operator who
//! has not opted in sees zero behaviour change.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use octravpn_core::session::SessionId;
use tracing::{debug, info, warn};

use crate::hub::{DrainOutcome, Hub};

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
    let margin = relay.resolved_margin_epochs();
    let quiesce = u64::from(relay.resolved_quiescent_ticks());
    info!(
        period_secs = period.as_secs(),
        margin_epochs = margin,
        quiescent_ticks = quiesce,
        "relay auto-claimer started"
    );

    // session -> tick at which we last submitted a claim (in-flight grace).
    // Seeded empty on boot: a durable `ClaimSubmitted` survives restart, so pass
    // 1 re-confirms a landed claim (draining it) rather than pass 2 blindly
    // re-revealing; a still-armed dropped claim is legitimately re-submitted.
    let mut inflight: HashMap<SessionId, u64> = HashMap::new();
    let mut tick: u64 = 0;

    loop {
        tokio::time::sleep(period).await;
        tick += 1;

        // ---- PASS 1: DRAIN (terminal only from a strict positive chain read) ----
        for (id, _entry) in hub.receipt_vault.armed_unclaimed() {
            let Some(sid) = id.as_u64() else { continue };
            match hub.relay_confirm_and_drain(sid).await {
                Ok(DrainOutcome::Claimed) => {
                    inflight.remove(&id);
                    debug!(session = sid, "relay claim confirmed on chain; drained to Claimed");
                }
                Ok(DrainOutcome::Refunded) => {
                    inflight.remove(&id);
                    debug!(session = sid, "relay session refunded on chain; drained to Refunded");
                }
                Ok(DrainOutcome::Pending) => {}
                Err(e) => {
                    debug!(session = sid, error = %e, "relay confirm-drain read failed; retry next tick");
                }
            }
        }

        // ---- PASS 2: SUBMIT (re-read: pass 1 may have drained some) ----
        for (id, _entry) in hub.receipt_vault.armed_unclaimed() {
            let Some(sid) = id.as_u64() else { continue };
            // In-flight grace: leave a just-submitted (still-unconfirmed) claim
            // alone for `quiesce` ticks so we don't spam re-reveals while a claim
            // tx is in the mempool. Submitted at tick `t`; on tick `t + n` the gap
            // is `n`, so `<=` gives exactly `quiesce` ticks of grace (with the
            // default quiesce=1, skip the very next tick). A plain `<` would make
            // quiesce=1 a no-op and re-submit immediately next tick.
            if let Some(t) = inflight.get(&id) {
                if within_grace(tick, *t, quiesce) {
                    continue;
                }
            }
            // Reserve BEFORE submitting so a submit error still holds the grace
            // window (no tight re-submit loop). `submit_relay_claim_from_vault` is
            // the authoritative gate (status==ARMED, margin, on-chain-hash match).
            inflight.insert(id.clone(), tick);
            match hub.relay_claim_session(sid).await {
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

        // ---- COMPACTION (slow cadence; only drops already-terminal entries) ----
        if tick % COMPACT_EVERY == 0 {
            if let Err(e) = hub.receipt_vault.compact() {
                warn!(error = %e, "relay vault compaction failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::within_grace;

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
}
