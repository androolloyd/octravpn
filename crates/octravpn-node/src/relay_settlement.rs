//! v4 relay-settlement operator caller path.
//!
//! The long-lived daemon owns the durable receipt vault, while the v3
//! chain context owns signing/submission. This module keeps the money
//! path small: load the vaulted receipt, verify the session is still
//! `RELAY_ARMED` and inside its claim window, then reveal the exact
//! `SignedReceipt::settlement_preimage()` on chain.

use anyhow::{anyhow, bail, Context, Result};
use octravpn_core::{
    receipt_vault::{LifecycleState, ReceiptVault},
    session::SessionId,
};

use crate::chain_v3::{ChainCtxV3, SESSION_RELAY_ARMED};

#[derive(Debug, Clone)]
pub(crate) struct RelayClaimSubmission {
    pub session_id: u64,
    pub tx_hash: String,
    pub settlement_hash: String,
    pub receipt_seq: u64,
    pub current_epoch: u64,
    pub relay_deadline: u64,
}

pub(crate) async fn submit_relay_claim_from_vault(
    ctx: &ChainCtxV3,
    vault: &ReceiptVault,
    session_id: u64,
    // Claim only while `epoch + margin <= relay_deadline`, so the claim tx can
    // never confirm at/after the deadline (where relay_claim reverts and the
    // client may relay_refund, wasting the revealed preimage). The manual/legacy
    // path passes 0 (its old `epoch < deadline` behaviour); the autonomous
    // claimer passes the clamped `[1,5]` config margin.
    margin: u64,
) -> Result<RelayClaimSubmission> {
    let vault_id = SessionId::from_u64(session_id);
    let entry = vault
        .entry(&vault_id)
        .ok_or_else(|| anyhow!("no vaulted receipt for session {session_id}"))?;
    let receipt = entry.receipt;
    let settlement_hash = receipt.settlement_hash();

    // Which vault states may proceed to a claim, and do we owe a pin first?
    // The canonical POST->ACK->arm order leaves the entry `Proposed`: the receipt
    // POST landed while the session was still SESSION_OPEN, so the receipt handler
    // never observed RELAY_ARMED and never called mark_armed (only a session
    // already armed at POST time gets pinned there). We promote Proposed->Armed
    // from the confirmed on-chain commitment below -- so the ARMED-freeze guards
    // the claim leg too without blocking the normal flow. `ClaimSubmitted` is a
    // prior broadcast that may have been dropped; re-revealing the same preimage
    // is idempotent (the on-chain claim self-guards on status), so allow retry.
    let needs_promotion = matches!(entry.state, LifecycleState::Proposed);
    let already_claim_submitted = matches!(entry.state, LifecycleState::ClaimSubmitted { .. });
    match &entry.state {
        LifecycleState::Proposed => {}
        LifecycleState::Armed {
            settlement_hash: pinned,
            ..
        } if *pinned == settlement_hash => {}
        LifecycleState::Armed {
            settlement_hash: pinned,
            ..
        } => bail!(
            "session {session_id}: vault Armed settlement hash {pinned} != receipt hash {settlement_hash}; refusing to reveal preimage"
        ),
        LifecycleState::ClaimSubmitted { .. } => {}
        other => bail!(
            "session {session_id}: vault entry cannot be claimed: state={other:?}"
        ),
    }

    let status = ctx
        .get_session_status(session_id)
        .await
        .context("get_session_status before relay_claim")?;
    if status != SESSION_RELAY_ARMED {
        bail!("session {session_id} is not RELAY_ARMED: status={status}");
    }

    let current_epoch = ctx
        .current_epoch()
        .await
        .context("current_epoch before relay_claim")?;
    let relay_deadline = ctx
        .get_relay_deadline(session_id)
        .await
        .context("get_relay_deadline before relay_claim")?;
    // Margin gate: refuse to claim inside `(deadline - margin, deadline]` so a
    // claim tx cannot confirm at/after D. epoch reads are a float-truncated lower
    // bound (see the fresh re-read below), and margin >= 1 absorbs that slack.
    if current_epoch + margin > relay_deadline {
        bail!(
            "relay claim window too close to deadline for session {session_id}: epoch={current_epoch} + margin={margin} > deadline={relay_deadline}"
        );
    }

    // AUDIT #3: never reveal a preimage that no longer matches the on-chain
    // commitment. The vault keeps only the latest receipt per session; if a
    // higher-seq receipt arrived AFTER arm, its settlement_hash differs from the
    // H the opener committed -> relay_claim would revert AND we'd have leaked a
    // useless preimage. Bail instead; the opener recovers via relay_refund.
    // (The deep fix is vault ARMED-freeze, spec Step 2.)
    let onchain_hash = ctx
        .get_relay_settlement_hash(session_id)
        .await
        .context("get_relay_settlement_hash before relay_claim")?;
    // R2 (fail-closed): a RELAY_ARMED session ALWAYS has a non-empty committed
    // hash (write_relay_arm sets it), so an empty response means the RPC failed
    // or is hostile -- exactly when we must NOT reveal the preimage. Do not gate
    // the bail on !is_empty(): treat empty as an error, then compare.
    if onchain_hash.is_empty() {
        bail!(
            "session {session_id}: empty on-chain settlement hash for a RELAY_ARMED session (RPC failure or hostile RPC?); refusing to reveal preimage"
        );
    }
    if onchain_hash != settlement_hash {
        bail!(
            "session {session_id}: vault receipt hash {settlement_hash} != on-chain committed hash {onchain_hash} (higher-seq receipt after arm?); refusing to reveal preimage"
        );
    }

    // Re-close the loop (Fable whole-flow review): the on-chain commitment is now
    // proven equal to this receipt's hash, so promote a `Proposed` entry to
    // `Armed` from chain truth before we reveal. The vault's Proposed->Armed guard
    // requires pin == receipt hash (just proven), and once Armed a later
    // higher-seq POST is frozen out -- so the freeze now guards the claim leg too,
    // instead of being a gate the canonical flow can never satisfy. This is the
    // spec Step-7 discovery sub-pass pulled onto the claim path.
    if needs_promotion {
        vault
            .mark_armed(&vault_id, relay_deadline, onchain_hash)
            .context("promote vault entry Proposed->Armed from chain truth before relay_claim")?;
    }

    // Re-read the epoch immediately before revealing and re-apply the margin
    // gate: several RPC round-trips elapsed since the first read, and the epoch
    // may have advanced into the no-claim zone. Never leak the preimage into a tx
    // that could confirm at/after the deadline.
    let fresh_epoch = ctx
        .current_epoch()
        .await
        .context("current_epoch re-read before revealing preimage")?;
    if fresh_epoch + margin > relay_deadline {
        bail!(
            "relay claim window closed before reveal for session {session_id}: epoch={fresh_epoch} + margin={margin} > deadline={relay_deadline}"
        );
    }

    let preimage = receipt.settlement_preimage();
    let fee = ctx.fee_or_fallback("contract_call").await;
    let call = ctx.build_relay_claim_call(session_id, &preimage, fee, 0);
    let tx_hash = ctx.submit_call(call).await.context("submit relay_claim")?;

    // Write the broadcast into the vault so a crash-retry (and the future
    // confirmation watcher) can see a claim tx was already revealed for this
    // session, and so the entry can later drain to a terminal state. Best-effort:
    // the preimage is already on the wire, so a bookkeeping-write failure must not
    // fail the claim. Skip when already ClaimSubmitted -- that self-transition is
    // not legal and the record already exists.
    if !already_claim_submitted {
        if let Err(e) = vault.mark_claim_submitted(&vault_id, tx_hash.clone()) {
            tracing::warn!(
                session = session_id,
                error = %e,
                "vault mark_claim_submitted after relay_claim broadcast failed",
            );
        }
    }

    Ok(RelayClaimSubmission {
        session_id,
        tx_hash,
        settlement_hash,
        receipt_seq: receipt.receipt.seq,
        current_epoch,
        relay_deadline,
    })
}
