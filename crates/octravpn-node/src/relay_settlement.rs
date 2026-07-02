//! v4 relay-settlement operator caller path.
//!
//! The long-lived daemon owns the durable receipt vault, while the v3
//! chain context owns signing/submission. This module keeps the money
//! path small: load the vaulted receipt, verify the session is still
//! `RELAY_ARMED` and inside its claim window, then reveal the exact
//! `SignedReceipt::settlement_preimage()` on chain.

use anyhow::{anyhow, bail, Context, Result};
use octravpn_core::{receipt_vault::ReceiptVault, session::SessionId};

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
) -> Result<RelayClaimSubmission> {
    let vault_id = SessionId::from_u64(session_id);
    let receipt = vault
        .get(&vault_id)
        .ok_or_else(|| anyhow!("no vaulted receipt for session {session_id}"))?;

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
    if current_epoch >= relay_deadline {
        bail!(
            "relay claim window elapsed for session {session_id}: epoch={current_epoch} deadline={relay_deadline}"
        );
    }

    let settlement_hash = receipt.settlement_hash();
    let preimage = receipt.settlement_preimage();
    let nonce = ctx.nonce().await.context("nonce before relay_claim")?;
    let fee = ctx.fee_or_fallback("contract_call").await;
    let call = ctx.build_relay_claim_call(session_id, &preimage, fee, nonce);
    let signed = ctx.sign_call(call)?;
    let tx_hash = ctx
        .submit_signed_tx(&signed)
        .await
        .context("submit relay_claim")?;

    Ok(RelayClaimSubmission {
        session_id,
        tx_hash,
        settlement_hash,
        receipt_seq: receipt.receipt.seq,
        current_epoch,
        relay_deadline,
    })
}
