//! Client-side settlement handler.
//!
//! Two-tx flow (v1 AML):
//!   1. GET /session/{id} on the exit's control plane to learn the
//!      exit's claimed `bytes_used` (informational; the AML does not
//!      look at the receipt signatures).
//!   2. Verify the exit's sig over its proposed receipt — that's
//!      our local sanity check, not a chain-side enforcement.
//!   3. Submit `settle_confirm(session_id, bytes_used)` on chain.
//!      If our local count matches the exit's, settlement applies.
//!      If we want to dispute, we submit a different value: the AML
//!      records `SettleDispute` and leaves the session open.
//!
//! Equivocation: the exit is responsible for submitting its own
//! `settle_claim`. If the exit ever submits two different claims
//! for the same session, the AML slashes the operator's bond
//! automatically. The client never has to do anything about it.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    control::{ProposedReceipt, SessionStateResponse},
    receipt::SignedReceipt,
    session::SessionId,
    sig::verify,
};
use serde_json::json;
use tracing::info;

use crate::runner::{ActiveSession, Client};

pub(crate) async fn settle_active(client: &Arc<Client>, active: ActiveSession) -> Result<()> {
    let exit = active.route.last().ok_or_else(|| anyhow!("empty route"))?;
    let proposed = fetch_proposed_receipt(client, &exit.validator.endpoint, &active.session_id)
        .await
        .context("fetch proposed receipt from exit")?;

    // Local sanity: verify the exit's signature over its proposed
    // receipt. The AML doesn't see this signature, but if the exit
    // is sending us garbage we want to know before we submit a
    // confirm against bogus bytes.
    let payload = proposed.receipt.signing_payload();
    verify(&proposed.node_pubkey, &payload, &proposed.node_sig)
        .context("verify exit's proposed-receipt signature")?;

    // The session-key signature is still useful for off-chain
    // dispute resolution; build the full signed receipt and stash
    // it locally even though we don't submit it.
    let client_sig = active.session_kp.sign(&payload);
    let signed = SignedReceipt {
        receipt: proposed.receipt,
        client_pubkey: active.session_kp.public,
        client_sig,
        node_pubkey: proposed.node_pubkey,
        node_sig: proposed.node_sig,
    };
    signed.verify().context("dual-sig self-verify")?;

    submit_settle_confirm(client, &active, signed.receipt.bytes_used).await
}

pub(crate) async fn settle(_client: &Arc<Client>, _session_id: &str) -> Result<()> {
    Err(anyhow!(
        "stand-alone settle not yet supported; keep `connect` running until clean shutdown"
    ))
}

pub(crate) async fn reclaim(client: &Arc<Client>, session_id_hex: &str) -> Result<()> {
    let id = SessionId::from_hex(session_id_hex).ok_or_else(|| anyhow!("bad session id hex"))?;
    let bal = client.rpc().balance(client.wallet_addr()).await?;
    let nonce = bal.pending_nonce.max(bal.nonce);
    let fee = client
        .rpc()
        .recommended_fee(Some("contract_call"))
        .await?
        .recommended;
    let call = json!({
        "kind": "contract_call",
        "from": client.wallet_addr().display(),
        "to": client.program_addr().display(),
        "method": "claim_no_show",
        "params": [hex::encode(id.as_bytes())],
        "value": 0,
        "fee": fee,
        "nonce": nonce,
    });
    let signed = crate::runner::sign_call(client.wallet_kp(), call)?;
    let r = client.rpc().submit(&signed).await?;
    info!(hash = %r.hash, "claim_no_show submitted");
    Ok(())
}

async fn submit_settle_confirm(
    client: &Arc<Client>,
    active: &ActiveSession,
    bytes_used: u64,
) -> Result<()> {
    let bal = client.rpc().balance(client.wallet_addr()).await?;
    let nonce = bal.pending_nonce.max(bal.nonce);
    let fee = client
        .rpc()
        .recommended_fee(Some("contract_call"))
        .await?
        .recommended;
    let sid_u64 = active
        .session_id
        .as_u64()
        .ok_or_else(|| anyhow!("v1 session ids are u64; got something else"))?;
    let call = json!({
        "kind": "contract_call",
        "from": client.wallet_addr().display(),
        "to": client.program_addr().display(),
        "method": "settle_confirm",
        "params": [sid_u64, bytes_used],
        "value": 0,
        "fee": fee,
        "nonce": nonce,
    });
    let signed_tx = crate::runner::sign_call(client.wallet_kp(), call)?;
    let r = client.rpc().submit(&signed_tx).await?;
    info!(hash = %r.hash, session = sid_u64, bytes_used, "settle_confirm submitted");
    Ok(())
}

async fn fetch_proposed_receipt(
    client: &Arc<Client>,
    wg_endpoint: &str,
    session_id: &SessionId,
) -> Result<ProposedReceipt> {
    let url = octravpn_core::control::session_state_url(wg_endpoint, session_id);
    let resp = client
        .http()
        .get(&url)
        .send()
        .await
        .context("control-plane GET")?;
    if !resp.status().is_success() {
        return Err(anyhow!("control GET status {}", resp.status()));
    }
    let body: SessionStateResponse = resp.json().await.context("decode session state")?;
    body.proposed.ok_or_else(|| anyhow!("no proposed receipt"))
}
