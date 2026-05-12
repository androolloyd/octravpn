//! Settlement and reclaim handlers.
//!
//! Flow:
//!   1. GET /session/{id} on the exit node's control plane.
//!   2. Take the exit's signed receipt proposal.
//!   3. Verify the node sig.
//!   4. Add the client's session-key signature.
//!   5. Submit `settle_session` on chain with the dual-signed payload.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    control::{ProposedReceipt, SessionStateResponse},
    receipt::SignedReceipt,
    session::{RouteOpening, SessionId},
    sig::verify,
};
use serde_json::json;
use tracing::info;

use crate::runner::{ActiveSession, Client};

pub(crate) async fn settle_active(client: &Arc<Client>, active: ActiveSession) -> Result<()> {
    let openings: Vec<RouteOpening> = active
        .route
        .iter()
        .map(|h| RouteOpening {
            node_addr: h.validator.addr.clone(),
            blind: octravpn_core::session::Blind::new(h.blind),
            split_bps: h.split_bps,
        })
        .collect();

    let exit = active.route.last().ok_or_else(|| anyhow!("empty route"))?;
    let proposed = fetch_proposed_receipt(client, &exit.validator.endpoint, &active.session_id)
        .await
        .context("fetch proposed receipt from exit")?;

    // Verify the exit's signature first.
    let payload = proposed.receipt.signing_payload();
    verify(&proposed.node_pubkey, &payload, &proposed.node_sig)
        .context("verify exit's proposed-receipt signature")?;

    // Client adds its session-key signature.
    let client_sig = active.session_kp.sign(&payload);
    let signed = SignedReceipt {
        receipt: proposed.receipt,
        client_pubkey: active.session_kp.public,
        client_sig,
        node_pubkey: proposed.node_pubkey,
        node_sig: proposed.node_sig,
    };
    signed.verify().context("dual-sig self-verify")?;

    submit_settle(client, &active, &openings, &signed).await
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

async fn submit_settle(
    client: &Arc<Client>,
    active: &ActiveSession,
    openings: &[RouteOpening],
    signed: &SignedReceipt,
) -> Result<()> {
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
        "method": "settle_session",
        "params": [
            hex::encode(active.session_id.as_bytes()),
            signed.receipt.seq,
            signed.receipt.bytes_used,
            hex::encode(signed.receipt.blind.as_bytes()),
            hex::encode(signed.client_sig.0),
            hex::encode(signed.node_sig.0),
            openings.iter().map(|o| json!({
                "node_addr": o.node_addr.display(),
                "blind": hex::encode(o.blind.as_bytes()),
                "split_bps": o.split_bps,
            })).collect::<Vec<_>>(),
        ],
        "value": 0,
        "fee": fee,
        "nonce": nonce,
    });
    let signed_tx = crate::runner::sign_call(client.wallet_kp(), call)?;
    let r = client.rpc().submit(&signed_tx).await?;
    info!(hash = %r.hash, "settle_session submitted");
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
