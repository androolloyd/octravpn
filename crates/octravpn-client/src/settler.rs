//! Settlement and reclaim handlers.
//!
//! The runner stashes an `ActiveSession` while the tunnel is up; on
//! shutdown we read it out and call `settle_active`. We fetch the latest
//! dual-signed receipt from the exit node's HTTP control plane, then
//! submit `settle_session` on chain with the route openings.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    receipt::{Receipt, SignedReceipt},
    session::{RouteOpening, SessionId},
    sig::KeyPair,
};
use serde_json::json;
use tracing::info;

use crate::runner::{ActiveSession, Client};

pub async fn settle_active(client: &Arc<Client>, active: ActiveSession) -> Result<()> {
    let openings: Vec<RouteOpening> = active
        .route
        .iter()
        .map(|h| RouteOpening {
            node_addr: h.validator.addr.clone(),
            blind: h.blind,
            split_bps: h.split_bps,
        })
        .collect();

    let exit = active
        .route
        .last()
        .ok_or_else(|| anyhow!("empty route"))?;
    let signed_receipt = fetch_latest_receipt(&exit.validator.endpoint, &active.session_id)
        .await
        .context("fetch latest signed receipt from exit")?;
    signed_receipt.verify().context("verify dual-sig")?;

    submit_settle(client, &active, &openings, &signed_receipt).await
}

pub async fn settle(_client: &Arc<Client>, _session_id: &str) -> Result<()> {
    Err(anyhow!(
        "stand-alone settle not yet supported; keep `connect` running until clean shutdown"
    ))
}

pub async fn reclaim(client: &Arc<Client>, session_id_hex: &str) -> Result<()> {
    let id = SessionId::from_hex(session_id_hex)
        .ok_or_else(|| anyhow!("bad session id hex"))?;
    let bal = client.rpc().balance(client.wallet_addr()).await?;
    let nonce = bal.pending_nonce.max(bal.nonce);
    let fee = client
        .rpc()
        .recommended_fee(Some("contract_call"))
        .await?
        .recommended;
    let call = json!({
        "kind": "contract_call",
        "from": client.wallet_addr().display,
        "to": client.program_addr().display,
        "method": "claim_no_show",
        "params": [hex::encode(id.0)],
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
        "from": client.wallet_addr().display,
        "to": client.program_addr().display,
        "method": "settle_session",
        "params": [
            hex::encode(active.session_id.0),
            signed.receipt.seq,
            signed.receipt.bytes_used,
            hex::encode(signed.receipt.blind),
            hex::encode(signed.client_sig.0),
            hex::encode(signed.node_sig.0),
            openings.iter().map(|o| json!({
                "node_addr": o.node_addr.display,
                "blind": hex::encode(o.blind),
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

async fn fetch_latest_receipt(
    wg_endpoint: &str,
    session_id: &SessionId,
) -> Result<SignedReceipt> {
    let host = wg_endpoint
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(wg_endpoint);
    let url = format!("http://{host}:51821/session/{}", session_id.to_hex());
    let resp = reqwest::get(&url).await.context("control-plane GET")?;
    if !resp.status().is_success() {
        return Err(anyhow!("control GET status {}", resp.status()));
    }
    let body: octravpn_core::control::SessionStateResponse =
        resp.json().await.context("decode session state")?;
    body.latest
        .ok_or_else(|| anyhow!("no receipts collected during session"))
}

/// Submit a single client-signed receipt to the exit node and return the
/// node's co-signed version.
pub async fn push_receipt(
    wg_endpoint: &str,
    receipt: Receipt,
    session_kp: &KeyPair,
) -> Result<SignedReceipt> {
    let host = wg_endpoint
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(wg_endpoint);
    let payload = receipt.signing_payload();
    let client_sig = session_kp.sign(&payload);
    let req = octravpn_core::control::SubmitReceiptRequest {
        receipt: receipt.clone(),
        client_pubkey: session_kp.public,
        client_sig,
    };
    let url = format!("http://{host}:51821/session/{}/receipt", receipt.session_id.to_hex());
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&req)
        .send()
        .await
        .context("push receipt")?;
    if !resp.status().is_success() {
        return Err(anyhow!("push receipt status {}", resp.status()));
    }
    let body: octravpn_core::control::SubmitReceiptResponse =
        resp.json().await.context("decode submit response")?;
    Ok(body.signed)
}
