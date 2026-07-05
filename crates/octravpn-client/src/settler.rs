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
    address::Address,
    control::{
        announce_signing_payload, AnnounceSessionRequest, PostReceiptResponse, ProposedReceipt,
        SessionStateResponse,
    },
    receipt::SignedReceipt,
    rpc::next_nonce,
    session::SessionId,
    sig::verify,
    v3_calls::ContractCallBuilder,
};
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::runner::{ActiveSession, Client};

const BYTES_PER_MB: u64 = 1_048_576;

pub(crate) async fn settle_active(client: &Arc<Client>, active: ActiveSession) -> Result<()> {
    if client.relay_config().enabled {
        client
            .open_settle_state()?
            .record_proposed(&active.session_id)?;
    }

    let exit = active.route.last().ok_or_else(|| anyhow!("empty route"))?;
    let proposed = fetch_proposed_receipt(client, &exit.validator.endpoint, &active.session_id)
        .await
        .context("fetch proposed receipt from exit")?;

    // v1.2 P1-5 guard: the receipt the exit sent us must bind the
    // same `(program_addr, chain_id, circle_id)` we configured locally.
    // If the operator is on a different program / chain / circle, the
    // receipt is not one we'd ever want to co-sign — refuse it before
    // even checking the sig. Catches a misconfigured operator and the
    // cross-deploy replay attack at the same point.
    let expected = client.receipt_context();
    let got = &proposed.receipt.context;
    if got != expected {
        return Err(anyhow!(
            "receipt context mismatch: client expected program={} chain_id={} circle={:?}; \
             operator sent program={} chain_id={} circle={:?}",
            expected.program_addr.display(),
            expected.chain_id,
            expected.circle_id.as_ref().map(Address::display),
            got.program_addr.display(),
            got.chain_id,
            got.circle_id.as_ref().map(Address::display),
        ));
    }

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
    // HFHE-2: forward whatever shadow-blob fields the operator
    // attached on its side. The client doesn't introspect them — it
    // just carries them through so the locally-stashed
    // `SignedReceipt` stays bit-identical to what the operator
    // signed. When the operator is on the no-sidecar path, all
    // three remain None and the receipt JSON drops the fields
    // entirely via serde skip_serializing_if.
    let signed = SignedReceipt {
        receipt: proposed.receipt,
        client_pubkey: active.session_kp.public,
        client_sig,
        node_pubkey: proposed.node_pubkey,
        node_sig: proposed.node_sig,
        enc_bytes_used: proposed.enc_bytes_used.clone(),
        enc_net: proposed.enc_net.clone(),
        pvac_zero_proof: proposed.pvac_zero_proof.clone(),
    };
    signed.verify().context("dual-sig self-verify")?;

    let receipt_posted = match post_countersigned_receipt(
        client,
        &exit.validator.endpoint,
        &active.session_id,
        &signed,
    )
    .await
    {
        Ok(()) => {
            info!(
                settlement_hash = %signed.settlement_hash(),
                "countersigned receipt posted to exit"
            );
            true
        }
        Err(e) => {
            warn!(
                error = %e,
                "countersigned receipt handback failed; falling back to v3 settle_confirm"
            );
            false
        }
    };

    if receipt_posted && client.relay_config().enabled {
        let net = relay_net(&active, signed.receipt.bytes_used);
        let store = client.open_settle_state()?;
        store.record_countersigned(&active.session_id, &signed, net)?;
        let env = client.arm_environment();
        store
            .arm_if_countersigned(client.as_ref(), &env, &active.session_id)
            .await?;
        return Ok(());
    }

    submit_settle_confirm(client, &active, signed.receipt.bytes_used).await
}

pub(crate) async fn arm_recorded_session(
    client: &Arc<Client>,
    session_id: SessionId,
) -> Result<()> {
    if !client.relay_config().enabled {
        return Err(anyhow!(
            "`settle arm` requires [v3.relay].enabled = true in client.toml"
        ));
    }
    let store = client.open_settle_state()?;
    let env = client.arm_environment();
    match store
        .arm_if_countersigned(client.as_ref(), &env, &session_id)
        .await?
    {
        Some(submitted) => {
            println!(
                "arm_relay: tx_hash = {} session_id = {} settlement_hash = {} net = {}",
                submitted.tx_hash, submitted.session_id, submitted.settlement_hash, submitted.net
            );
            Ok(())
        }
        None => Err(anyhow!(
            "session {} is not in durable Countersigned state",
            session_id.to_hex()
        )),
    }
}

pub(crate) async fn reclaim(client: &Arc<Client>, session_id_hex: &str) -> Result<()> {
    let id = SessionId::from_hex(session_id_hex).ok_or_else(|| anyhow!("bad session id hex"))?;
    let bal = client.rpc().balance(client.wallet_addr()).await?;
    let nonce = next_nonce(&bal);
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
    let nonce = next_nonce(&bal);
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

pub(crate) fn build_arm_params(
    program_addr: &Address,
    wallet_addr: &Address,
    session_id_u64: u64,
    settlement_hash: &str,
    net: u64,
    relay_expiry_epochs: u64,
    fee: u64,
) -> Value {
    ContractCallBuilder::new(program_addr.clone(), wallet_addr.clone()).arm_relay_call(
        session_id_u64,
        settlement_hash,
        net,
        relay_expiry_epochs,
        0,
        fee,
        0,
    )
}

pub(crate) async fn submit_arm(client: &Client, call: Value) -> Result<String> {
    client
        .chain_tx_queue()
        .submit(call)
        .await
        .map_err(|e| anyhow!("chain tx queue arm_relay submit: {e}"))
}

fn relay_net(active: &ActiveSession, bytes_used: u64) -> u64 {
    let price_per_mb = active
        .route
        .last()
        .map(|hop| hop.validator.price_per_mb)
        .unwrap_or(0);
    compute_relay_net(bytes_used, price_per_mb, active.deposit)
}

fn compute_relay_net(bytes_used: u64, price_per_mb: u64, deposit: u64) -> u64 {
    let raw = (bytes_used / BYTES_PER_MB).saturating_mul(price_per_mb);
    raw.min(deposit)
}

pub(crate) async fn announce_session_to_exit(
    client: &Arc<Client>,
    active: &ActiveSession,
) -> Result<()> {
    let exit = active.route.last().ok_or_else(|| anyhow!("empty route"))?;
    let ctrl_endpoint =
        octravpn_core::control::base_url_for(&normalize_control_endpoint(&exit.validator.endpoint));
    let client_wg_secret = octravpn_core::util::derive_subkey(
        &active.session_kp.public.0,
        octravpn_core::util::DOMAIN_NOISE,
    );
    let client_wg_pubkey =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(client_wg_secret))
            .to_bytes();
    let body = AnnounceSessionRequest {
        session_id: active.session_id.clone(),
        client_pubkey: active.session_kp.public,
        client_wg_pubkey,
        open_tx_hash: active.open_tx_hash.clone(),
        client_sig: active.session_kp.sign(&announce_signing_payload(
            &active.session_id,
            &active.session_kp.public,
            &client_wg_pubkey,
            &active.open_tx_hash,
        )),
    };
    let resp = client
        .http()
        .post(format!("{ctrl_endpoint}/session"))
        .json(&body)
        .send()
        .await
        .context("announce session HTTP")?;
    if !resp.status().is_success() {
        return Err(anyhow!("exit announce: status {}", resp.status()));
    }
    Ok(())
}

pub(crate) fn session_id_from_cli(raw: &str) -> Result<SessionId> {
    if let Ok(id) = raw.parse::<u64>() {
        return Ok(SessionId::from_u64(id));
    }
    SessionId::from_hex(raw).ok_or_else(|| anyhow!("bad session id: expected decimal u64 or hex"))
}

pub(crate) fn normalize_control_endpoint(endpoint: &str) -> String {
    endpoint
        .trim()
        .strip_prefix("wg://")
        .unwrap_or_else(|| endpoint.trim())
        .trim_end_matches('/')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_relay_net_floors_to_mb_and_caps_to_deposit() {
        assert_eq!(compute_relay_net(BYTES_PER_MB - 1, 100, 1_000), 0);
        assert_eq!(compute_relay_net(2 * BYTES_PER_MB, 100, 1_000), 200);
        assert_eq!(compute_relay_net(20 * BYTES_PER_MB, 100, 1_500), 1_500);
    }
}

async fn fetch_proposed_receipt(
    client: &Arc<Client>,
    wg_endpoint: &str,
    session_id: &SessionId,
) -> Result<ProposedReceipt> {
    let endpoint = normalize_control_endpoint(wg_endpoint);
    let url = octravpn_core::control::session_state_url(&endpoint, session_id);
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

async fn post_countersigned_receipt(
    client: &Arc<Client>,
    wg_endpoint: &str,
    session_id: &SessionId,
    signed: &SignedReceipt,
) -> Result<()> {
    let endpoint = normalize_control_endpoint(wg_endpoint);
    let url = octravpn_core::control::receipt_url(&endpoint, session_id);
    let local_hash = signed.settlement_hash();
    let resp = client
        .http()
        .post(&url)
        .json(signed)
        .send()
        .await
        .context("control-plane POST receipt")?;
    if !resp.status().is_success() {
        return Err(anyhow!("control POST receipt status {}", resp.status()));
    }
    let body: PostReceiptResponse = resp.json().await.context("decode receipt POST response")?;
    if !body.accepted {
        return Err(anyhow!("operator rejected countersigned receipt"));
    }
    if body.settlement_hash != local_hash {
        return Err(anyhow!(
            "settlement_hash mismatch: local={} operator={}",
            local_hash,
            body.settlement_hash
        ));
    }
    Ok(())
}
