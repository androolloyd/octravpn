//! Verify operator receipts against the pinned domain and local traffic ceiling,
//! persist the countersignature, and hand it back for durable operator delivery.
//! The current application requires both settlement legs to agree on bytes and
//! the independently quoted microOCT amount. Receipt signatures are checked by
//! the clients and operator; the AML checks its explicit claim/confirm fields.
//! Acknowledgement alone never marks a receipt as canonically settled.

use std::{path::Path, sync::Arc};

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    address::Address,
    control::{
        announce_opener_binding_payload, announce_signing_payload, AnnounceSessionRequest,
        AnnounceSessionResponse, PostReceiptResponse, ProposedReceipt, SessionStateResponse,
    },
    receipt::SignedReceipt,
    session::SessionId,
    sig::{verify, KeyPair},
    v3_calls::ContractCallBuilder,
};
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::{
    runner::{ActiveSession, Client},
    settle_state::{ArmChain, ArmEnvironment, ArmSubmission, SettleStateStore},
};

const BYTES_PER_MB: u64 = 1_048_576;

pub(crate) async fn settle_active(client: &Arc<Client>, active: ActiveSession) -> Result<()> {
    if client.relay_config().enabled {
        client
            .open_settle_state()?
            .record_proposed(&active.session_id)?;
    }

    let signed = receipt_for_active(client, &active).await?;

    // Open the durable store and compute net before the operator ACK. The
    // only step between ACK and Countersigned is the local durable write.
    let relay_prep = if client.relay_config().enabled {
        let net = relay_net(&active, signed.receipt.bytes_used);
        Some((client.open_settle_state()?, net))
    } else {
        None
    };

    let receipt_posted = match post_countersigned_receipt(
        client,
        &control_base(&active)?,
        &active.session_id,
        &signed,
    )
    .await
    {
        Ok(()) => {
            info!(settlement_hash = %signed.settlement_hash(), "countersigned receipt posted to exit");
            true
        }
        Err(error) => {
            warn!(%error, "countersigned receipt handback failed");
            false
        }
    };

    if let Some((store, net)) = relay_prep {
        if !receipt_posted {
            return Err(anyhow!(
                "relay receipt handback failed for session {}; not arming and not \
                 falling back to settle_confirm (wrong mechanism for the relay lane)",
                active.session_id.to_hex()
            ));
        }
        if net == 0 {
            info!(session = %active.session_id.to_hex(), bytes_used = signed.receipt.bytes_used,
                "relay net is 0; nothing to settle on chain, not arming");
            return Ok(());
        }
        store.record_countersigned(&active.session_id, &signed, net)?;
        let env = client.arm_environment();
        store
            .arm_if_countersigned(client.as_ref(), &env, &active.session_id)
            .await?;
        return Ok(());
    }

    submit_settle_confirm(client, &active, signed.receipt.bytes_used).await
}

async fn receipt_for_active(client: &Client, active: &ActiveSession) -> Result<SignedReceipt> {
    let exit = &active.exit;
    let proposed = fetch_proposed_receipt(client, &control_base(active)?, &active.session_id)
        .await
        .context("fetch proposed receipt from exit")?;

    if proposed.receipt.session_id != active.session_id {
        return Err(anyhow!(
            "operator proposed a receipt for a different session"
        ));
    }
    if exit.receipt_pubkey.0 == [0; 32] || proposed.node_pubkey != exit.receipt_pubkey {
        return Err(anyhow!(
            "operator receipt key does not match its authenticated advertisement"
        ));
    }
    if active
        .metered_bytes
        .is_some_and(|bytes| proposed.receipt.bytes_used > bytes)
    {
        return Err(anyhow!(
            "operator receipt exceeds locally observed session traffic"
        ));
    }

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

    Ok(signed)
}

/// The four-argument v3 confirmation caller owns the chain transaction. This
/// function performs the same pinned local receipt checks and handback first.
pub(crate) async fn countersign_active(
    client: &Client,
    active: &ActiveSession,
) -> Result<SignedReceipt> {
    let signed = receipt_for_active(client, active).await?;
    client.open_settle_state()?.record_countersigned(
        &active.session_id,
        &signed,
        relay_net(active, signed.receipt.bytes_used),
    )?;
    post_countersigned_receipt(client, &control_base(active)?, &active.session_id, &signed).await?;
    Ok(signed)
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
    let submitted =
        arm_recorded_session_from_store(client.as_ref(), &store, &env, &session_id).await?;
    print_arm_submission(&submitted);
    Ok(())
}

/// `settle refund` — explicit trigger for the funder-side refund watcher (also
/// runs at client boot). Refunds every durable session still RELAY_ARMED past
/// its deadline + margin (operator no-show), returning the deposit to the funder.
pub(crate) async fn refund_no_show(client: &Arc<Client>) -> Result<()> {
    if !client.relay_config().enabled {
        return Err(anyhow!(
            "`settle refund` requires [v3.relay].enabled = true in client.toml"
        ));
    }
    let store = client.open_settle_state()?;
    let env = client.arm_environment();
    let margin = client.relay_config().resolved_refund_margin_epochs();
    let summary = store.refund_pending(client.as_ref(), &env, margin).await?;
    println!(
        "relay refund scan: submitted={} refunded={} settled={}",
        summary.refund_submitted, summary.drained_refunded, summary.drained_settled
    );
    Ok(())
}

pub(crate) async fn arm_session_from_receipt(
    client: &Arc<Client>,
    session_id: SessionId,
    receipt_path: &Path,
    net: u64,
    relay_expiry_epochs: u64,
) -> Result<()> {
    if !client.relay_config().enabled {
        return Err(anyhow!(
            "`settle arm` requires [v3.relay].enabled = true in client.toml"
        ));
    }
    if net == 0 {
        return Err(anyhow!(
            "cannot arm relay session {}: net=0 (nothing owed); arm_relay requires net>0",
            session_id.to_hex()
        ));
    }
    let receipt = read_signed_receipt(receipt_path)?;
    validate_arm_receipt(client.as_ref(), &session_id, &receipt)?;
    let store = client.open_settle_state()?;
    let mut env = client.arm_environment();
    env.relay_expiry_epochs = relay_expiry_epochs;
    let submitted = prime_and_arm_recorded_session_from_store(
        client.as_ref(),
        &store,
        &env,
        &session_id,
        &receipt,
        net,
    )
    .await?;
    print_arm_submission(&submitted);
    Ok(())
}

fn read_signed_receipt(path: &Path) -> Result<SignedReceipt> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&raw).with_context(|| format!("decode SignedReceipt {}", path.display()))
}

fn validate_arm_receipt(
    client: &Client,
    session_id: &SessionId,
    receipt: &SignedReceipt,
) -> Result<()> {
    if receipt.receipt.session_id != *session_id {
        return Err(anyhow!(
            "receipt session_id {} does not match CLI session_id {}",
            receipt.receipt.session_id.to_hex(),
            session_id.to_hex()
        ));
    }
    if &receipt.receipt.context != client.receipt_context() {
        let expected = client.receipt_context();
        let got = &receipt.receipt.context;
        return Err(anyhow!(
            "receipt context mismatch: client expected program={} chain_id={} circle={:?}; \
             receipt has program={} chain_id={} circle={:?}",
            expected.program_addr.display(),
            expected.chain_id,
            expected.circle_id.as_ref().map(Address::display),
            got.program_addr.display(),
            got.chain_id,
            got.circle_id.as_ref().map(Address::display),
        ));
    }
    receipt.verify().context("verify countersigned receipt")?;
    Ok(())
}

fn prime_countersigned_receipt(
    store: &SettleStateStore,
    session_id: &SessionId,
    receipt: &SignedReceipt,
    net: u64,
) -> Result<()> {
    store.record_proposed(session_id)?;
    store.record_countersigned(session_id, receipt, net)
}

async fn prime_and_arm_recorded_session_from_store<C: ArmChain>(
    chain: &C,
    store: &SettleStateStore,
    env: &ArmEnvironment,
    session_id: &SessionId,
    receipt: &SignedReceipt,
    net: u64,
) -> Result<ArmSubmission> {
    prime_countersigned_receipt(store, session_id, receipt, net)?;
    arm_recorded_session_from_store(chain, store, env, session_id).await
}

async fn arm_recorded_session_from_store<C: ArmChain>(
    chain: &C,
    store: &SettleStateStore,
    env: &ArmEnvironment,
    session_id: &SessionId,
) -> Result<ArmSubmission> {
    store
        .arm_if_countersigned(chain, env, session_id)
        .await?
        .ok_or_else(|| {
            anyhow!(
                "session {} is not in durable Countersigned state",
                session_id.to_hex()
            )
        })
}

fn print_arm_submission(submitted: &ArmSubmission) {
    println!(
        "arm_relay: tx_hash = {} session_id = {} settlement_hash = {} net = {}",
        submitted.tx_hash, submitted.session_id, submitted.settlement_hash, submitted.net
    );
}

pub(crate) async fn reclaim(client: &Arc<Client>, raw_session_id: &str) -> Result<()> {
    let id = session_id_from_cli(raw_session_id)?
        .as_u64()
        .ok_or_else(|| anyhow!("v3 session id must fit uint64"))?;
    let fee = client
        .rpc()
        .recommended_fee(Some(client.application().operation()))
        .await?
        .recommended;
    let context = client.chain_context();
    let call = context.build_claim_no_show_call(id, fee, 0);
    let hash = context
        .submit_call(call)
        .await
        .map_err(|e| anyhow!("chain tx queue claim_no_show submit: {e}"))?;
    info!(hash = %hash, "claim_no_show submitted");
    Ok(())
}

async fn submit_settle_confirm(
    client: &Arc<Client>,
    active: &ActiveSession,
    bytes_used: u64,
) -> Result<()> {
    let fee = client
        .rpc()
        .recommended_fee(Some(client.application().operation()))
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
        "nonce": 0,
    });
    let hash = client
        .submit_application(call)
        .await
        .map_err(|e| anyhow!("chain tx queue settle_confirm submit: {e}"))?;
    info!(hash = %hash, session = sid_u64, bytes_used, "settle_confirm submitted");
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
        .submit_application(call)
        .await
        .map_err(|e| anyhow!("chain tx queue arm_relay submit: {e}"))
}

/// Build a `relay_refund(session_id)` call (opener refunds a no-show operator's
/// armed session after the deadline). Value is 0; the deposit is returned by the
/// program to the funder.
pub(crate) fn build_relay_refund_params(
    program_addr: &Address,
    wallet_addr: &Address,
    session_id_u64: u64,
    fee: u64,
) -> Value {
    ContractCallBuilder::new(program_addr.clone(), wallet_addr.clone()).relay_refund_call(
        session_id_u64,
        0,
        fee,
        0,
    )
}

pub(crate) async fn submit_refund(client: &Client, call: Value) -> Result<String> {
    client
        .submit_application(call)
        .await
        .map_err(|e| anyhow!("chain tx queue relay_refund submit: {e}"))
}

fn relay_net(active: &ActiveSession, bytes_used: u64) -> u64 {
    let price_per_mb = active.exit.price_per_mb;
    compute_relay_net(bytes_used, price_per_mb, active.deposit)
}

fn compute_relay_net(bytes_used: u64, price_per_mb: u64, deposit: u64) -> u64 {
    let raw = (bytes_used / BYTES_PER_MB).saturating_mul(price_per_mb);
    raw.min(deposit)
}

pub(crate) async fn announce_session_with_opener(
    client: &Client,
    active: &ActiveSession,
    opener: &KeyPair,
) -> Result<()> {
    let exit = &active.exit;
    let ctrl_endpoint = control_base(active)?;
    let client_wg_pubkey = crate::wireguard::public_key(&active.session_kp);
    let client_sig_payload = announce_signing_payload(
        &active.session_id,
        &active.session_kp.public,
        &client_wg_pubkey,
        &active.open_tx_hash,
    );
    let opener_sig_payload = announce_opener_binding_payload(
        &active.session_id,
        &active.session_kp.public,
        &client_wg_pubkey,
        &active.open_tx_hash,
    );
    let body = AnnounceSessionRequest {
        session_id: active.session_id.clone(),
        client_pubkey: active.session_kp.public,
        client_wg_pubkey,
        open_tx_hash: active.open_tx_hash.clone(),
        client_sig: active.session_kp.sign(&client_sig_payload),
        opener_pubkey: opener.public,
        opener_sig: opener.sign(&opener_sig_payload),
    };
    let resp = client
        .http()
        .post(format!("{ctrl_endpoint}/session"))
        .json(&body)
        .send()
        .await
        .context("announce session HTTP")?;
    if !resp.status().is_success() {
        return Err(ControlStatus(resp.status()).into());
    }
    let body: AnnounceSessionResponse = control_json(resp)
        .await
        .context("decode session announcement")?;
    if !body.accepted || body.node_pubkey != exit.receipt_pubkey {
        return Err(anyhow!(
            "operator rejected session or returned an unadvertised receipt key"
        ));
    }
    Ok(())
}

pub(crate) fn control_base(active: &ActiveSession) -> Result<String> {
    if let Some(endpoint) = &active.control_endpoint {
        return validate_control_endpoint(endpoint);
    }
    let exit = &active.exit;
    Ok(octravpn_core::control::base_url_for(
        &normalize_control_endpoint(&exit.endpoint),
    ))
}

pub(crate) fn validate_control_endpoint(endpoint: &str) -> Result<String> {
    let url = reqwest::Url::parse(endpoint).context("parse operator control endpoint")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(anyhow!(
            "operator control endpoint must be an HTTP(S) origin"
        ));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
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

#[derive(Debug, thiserror::Error)]
#[error("operator control status {0}")]
pub(crate) struct ControlStatus(pub reqwest::StatusCode);

pub(crate) async fn fetch_proposed_receipt(
    client: &Client,
    control_endpoint: &str,
    session_id: &SessionId,
) -> Result<ProposedReceipt> {
    let url = format!(
        "{}{}",
        control_endpoint,
        octravpn_core::control::path_state(session_id)
    );
    let resp = client
        .http()
        .get(&url)
        .send()
        .await
        .context("control-plane GET")?;
    if !resp.status().is_success() {
        return Err(ControlStatus(resp.status()).into());
    }
    let body: SessionStateResponse = control_json(resp).await.context("decode session state")?;
    body.proposed.ok_or_else(|| anyhow!("no proposed receipt"))
}

async fn post_countersigned_receipt(
    client: &Client,
    control_endpoint: &str,
    session_id: &SessionId,
    signed: &SignedReceipt,
) -> Result<()> {
    let url = format!(
        "{}{}",
        control_endpoint,
        octravpn_core::control::path_receipt(session_id)
    );
    let local_hash = signed.settlement_hash();
    // Native operators acknowledge after canonical inclusion. HTTP timeout or
    // 503 preserves this exact durable countersignature for idempotent retry.
    let mut attempts = 0;
    let resp = loop {
        let response = client
            .http()
            .post(&url)
            .json(signed)
            .timeout(std::time::Duration::from_secs(20))
            .send()
            .await;
        attempts += 1;
        match response {
            Ok(response) if response.status().is_server_error() && attempts < 4 => (),
            Ok(response) => break response,
            Err(_) if attempts < 4 => (),
            Err(error) => return Err(error).context("control-plane POST receipt"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    };
    if !resp.status().is_success() {
        return Err(anyhow!("control POST receipt status {}", resp.status()));
    }
    let body: PostReceiptResponse = control_json(resp)
        .await
        .context("decode receipt POST response")?;
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

async fn control_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T> {
    const LIMIT: usize = 1_048_576;
    if response
        .content_length()
        .is_some_and(|bytes| bytes > LIMIT as u64)
    {
        return Err(anyhow!("operator control response exceeds the byte limit"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read operator control response")?
    {
        if chunk.len() > LIMIT.saturating_sub(bytes.len()) {
            return Err(anyhow!("operator control response exceeds the byte limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).context("decode operator control response JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use octravpn_core::{
        receipt::{Receipt, ReceiptContext, CHAIN_ID_TEST},
        session::Blind,
        sig::KeyPair,
    };
    use parking_lot::Mutex;
    use serde_json::json;

    #[test]
    fn compute_relay_net_floors_to_mb_and_caps_to_deposit() {
        assert_eq!(compute_relay_net(BYTES_PER_MB - 1, 100, 1_000), 0);
        assert_eq!(compute_relay_net(2 * BYTES_PER_MB, 100, 1_000), 200);
        assert_eq!(compute_relay_net(20 * BYTES_PER_MB, 100, 1_500), 1_500);
    }

    #[derive(Default)]
    struct MockChain {
        fee_calls: Mutex<usize>,
        submit_calls: Mutex<Vec<Value>>,
    }

    #[async_trait]
    impl ArmChain for MockChain {
        async fn arm_fee(&self) -> Result<u64> {
            *self.fee_calls.lock() += 1;
            Ok(777)
        }

        async fn submit_arm_call(&self, call: Value) -> Result<String> {
            self.submit_calls.lock().push(call);
            Ok("arm-from-settler-test".to_string())
        }

        async fn get_session_status(&self, _session_id: u64) -> Result<u64> {
            Ok(0)
        }
    }

    fn addr(byte: u8) -> Address {
        Address::from_pubkey(&[byte; 32])
    }

    fn env(relay_expiry_epochs: u64) -> ArmEnvironment {
        ArmEnvironment {
            program_addr: addr(0x33),
            wallet_addr: addr(0x44),
            relay_expiry_epochs,
        }
    }

    fn store(dir: &Path) -> SettleStateStore {
        SettleStateStore::open(dir, &addr(0x44)).unwrap()
    }

    fn id(n: u64) -> SessionId {
        SessionId::from_u64(n)
    }

    fn signed(session_id: SessionId, seq: u64, bytes_used: u64) -> SignedReceipt {
        let client = KeyPair::from_secret_bytes(&[0x11; 32]);
        let node = KeyPair::from_secret_bytes(&[0x22; 32]);
        let ctx = ReceiptContext::v1_1(addr(0x33), CHAIN_ID_TEST);
        SignedReceipt::build(
            Receipt::new(ctx, session_id, seq, bytes_used, Blind::new([0x55; 32])),
            &client,
            &node,
        )
    }

    #[tokio::test]
    async fn from_receipt_primes_countersigned_then_arms() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(42);
        let receipt = signed(sid.clone(), 2, 4_096);
        let receipt_path = dir.path().join("receipt.json");
        std::fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
        let decoded = read_signed_receipt(&receipt_path).unwrap();
        let chain = MockChain::default();

        let out =
            prime_and_arm_recorded_session_from_store(&chain, &s, &env(333), &sid, &decoded, 3_000)
                .await
                .unwrap();

        assert_eq!(out.session_id, 42);
        assert_eq!(out.settlement_hash, receipt.settlement_hash());
        assert_eq!(out.net, 3_000);
        assert_eq!(
            s.state(&sid).unwrap(),
            Some(crate::settle_state::SettlementState::ArmSubmitted)
        );
        assert_eq!(s.arm_material(&sid).unwrap(), (receipt.clone(), 3_000));
        assert_eq!(*chain.fee_calls.lock(), 1);
        let calls = chain.submit_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["method"], "arm_relay");
        assert_eq!(
            calls[0]["params"],
            json!([42, receipt.settlement_hash(), 3_000, 333])
        );
    }

    #[tokio::test]
    async fn plain_arm_uses_pre_recorded_countersigned_session() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(43);
        let receipt = signed(sid.clone(), 1, 8_192);
        s.record_proposed(&sid).unwrap();
        s.record_countersigned(&sid, &receipt, 1_500).unwrap();
        let chain = MockChain::default();

        let out = arm_recorded_session_from_store(&chain, &s, &env(200), &sid)
            .await
            .unwrap();

        assert_eq!(out.session_id, 43);
        assert_eq!(out.settlement_hash, receipt.settlement_hash());
        assert_eq!(out.net, 1_500);
        assert_eq!(
            s.state(&sid).unwrap(),
            Some(crate::settle_state::SettlementState::ArmSubmitted)
        );
        let calls = chain.submit_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0]["params"],
            json!([43, receipt.settlement_hash(), 1_500, 200])
        );
    }
}
