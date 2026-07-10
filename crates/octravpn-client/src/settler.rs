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

use std::{path::Path, sync::Arc};

use anyhow::{anyhow, Context, Result};
use octravpn_core::{
    address::Address,
    control::{
        announce_opener_binding_payload, announce_signing_payload, AnnounceSessionRequest,
        PostReceiptResponse, ProposedReceipt, SessionStateResponse,
    },
    receipt::SignedReceipt,
    session::SessionId,
    sig::verify,
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

    // AUDIT #4 (I1): open the durable store + compute net BEFORE the POST, so the
    // ONLY step between the operator's ACK (POST -> Ok, receipt fsynced in their
    // vault) and our durable Countersigned record is a single local write. This
    // shrinks the crash window where the operator holds the receipt but we're
    // stuck at Proposed and would never arm.
    let relay_prep = if client.relay_config().enabled {
        let net = relay_net(&active, signed.receipt.bytes_used);
        Some((client.open_settle_state()?, net))
    } else {
        None
    };

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

    if receipt_posted {
        if let Some((store, net)) = relay_prep {
            // Only step after the ACK: the local durable write, then arm.
            store.record_countersigned(&active.session_id, &signed, net)?;
            let env = client.arm_environment();
            store
                .arm_if_countersigned(client.as_ref(), &env, &active.session_id)
                .await?;
            return Ok(());
        }
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
    let submitted =
        arm_recorded_session_from_store(client.as_ref(), &store, &env, &session_id).await?;
    print_arm_submission(&submitted);
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

pub(crate) async fn reclaim(client: &Arc<Client>, session_id_hex: &str) -> Result<()> {
    let id = SessionId::from_hex(session_id_hex).ok_or_else(|| anyhow!("bad session id hex"))?;
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
        "nonce": 0,
    });
    let hash = client
        .chain_tx_queue()
        .submit(call)
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
        "nonce": 0,
    });
    let hash = client
        .chain_tx_queue()
        .submit(call)
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
        opener_pubkey: client.wallet_kp().public,
        opener_sig: client.wallet_kp().sign(&opener_sig_payload),
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
