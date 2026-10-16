use anyhow::{anyhow, bail, Context, Result};
use octravpn_core::{
    address::Address,
    control::{announce_opener_binding_payload, announce_signing_payload, AnnounceSessionRequest},
    receipt::{ReceiptContext, SignedReceipt},
    session::SessionId,
    sig::{verify, PublicKey, Signature},
    tx_signer::canonical_tx_from_call,
    v3_calls::Application,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bundle {
    pub version: u32,
    pub sessions: Vec<Binding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub session_id: SessionId,
    pub opening_transaction: Value,
    pub announce: AnnounceSessionRequest,
}

pub(super) fn authenticate(
    binding: &Binding,
    receipt: &SignedReceipt,
    application: Application,
    context: &ReceiptContext,
    wallet: &Address,
) -> Result<()> {
    if receipt.receipt.session_id != binding.session_id || receipt.receipt.context != *context {
        bail!("receipt session or deployment domain differs");
    }
    for public in [
        receipt.client_pubkey,
        receipt.node_pubkey,
        binding.announce.opener_pubkey,
    ] {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public.0)
            .context("invalid evidence public key")?;
        if key.is_weak() {
            bail!("weak evidence public key");
        }
    }
    receipt
        .verify()
        .context("receipt signatures do not authenticate the stored domain")?;
    let opening = &binding.opening_transaction;
    if opening.get("kind").is_some() {
        bail!("opening evidence must be an original canonical signed envelope");
    }
    let tx = canonical_tx_from_call(opening).map_err(|error| anyhow!(error))?;
    if tx.op_type != application.operation() {
        bail!("signed opening operation does not match configured application");
    }
    if tx.to != context.program_addr.display()
        || tx.from != wallet.display()
        || !tx.timestamp.is_finite()
    {
        bail!("signed opening target or funder does not match configured deployment");
    }
    let encoded_key = opening
        .get("public_key")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("signed opening public_key missing"))?;
    let encoded_sig = opening
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("signed opening signature missing"))?;
    let public = PublicKey(decode::<32>(encoded_key)?);
    let signature = Signature(decode::<64>(encoded_sig)?);
    if Address::from_pubkey(&public.0) != *wallet || public != binding.announce.opener_pubkey {
        bail!("opening and announcement are not signed by this wallet");
    }
    verify(&public, tx.signing_preimage().as_bytes(), &signature)
        .context("opening transaction signature invalid")?;
    let hash = tx.tx_hash(encoded_sig, Some(encoded_key));
    let announce = &binding.announce;
    if announce.session_id != binding.session_id
        || announce.client_pubkey != receipt.client_pubkey
        || announce.open_tx_hash != hash
    {
        bail!("wallet announcement does not bind this receipt session to the signed opening");
    }
    verify(
        &announce.client_pubkey,
        &announce_signing_payload(
            &announce.session_id,
            &announce.client_pubkey,
            &announce.client_wg_pubkey,
            &announce.open_tx_hash,
        ),
        &announce.client_sig,
    )
    .context("announcement client signature invalid")?;
    verify(
        &announce.opener_pubkey,
        &announce_opener_binding_payload(
            &announce.session_id,
            &announce.client_pubkey,
            &announce.client_wg_pubkey,
            &announce.open_tx_hash,
        ),
        &announce.opener_sig,
    )
    .context("announcement funder signature invalid")?;
    crate::wireguard::validate_peer_key(announce.client_wg_pubkey)?;
    let method = tx
        .encrypted_data
        .as_deref()
        .ok_or_else(|| anyhow!("signed opening method missing"))?;
    if !matches!(method, "open_session" | "open_session_from_treasury") {
        bail!("signed transaction is not a session opening");
    }
    let params: Value = serde_json::from_str(
        tx.message
            .as_deref()
            .ok_or_else(|| anyhow!("signed opening arguments missing"))?,
    )?;
    let params = params
        .as_array()
        .ok_or_else(|| anyhow!("signed opening arguments must be an array"))?;
    if params.len() != 3 {
        bail!("signed opening argument count differs");
    }
    let circle = context
        .circle_id
        .as_ref()
        .ok_or_else(|| anyhow!("legacy receipt has no Circle domain"))?;
    if params[1].as_str() != Some(circle.display()) {
        bail!("signed opening Circle differs from the signed receipt domain");
    }
    uint(&params[0])?;
    let max_pay = uint(&params[2])?;
    if max_pay == 0
        || (method == "open_session" && tx.amount < max_pay)
        || (method == "open_session_from_treasury" && tx.amount != 0)
    {
        bail!("signed opening funding arguments are inconsistent");
    }
    Ok(())
}

fn uint(value: &Value) -> Result<u64> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    let text = value
        .as_str()
        .ok_or_else(|| anyhow!("opening integer missing"))?;
    let number: u64 = text.parse()?;
    if number.to_string() != text {
        bail!("opening integer is not canonical decimal");
    }
    Ok(number)
}

fn decode<const N: usize>(encoded: &str) -> Result<[u8; N]> {
    let decoded =
        octravpn_core::b64::decode(encoded).map_err(|error| anyhow!("evidence base64: {error}"))?;
    let bytes: [u8; N] = decoded
        .try_into()
        .map_err(|_| anyhow!("evidence byte length must be {N}"))?;
    if octravpn_core::b64::encode(bytes) != encoded {
        bail!("evidence base64 is not canonical");
    }
    Ok(bytes)
}
