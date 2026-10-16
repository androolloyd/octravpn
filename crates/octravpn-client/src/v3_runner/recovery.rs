//! Bounded reconnection of the existing escrow and identities. This module has
//! no funding or transaction-submission path.
use super::{
    bail, fetch_operator_policy, info, opening_session_id, settler, warn, ActiveSession,
    ChainCtxV3, Client, Context, Duration, OperatorPolicy, PublicKey, Result, SessionId,
};
use crate::wireguard::recovery::Control;
use octravpn_core::{control::ProposedReceipt, receipt::ReceiptContext, sig::verify};
use tokio::time::{timeout, timeout_at, Instant};

#[derive(Debug, thiserror::Error)]
#[error("existing VPN session is terminal: {0}")]
struct Closed(&'static str);
fn closed(reason: &'static str) -> anyhow::Error {
    Closed(reason).into()
}
fn terminal(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.is::<Closed>()
            || cause
                .downcast_ref::<settler::ControlStatus>()
                .is_some_and(|status| matches!(status.0.as_u16(), 400 | 401 | 403 | 409))
    })
}
fn proposal(
    context: &ReceiptContext,
    session: &SessionId,
    key: PublicKey,
    proposed: &ProposedReceipt,
    prior: Option<(u64, u64)>,
) -> Result<(u64, u64)> {
    if &proposed.receipt.session_id != session
        || proposed.node_pubkey != key
        || &proposed.receipt.context != context
    {
        return Err(closed("operator changed session, receipt key or domain"));
    }
    verify(
        &proposed.node_pubkey,
        &proposed.receipt.signing_payload(),
        &proposed.node_sig,
    )
    .map_err(|_| closed("invalid operator receipt signature"))?;
    let current = (proposed.receipt.seq, proposed.receipt.bytes_used);
    if prior.is_some_and(|old| current.0 <= old.0 || current.1 < old.1) {
        return Err(closed("signed receipt sequence or byte floor regressed"));
    }
    Ok(current)
}
async fn open(
    ctx: &ChainCtxV3<'_>,
    client: &Client,
    active: &ActiveSession,
    anchor: &str,
    policy: &OperatorPolicy,
    tailnet: u64,
) -> Result<()> {
    let sid = active
        .session_id
        .as_u64()
        .context("application session must be uint")?;
    if ctx.get_session_status_strict(sid).await? != 0 {
        return Err(closed("settled, refunded or otherwise closed"));
    }
    if ctx.session_policy_root(sid).await? != anchor {
        return Err(closed("opening policy anchor changed"));
    }
    if ctx
        .view("get_session_opener", &[serde_json::json!(sid)])
        .await?
        .as_str()
        != Some(ctx.wallet_addr().display())
        || ctx
            .view("get_session_exit", &[serde_json::json!(sid)])
            .await?
            .as_str()
            != Some(active.exit.addr.display())
    {
        return Err(closed("opening wallet or operator changed"));
    }
    match ctx
        .view("get_claim_net_set", &[serde_json::json!(sid)])
        .await?
        .as_u64()
    {
        Some(0) => (),
        Some(1) => return Err(closed("operator already fixed settlement")),
        _ => return Err(closed("operator claim flag is malformed")),
    }
    if ctx
        .get_circle_receipt_pubkey(active.exit.addr.display())
        .await?
        != active.exit.receipt_pubkey
    {
        return Err(closed("registered receipt key changed"));
    }
    let receipt = client
        .rpc()
        .raw_call("contract_receipt", serde_json::json!([active.open_tx_hash]))
        .await?;
    if opening_session_id(
        &receipt,
        client.program_addr().display(),
        tailnet,
        active.exit.addr.display(),
        active.deposit,
    )? != sid
    {
        return Err(closed("original canonical opening changed"));
    }
    let loaded = fetch_operator_policy(ctx, active.exit.addr.display(), anchor).await?;
    if &loaded != policy {
        return Err(closed("immutable opening policy changed"));
    }
    Ok(())
}

pub(super) async fn heartbeat(
    ctx: &ChainCtxV3<'_>,
    client: &Client,
    active: &ActiveSession,
    anchor: &str,
    policy: &OperatorPolicy,
    tailnet: u64,
    mut control: Control,
) -> Result<()> {
    let endpoint = settler::control_base(active)?;
    let mut timer = tokio::time::interval(Duration::from_secs(15));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut prior = None;
    loop {
        let transport_failed =
            tokio::select! {_=timer.tick()=>false,result=control.fault()=>{result?;true}};
        if !transport_failed {
            let result = timeout(Duration::from_secs(5), async {
                if ctx
                    .get_session_status_strict(
                        active
                            .session_id
                            .as_u64()
                            .context("application session must be uint")?,
                    )
                    .await?
                    != 0
                {
                    return Err(closed("settled, refunded or otherwise closed"));
                }
                let value =
                    settler::fetch_proposed_receipt(client, &endpoint, &active.session_id).await?;
                proposal(
                    client.receipt_context(),
                    &active.session_id,
                    active.exit.receipt_pubkey,
                    &value,
                    prior,
                )
            })
            .await;
            match result {
                Ok(Ok(current)) => {
                    prior = Some(current);
                    continue;
                }
                Ok(Err(error)) if terminal(&error) => {
                    control.pause();
                    return Err(error);
                }
                failure => warn!(
                    ?failure,
                    "existing VPN session control unavailable; pausing for authenticated recovery"
                ),
            }
        }
        control.pause();
        warn!(session=%active.session_id.to_hex(), "pausing existing VPN session for authenticated recovery");
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut restored = false;
        let mut last = String::new();
        for attempt in 0..4 {
            let attempt_deadline = deadline.min(Instant::now() + Duration::from_secs(25));
            let result = timeout_at(attempt_deadline, async {
                open(ctx, client, active, anchor, policy, tailnet).await?;
                settler::announce_session_with_opener(client, active, client.wallet_kp()).await?;
                let value =
                    settler::fetch_proposed_receipt(client, &endpoint, &active.session_id).await?;
                let current = proposal(
                    client.receipt_context(),
                    &active.session_id,
                    active.exit.receipt_pubkey,
                    &value,
                    prior,
                )?;
                // Observing a valid signature advances the floor even when
                // this attempt is cancelled during its subsequent handshake.
                prior = Some(current);
                let generation = control.handshake().await?;
                // Recheck after cryptographic authentication; a concurrent
                // canonical close or key change never enables packet resume.
                open(ctx, client, active, anchor, policy, tailnet).await?;
                control.resume(generation)?;
                Ok::<_, anyhow::Error>(current)
            })
            .await;
            match result {
                Ok(Ok(current)) => {
                    prior = Some(current);
                    restored = true;
                    info!(session=%active.session_id.to_hex(),"existing VPN session authenticated and resumed without new escrow");
                    break;
                }
                Ok(Err(error)) if terminal(&error) => return Err(error),
                failure => {
                    last = format!("{failure:?}");
                    warn!(attempt,reason=%last,"existing VPN session recovery remains paused");
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep_until(
                (Instant::now() + Duration::from_secs(1 << attempt)).min(deadline),
            )
            .await;
        }
        if !restored {
            bail!("existing VPN session recovery exhausted; traffic stayed paused and escrow remains recoverable: {last}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use octravpn_core::{address::Address, receipt::Receipt, session::Blind, sig::KeyPair};

    #[test]
    fn recovery_rejects_replayed_or_rebound_signed_state() {
        let key = KeyPair::from_secret_bytes(&[79; 32]);
        let context = ReceiptContext::v2(
            Address::from_pubkey(&[80; 32]),
            99,
            Address::from_pubkey(&[81; 32]),
        );
        let sid = SessionId::from_u64(42);
        let receipt = Receipt::new(context.clone(), sid.clone(), 8, 1000, Blind::new([0; 32]));
        let signed = |receipt: Receipt| ProposedReceipt {
            node_sig: key.sign(&receipt.signing_payload()),
            receipt,
            node_pubkey: key.public,
            enc_bytes_used: None,
            enc_net: None,
            pvac_zero_proof: None,
        };
        let valid = signed(receipt.clone());
        assert_eq!(
            proposal(&context, &sid, key.public, &valid, Some((7, 1000))).unwrap(),
            (8, 1000)
        );
        // Valid signatures alone cannot reset either durable observation floor.
        for prior in [(8, 1000), (9, 999), (7, 1001)] {
            assert!(terminal(
                &proposal(&context, &sid, key.public, &valid, Some(prior)).unwrap_err()
            ));
        }
        for changed in [
            Receipt {
                session_id: SessionId::from_u64(43),
                ..receipt.clone()
            },
            Receipt {
                context: ReceiptContext {
                    chain_id: 100,
                    ..context.clone()
                },
                ..receipt.clone()
            },
        ] {
            assert!(terminal(
                &proposal(&context, &sid, key.public, &signed(changed), None).unwrap_err()
            ));
        }
        let other = KeyPair::from_secret_bytes(&[82; 32]);
        assert!(terminal(
            &proposal(&context, &sid, other.public, &valid, None).unwrap_err()
        ));
        let forged = ProposedReceipt {
            receipt: Receipt {
                bytes_used: 999,
                ..receipt
            },
            ..valid
        };
        assert!(terminal(
            &proposal(&context, &sid, key.public, &forged, None).unwrap_err()
        ));
    }

    #[test]
    fn recovery_distinguishes_missing_process_state_from_terminal_admission() {
        for code in [400, 401, 403, 409] {
            let error = anyhow::Error::new(settler::ControlStatus(
                reqwest::StatusCode::from_u16(code).unwrap(),
            ));
            assert!(terminal(&error));
        }
        for code in [404, 429, 500, 503] {
            let error = anyhow::Error::new(settler::ControlStatus(
                reqwest::StatusCode::from_u16(code).unwrap(),
            ));
            assert!(!terminal(&error));
        }
        assert!(terminal(&closed("closed on chain")));
        assert!(!terminal(&anyhow!("temporarily unavailable")));
    }
}
