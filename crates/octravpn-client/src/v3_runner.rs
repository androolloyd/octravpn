//! Circle-resident VPN admission, authenticated traffic and settlement.
//!
//! Read the immutable operator metadata from its on-chain anchor, verify the
//! committed policy, independently pin the registered receipt key, and open
//! self-funded escrow. A wallet-bound announcement authorizes a fresh session
//! identity. One WireGuard exit carries either a pinned loopback UDP flow or
//! validated IPv4 packets from a host-provisioned TUN. On disconnect, receipt
//! claims are bounded by local session-frame counters before countersigning.
//! Bounded operator recovery revalidates the same opening and completes a new
//! authenticated handshake before packet delivery resumes, without new escrow.
//! The explicit fixture path performs no network traffic and requires an
//! operator-supplied byte count or no-show request.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use octravpn_core::v3_policy::OperatorPolicy;
use octravpn_core::v3_state_root::StateRoot;
use octravpn_core::{
    address::Address,
    session::{SessionId, ValidatorRecord},
    sig::{KeyPair, PublicKey},
};
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::{
    chain_v3::{ChainCtxV3, SettleConfirmParams},
    config::ClientConfig,
    runner::{ActiveSession, Client},
    settler,
    wireguard::{Mode, Tunnel},
};
mod recovery;
#[cfg(test)]
mod settlement_tests;

/// One MiB in bytes. The price tier is per-MiB; we floor-divide.
const BYTES_PER_MB: u64 = 1_048_576;

/// Sealed-asset path of the operator's canonical state-root commitment.
/// Mirrors `docs/v3-circle-resident-architecture.md` §2.
const STATE_ROOT_ASSET_PATH: &str = "/state-root.json";

/// Sealed-asset path of the operator's canonical policy advertisement.
/// Mirrors `docs/v3-policy-schema.md` §1.
const POLICY_ASSET_PATH: &str = "/policy.json";

/// Body of the `connect-v3` subcommand.
///
/// `bytes_used_override` is plumbed through so the integration tests
/// can pin a deterministic session-counter value without bringing up
/// real WG infra. Production callers pass `None`.
pub(crate) async fn connect_v3(
    client: &Arc<Client>,
    cfg: &Arc<ClientConfig>,
    bytes_used_override: Option<u64>,
    force_no_show: bool,
    mode: Option<Mode>,
) -> Result<()> {
    require_v3(cfg)?;
    if mode.is_some() && (bytes_used_override.is_some() || force_no_show) {
        bail!("live forwarding cannot use fixture byte counts or the no-show flow");
    }
    if mode.is_none() && bytes_used_override.is_none() && !force_no_show {
        bail!("connect-v3 requires --udp-target or --tun-name for live traffic; --bytes-used is an explicit settlement fixture");
    }
    let prepared = match mode {
        Some(mode) => Some(mode.prepare().await?),
        None => None,
    };

    let v3 = &cfg.v3;
    if v3.circle_id.trim().is_empty() {
        bail!(
            "[v3].circle_id is required for `connect-v3` — set it to the operator's `oct…` address"
        );
    }

    // Client initialization resolves and pins the effective wallet once, so
    // key-file replacement cannot move funding outside its recovery scope.
    let wallet_kp = KeyPair::from_secret_bytes(&client.wallet_kp().secret_bytes());
    let queue = client.chain_tx_queue();
    let ctx =
        ChainCtxV3::new_with_tx_queue(client.rpc(), client.program_addr(), &wallet_kp, Some(queue))
            .with_application(cfg.v3.application);
    ctx.require_priced_settlement().await?;

    // Fetch the chain pin before resolving immutable metadata and policy.
    let anchor = ctx
        .get_circle_state_root(&v3.circle_id)
        .await
        .context("fetch circle state-root anchor")?
        .ok_or_else(|| {
            anyhow!(
                "circle {} has no state-root anchor on chain — operator hasn't called register_circle yet",
                v3.circle_id,
            )
        })?;
    info!(
        circle = v3.circle_id.as_str(),
        anchor = %anchor,
        "v3 circle state-root anchor (trust pin)"
    );

    // 2a. Fetch the operator's sealed policy and validate its hash
    //     against the on-chain anchor. Hard-fail on mismatch — we will
    //     NOT open a session against an operator whose advertised
    //     policy doesn't match what they committed on chain.
    let policy = fetch_operator_policy(&ctx, &v3.circle_id, &anchor)
        .await
        .with_context(|| format!("fetch operator policy for circle {}", v3.circle_id))?;
    let price_per_mb = policy.price_per_mb_shared;
    if policy
        .unknown
        .get("application")
        .is_some_and(|value| value != &serde_json::json!(cfg.v3.application))
    {
        bail!("operator policy application differs from the configured settlement application");
    }
    if policy
        .unknown
        .get("receipt_chain_id")
        .is_some_and(|value| value.as_u64() != Some(u64::from(cfg.chain.chain_id)))
    {
        bail!("operator policy receipt chain differs from the configured receipt domain");
    }
    let transport = if prepared.is_some() {
        policy_transport(&policy)?
    } else {
        octravpn_tun::amnezia::WireTransport::Wireguard
    };
    if prepared.is_some() || client.relay_config().enabled {
        // Check every field needed for admission and settlement before funds
        // leave the wallet. This key is covered by the canonical policy hash.
        let advertised = policy_receipt_key(&policy)?;
        let registered = ctx
            .get_circle_receipt_pubkey(&v3.circle_id)
            .await
            .context("pin live operator receipt key before opening escrow")?;
        if advertised != registered {
            bail!("operator policy receipt key differs from the registered on-chain key");
        }
        policy_control_endpoint(&policy)?;
        crate::wireguard::validate_endpoint(&policy.endpoint)?;
        crate::wireguard::validate_peer_key(decode_policy_pubkey(&policy.wg_pubkey_b64)?.0)?;
    }
    if matches!(prepared.as_ref(), Some(mode) if mode.raw_ip())
        && policy.unknown.get("ip_tunnel_v1") != Some(&Value::Bool(true))
    {
        bail!("operator policy does not advertise ip_tunnel_v1; no raw-IP escrow was opened");
    }
    info!(
        circle = v3.circle_id.as_str(),
        endpoint = policy.endpoint.as_str(),
        region = policy.region.as_str(),
        price_per_mb_shared = price_per_mb,
        price_per_mb_internal = policy.price_per_mb_internal,
        effective_epoch = policy.effective_epoch,
        "v3 operator policy validated against anchor"
    );

    // Membership metadata is informational for this self-funded path.
    // Treasury-sponsored sessions require the application's spend authority.
    match ctx.get_tailnet_members_root(v3.tailnet_id).await {
        Ok(Some(root)) => {
            info!(
                tailnet_id = v3.tailnet_id,
                members_root = %root,
                "v3 tailnet members_root (self-funded session; off-chain admission hint)"
            );
        }
        Ok(None) => {
            warn!(
                tailnet_id = v3.tailnet_id,
                "no members_root anchored yet for tailnet — proceeding with self-funded session"
            );
        }
        Err(e) => {
            warn!(
                tailnet_id = v3.tailnet_id,
                error = %e,
                "members_root view failed — proceeding with self-funded session"
            );
        }
    }

    // 4. payable open_session(tailnet_id, circle, max_pay) with value=max_pay.
    let fee = ctx.fee_or_fallback("contract_call").await;
    let open_call = ctx.build_open_session_call(v3.tailnet_id, &v3.circle_id, v3.max_pay, fee, 0);
    let tx_hash = ctx
        .submit_call(open_call)
        .await
        .context("submit open_session")?;
    info!(tx_hash = %tx_hash, "v3 open_session submitted");

    let session_id =
        poll_session_id_v3(client, &tx_hash, v3.tailnet_id, &v3.circle_id, v3.max_pay).await?;
    let session_id_wrapped = SessionId::from_u64(session_id);
    client
        .open_settle_state()?
        .record_proposed(&session_id_wrapped)?;
    if ctx.session_policy_root(session_id).await? != anchor {
        bail!("funded session {session_id} captured a different policy than the quoted anchor; no traffic was sent, retain this session for refund recovery");
    }
    println!("v3 session opened: id={session_id}");
    println!("  tailnet_id    = {}", v3.tailnet_id);
    println!("  circle        = {}", v3.circle_id);
    println!("  max_pay       = {}", v3.max_pay);
    println!("  anchor        = {anchor}");

    if force_no_show {
        return run_claim_no_show(&ctx, session_id).await;
    }
    if prepared.is_some() || client.relay_config().enabled {
        let mut active = active_session_from_v3_policy(
            session_id_wrapped,
            tx_hash,
            &v3.circle_id,
            &policy,
            v3.max_pay,
        )?;
        // The final /32 depends on the committed session id. Open before
        // announcing or sending any application data, with recovery context.
        let ready = prepared.map(|prepared| prepared.bind(
            &active.session_id,
            &crate::wireguard::public_key(&active.session_kp),
        )).transpose().with_context(|| format!(
            "prepare local forwarding for funded session {session_id}; escrow remains recoverable through the program's refund path"
        ))?;
        settler::announce_session_with_opener(client, &active, &wallet_kp)
            .await
            .context("announce v3 relay session to exit")?;
        let transport_result = if let Some(ready) = ready {
            let mut tunnel = Tunnel::connect(
                active.session_id.clone(),
                &active.session_kp,
                &policy.endpoint,
                active.exit.wg_pubkey.0,
                traffic_ceiling(v3.max_pay, price_per_mb),
                transport,
            )
            .await
            .context("authenticate operator WireGuard peer")?;
            let control = tunnel.recovery()?;
            let (traffic, result) = Box::pin(ready.run(
                tunnel,
                recovery::heartbeat(
                    &ctx,
                    client,
                    &active,
                    &anchor,
                    &policy,
                    v3.tailnet_id,
                    control,
                ),
            ))
            .await;
            active.metered_bytes = Some(traffic.total()?);
            info!(
                session_id,
                submitted = traffic.submitted,
                received = traffic.received,
                "forwarding closed; retaining local ceiling for final receipt"
            );
            result
        } else {
            active.metered_bytes = bytes_used_override;
            Ok(())
        };
        // The socket is closed before fetching the final receipt. Refuse to
        // co-sign any claim above the locally submitted/received byte ceiling.
        let meter = active.metered_bytes;
        let settlement = if client.relay_config().enabled {
            settler::settle_active(client, active).await
        } else {
            async {
                let signed = settler::countersign_active(client, &active).await?;
                run_settle_confirm(&ctx, session_id, signed.receipt.bytes_used, price_per_mb)
                    .await?;
                client
                    .open_settle_state()?
                    .record_settled(&active.session_id)
            }
            .await
        };
        settlement.with_context(||format!("funded session {session_id} requires recovery; local traffic ceiling={meter:?}, forwarding outcome={transport_result:?}"))?;
        return transport_result;
    }
    run_settle_confirm(
        &ctx,
        session_id,
        bytes_used_override.unwrap_or(0),
        price_per_mb,
    )
    .await
}

fn policy_transport(policy: &OperatorPolicy) -> Result<octravpn_tun::amnezia::WireTransport> {
    let raw=policy.unknown.get("transport").context("operator policy has no committed transport; republish the operator policy before funding a live session")?;
    let transport: octravpn_tun::amnezia::WireTransport = serde_json::from_value(raw.clone())
        .context("operator advertises unsupported transport metadata")?;
    transport
        .config()
        .map_err(|error| anyhow!("invalid committed transport: {error}"))?;
    Ok(transport)
}

fn active_session_from_v3_policy(
    session_id: SessionId,
    open_tx_hash: String,
    circle_id: &str,
    policy: &OperatorPolicy,
    deposit: u64,
) -> Result<ActiveSession> {
    let endpoint = settler::normalize_control_endpoint(&policy.endpoint);
    let wg_pubkey = decode_policy_pubkey(&policy.wg_pubkey_b64)
        .with_context(|| format!("decode wg_pubkey_b64 for circle {circle_id}"))?;
    let validator = ValidatorRecord {
        addr: Address::from_display(circle_id),
        active: true,
        endpoint,
        wg_pubkey,
        receipt_pubkey: policy_receipt_key(policy)?,
        view_pubkey: [0u8; 32],
        region: policy.region.clone(),
        price_per_mb: policy.price_per_mb_shared,
        registered_at: policy.effective_epoch,
        reputation: 0,
    };
    Ok(ActiveSession {
        session_id,
        session_kp: KeyPair::generate(),
        open_tx_hash,
        exit: validator,
        deposit,
        control_endpoint: policy_control_endpoint(policy)?,
        metered_bytes: None,
    })
}

fn policy_receipt_key(policy: &OperatorPolicy) -> Result<PublicKey> {
    let encoded = policy
        .unknown
        .get("receipt_pubkey_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow!("operator policy must commit receipt_pubkey_b64 before live session admission")
        })?;
    let key = decode_policy_pubkey(encoded)?;
    let verifier = ed25519_dalek::VerifyingKey::from_bytes(&key.0)
        .context("operator policy receipt key is invalid")?;
    if verifier.is_weak() {
        bail!("operator policy receipt key is weak");
    }
    Ok(key)
}

fn policy_control_endpoint(policy: &OperatorPolicy) -> Result<Option<String>> {
    policy
        .unknown
        .get("control_endpoint")
        .map(|value| {
            let encoded = value
                .as_str()
                .ok_or_else(|| anyhow!("policy control_endpoint must be a string"))?;
            settler::validate_control_endpoint(encoded)
        })
        .transpose()
}

/// The tariff floor-divides usage by MiB. Stop before the first byte that
/// would exceed the deposit; zero-price policies have no paid byte ceiling.
fn traffic_ceiling(deposit: u64, price_per_mb: u64) -> Option<u64> {
    if price_per_mb == 0 {
        return None;
    }
    (deposit / price_per_mb)
        .checked_add(1)
        .and_then(|mb| mb.checked_mul(BYTES_PER_MB))
        .map(|bytes| bytes - 1)
}

fn decode_policy_pubkey(raw: &str) -> Result<PublicKey> {
    let bytes = octravpn_core::b64::decode(raw).map_err(|e| anyhow!("base64: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("expected 32 bytes, got {}", v.len()))?;
    Ok(PublicKey(arr))
}

/// Submit the opener-side `settle_confirm` for a freshly-closed
/// session. Centralised so the integration test can drive it directly.
/// `price_per_mb` is the operator's `policy.price_per_mb_shared`,
/// fetched + validated upstream of this call.
pub(crate) async fn run_settle_confirm(
    ctx: &ChainCtxV3<'_>,
    session_id: u64,
    bytes_used: u64,
    price_per_mb: u64,
) -> Result<()> {
    let net = compute_net(bytes_used, price_per_mb);
    if ctx.claim_net(session_id).await? != net {
        bail!("operator claim amount differs from the authenticated session tariff; session {session_id} remains recoverable");
    }
    let blinding = fresh_blinding_hex();
    // Logging the raw blinding would leak the secret that anchors the
    // earnings hash chain; log only its sha256 prefix so support
    // bundles stay safe to share.
    let bh = Sha256::digest(blinding.as_bytes());
    info!(
        session_id,
        bytes_used,
        net,
        blinding_sha256_prefix = %hex::encode(&bh[..8]),
        "v3 settle_confirm prepared"
    );

    let fee = ctx.fee_or_fallback("contract_call").await;
    let p = SettleConfirmParams {
        session_id,
        bytes_used,
        net,
        settle_blinding: &blinding,
        fee,
        nonce: 0,
    };
    let call = ctx.build_settle_confirm_call(&p);
    let tx_hash = ctx
        .submit_call(call)
        .await
        .context("submit settle_confirm")?;
    // A successful VM call may return false on a bytes dispute. Inclusion and
    // VM success alone cannot advance the durable client floor to Settled.
    let mut confirmed = false;
    for _ in 0..60 {
        match ctx.get_session_status_strict(session_id).await {
            Ok(1) => { confirmed = true; break; },
            Ok(0) | Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
            Ok(status) => bail!("settle_confirm {tx_hash} left session {session_id} in status {status}; retain its receipt for recovery"),
        }
    }
    if !confirmed {
        bail!("settle_confirm {tx_hash} did not prove session {session_id} settled; retain its receipt for recovery");
    }
    info!(session_id, tx_hash = %tx_hash, "v3 settle_confirm submitted");
    println!(
        "v3 settlement submitted: id={session_id} net={net} bytes_used={bytes_used} hash={tx_hash}"
    );
    Ok(())
}

/// Submit the opener-side `claim_no_show` when the operator never
/// claimed within session grace.
pub(crate) async fn run_claim_no_show(ctx: &ChainCtxV3<'_>, session_id: u64) -> Result<()> {
    let fee = ctx.fee_or_fallback("contract_call").await;
    let call = ctx.build_claim_no_show_call(session_id, fee, 0);
    let tx_hash = ctx
        .submit_call(call)
        .await
        .context("submit claim_no_show")?;
    info!(session_id, tx_hash = %tx_hash, "v3 claim_no_show submitted");
    println!("v3 no-show refund submitted: id={session_id} hash={tx_hash}");
    Ok(())
}

/// Floor-divide bytes by 1 MiB then multiply by the per-MB price.
/// Both factors are u64 so we never lose precision below MB granularity.
pub(crate) fn compute_net(bytes_used: u64, price_per_mb: u64) -> u64 {
    let mbs = bytes_used / BYTES_PER_MB;
    mbs.saturating_mul(price_per_mb)
}

/// Resolve immutable metadata by its chain anchor, then immutable policy by
/// the metadata policy hash. Historical fixed paths are fallback locations
/// only when the corresponding immutable asset is absent; mismatches fail.
pub(crate) async fn fetch_operator_policy(
    ctx: &ChainCtxV3<'_>,
    circle_id: &str,
    state_root_anchor: &str,
) -> Result<OperatorPolicy> {
    let metadata = fetch_snapshot(ctx, circle_id, state_root_anchor, STATE_ROOT_ASSET_PATH).await?;
    let state_root = checked_state_root(circle_id, &metadata, state_root_anchor)?;
    let bytes = fetch_snapshot(ctx, circle_id, &state_root.policy_hash, POLICY_ASSET_PATH).await?;
    let policy = OperatorPolicy::decode_lenient(&bytes)
        .map_err(|error| anyhow!("decode committed policy for circle {circle_id}: {error}"))?;
    check_policy_matches_anchor(circle_id, &policy, &metadata, state_root_anchor)?;
    Ok(policy)
}

async fn fetch_snapshot(
    ctx: &ChainCtxV3<'_>,
    circle_id: &str,
    hash: &str,
    logical: &str,
) -> Result<Vec<u8>> {
    let path = octravpn_core::v3_state_root::snapshot_path(&hash.to_ascii_lowercase(), logical)?;
    let bytes = match ctx
        .fetch_circle_asset_bytes(circle_id, &path)
        .await
        .with_context(|| format!("fetch immutable operator asset {path}"))?
    {
        Some(bytes) => bytes,
        None => ctx
            .fetch_circle_asset_bytes(circle_id, logical)
            .await
            .with_context(|| format!("fetch historical operator asset {logical}"))?
            .ok_or_else(|| {
                anyhow!("circle {circle_id} has no committed operator asset at {path} or {logical}")
            })?,
    };
    if bytes.len() > 262_144 {
        bail!("operator metadata exceeds the byte limit");
    }
    Ok(bytes)
}

fn checked_state_root(circle_id: &str, bytes: &[u8], anchor: &str) -> Result<StateRoot> {
    let state_root = StateRoot::decode_lenient(bytes)
        .map_err(|error| anyhow!("decode committed state-root for circle {circle_id}: {error}"))?;
    if !state_root.anchor_hex()?.eq_ignore_ascii_case(anchor) {
        bail!("state-root.json hash mismatch for circle {circle_id}");
    }
    if state_root.circle_id != circle_id {
        bail!(
            "state-root.json circle_id mismatch: expected {circle_id}, got {}",
            state_root.circle_id
        );
    }
    Ok(state_root)
}

/// Pure helper: given the served state-root.json bytes, the served
/// policy, the circle id, and the on-chain state-root anchor, decide
/// whether the policy is consistent with the chain. Pulled out of
/// the fetching path so unit tests can exercise the
/// equality logic without spinning a mock RPC.
pub(crate) fn check_policy_matches_anchor(
    circle_id: &str,
    policy: &OperatorPolicy,
    state_root_bytes: &[u8],
    state_root_anchor: &str,
) -> Result<()> {
    let state_root = checked_state_root(circle_id, state_root_bytes, state_root_anchor)?;

    // Now cross-check the policy bytes against the policy_hash field
    // inside the (anchor-validated) state-root.json.
    let policy_hash = policy
        .hash_hex()
        .map_err(|e| anyhow!("hash policy.json for circle {circle_id}: {e}"))?;
    if !state_root.policy_hash.eq_ignore_ascii_case(&policy_hash) {
        bail!(
            "policy.json hash mismatch for circle {circle_id}: \
             state-root.policy_hash {} != recomputed {policy_hash} \
             — operator is serving a different policy than what they committed",
            state_root.policy_hash,
        );
    }

    let key = decode_policy_pubkey(&policy.wg_pubkey_b64)?;
    let key_hash = hex::encode(Sha256::digest(key.0));
    if !state_root.wg_pubkey_hash.eq_ignore_ascii_case(&key_hash) {
        bail!("state-root WireGuard key hash does not match the committed policy");
    }

    Ok(())
}

/// Generate a fresh 32-byte settle blinding, encoded as 64-char
/// lowercase hex (the AML reads it as a `bytes` field). Uses
/// `rand::rngs::OsRng` (the same source the rest of the client uses
/// for fresh secrets — see `commands.rs::keygen`).
fn fresh_blinding_hex() -> String {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn require_v3(cfg: &ClientConfig) -> Result<()> {
    if cfg.is_v3() {
        return Ok(());
    }
    bail!(
        "v3 subcommands require `[chain].protocol_version = \"v3\"` in your client.toml \
         (currently `{}`)",
        cfg.chain.protocol_version,
    )
}

/// SessionOpened belongs to the execution receipt, not the transaction
/// status projection. Bind the event to the submitted root call and funding.
async fn poll_session_id_v3(
    client: &Client,
    tx_hash: &str,
    tailnet: u64,
    circle: &str,
    deposit: u64,
) -> Result<u64> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut delay_ms = 100;
    for _ in 0..20 {
        let result = tokio::time::timeout_at(
            deadline,
            client
                .rpc()
                .raw_call("contract_receipt", serde_json::json!([tx_hash])),
        )
        .await
        .with_context(|| {
            format!("session opening receipt timed out; retain transaction {tx_hash} for recovery")
        })?;
        match result {
            Ok(receipt) => {
                return opening_session_id(
                    &receipt,
                    client.program_addr().display(),
                    tailnet,
                    circle,
                    deposit,
                )
            }
            Err(error)
                if error
                    .to_string()
                    .contains("rpc contract_receipt error 112:") => {}
            Err(error) => return Err(error.into()),
        }
        tokio::time::sleep_until(
            (tokio::time::Instant::now() + Duration::from_millis(delay_ms)).min(deadline),
        )
        .await;
        delay_ms = (delay_ms * 2).min(2_000);
        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    bail!("session opening receipt not observed; retain transaction {tx_hash} for recovery")
}

fn opening_session_id(
    receipt: &Value,
    program: &str,
    tailnet: u64,
    circle: &str,
    deposit: u64,
) -> Result<u64> {
    if receipt.get("success") != Some(&Value::Bool(true))
        || receipt.get("contract").and_then(Value::as_str) != Some(program)
        || receipt.get("method").and_then(Value::as_str) != Some("open_session")
        || receipt.get("error") != Some(&Value::Null)
    {
        bail!("session opening receipt does not prove a successful call to the configured program");
    }
    let epoch = receipt
        .get("epoch")
        .ok_or_else(|| anyhow!("session opening epoch missing"))?;
    let epoch = receipt_uint(epoch)?;
    let events = receipt
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("session opening receipt events missing"))?;
    let mut opened = None;
    for event in events {
        if event.get("event").and_then(Value::as_str) != Some("SessionOpened")
            || event.get("contract").and_then(Value::as_str) != Some(program)
            || event.get("depth").and_then(Value::as_u64) != Some(0)
        {
            continue;
        }
        let values = event
            .get("values")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("session opening event values missing"))?;
        if values.len() != 5
            || receipt_uint(&values[1])? != tailnet
            || values[2].as_str() != Some(circle)
            || receipt_uint(&values[3])? != deposit
            || receipt_uint(&values[4])? != epoch
            || opened.is_some()
        {
            bail!("session opening event differs from the submitted escrow");
        }
        opened = Some(receipt_uint(&values[0])?);
    }
    opened.ok_or_else(|| anyhow!("session opening event missing from successful execution receipt"))
}

fn receipt_uint(value: &Value) -> Result<u64> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    let text = value
        .as_str()
        .ok_or_else(|| anyhow!("receipt integer is not unsigned"))?;
    let number: u64 = text.parse().context("decode receipt integer")?;
    if number.to_string() != text {
        bail!("receipt integer is not canonical decimal");
    }
    Ok(number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ChainCfg, V2Cfg, V3Cfg, WalletCfg};

    fn cfg_v1() -> ClientConfig {
        ClientConfig {
            chain: ChainCfg {
                rpc_url: "http://x".into(),
                program_addr: "oct".into(),
                protocol_version: "v1.1".into(),
                chain_id: octravpn_core::receipt::CHAIN_ID_TEST,
                pinned_root_paths: None,
            },
            wallet: WalletCfg {
                addr: "oct".into(),
                secret_path: "/dev/null".into(),
            },
            v2: V2Cfg::default(),
            v3: V3Cfg::default(),
        }
    }

    fn cfg_v3() -> ClientConfig {
        let mut c = cfg_v1();
        c.chain.protocol_version = "v3".into();
        c
    }

    #[test]
    fn require_v3_rejects_v1() {
        let err = require_v3(&cfg_v1()).unwrap_err().to_string();
        assert!(err.contains("v3"));
    }

    #[test]
    fn require_v3_accepts_v3_case_insensitive() {
        let mut c = cfg_v3();
        c.chain.protocol_version = "V3".into();
        require_v3(&c).unwrap();
        c.chain.protocol_version = "3".into();
        require_v3(&c).unwrap();
    }

    #[test]
    fn compute_net_floors_to_whole_mibs() {
        // Pin against a sample fetched policy price (1000 OU/MiB).
        const SAMPLE_PRICE_PER_MB: u64 = 1_000;
        assert_eq!(compute_net(0, SAMPLE_PRICE_PER_MB), 0);
        assert_eq!(compute_net(BYTES_PER_MB - 1, SAMPLE_PRICE_PER_MB), 0);
        assert_eq!(compute_net(BYTES_PER_MB, SAMPLE_PRICE_PER_MB), 1_000);
        assert_eq!(compute_net(2 * BYTES_PER_MB, SAMPLE_PRICE_PER_MB), 2_000);
        // 1 MiB + 100 bytes still floors to 1.
        assert_eq!(compute_net(BYTES_PER_MB + 100, SAMPLE_PRICE_PER_MB), 1_000);
    }

    #[test]
    fn compute_net_uses_passed_price() {
        // Different prices yield different settle amounts for the same
        // byte count; this is the central invariant of removing
        // `DEFAULT_PRICE_PER_MB`. 2 MiB at price 750 → 1500; at price
        // 0 → 0 (free internal tier); at price u64::MAX → saturates.
        let two_mib = 2 * BYTES_PER_MB;
        assert_eq!(compute_net(two_mib, 750), 1_500);
        assert_eq!(compute_net(two_mib, 0), 0);
        // Saturating multiplication branch.
        assert_eq!(compute_net(two_mib, u64::MAX), u64::MAX);
    }

    /// Build a matched (state_root, policy) pair: hashes line up, both
    /// committed under `circle_id`. Returns the canonical bytes of
    /// state-root.json + its on-chain anchor (hex) + the policy struct.
    fn matched_fixture(circle_id: &str) -> (Vec<u8>, String, OperatorPolicy) {
        // Worked-example values from docs/v3-policy-schema.md §6.
        let raw_key = [0x11_u8; 32];
        let wg = octravpn_core::b64::encode(raw_key);
        let policy = OperatorPolicy::new_v1(
            "wg://relay.example:51820",
            wg,
            "us-east-1",
            1000,
            0,
            12345,
            1_705_000_000,
            Some("https://op.example/attestation".to_string()),
        );
        let policy_hash = policy.hash_hex().unwrap();
        // wg_pubkey_hash is sha256 of the raw 32-byte WG pubkey
        // (NOT base64) — see v3_state_root.rs `wg_pubkey_hash` doc.
        let wg_pubkey_hash = hex::encode(sha2::Sha256::digest(raw_key));
        let state_root = StateRoot::new_v1(
            circle_id,
            policy_hash,
            wg_pubkey_hash,
            None,
            "us-east-1",
            1,
            12345,
            1_705_000_000,
        );
        let anchor = state_root.anchor_hex().unwrap();
        let bytes = state_root.canonical_bytes().unwrap();
        (bytes, anchor, policy)
    }

    #[test]
    fn validate_policy_against_anchor_accepts_matching_hash() {
        let circle = "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun";
        let (sr_bytes, anchor, policy) = matched_fixture(circle);
        check_policy_matches_anchor(circle, &policy, &sr_bytes, &anchor)
            .expect("matched fixture must validate");
    }

    #[test]
    fn validate_policy_against_anchor_rejects_mismatched_hash() {
        // The state-root commits policy_hash = H(policy_A); the
        // operator then serves policy_B with a different price tier
        // (and thus a different hash). The validator must reject.
        let circle = "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun";
        let (sr_bytes, anchor, mut policy) = matched_fixture(circle);
        // Mutate the policy without re-committing on chain.
        policy.price_per_mb_shared = 9_999;
        let err = check_policy_matches_anchor(circle, &policy, &sr_bytes, &anchor)
            .expect_err("mismatched policy hash must error");
        let s = err.to_string();
        assert!(
            s.contains("policy.json hash mismatch"),
            "wrong error variant: {s}"
        );

        // Sanity: mutating the anchor (chain side) is also caught,
        // through a distinct error path. This pins the
        // "state-root.json bytes don't match the on-chain anchor" half
        // of the validator (e.g. operator serving a stale or rolled-back
        // state-root.json).
        let (sr_bytes2, _real_anchor, policy2) = matched_fixture(circle);
        let bad_anchor = "0000000000000000000000000000000000000000000000000000000000000000";
        let err2 = check_policy_matches_anchor(circle, &policy2, &sr_bytes2, bad_anchor)
            .expect_err("mismatched anchor must error");
        assert!(
            err2.to_string().contains("state-root.json hash mismatch"),
            "wrong error variant: {err2}"
        );
    }

    #[test]
    fn fresh_blinding_is_64_char_lowercase_hex() {
        let a = fresh_blinding_hex();
        assert_eq!(a.len(), 64, "blinding must be 32 bytes / 64 hex chars");
        assert!(a
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        // Two consecutive calls must produce different bytes — proves
        // we're actually pulling from the OS RNG, not a fixed buffer.
        let b = fresh_blinding_hex();
        assert_ne!(a, b);
    }
}
