//! v3 (chain-minimal, circle-resident) end-to-end client flow.
//!
//! Mirrors the v2 runner shape but talks to `program/main-v3.aml`
//! (devnet `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`). The v3
//! chain holds only an anchor (`circle_state_root`) + a receipt
//! pubkey for the circle; everything semantic — endpoint, WG pubkey,
//! price tier, member set — lives in the operator's sealed
//! `state-root.json` and tailnet-owner's `members.json`.
//!
//! End-to-end:
//!
//!   1. Read `[v3]` config: program_addr, tailnet_id, circle_id.
//!   2. Fetch + sanity-display the circle's on-chain state-root anchor
//!      via `get_circle_state_root`. The full sealed-asset fetch +
//!      Merkle proof verification land in the 191 follow-up; for now
//!      we log the anchor as the trust pin.
//!   3. Fetch the tailnet's `members_root` anchor. Real Merkle proof
//!      verification is the same follow-up; for now we log the root
//!      and warn that membership is taken on trust.
//!   4. Call `open_session(tailnet_id, circle, max_pay)` and capture
//!      the returned sid from the tx's `SessionOpened` event.
//!   5. Run the WG tunnel (deferred to the existing v2/v1 control
//!      plane — see `runner::print_wg_config`).
//!   6. On disconnect: compute `bytes_used` from session counters,
//!      compute `net = bytes_used * DEFAULT_PRICE_PER_MB / 1_048_576`
//!      (price-per-MB tier is a placeholder until policy.json schema
//!      lands), generate a 32-byte fresh blinding via `getrandom`-y
//!      `OsRng`, call `settle_confirm(sid, bytes_used, net, blinding)`.
//!   7. If the operator never `settle_claim`-s within session grace,
//!      `claim_no_show(sid)` runs instead.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use octravpn_core::sig::KeyPair;
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::{
    chain_v3::{ChainCtxV3, SettleConfirmParams},
    config::ClientConfig,
    runner::Client,
    wallet,
};

/// Placeholder operator price tier (raw OU per MiB). Real lookup
/// lives in the policy.json schema follow-up (#191); until that lands
/// every v3 session is charged at this rate. Centralised here so the
/// future swap is a one-line edit.
pub(crate) const DEFAULT_PRICE_PER_MB: u64 = 1_000;

/// One MiB in bytes. The price tier is per-MiB; we floor-divide.
const BYTES_PER_MB: u64 = 1_048_576;

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
) -> Result<()> {
    require_v3(cfg)?;

    let v3 = &cfg.v3;
    if v3.circle_id.trim().is_empty() {
        bail!(
            "[v3].circle_id is required for `connect-v3` — set it to the operator's `oct…` address"
        );
    }

    // 1. Resolve the wallet (v3 lets us override `[wallet].secret_path`).
    let wallet_kp: KeyPair = if let Some(path) = v3.wallet_key_path.as_deref() {
        wallet::load_keypair(path)
            .with_context(|| format!("load [v3].wallet_key_path = {path}"))?
    } else {
        // Reuse the keypair already loaded into the shared Client so
        // we don't re-read the secret file. Cheap clone via secret bytes.
        let secret = client.wallet_kp().secret_bytes();
        KeyPair::from_secret_bytes(&secret)
    };

    let ctx = ChainCtxV3::new(client.rpc(), client.program_addr(), &wallet_kp);

    // 2. Fetch + log the on-chain anchor. Real verification of the
    //    sealed state-root.json against this anchor lives in #191.
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

    // 3. Fetch the tailnet's members_root. Real Merkle proof against
    //    the client's wallet address ships in #191.
    match ctx.get_tailnet_members_root(v3.tailnet_id).await {
        Ok(Some(root)) => {
            info!(
                tailnet_id = v3.tailnet_id,
                members_root = %root,
                "v3 tailnet members_root (membership taken on trust until 191 lands)"
            );
        }
        Ok(None) => {
            warn!(
                tailnet_id = v3.tailnet_id,
                "no members_root anchored yet for tailnet — proceeding on trust"
            );
        }
        Err(e) => {
            warn!(
                tailnet_id = v3.tailnet_id,
                error = %e,
                "members_root view failed — proceeding on trust"
            );
        }
    }

    // 4. open_session(tailnet_id, circle, max_pay).
    let nonce = ctx.nonce().await?;
    let fee = ctx.fee_or_fallback("contract_call").await;
    let open_call = ctx.build_open_session_call(
        v3.tailnet_id,
        &v3.circle_id,
        v3.max_pay,
        fee,
        nonce,
    );
    let signed = ctx.sign_call(open_call)?;
    let tx_hash = ctx
        .submit_signed(&signed)
        .await
        .context("submit open_session")?;
    info!(tx_hash = %tx_hash, "v3 open_session submitted");

    let session_id = poll_session_id_v3(client, &tx_hash).await?;
    println!("v3 session opened: id={session_id}");
    println!("  tailnet_id    = {}", v3.tailnet_id);
    println!("  circle        = {}", v3.circle_id);
    println!("  max_pay       = {}", v3.max_pay);
    println!("  anchor        = {anchor}");

    // 5. Data plane bring-up is deferred to the existing WG path. The
    //    v2 runner does the same `print_wg_handoff` thing; in v3 the
    //    WG endpoint lives behind the sealed state-root.json which is
    //    the 191 follow-up. We log a placeholder here so smoke tests
    //    don't accidentally start moving bytes against a stub policy.
    info!(
        session_id,
        "v3 data plane bring-up deferred to WireGuard infrastructure (sealed policy lookup is #191)"
    );

    // 6. Disconnect path: either the opener claims `no_show` (if the
    //    integration test asked for it) or it runs the normal
    //    settle_confirm path with a fresh blinding.
    if force_no_show {
        return run_claim_no_show(&ctx, session_id).await;
    }
    let bytes_used = bytes_used_override.unwrap_or(0);
    run_settle_confirm(&ctx, session_id, bytes_used).await
}

/// Submit the opener-side `settle_confirm` for a freshly-closed
/// session. Centralised so the integration test can drive it directly.
pub(crate) async fn run_settle_confirm(
    ctx: &ChainCtxV3<'_>,
    session_id: u64,
    bytes_used: u64,
) -> Result<()> {
    let net = compute_net(bytes_used, DEFAULT_PRICE_PER_MB);
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

    let nonce = ctx.nonce().await?;
    let fee = ctx.fee_or_fallback("contract_call").await;
    let p = SettleConfirmParams {
        session_id,
        bytes_used,
        net,
        settle_blinding: &blinding,
        fee,
        nonce,
    };
    let call = ctx.build_settle_confirm_call(&p);
    let signed = ctx.sign_call(call)?;
    let tx_hash = ctx.submit_signed(&signed).await.context("submit settle_confirm")?;
    info!(session_id, tx_hash = %tx_hash, "v3 settle_confirm submitted");
    println!("v3 session settled: id={session_id} net={net} bytes_used={bytes_used}");
    Ok(())
}

/// Submit the opener-side `claim_no_show` when the operator never
/// claimed within session grace.
pub(crate) async fn run_claim_no_show(ctx: &ChainCtxV3<'_>, session_id: u64) -> Result<()> {
    let nonce = ctx.nonce().await?;
    let fee = ctx.fee_or_fallback("contract_call").await;
    let call = ctx.build_claim_no_show_call(session_id, fee, nonce);
    let signed = ctx.sign_call(call)?;
    let tx_hash = ctx
        .submit_signed(&signed)
        .await
        .context("submit claim_no_show")?;
    info!(session_id, tx_hash = %tx_hash, "v3 claim_no_show submitted");
    println!("v3 session no-show refund: id={session_id}");
    Ok(())
}

/// Floor-divide bytes by 1 MiB then multiply by the per-MB price.
/// Both factors are u64 so we never lose precision below MB granularity.
pub(crate) fn compute_net(bytes_used: u64, price_per_mb: u64) -> u64 {
    let mbs = bytes_used / BYTES_PER_MB;
    mbs.saturating_mul(price_per_mb)
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

/// Poll the transaction receipt until the `SessionOpened` event
/// surfaces the session id. Caps out at ~30s wall clock. Mirrors the
/// v2 runner's `poll_session_id_v2`.
async fn poll_session_id_v3(client: &Client, tx_hash: &str) -> Result<u64> {
    let mut delay_ms: u64 = 100;
    for _ in 0..20 {
        let v = client.rpc().transaction(tx_hash).await?;
        if let Some(events) = v.get("events").and_then(|x| x.as_array()) {
            for e in events {
                if e.get("name").and_then(Value::as_str) == Some("SessionOpened") {
                    if let Some(sid) = e.get("session_id").and_then(Value::as_u64) {
                        return Ok(sid);
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        delay_ms = (delay_ms * 2).min(2_000);
    }
    Err(anyhow!("v3 session id not observed before timeout"))
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
        assert_eq!(compute_net(0, DEFAULT_PRICE_PER_MB), 0);
        assert_eq!(compute_net(BYTES_PER_MB - 1, DEFAULT_PRICE_PER_MB), 0);
        assert_eq!(compute_net(BYTES_PER_MB, DEFAULT_PRICE_PER_MB), 1_000);
        assert_eq!(compute_net(2 * BYTES_PER_MB, DEFAULT_PRICE_PER_MB), 2_000);
        // 1 MiB + 100 bytes still floors to 1.
        assert_eq!(compute_net(BYTES_PER_MB + 100, DEFAULT_PRICE_PER_MB), 1_000);
    }

    #[test]
    fn fresh_blinding_is_64_char_lowercase_hex() {
        let a = fresh_blinding_hex();
        assert_eq!(a.len(), 64, "blinding must be 32 bytes / 64 hex chars");
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        // Two consecutive calls must produce different bytes — proves
        // we're actually pulling from the OS RNG, not a fixed buffer.
        let b = fresh_blinding_hex();
        assert_ne!(a, b);
    }
}
