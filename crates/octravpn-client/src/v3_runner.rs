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
//!      compute `net = bytes_used * policy.price_per_mb_shared /
//!      1_048_576` (the price tier comes from the operator's sealed
//!      `policy.json`, validated against the on-chain anchor), generate
//!      a 32-byte fresh blinding via `getrandom`-y `OsRng`, call
//!      `settle_confirm(sid, bytes_used, net, blinding)`.
//!   7. If the operator never `settle_claim`-s within session grace,
//!      `claim_no_show(sid)` runs instead.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use octravpn_core::sig::KeyPair;
use octravpn_core::v3_policy::OperatorPolicy;
use octravpn_core::v3_state_root::StateRoot;
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
        wallet::load_keypair(path).with_context(|| format!("load [v3].wallet_key_path = {path}"))?
    } else {
        // Reuse the keypair already loaded into the shared Client so
        // we don't re-read the secret file. Cheap clone via secret bytes.
        let secret = client.wallet_kp().secret_bytes();
        KeyPair::from_secret_bytes(&secret)
    };

    let ctx = ChainCtxV3::new(client.rpc(), client.program_addr(), &wallet_kp);

    // 2. Fetch + log the on-chain anchor. The full sealed-asset
    //    state-root.json + members.json Merkle-proof verifier is the
    //    #191 follow-up; right here we already use the anchor to cross-
    //    check the operator's `policy.json` (via `state-root.policy_hash`).
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
    let policy = fetch_operator_policy(&ctx, &v3.circle_id)
        .await
        .with_context(|| format!("fetch operator policy for circle {}", v3.circle_id))?;
    validate_policy_against_anchor(&ctx, &v3.circle_id, &policy, &anchor)
        .await
        .context("validate operator policy.json against on-chain state-root anchor")?;
    let price_per_mb = policy.price_per_mb_shared;
    info!(
        circle = v3.circle_id.as_str(),
        endpoint = policy.endpoint.as_str(),
        region = policy.region.as_str(),
        price_per_mb_shared = price_per_mb,
        price_per_mb_internal = policy.price_per_mb_internal,
        effective_epoch = policy.effective_epoch,
        "v3 operator policy validated against anchor"
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
    let open_call =
        ctx.build_open_session_call(v3.tailnet_id, &v3.circle_id, v3.max_pay, fee, nonce);
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
    run_settle_confirm(&ctx, session_id, bytes_used, price_per_mb).await
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
    let tx_hash = ctx
        .submit_signed(&signed)
        .await
        .context("submit settle_confirm")?;
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

/// Fetch the operator's sealed `/policy.json` and decode it leniently
/// (so we keep working when the operator has bumped the schema version
/// past `v=1` but the field-level invariants on what we read still hold).
///
/// `circle_asset` is the chain RPC the wider Octra tooling uses for
/// plaintext-by-path reads inside a circle (see
/// `octra-foundry/crates/octra-cli/src/cast/circle.rs::asset`). Sibling
/// to v2's `circle_asset_ciphertext_by_resource_key`; the v3 plaintext
/// path doesn't go through the per-tailnet sealing key.
///
/// Errors when:
///   * the chain has no `policy.json` for this circle (operator hasn't
///     published one yet),
///   * the asset RPC returns an unexpected shape,
///   * the bytes don't decode as a v3 `OperatorPolicy`.
pub(crate) async fn fetch_operator_policy(
    ctx: &ChainCtxV3<'_>,
    circle_id: &str,
) -> Result<OperatorPolicy> {
    let bytes = ctx
        .fetch_circle_asset_bytes(circle_id, POLICY_ASSET_PATH)
        .await
        .with_context(|| format!("fetch {POLICY_ASSET_PATH} for circle {circle_id}"))?
        .ok_or_else(|| {
            anyhow!(
                "circle {circle_id} has no {POLICY_ASSET_PATH} asset — operator hasn't sealed a v3 policy yet"
            )
        })?;
    OperatorPolicy::decode_lenient(&bytes)
        .map_err(|e| anyhow!("decode {POLICY_ASSET_PATH} for circle {circle_id}: {e}"))
}

/// Fetch the operator's sealed `/state-root.json` and assert that its
/// `policy_hash` field matches `sha256(canonical_bytes(policy))`.
///
/// Two distinct anchors are involved here:
///
///   * `state_root_anchor` (passed in): the 64-char hex value the chain
///     stores at `circle_state_root[circle]`. It is the SHA-256 of the
///     state-root.json's canonical bytes. We compare the
///     just-fetched state-root.json against this so we know the
///     operator is serving the same state-root they committed on chain.
///   * `state_root.policy_hash`: a field inside that JSON, equal to
///     SHA-256 of the canonical bytes of policy.json. We compare it
///     against `policy.hash_hex()` so we know the policy bytes we
///     fetched are the ones the operator committed.
///
/// Errors loudly on either mismatch — the operator is serving a
/// different policy or state-root than what they committed on chain.
pub(crate) async fn validate_policy_against_anchor(
    ctx: &ChainCtxV3<'_>,
    circle_id: &str,
    policy: &OperatorPolicy,
    state_root_anchor: &str,
) -> Result<()> {
    let bytes = ctx
        .fetch_circle_asset_bytes(circle_id, STATE_ROOT_ASSET_PATH)
        .await
        .with_context(|| format!("fetch {STATE_ROOT_ASSET_PATH} for circle {circle_id}"))?
        .ok_or_else(|| {
            anyhow!(
                "circle {circle_id} has no {STATE_ROOT_ASSET_PATH} asset — \
                 chain anchor exists but the operator hasn't sealed the state-root yet"
            )
        })?;

    // Recompute the chain anchor from the served bytes. Use the same
    // SHA-256 over canonical bytes that the operator-side encoder uses
    // (we re-canonicalise after decode_lenient to guarantee byte form,
    // since the served file may have non-canonical whitespace / key
    // order).
    check_policy_matches_anchor(circle_id, policy, &bytes, state_root_anchor)
}

/// Pure helper: given the served state-root.json bytes, the served
/// policy, the circle id, and the on-chain state-root anchor, decide
/// whether the policy is consistent with the chain. Pulled out of
/// `validate_policy_against_anchor` so unit tests can exercise the
/// equality logic without spinning a mock RPC.
pub(crate) fn check_policy_matches_anchor(
    circle_id: &str,
    policy: &OperatorPolicy,
    state_root_bytes: &[u8],
    state_root_anchor: &str,
) -> Result<()> {
    // Recompute the chain anchor from the served bytes. Use the same
    // SHA-256 over canonical bytes that the operator-side encoder uses
    // (we re-canonicalise after decode_lenient to guarantee byte form,
    // since the served file may have non-canonical whitespace / key
    // order).
    let state_root = StateRoot::decode_lenient(state_root_bytes)
        .map_err(|e| anyhow!("decode {STATE_ROOT_ASSET_PATH} for circle {circle_id}: {e}"))?;
    let recomputed_anchor = state_root
        .anchor_hex()
        .map_err(|e| anyhow!("re-canonicalise {STATE_ROOT_ASSET_PATH}: {e}"))?;
    if !recomputed_anchor.eq_ignore_ascii_case(state_root_anchor) {
        bail!(
            "state-root.json hash mismatch for circle {circle_id}: \
             on-chain anchor {state_root_anchor} != recomputed {recomputed_anchor} \
             — operator is serving a different state-root than what they committed"
        );
    }

    // Self-binding: `state_root.circle_id` must equal the circle whose
    // anchor we just verified. Without this check a malicious operator
    // could serve another operator's state-root.json under their own
    // path (see `v3_state_root.rs::circle_id` doc).
    if state_root.circle_id != circle_id {
        bail!(
            "state-root.json circle_id mismatch: expected {circle_id}, got {} \
             — operator is hosting another circle's state-root",
            state_root.circle_id,
        );
    }

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
        use base64::engine::general_purpose::STANDARD as BASE64_STD;
        use base64::Engine as _;
        // Worked-example values from docs/v3-policy-schema.md §6.
        let raw_key = [0x11_u8; 32];
        let wg = BASE64_STD.encode(raw_key);
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
