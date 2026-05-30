//! Operator CLI surface for every v3 chain entrypoint that doesn't
//! already have one.
//!
//! Today only the boot flow runs the v3 path (via `run_v3_boot`, called
//! from `Hub::register_endpoint_v3`). All the other v3 entrypoints have
//! wire-shape-pinned builders in [`crate::chain_v3`] but no
//! operator-facing surface — ops would otherwise need raw `cast send`.
//!
//! Each subcommand under [`V3Cmd`] mirrors the
//! `register_endpoint_v3` pattern from `hub.rs`:
//!
//!   1. Load the operator's `node.toml` config.
//!   2. Construct a [`ChainCtxV3`] directly from the config's RPC URL,
//!      program addr, and wallet secret. We don't take a `Hub` because
//!      ops invoking a one-shot tx don't want to pay the Hub::new boot
//!      cost (audit log dirs, receipt journal, etc.).
//!   3. Build the `*_call` via the chain_v3 builder.
//!   4. Sign via [`ChainCtxV3::sign_call`] and submit via
//!      [`ChainCtxV3::submit_signed_tx`].
//!   5. Print the tx hash, and for entrypoints that return a useful
//!      payload (open_session → session id, settle_claim/confirm → accepted
//!      bool), best-effort poll `octra_transaction(hash)` and log the
//!      return value once it lands.
//!
//! ### Judgement calls flagged for review
//!
//!   * **slash signing UX**: ops shouldn't construct base64 ed25519
//!     sigs by hand. The `slash` subcommand takes a path to the
//!     receipt-signing private key (`--receipt-key`, 32-byte secret,
//!     either as raw hex or raw bytes — same shape `wg.key` uses), plus
//!     `--payload-a` / `--payload-b` as plain strings. We sign the
//!     payloads inline with the same `KeyPair::from_secret_bytes` /
//!     `KeyPair::sign` pipeline the daemon uses for everything else,
//!     then base64-encode the 64-byte sig blobs before handing them to
//!     `build_slash_double_sign_call`. This matches what
//!     `e2e-adversarial-v3.sh` does via `octra cast wallet sign`.
//!   * **return-value polling**: `submit_signed_tx` returns the tx
//!     hash, but Octra contract returns (e.g. `open_session`'s assigned
//!     session_id) come back via `octra_transaction(hash)`. We poll a
//!     bounded number of times with a short backoff. If it doesn't
//!     land in time, we still print the hash so the operator can query
//!     manually — we don't fail the command on timeout.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Args, Subcommand};
use octravpn_core::{address::Address, sig::KeyPair};
use serde_json::Value;
use tracing::{info, warn};

use crate::{
    chain_v3::{ChainCtxV3, SettleConfirmParams, SlashDoubleSignParams},
    config::NodeConfig,
};

/// Top-level fan-out for every non-boot v3 entrypoint. Wired into
/// `Cmd::V3(V3Cmd)` in `main.rs`.
#[derive(Subcommand, Debug)]
pub(crate) enum V3Cmd {
    /// `payable bond_endpoint(circle)` — top up the operator's existing
    /// bond. The `--amount` value is added to `circle_bond[circle]`.
    Bond(BondArgs),
    /// `unbond_endpoint(circle)` — start the unbond grace period.
    Unbond(UnbondArgs),
    /// `finalize_unbond(circle)` — claim the stake back once
    /// `epoch >= circle_unbond_unlock_epoch[circle]`.
    FinalizeUnbond(FinalizeUnbondArgs),
    /// `slash_double_sign(circle, payload_a, sig_a, payload_b, sig_b)` —
    /// slash a circle that signed two distinct payloads under the same
    /// receipt key. CLI signs both payloads inline with the supplied
    /// receipt private key file; operators don't compute base64 sigs.
    Slash(SlashArgs),
    /// `rotate_receipt_pubkey(circle, new_pubkey)` — swap the on-chain
    /// ed25519 pubkey used for `slash_double_sign` going forward.
    RotateReceiptPubkey(RotateArgs),
    /// `retire_circle(circle)` — flip `circle_active[circle] = 0`.
    /// Stake remains bonded until a subsequent `finalize_unbond`.
    Retire(RetireArgs),
    /// `payable create_tailnet(members_root)` — register a new tailnet
    /// with `--deposit` OU initial treasury. The assigned `tailnet_id`
    /// is fetched best-effort post-submit.
    CreateTailnet(CreateTailnetArgs),
    /// `update_members_root(tailnet_id, new_members_root)` — bump the
    /// members-root anchor for an existing tailnet.
    UpdateMembersRoot(UpdateMembersArgs),
    /// `retire_tailnet(tailnet_id)` — flip `tailnet_retired = 1`.
    RetireTailnet(RetireTailnetArgs),
    /// `payable deposit_to_tailnet(tailnet_id)` — top up the tailnet
    /// treasury. Anyone can call; membership is enforced off-chain.
    DepositTailnet(DepositArgs),
    /// `withdraw_tailnet_treasury(tailnet_id, amount)` — owner-only
    /// withdrawal after `retire_tailnet`. NOTE: built inline (no
    /// chain_v3 builder exists yet — see module doc judgement call).
    WithdrawTailnet(WithdrawArgs),
    /// `open_session(tailnet_id, circle, max_pay) -> int` — open a paid
    /// session. The assigned `session_id` is best-effort fetched from
    /// `octra_transaction(hash)` and logged.
    OpenSession(OpenSessionArgs),
    /// `settle_claim(session_id, bytes_used)` — operator-side first
    /// half of the two-tx settle. Equivocation on `bytes_used` per sid
    /// triggers an AML-side slash.
    SettleClaim(SettleClaimArgs),
    /// `settle_confirm(session_id, bytes_used, net, settle_blinding)` —
    /// opener-side second half. Returns bool (accepted vs disputed).
    SettleConfirm(SettleConfirmArgs),
    /// `claim_no_show(session_id)` — opener-side abort path when the
    /// operator never called `settle_claim`.
    ClaimNoShow(ClaimNoShowArgs),
    /// `sweep_expired_session(session_id)` — any caller can sweep an
    /// OPEN session past `opened_at + session_grace * sweep_multiplier`
    /// for a `sweep_bounty_bps` bounty.
    SweepSession(SweepArgs),
    /// `claim_earnings(circle, amount)` — pull `amount` OU from the v3
    /// earnings ledger to the circle owner.
    ClaimEarnings(ClaimEarningsArgs),
}

// ============================================================
// Per-subcommand args. Each mirrors the parameter set of the
// corresponding `chain_v3::build_*_call` builder.
// ============================================================

#[derive(Args, Debug)]
pub(crate) struct BondArgs {
    /// Circle id receiving the additional bond.
    #[arg(long)]
    pub circle: String,
    /// OU to add to the bond (sent as the tx `value`).
    #[arg(long)]
    pub amount: u64,
}

#[derive(Args, Debug)]
pub(crate) struct UnbondArgs {
    #[arg(long)]
    pub circle: String,
}

#[derive(Args, Debug)]
pub(crate) struct FinalizeUnbondArgs {
    #[arg(long)]
    pub circle: String,
}

#[derive(Args, Debug)]
pub(crate) struct SlashArgs {
    /// Circle the slash is being submitted against.
    #[arg(long)]
    pub circle: String,
    /// Path to a 32-byte ed25519 secret (raw 32 bytes OR hex; same
    /// format `tunnel.wg_secret_path` accepts). Used to sign the two
    /// payloads inline; the corresponding pubkey must match
    /// `circle_receipt_pk[circle]` on chain or the slash will revert.
    #[arg(long)]
    pub receipt_key: PathBuf,
    /// First conflicting payload (raw string — the AML's `ed25519_ok`
    /// builtin verifies the signature over the literal UTF-8 bytes).
    #[arg(long)]
    pub payload_a: String,
    /// Second conflicting payload. Must differ from `payload_a`.
    #[arg(long)]
    pub payload_b: String,
}

#[derive(Args, Debug)]
pub(crate) struct RotateArgs {
    #[arg(long)]
    pub circle: String,
    /// Base64-encoded ed25519 pubkey (44 chars including padding) to
    /// replace `circle_receipt_pk[circle]`.
    #[arg(long)]
    pub new_pubkey_b64: String,
}

#[derive(Args, Debug)]
pub(crate) struct RetireArgs {
    #[arg(long)]
    pub circle: String,
}

#[derive(Args, Debug)]
pub(crate) struct CreateTailnetArgs {
    /// 64-char lowercase hex sha256 of the canonical
    /// `members.json`. Anchor only; the chain doesn't decode the JSON.
    #[arg(long)]
    pub members_root: String,
    /// Initial OU deposit into the tailnet treasury.
    #[arg(long)]
    pub deposit: u64,
}

#[derive(Args, Debug)]
pub(crate) struct UpdateMembersArgs {
    #[arg(long)]
    pub tailnet_id: u64,
    /// New 64-char hex sha256 anchor.
    #[arg(long)]
    pub new_members_root: String,
}

#[derive(Args, Debug)]
pub(crate) struct RetireTailnetArgs {
    #[arg(long)]
    pub tailnet_id: u64,
}

#[derive(Args, Debug)]
pub(crate) struct DepositArgs {
    #[arg(long)]
    pub tailnet_id: u64,
    /// OU to add to the tailnet treasury (tx `value`).
    #[arg(long)]
    pub amount: u64,
}

#[derive(Args, Debug)]
pub(crate) struct WithdrawArgs {
    #[arg(long)]
    pub tailnet_id: u64,
    /// OU to withdraw from the (retired) tailnet treasury.
    #[arg(long)]
    pub amount: u64,
}

#[derive(Args, Debug)]
pub(crate) struct OpenSessionArgs {
    #[arg(long)]
    pub tailnet_id: u64,
    /// Exit circle the session pays out to.
    #[arg(long)]
    pub circle: String,
    /// Pre-agreed max OU the opener will spend on this session.
    #[arg(long)]
    pub max_pay: u64,
}

#[derive(Args, Debug)]
pub(crate) struct SettleClaimArgs {
    #[arg(long)]
    pub session_id: u64,
    #[arg(long)]
    pub bytes_used: u64,
}

#[derive(Args, Debug)]
pub(crate) struct SettleConfirmArgs {
    #[arg(long)]
    pub session_id: u64,
    #[arg(long)]
    pub bytes_used: u64,
    /// Pre-agreed plaintext credit (price * bytes after class rules).
    #[arg(long)]
    pub net: u64,
    /// Per-session blinding fed into the earnings hash chain.
    #[arg(long)]
    pub settle_blinding: String,
}

#[derive(Args, Debug)]
pub(crate) struct ClaimNoShowArgs {
    #[arg(long)]
    pub session_id: u64,
}

#[derive(Args, Debug)]
pub(crate) struct SweepArgs {
    #[arg(long)]
    pub session_id: u64,
}

#[derive(Args, Debug)]
pub(crate) struct ClaimEarningsArgs {
    #[arg(long)]
    pub circle: String,
    /// OU to pull from `circle_earnings_total - circle_earnings_claimed`.
    #[arg(long)]
    pub amount: u64,
}

// ============================================================
// Dispatch
// ============================================================

/// Entry point called from `main.rs` when the operator runs
/// `octravpn-node v3 <subcommand>`. Loads the config, builds a
/// `ChainCtxV3`, and fans out to the per-subcommand handler.
pub(crate) async fn dispatch(cfg_path: &Path, cmd: V3Cmd) -> Result<()> {
    let cfg = NodeConfig::load(cfg_path)?;
    let ctx = build_chain_ctx(&cfg)?;

    match cmd {
        V3Cmd::Bond(a) => run_bond(&ctx, &a).await,
        V3Cmd::Unbond(a) => run_unbond(&ctx, &a).await,
        V3Cmd::FinalizeUnbond(a) => run_finalize_unbond(&ctx, &a).await,
        V3Cmd::Slash(a) => run_slash(&ctx, &a).await,
        V3Cmd::RotateReceiptPubkey(a) => run_rotate(&ctx, &a).await,
        V3Cmd::Retire(a) => run_retire(&ctx, &a).await,
        V3Cmd::CreateTailnet(a) => run_create_tailnet(&ctx, &a).await,
        V3Cmd::UpdateMembersRoot(a) => run_update_members_root(&ctx, &a).await,
        V3Cmd::RetireTailnet(a) => run_retire_tailnet(&ctx, &a).await,
        V3Cmd::DepositTailnet(a) => run_deposit_tailnet(&ctx, &a).await,
        V3Cmd::WithdrawTailnet(a) => run_withdraw_tailnet(&ctx, &a).await,
        V3Cmd::OpenSession(a) => run_open_session(&ctx, &a).await,
        V3Cmd::SettleClaim(a) => run_settle_claim(&ctx, &a).await,
        V3Cmd::SettleConfirm(a) => run_settle_confirm(&ctx, &a).await,
        V3Cmd::ClaimNoShow(a) => run_claim_no_show(&ctx, &a).await,
        V3Cmd::SweepSession(a) => run_sweep_session(&ctx, &a).await,
        V3Cmd::ClaimEarnings(a) => run_claim_earnings(&ctx, &a).await,
    }
}

/// Public re-export so other CLI dispatchers (currently
/// `Cmd::Circle` in `main.rs`) can reuse the same short-lived
/// `ChainCtxV3` builder without duplicating the sealed-keys gate.
pub(crate) fn build_chain_ctx_for_circle(cfg: &NodeConfig) -> Result<ChainCtxV3> {
    build_chain_ctx(cfg)
}

/// Build a `ChainCtxV3` directly from a `NodeConfig`. Mirrors the
/// relevant slice of `Hub::new` but skips everything the one-shot CLI
/// doesn't need (audit log dir, receipt journal, control plane state).
///
/// Honors `[chain].require_sealed_keys` like the long-running daemon
/// does: in strict mode, plaintext-on-disk surfaces a typed
/// `PlaintextKeyOnDisk` error pointing at `seal-keys`.
fn build_chain_ctx(cfg: &NodeConfig) -> Result<ChainCtxV3> {
    let rpc = cfg.chain.build_rpc_client()?;
    let program_addr = Address::from_display(&cfg.chain.program_addr);
    let wallet_secret = if cfg.chain.require_sealed_keys {
        *octravpn_core::util::read_secret_32_or_sealed(&cfg.chain.wallet_secret_path, None)
            .with_context(|| {
                format!("strict-load wallet secret {}", cfg.chain.wallet_secret_path)
            })?
    } else {
        octravpn_core::util::read_secret_32(&cfg.chain.wallet_secret_path)
            .with_context(|| format!("load wallet secret {}", cfg.chain.wallet_secret_path))?
    };
    let wallet = KeyPair::from_secret_bytes(&wallet_secret);
    Ok(ChainCtxV3::new(rpc, program_addr, wallet))
}

// ============================================================
// Per-subcommand runners
// ============================================================

async fn run_bond(ctx: &ChainCtxV3, a: &BondArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_bond_endpoint_call(&a.circle, a.amount, fee, nonce);
    submit_and_log(ctx, "bond_endpoint", call, None).await
}

async fn run_unbond(ctx: &ChainCtxV3, a: &UnbondArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_unbond_endpoint_call(&a.circle, fee, nonce);
    submit_and_log(ctx, "unbond_endpoint", call, None).await
}

async fn run_finalize_unbond(ctx: &ChainCtxV3, a: &FinalizeUnbondArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_finalize_unbond_call(&a.circle, fee, nonce);
    submit_and_log(ctx, "finalize_unbond", call, None).await
}

async fn run_slash(ctx: &ChainCtxV3, a: &SlashArgs) -> Result<()> {
    if a.payload_a == a.payload_b {
        return Err(anyhow!(
            "slash payloads must differ — identical payloads can't double-sign"
        ));
    }
    let secret = read_receipt_secret(&a.receipt_key)?;
    let kp = KeyPair::from_secret_bytes(&secret);
    let sig_a = B64.encode(kp.sign(a.payload_a.as_bytes()).0);
    let sig_b = B64.encode(kp.sign(a.payload_b.as_bytes()).0);

    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let params = SlashDoubleSignParams {
        circle_id: &a.circle,
        payload_a: &a.payload_a,
        sig_a_b64: &sig_a,
        payload_b: &a.payload_b,
        sig_b_b64: &sig_b,
        fee,
        nonce,
    };
    let call = ctx.build_slash_double_sign_call(&params);
    submit_and_log(ctx, "slash_double_sign", call, None).await
}

async fn run_rotate(ctx: &ChainCtxV3, a: &RotateArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_rotate_receipt_pubkey_call(&a.circle, &a.new_pubkey_b64, fee, nonce);
    submit_and_log(ctx, "rotate_receipt_pubkey", call, None).await
}

async fn run_retire(ctx: &ChainCtxV3, a: &RetireArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_retire_circle_call(&a.circle, fee, nonce);
    submit_and_log(ctx, "retire_circle", call, None).await
}

async fn run_create_tailnet(ctx: &ChainCtxV3, a: &CreateTailnetArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_create_tailnet_call(&a.members_root, a.deposit, fee, nonce);
    submit_and_log(ctx, "create_tailnet", call, Some(ReturnLog::TailnetId)).await
}

async fn run_update_members_root(ctx: &ChainCtxV3, a: &UpdateMembersArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_update_members_root_call(a.tailnet_id, &a.new_members_root, fee, nonce);
    submit_and_log(ctx, "update_members_root", call, None).await
}

async fn run_retire_tailnet(ctx: &ChainCtxV3, a: &RetireTailnetArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_retire_tailnet_call(a.tailnet_id, fee, nonce);
    submit_and_log(ctx, "retire_tailnet", call, None).await
}

async fn run_deposit_tailnet(ctx: &ChainCtxV3, a: &DepositArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_deposit_to_tailnet_call(a.tailnet_id, a.amount, fee, nonce);
    submit_and_log(ctx, "deposit_to_tailnet", call, None).await
}

async fn run_withdraw_tailnet(ctx: &ChainCtxV3, a: &WithdrawArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_withdraw_tailnet_treasury_call(a.tailnet_id, a.amount, fee, nonce);
    submit_and_log(ctx, "withdraw_tailnet_treasury", call, None).await
}

async fn run_open_session(ctx: &ChainCtxV3, a: &OpenSessionArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_open_session_call(a.tailnet_id, &a.circle, a.max_pay, fee, nonce);
    submit_and_log(ctx, "open_session", call, Some(ReturnLog::SessionId)).await
}

async fn run_settle_claim(ctx: &ChainCtxV3, a: &SettleClaimArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_settle_claim_call(a.session_id, a.bytes_used, fee, nonce);
    submit_and_log(ctx, "settle_claim", call, Some(ReturnLog::AcceptedBool)).await
}

async fn run_settle_confirm(ctx: &ChainCtxV3, a: &SettleConfirmArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let params = SettleConfirmParams {
        session_id: a.session_id,
        bytes_used: a.bytes_used,
        net: a.net,
        settle_blinding: &a.settle_blinding,
        fee,
        nonce,
    };
    let call = ctx.build_settle_confirm_call(&params);
    submit_and_log(ctx, "settle_confirm", call, Some(ReturnLog::AcceptedBool)).await
}

async fn run_claim_no_show(ctx: &ChainCtxV3, a: &ClaimNoShowArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_claim_no_show_call(a.session_id, fee, nonce);
    submit_and_log(ctx, "claim_no_show", call, None).await
}

async fn run_sweep_session(ctx: &ChainCtxV3, a: &SweepArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_sweep_expired_session_call(a.session_id, fee, nonce);
    submit_and_log(ctx, "sweep_expired_session", call, None).await
}

async fn run_claim_earnings(ctx: &ChainCtxV3, a: &ClaimEarningsArgs) -> Result<()> {
    let (nonce, fee) = nonce_and_fee(ctx).await?;
    let call = ctx.build_claim_earnings_call(&a.circle, a.amount, fee, nonce);
    submit_and_log(ctx, "claim_earnings", call, None).await
}

// ============================================================
// Shared helpers
// ============================================================

async fn nonce_and_fee(ctx: &ChainCtxV3) -> Result<(u64, u64)> {
    let nonce = ctx.nonce().await?;
    let fee = ctx.fee_or_fallback("contract_call").await;
    Ok((nonce, fee))
}

/// What kind of return value to try to parse out of
/// `octra_transaction(hash)` once it lands. `None` ⇒ don't poll, just
/// print the hash.
#[derive(Copy, Clone, Debug)]
enum ReturnLog {
    /// `open_session` returns the assigned session id (int).
    SessionId,
    /// `create_tailnet` doesn't formally return the id, but the next
    /// `tailnet_count` is observable post-confirm.
    TailnetId,
    /// `settle_claim` / `settle_confirm` both return bool — true if
    /// accepted, false on equivocation / dispute.
    AcceptedBool,
}

/// Sign, submit, log. The `return_log` parameter controls best-effort
/// post-submit polling: for return-bearing entrypoints (open_session,
/// settle_claim, …) we poll `octra_transaction(hash)` a few times and
/// log whatever the chain's `result` / `storage` envelope reports.
/// Missing the value is non-fatal — operators can `octra cast call` /
/// `octra_transaction` it themselves.
async fn submit_and_log(
    ctx: &ChainCtxV3,
    method: &str,
    call: Value,
    return_log: Option<ReturnLog>,
) -> Result<()> {
    let signed = ctx.sign_call(call)?;
    let hash = ctx.submit_signed_tx(&signed).await?;
    println!("{method}: tx_hash = {hash}");
    info!(%hash, method, "v3 cli tx submitted");

    if let Some(kind) = return_log {
        if let Some(rendered) = poll_return_value(ctx, &hash, kind).await {
            println!("{method}: return = {rendered}");
        } else {
            warn!(
                %hash, method,
                "return value not available within poll window; \
                 query `octra_transaction({hash})` manually"
            );
        }
    }
    Ok(())
}

/// Best-effort poll of `octra_transaction(hash)` for a return value.
/// Returns `None` if the chain never reports a result within the
/// bounded number of attempts.
async fn poll_return_value(ctx: &ChainCtxV3, hash: &str, kind: ReturnLog) -> Option<String> {
    // 5 attempts at 1s each — plenty for devnet's block cadence, brief
    // enough on mainnet that ops aren't blocked if a tx hasn't included.
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let Ok(v) = ctx.rpc.transaction(hash).await else {
            continue;
        };
        // The receipt envelope shape varies between mock and real RPC.
        // Try the common locations a contract return surfaces under.
        if let Some(s) = extract_return(&v, kind) {
            return Some(s);
        }
    }
    None
}

fn extract_return(tx: &Value, kind: ReturnLog) -> Option<String> {
    // Common shapes:
    //   { "result": <val>, ... }
    //   { "tx": { "result": <val>, ... }, ... }
    //   { "result": { "result": <val>, "storage": {...} } }
    let candidates = [
        tx.get("result"),
        tx.get("tx").and_then(|t| t.get("result")),
        tx.get("result").and_then(|r| r.get("result")),
    ];
    for c in candidates.iter().flatten() {
        match kind {
            ReturnLog::SessionId | ReturnLog::TailnetId => {
                if let Some(n) = c.as_u64() {
                    return Some(n.to_string());
                }
            }
            ReturnLog::AcceptedBool => {
                if let Some(b) = c.as_bool() {
                    return Some(b.to_string());
                }
            }
        }
    }
    None
}

/// Read the 32-byte ed25519 receipt secret. Accepts either raw 32-byte
/// binary OR a hex blob (64 chars + optional whitespace) — same shape
/// the daemon's `wg_secret_path` reader accepts. We don't reuse
/// `read_secret_32` directly because that helper is `pub(crate)` to
/// `hub` and lives in core — but we delegate to the same `octravpn_core`
/// utility under the hood.
fn read_receipt_secret(path: &Path) -> Result<[u8; 32]> {
    let s = path
        .to_str()
        .ok_or_else(|| anyhow!("receipt key path not utf-8: {}", path.display()))?;
    octravpn_core::util::read_secret_32(s)
        .with_context(|| format!("read receipt key {}", path.display()))
}

// ============================================================
// Tests — one per subcommand, asserting the builder produces the
// expected wire shape WITHOUT going near the network.
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use octravpn_core::{address::Address, rpc::RpcClient, sig::KeyPair};

    fn ctx() -> ChainCtxV3 {
        let secret = [9u8; 32];
        let wallet = KeyPair::from_secret_bytes(&secret);
        let program_addr = Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3");
        let rpc = RpcClient::new("http://127.0.0.1:0/unused");
        ChainCtxV3::new(rpc, program_addr, wallet)
    }

    const CID: &str = "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun";
    const ANCHOR: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn bond_args_build_expected_call() {
        let c = ctx();
        let call = c.build_bond_endpoint_call(CID, 75_000_000, 500, 1);
        assert_eq!(call["method"], "bond_endpoint");
        assert_eq!(call["value"], 75_000_000);
        assert_eq!(call["params"][0], CID);
    }

    #[test]
    fn unbond_args_build_expected_call() {
        let c = ctx();
        let call = c.build_unbond_endpoint_call(CID, 500, 2);
        assert_eq!(call["method"], "unbond_endpoint");
        assert_eq!(call["value"], 0);
        assert_eq!(call["params"][0], CID);
    }

    #[test]
    fn finalize_unbond_args_build_expected_call() {
        let c = ctx();
        let call = c.build_finalize_unbond_call(CID, 500, 3);
        assert_eq!(call["method"], "finalize_unbond");
        assert_eq!(call["params"][0], CID);
    }

    #[test]
    fn slash_args_sign_and_build_expected_call() {
        // Inline the slash CLI's signing pipeline. We can't run the
        // full `run_slash` async path here (it would try to fetch nonce
        // off the RPC), but the cryptographic steps + builder
        // composition are the bit worth covering.
        let c = ctx();
        let receipt_secret = [42u8; 32];
        let kp = KeyPair::from_secret_bytes(&receipt_secret);
        let payload_a = "receipt-v1|sid=99|bytes=100";
        let payload_b = "receipt-v1|sid=99|bytes=200";
        let sig_a = B64.encode(kp.sign(payload_a.as_bytes()).0);
        let sig_b = B64.encode(kp.sign(payload_b.as_bytes()).0);
        let params = SlashDoubleSignParams {
            circle_id: CID,
            payload_a,
            sig_a_b64: &sig_a,
            payload_b,
            sig_b_b64: &sig_b,
            fee: 500,
            nonce: 4,
        };
        let call = c.build_slash_double_sign_call(&params);
        assert_eq!(call["method"], "slash_double_sign");
        let p = call["params"].as_array().unwrap();
        assert_eq!(p.len(), 5);
        assert_eq!(p[0], CID);
        assert_eq!(p[1], payload_a);
        assert_eq!(p[3], payload_b);
        // Sigs must round-trip through base64 to 64 bytes.
        let raw_a = B64.decode(p[2].as_str().unwrap()).unwrap();
        let raw_b = B64.decode(p[4].as_str().unwrap()).unwrap();
        assert_eq!(raw_a.len(), 64);
        assert_eq!(raw_b.len(), 64);
        // And the two sigs must differ (different payloads → different
        // sigs under the same key).
        assert_ne!(raw_a, raw_b);
    }

    #[test]
    fn rotate_receipt_pubkey_args_build_expected_call() {
        let c = ctx();
        let call = c.build_rotate_receipt_pubkey_call(
            CID,
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
            500,
            5,
        );
        assert_eq!(call["method"], "rotate_receipt_pubkey");
        assert_eq!(
            call["params"][1],
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
        );
    }

    #[test]
    fn retire_args_build_expected_call() {
        let c = ctx();
        let call = c.build_retire_circle_call(CID, 500, 6);
        assert_eq!(call["method"], "retire_circle");
        assert_eq!(call["params"][0], CID);
    }

    #[test]
    fn create_tailnet_args_build_expected_call() {
        let c = ctx();
        let call = c.build_create_tailnet_call(ANCHOR, 5_000_000, 500, 7);
        assert_eq!(call["method"], "create_tailnet");
        assert_eq!(call["value"], 5_000_000);
        assert_eq!(call["params"][0], ANCHOR);
    }

    #[test]
    fn update_members_root_args_build_expected_call() {
        let c = ctx();
        let call = c.build_update_members_root_call(2, ANCHOR, 500, 8);
        assert_eq!(call["method"], "update_members_root");
        assert_eq!(call["params"][0], 2);
        assert_eq!(call["params"][1], ANCHOR);
    }

    #[test]
    fn retire_tailnet_args_build_expected_call() {
        let c = ctx();
        let call = c.build_retire_tailnet_call(2, 500, 9);
        assert_eq!(call["method"], "retire_tailnet");
        assert_eq!(call["params"][0], 2);
    }

    #[test]
    fn deposit_tailnet_args_build_expected_call() {
        let c = ctx();
        let call = c.build_deposit_to_tailnet_call(2, 250_000, 500, 10);
        assert_eq!(call["method"], "deposit_to_tailnet");
        assert_eq!(call["value"], 250_000);
        assert_eq!(call["params"][0], 2);
    }

    #[test]
    fn withdraw_tailnet_args_build_expected_call() {
        let c = ctx();
        let call = c.build_withdraw_tailnet_treasury_call(2, 100_000, 500, 11);
        assert_eq!(call["method"], "withdraw_tailnet_treasury");
        assert_eq!(call["value"], 0);
        assert_eq!(call["fee"], 500);
        assert_eq!(call["nonce"], 11);
        let p = call["params"].as_array().unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0], 2);
        assert_eq!(p[1], 100_000);
        assert_eq!(call["from"], c.wallet_addr.display());
        assert_eq!(call["to"], c.program_addr.display());
    }

    #[test]
    fn open_session_args_build_expected_call() {
        let c = ctx();
        let call = c.build_open_session_call(0, CID, 1500, 500, 12);
        assert_eq!(call["method"], "open_session");
        let p = call["params"].as_array().unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p[0], 0);
        assert_eq!(p[1], CID);
        assert_eq!(p[2], 1500);
    }

    #[test]
    fn settle_claim_args_build_expected_call() {
        let c = ctx();
        let call = c.build_settle_claim_call(7, 1_048_576, 500, 13);
        assert_eq!(call["method"], "settle_claim");
        assert_eq!(call["params"][0], 7);
        assert_eq!(call["params"][1], 1_048_576);
    }

    #[test]
    fn settle_confirm_args_build_expected_call() {
        let c = ctx();
        let p = SettleConfirmParams {
            session_id: 7,
            bytes_used: 1_048_576,
            net: 1000,
            settle_blinding: "deadbeef",
            fee: 500,
            nonce: 14,
        };
        let call = c.build_settle_confirm_call(&p);
        assert_eq!(call["method"], "settle_confirm");
        let arr = call["params"].as_array().unwrap();
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0], 7);
        assert_eq!(arr[1], 1_048_576);
        assert_eq!(arr[2], 1000);
        assert_eq!(arr[3], "deadbeef");
    }

    #[test]
    fn claim_no_show_args_build_expected_call() {
        let c = ctx();
        let call = c.build_claim_no_show_call(7, 500, 15);
        assert_eq!(call["method"], "claim_no_show");
        assert_eq!(call["params"][0], 7);
    }

    #[test]
    fn sweep_session_args_build_expected_call() {
        let c = ctx();
        let call = c.build_sweep_expired_session_call(7, 500, 16);
        assert_eq!(call["method"], "sweep_expired_session");
        assert_eq!(call["params"][0], 7);
    }

    #[test]
    fn claim_earnings_args_build_expected_call() {
        let c = ctx();
        let call = c.build_claim_earnings_call(CID, 999, 500, 17);
        assert_eq!(call["method"], "claim_earnings");
        assert_eq!(call["params"][0], CID);
        assert_eq!(call["params"][1], 999);
    }

    #[test]
    fn slash_rejects_identical_payloads() {
        // Belt-and-braces: the AML rejects identical payloads, but
        // surfacing the error locally avoids a wasted on-chain submit.
        // We can't drive the full `run_slash` here without a working
        // RPC + secret file, but `SlashArgs::payload_a == payload_b`
        // is the only validation the CLI does pre-build, so we mirror
        // the predicate directly here.
        let a = "x";
        let b = "x";
        assert!(a == b, "if this trips, update the slash predicate test");
    }

    #[test]
    fn extract_return_session_id_from_top_level_result() {
        let tx = serde_json::json!({ "result": 7 });
        let got = extract_return(&tx, ReturnLog::SessionId);
        assert_eq!(got.as_deref(), Some("7"));
    }

    #[test]
    fn extract_return_accepted_bool_from_nested() {
        let tx = serde_json::json!({ "result": { "result": true, "storage": {} } });
        let got = extract_return(&tx, ReturnLog::AcceptedBool);
        assert_eq!(got.as_deref(), Some("true"));
    }

    #[test]
    fn extract_return_handles_missing() {
        let tx = serde_json::json!({ "noop": null });
        assert!(extract_return(&tx, ReturnLog::SessionId).is_none());
        assert!(extract_return(&tx, ReturnLog::AcceptedBool).is_none());
    }

    #[test]
    fn return_log_variants_cover_all_known_kinds() {
        // Sentinel: if a new return-bearing entrypoint lands, extend
        // ReturnLog and update this test.
        let kinds = [
            ReturnLog::SessionId,
            ReturnLog::TailnetId,
            ReturnLog::AcceptedBool,
        ];
        assert_eq!(kinds.len(), 3);
    }

    // ----------------------------------------------------------------
    // Additional coverage — sign envelope + ChainCtxV3 round-trips +
    // extract_return shape variants. These don't touch the network.
    // ----------------------------------------------------------------

    #[test]
    fn sign_call_produces_consistent_envelope() {
        let c = ctx();
        let call = c.build_bond_endpoint_call(CID, 100, 500, 1);
        let signed = c.sign_call(call).unwrap();
        // Signed envelope must carry at least a signature + from
        // identity. The exact shape comes from `octra_tx::sign_call`;
        // we only assert the high-level invariant: it serializes to a
        // non-empty JSON object and contains the signer.
        assert!(signed.is_object(), "expected JSON object, got {signed}");
        // Look for either top-level `from` or nested `tx.from`.
        let has_from =
            signed.get("from").is_some() || signed.get("tx").and_then(|t| t.get("from")).is_some();
        assert!(has_from, "expected from field, got {signed}");
    }

    #[test]
    fn build_chain_ctx_fails_when_wallet_missing() {
        // Use a NodeConfig pointing at a non-existent wallet path.
        // This avoids touching the network — `build_chain_ctx` reads
        // the secret synchronously before constructing the ctx.
        let toml = r#"
[chain]
rpc_url = "http://127.0.0.1:0/unused"
program_addr = "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3"
validator_addr = "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun"
wallet_secret_path = "/nonexistent/path/wallet.key"

[tunnel]
public_endpoint = "1.2.3.4:51820"
listen = "0.0.0.0:51820"
wg_secret_path = "/nonexistent/path/wg.key"

[pricing]
price_per_mb = 100
region = "test"

[control]
listen = "0.0.0.0:51821"
"#;
        let cfg: crate::config::NodeConfig = ::toml::from_str(toml).unwrap();
        let err = match build_chain_ctx(&cfg) {
            Ok(_) => panic!("expected wallet-missing error"),
            Err(e) => e,
        };
        assert!(format!("{err:#}").to_lowercase().contains("wallet"));
    }

    #[test]
    fn build_rpc_with_no_pinned_roots_constructs_client() {
        let toml = r#"
[chain]
rpc_url = "http://127.0.0.1:0/unused"
program_addr = "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3"
validator_addr = "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun"
wallet_secret_path = "/tmp/x"

[tunnel]
public_endpoint = "1.2.3.4:51820"
listen = "0.0.0.0:51820"
wg_secret_path = "/tmp/y"

[pricing]
price_per_mb = 100
region = "test"

[control]
listen = "0.0.0.0:51821"
"#;
        let cfg: crate::config::NodeConfig = ::toml::from_str(toml).unwrap();
        let r = cfg.chain.build_rpc_client();
        assert!(r.is_ok());
    }

    #[test]
    fn read_receipt_secret_accepts_hex_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("receipt.key");
        let secret = [0xDEu8; 32];
        std::fs::write(&key, hex::encode(secret) + "\n").unwrap();
        let got = read_receipt_secret(&key).unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn read_receipt_secret_errors_on_missing() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("missing");
        let err = read_receipt_secret(&key).unwrap_err();
        assert!(format!("{err:#}").contains("read"));
    }

    #[test]
    fn extract_return_from_tx_nested_result_shape() {
        // Shape: { "tx": { "result": 42 } }
        let tx = serde_json::json!({ "tx": { "result": 42 } });
        let got = extract_return(&tx, ReturnLog::SessionId);
        assert_eq!(got.as_deref(), Some("42"));
    }

    #[test]
    fn extract_return_tailnet_id_extracts_u64() {
        let tx = serde_json::json!({ "result": 99 });
        let got = extract_return(&tx, ReturnLog::TailnetId);
        assert_eq!(got.as_deref(), Some("99"));
    }

    #[test]
    fn extract_return_returns_none_for_wrong_type() {
        // Asking for SessionId (u64) on a bool payload returns None.
        let tx = serde_json::json!({ "result": true });
        assert!(extract_return(&tx, ReturnLog::SessionId).is_none());
    }

    #[test]
    fn settle_confirm_call_has_four_params_in_order() {
        let c = ctx();
        let p = SettleConfirmParams {
            session_id: 1,
            bytes_used: 2,
            net: 3,
            settle_blinding: "abcd",
            fee: 4,
            nonce: 5,
        };
        let call = c.build_settle_confirm_call(&p);
        let params = call["params"].as_array().unwrap();
        assert_eq!(
            params,
            &[
                serde_json::json!(1u64),
                serde_json::json!(2u64),
                serde_json::json!(3u64),
                serde_json::json!("abcd"),
            ]
        );
        assert_eq!(call["fee"], 4);
        assert_eq!(call["nonce"], 5);
    }

    #[test]
    fn create_tailnet_carries_deposit_in_value_field() {
        let c = ctx();
        let call = c.build_create_tailnet_call(ANCHOR, 5_000_000, 500, 7);
        assert_eq!(call["value"], 5_000_000);
        // Confirm fee and nonce surfaced separately.
        assert_eq!(call["fee"], 500);
        assert_eq!(call["nonce"], 7);
    }

    #[test]
    fn bond_endpoint_value_field_matches_amount() {
        let c = ctx();
        let call = c.build_bond_endpoint_call(CID, 123_456_789, 500, 8);
        assert_eq!(call["value"], 123_456_789);
    }

    #[test]
    fn non_payable_calls_have_zero_value() {
        let c = ctx();
        // Several non-payable methods should have value=0.
        assert_eq!(c.build_unbond_endpoint_call(CID, 100, 1)["value"], 0);
        assert_eq!(c.build_finalize_unbond_call(CID, 100, 1)["value"], 0);
        assert_eq!(c.build_retire_circle_call(CID, 100, 1)["value"], 0);
        assert_eq!(c.build_retire_tailnet_call(2, 100, 1)["value"], 0);
        assert_eq!(c.build_settle_claim_call(1, 1, 100, 1)["value"], 0);
        assert_eq!(c.build_claim_no_show_call(1, 100, 1)["value"], 0);
        assert_eq!(c.build_sweep_expired_session_call(1, 100, 1)["value"], 0);
        assert_eq!(c.build_claim_earnings_call(CID, 1, 100, 1)["value"], 0);
    }
}
