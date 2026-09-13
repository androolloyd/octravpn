//! `octravpn-node auth` — manage the private-mesh enrollment allowlist.
//!
//! The allowlist is the operator's admission gate for circle-resident
//! enrollment: which wallets MAY join the private mesh. It's stored sealed
//! at `oct://<circle>/auth/allowed.json` and anchored under the operator's
//! `circle_state_root.auth_allowed_hash`, so every operator node reads the
//! same list and edits are tamper-evident. These commands do the sealed
//! read-modify-write + re-anchor through [`CircleStore`].
//!
//! This gates the PRIVATE mesh only — public paid-exit clients fund
//! `open_session` escrow and never appear on any allowlist.

use std::sync::Arc;

use anyhow::{bail, Context as _, Result};
use async_trait::async_trait;
use clap::{Args, Subcommand as ClapSubcommand};
use octravpn_core::v3_members::{Member, TailnetMembers};

use super::{CliContext, Subcommand};
use crate::chain_v3::ChainCtxV3;
use crate::circle_update::SealedAssetCreds;
use crate::config::NodeConfig;
use crate::control::enroll::EnrollStore;
use crate::control::enroll_circle::{CircleEnrollStore, CircleStore};
use crate::v3_cli;

/// Operator-side management of the enrollment allowlist.
#[derive(Args, Debug)]
pub(crate) struct AuthArgs {
    /// Operator circle id (`oct…`) the allowlist is anchored in.
    #[arg(long)]
    pub(crate) circle: String,
    /// Sealed-asset passphrase. Falls back to `$OCTRAVPN_SEALED_PASSPHRASE`.
    #[arg(long)]
    pub(crate) passphrase: Option<String>,
    /// Return as soon as the tx is submitted instead of waiting for the
    /// chain to apply it. Every `auth` edit is a read-modify-write of a
    /// sealed blob, and the chain applies a submitted tx at the next epoch
    /// (~10s), so a second edit issued before the first applies reads the
    /// pre-edit set and silently drops it. Only pass this when nothing
    /// else will touch the same circle.
    #[arg(long)]
    pub(crate) no_wait: bool,
    #[command(subcommand)]
    pub(crate) cmd: AuthCmd,
}

#[derive(ClapSubcommand, Debug)]
pub(crate) enum AuthCmd {
    /// Authorize a wallet to enroll into the private mesh (idempotent).
    Allow {
        /// `oct…` wallet address.
        wallet: String,
    },
    /// Remove a wallet's authorization. Already-enrolled devices are not
    /// evicted by this (revoking enrollment is a separate member-set edit).
    Revoke {
        /// `oct…` wallet address.
        wallet: String,
    },
    /// Print the current allowlist.
    List,
    /// The anchored member set (`/auth/members.json`): which devices the
    /// wire admits. Item 4 renders it into the Tailscale packet filter.
    Members {
        #[command(subcommand)]
        cmd: MembersCmd,
    },
}

#[derive(ClapSubcommand, Debug)]
pub(crate) enum MembersCmd {
    /// Print the anchored member set.
    List {
        #[arg(long, default_value_t = 0)]
        tailnet_id: u64,
    },
    /// Admit a device: bind `wallet` to the key(s) that identify it and
    /// re-anchor the set. Re-admitting a wallet updates the identities you
    /// pass and keeps the ones you don't.
    ///
    /// For a **stock tailscale** device use `--machine-key`: its node key
    /// is regenerated on every re-authentication (a refused registration
    /// burns it at once), so it cannot be named ahead of time. The machine
    /// key is stable, and the daemon's refusal log reports it. For
    /// **octravpn's own client**, whose WireGuard key is stable and also
    /// drives its tailnet IP, use `--node-key`.
    Admit {
        /// `oct…` wallet address the device belongs to.
        #[arg(long)]
        wallet: String,
        /// Node/WireGuard key: `nodekey:<hex>`, bare 64-hex, or the
        /// 44-char base64 WireGuard public key.
        #[arg(long)]
        node_key: Option<String>,
        /// Tailscale machine key: `mkey:<hex>` or bare 64-hex. The stable
        /// device identity; required for stock clients.
        #[arg(long)]
        machine_key: Option<String>,
        #[arg(long, default_value_t = 0)]
        tailnet_id: u64,
    },
    /// Evict a wallet's device and re-anchor the set.
    Evict {
        #[arg(long)]
        wallet: String,
        #[arg(long, default_value_t = 0)]
        tailnet_id: u64,
    },
}

#[async_trait]
impl Subcommand for AuthArgs {
    fn needs_hub(&self) -> bool {
        // Pure chain/circle I/O — no running Hub needed.
        false
    }

    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        let cfg = NodeConfig::load(ctx.cfg_path)?;
        let chain = Arc::new(v3_cli::build_chain_ctx_for_circle(&cfg)?);
        let creds = super::circle::resolve_sealed_passphrase(self.passphrase.as_deref())?;
        if let AuthCmd::Members { cmd } = self.cmd {
            run_members(chain, creds, &self.circle, cmd, !self.no_wait).await?;
            return Ok(0);
        }
        let wait = !self.no_wait;
        let store = CircleStore::new(chain, creds, self.circle.clone());

        match self.cmd {
            AuthCmd::List => {
                let al = store.load_allowlist().await?;
                println!(
                    "allowlist for circle {} — {} wallet(s):",
                    self.circle,
                    al.wallets.len()
                );
                for w in &al.wallets {
                    println!("  {w}");
                }
            }
            AuthCmd::Allow { wallet } => {
                let mut al = store.load_allowlist().await?;
                if al.wallets.iter().any(|w| w == &wallet) {
                    println!("already authorized: {wallet}");
                } else {
                    al.wallets.push(wallet.clone());
                    al.wallets.sort(); // deterministic canonical order
                    let v = store.commit_allowlist(&al).await?;
                    println!("authorized {wallet} (allowlist now v{v})");
                    report_applied(
                        wait,
                        wait_allowlist_applied(&store, &al.wallets, wait).await,
                    );
                }
            }
            AuthCmd::Revoke { wallet } => {
                let mut al = store.load_allowlist().await?;
                let before = al.wallets.len();
                al.wallets.retain(|w| w != &wallet);
                if al.wallets.len() == before {
                    println!("not on allowlist: {wallet}");
                } else {
                    let v = store.commit_allowlist(&al).await?;
                    println!("revoked {wallet} (allowlist now v{v})");
                    report_applied(
                        wait,
                        wait_allowlist_applied(&store, &al.wallets, wait).await,
                    );
                }
            }
            AuthCmd::Members { .. } => unreachable!("handled above"),
        }
        Ok(0)
    }
}

/// Accept a node key as Tailscale prints it (`nodekey:<hex>`), bare hex,
/// or the base64 WireGuard form; return the canonical `wg_pubkey_b64`.
fn parse_node_key(raw: &str) -> Result<String> {
    let s = raw.trim();
    let s = s.strip_prefix("nodekey:").unwrap_or(s);
    let bytes = if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(s).context("node key hex")?
    } else {
        octravpn_core::b64::decode(s).map_err(|e| anyhow::anyhow!("node key base64: {e}"))?
    };
    if bytes.len() != 32 {
        bail!("node key decodes to {} bytes, want 32", bytes.len());
    }
    Ok(octravpn_core::b64::encode(bytes))
}

/// Accept a machine key as `mkey:<hex>` or bare hex; return the canonical
/// lowercase hex the member set stores.
fn parse_machine_key(raw: &str) -> Result<String> {
    let s = raw.trim();
    let s = s.strip_prefix("mkey:").unwrap_or(s);
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("machine key must be 64 hex chars (optionally `mkey:`-prefixed), got {s:?}");
    }
    Ok(s.to_ascii_lowercase())
}

/// Fresh 64-hex `ip_salt` for a member set that does not exist yet. An
/// existing set keeps the salt it was created with.
fn fresh_ip_salt() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

/// How long to wait for the chain to apply an `auth` edit. Epochs are
/// hardcoded at 10s; 90s tolerates a slow epoch or a node catching up.
const APPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
const APPLY_POLL: std::time::Duration = std::time::Duration::from_secs(3);

/// Poll until a fresh read of the anchored member set is the one we just
/// wrote. `Some(true)` applied, `Some(false)` still pending, `None` when the
/// caller opted out of waiting.
async fn wait_members_applied(
    store: &CircleEnrollStore,
    tailnet_id: u64,
    committed: &TailnetMembers,
    wait: bool,
) -> Option<bool> {
    if !wait {
        return None;
    }
    let expected = committed.hash_hex().ok()?;
    let deadline = std::time::Instant::now() + APPLY_TIMEOUT;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(APPLY_POLL).await;
        if let Ok(state) = store.load_enroll_state(tailnet_id).await {
            if state.members.hash_hex().is_ok_and(|h| h == expected) {
                return Some(true);
            }
        }
    }
    Some(false)
}

/// Same wait for the enrollment allowlist.
async fn wait_allowlist_applied(
    store: &CircleStore,
    committed: &[String],
    wait: bool,
) -> Option<bool> {
    if !wait {
        return None;
    }
    let deadline = std::time::Instant::now() + APPLY_TIMEOUT;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(APPLY_POLL).await;
        if let Ok(current) = store.load_allowlist().await {
            if current.wallets == committed {
                return Some(true);
            }
        }
    }
    Some(false)
}

fn report_applied(wait: bool, applied: Option<bool>) {
    match applied {
        Some(true) => println!("  applied on chain"),
        Some(false) => println!(
            "  WARNING: still not applied after {}s. The tx is submitted and may yet land — \
             confirm with `auth … list` before the next edit, or it will be overwritten.",
            APPLY_TIMEOUT.as_secs()
        ),
        None => {
            debug_assert!(!wait);
            println!("  --no-wait: submitted; applies at the next epoch (~10s)");
        }
    }
}

async fn run_members(
    chain: Arc<ChainCtxV3>,
    creds: SealedAssetCreds,
    circle: &str,
    cmd: MembersCmd,
    wait: bool,
) -> Result<()> {
    let store = CircleEnrollStore::new(chain.clone(), creds, circle, fresh_ip_salt());
    match cmd {
        MembersCmd::List { tailnet_id } => {
            let state = store.load_enroll_state(tailnet_id).await?;
            let m = &state.members;
            println!(
                "members for circle {circle} — tailnet {} — {} device(s) — set hash {}",
                m.tailnet_id,
                m.members.len(),
                m.hash_hex().unwrap_or_else(|_| "<unhashable>".into())
            );
            for member in &m.members {
                let node_key = if member.wg_pubkey_b64.is_empty() {
                    "nodekey:-".to_string()
                } else {
                    crate::members_policy::member_node_key_hex(&member.wg_pubkey_b64).map_or_else(
                        |_| "nodekey:<invalid>".to_string(),
                        |h| format!("nodekey:{h}"),
                    )
                };
                let machine_key = if member.machine_key_hex.is_empty() {
                    "mkey:-".to_string()
                } else {
                    format!("mkey:{}", member.machine_key_hex)
                };
                println!(
                    "  {}  {}  {}  joined_epoch={}",
                    member.wallet, node_key, machine_key, member.joined_epoch
                );
            }
        }
        MembersCmd::Admit {
            wallet,
            node_key,
            machine_key,
            tailnet_id,
        } => {
            if node_key.is_none() && machine_key.is_none() {
                bail!(
                    "admit needs at least one identity: --machine-key for a stock tailscale \
                     device (stable across re-auth), --node-key for octravpn's own client"
                );
            }
            let wg_pubkey_b64 = node_key.as_deref().map(parse_node_key).transpose()?;
            let machine_key_hex = machine_key.as_deref().map(parse_machine_key).transpose()?;
            let mut members = store.load_enroll_state(tailnet_id).await?.members;
            let joined_epoch = chain.current_epoch().await.unwrap_or(0);
            // Re-admitting merges: an operator adding a node key to a device
            // already bound by machine key must not silently drop the
            // identity that survives its re-auth.
            let replaced =
                if let Some(existing) = members.members.iter_mut().find(|m| m.wallet == wallet) {
                    if let Some(wg) = wg_pubkey_b64 {
                        existing.wg_pubkey_b64 = wg;
                    }
                    if let Some(mk) = machine_key_hex {
                        existing.machine_key_hex = mk;
                    }
                    existing.joined_epoch = joined_epoch;
                    true
                } else {
                    members.members.push(Member {
                        wallet: wallet.clone(),
                        wg_pubkey_b64: wg_pubkey_b64.unwrap_or_default(),
                        machine_key_hex: machine_key_hex.unwrap_or_default(),
                        joined_epoch,
                    });
                    false
                };
            members.validate()?;
            let v = store.commit_members(tailnet_id, &members).await?;
            println!(
                "{} {wallet} (members now {} device(s), circle state v{v})",
                if replaced { "re-keyed" } else { "admitted" },
                members.members.len()
            );
            report_applied(
                wait,
                wait_members_applied(&store, tailnet_id, &members, wait).await,
            );
        }
        MembersCmd::Evict { wallet, tailnet_id } => {
            let mut members = store.load_enroll_state(tailnet_id).await?.members;
            let before = members.members.len();
            members.members.retain(|m| m.wallet != wallet);
            if members.members.len() == before {
                println!("not a member: {wallet}");
                return Ok(());
            }
            let v = store.commit_members(tailnet_id, &members).await?;
            println!(
                "evicted {wallet} (members now {} device(s), circle state v{v})",
                members.members.len()
            );
            report_applied(
                wait,
                wait_members_applied(&store, tailnet_id, &members, wait).await,
            );
        }
    }
    Ok(())
}
