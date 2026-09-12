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
use octravpn_core::v3_members::Member;

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
    /// Admit a device: bind `wallet` to its WireGuard/Tailscale node key
    /// and re-anchor the set. Re-admitting a wallet replaces its key.
    Admit {
        /// `oct…` wallet address the device belongs to.
        #[arg(long)]
        wallet: String,
        /// Node key: `nodekey:<hex>`, bare 64-hex, or the 44-char base64
        /// WireGuard public key. (`tailscale status --json` → `Self.PublicKey`.)
        #[arg(long)]
        node_key: String,
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
            run_members(chain, creds, &self.circle, cmd).await?;
            return Ok(0);
        }
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

/// Fresh 64-hex `ip_salt` for a member set that does not exist yet. An
/// existing set keeps the salt it was created with.
fn fresh_ip_salt() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

async fn run_members(
    chain: Arc<ChainCtxV3>,
    creds: SealedAssetCreds,
    circle: &str,
    cmd: MembersCmd,
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
                let node_key = crate::members_policy::member_node_key_hex(&member.wg_pubkey_b64)
                    .map_or_else(|_| "<invalid key>".to_string(), |h| format!("nodekey:{h}"));
                println!(
                    "  {}  {}  joined_epoch={}",
                    member.wallet, node_key, member.joined_epoch
                );
            }
        }
        MembersCmd::Admit {
            wallet,
            node_key,
            tailnet_id,
        } => {
            let wg_pubkey_b64 = parse_node_key(&node_key)?;
            let mut members = store.load_enroll_state(tailnet_id).await?.members;
            let joined_epoch = chain.current_epoch().await.unwrap_or(0);
            let entry = Member {
                wallet: wallet.clone(),
                wg_pubkey_b64,
                joined_epoch,
            };
            let replaced =
                if let Some(existing) = members.members.iter_mut().find(|m| m.wallet == wallet) {
                    *existing = entry;
                    true
                } else {
                    members.members.push(entry);
                    false
                };
            members.validate()?;
            let v = store.commit_members(tailnet_id, &members).await?;
            println!(
                "{} {wallet} (members now {} device(s), circle state v{v}; applies next epoch)",
                if replaced { "re-keyed" } else { "admitted" },
                members.members.len()
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
                "evicted {wallet} (members now {} device(s), circle state v{v}; applies next epoch)",
                members.members.len()
            );
        }
    }
    Ok(())
}
