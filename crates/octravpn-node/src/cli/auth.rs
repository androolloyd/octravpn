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

use anyhow::Result;
use async_trait::async_trait;
use clap::{Args, Subcommand as ClapSubcommand};

use super::{CliContext, Subcommand};
use crate::config::NodeConfig;
use crate::control::enroll_circle::CircleStore;
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
        }
        Ok(0)
    }
}
