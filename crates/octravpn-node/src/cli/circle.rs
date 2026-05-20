//! `circle` subcommand tree — atomic update primitive for sealed
//! circle assets. Delegates to `crate::circle_update`. No Hub; builds a
//! short-lived `ChainCtxV3` via `v3_cli::build_chain_ctx_for_circle`.

use anyhow::{Context as _, Result};
use async_trait::async_trait;

use crate::circle_update;
use crate::config::NodeConfig;
use crate::v3_cli;

use super::{CliContext, Subcommand};

/// `octravpn-node circle <subcmd>`
#[derive(clap::Args, Debug)]
pub(crate) struct CircleArgs {
    #[command(subcommand)]
    pub(crate) cmd: CircleCmd,
}

#[async_trait]
impl Subcommand for CircleArgs {
    fn needs_hub(&self) -> bool {
        false
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        run_circle_cmd(std::path::Path::new(ctx.cfg_path), self.cmd).await?;
        Ok(0)
    }
}

/// Circle-asset subcommands.
#[derive(clap::Subcommand, Debug)]
pub(crate) enum CircleCmd {
    /// Atomic update of one or more sealed circle assets + their
    /// state-root anchor. Blobs are written first; the anchor flip is
    /// the last tx. A failure between the two leaves chain state on
    /// the OLD anchor (old blobs still bound, new blobs are orphans
    /// recoverable via `retry-anchor`).
    Update(CircleUpdateArgs),
    /// Diagnostic: probe known sealed-asset paths and report any whose
    /// plaintext hash is not bound by the current on-chain anchor.
    ListOrphans(CircleListOrphansArgs),
    /// Re-submit only the `update_circle_state` tx with a pre-computed
    /// anchor. Used after an interrupted `update`.
    RetryAnchor(CircleRetryAnchorArgs),
}

#[derive(clap::Args, Debug)]
pub(crate) struct CircleUpdateArgs {
    /// Operator-circle id this update targets.
    #[arg(long)]
    pub(crate) circle: String,
    /// Sealed-asset passphrase. Falls back to
    /// `OCTRAVPN_SEALED_PASSPHRASE` env var when omitted.
    #[arg(long)]
    pub(crate) passphrase: Option<String>,
    /// Blob spec: `<asset_path>:<file>:<key_id>:<padding>`. Repeatable.
    /// `padding` is one of `none|4k|16k|32k|128k`.
    /// Example: `--blob /policy.json:./policy.json:default:4k`.
    #[arg(long = "blob")]
    pub(crate) blobs: Vec<String>,
    /// Override `state_root.region`.
    #[arg(long)]
    pub(crate) set_region: Option<String>,
    /// Override `state_root.member_count`.
    #[arg(long)]
    pub(crate) set_member_count: Option<u64>,
    /// Force `state_root.policy_hash` to a specific 64-char hex digest.
    #[arg(long)]
    pub(crate) set_policy_hash: Option<String>,
    /// Force `state_root.wg_pubkey_hash`.
    #[arg(long)]
    pub(crate) set_wg_pubkey_hash: Option<String>,
    /// Force `state_root.attestation_hash`. Empty string clears it.
    #[arg(long)]
    pub(crate) set_attestation_hash: Option<String>,
    /// Default ON: describe txs without broadcasting.
    #[arg(long, default_value_t = true)]
    pub(crate) dry_run: bool,
    /// Explicit opposite of `--dry-run`.
    #[arg(long, conflicts_with = "dry_run")]
    pub(crate) commit: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct CircleListOrphansArgs {
    #[arg(long)]
    pub(crate) circle: String,
    #[arg(long)]
    pub(crate) passphrase: Option<String>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct CircleRetryAnchorArgs {
    #[arg(long)]
    pub(crate) circle: String,
    /// 64-char hex anchor to commit.
    #[arg(long)]
    pub(crate) anchor: String,
}

/// Dispatch a `circle …` subcommand. Builds a short-lived `ChainCtxV3`
/// (no Hub) the same way the v3 CLI does. On
/// `UpdateError::AnchorUpdateFailed` we surface the target anchor +
/// recovery hint so the operator can re-run
/// `circle retry-anchor --anchor <hex>`.
pub(crate) async fn run_circle_cmd(cfg_path: &std::path::Path, cmd: CircleCmd) -> Result<()> {
    use circle_update::{
        apply, list_orphaned_blobs, retry_anchor, AnchorOverrides, UpdateBundle, UpdateError,
    };

    let cfg = NodeConfig::load(cfg_path)?;
    let ctx = v3_cli::build_chain_ctx_for_circle(&cfg)?;

    match cmd {
        CircleCmd::Update(args) => {
            let dry_run = args.dry_run && !args.commit;
            let creds = resolve_sealed_passphrase(args.passphrase.as_deref())?;
            let blobs = parse_blob_specs(&args.blobs)?;
            let anchor_overrides = AnchorOverrides {
                policy_hash: args.set_policy_hash.clone(),
                members_hash: None,
                wg_pubkey_hash: args.set_wg_pubkey_hash.clone(),
                attestation_hash: args.set_attestation_hash.map(|s| {
                    if s.is_empty() {
                        None
                    } else {
                        Some(s)
                    }
                }),
                region: args.set_region.clone(),
                member_count: args.set_member_count,
            };
            let bundle = UpdateBundle {
                circle_id: args.circle.clone(),
                blobs,
                anchor_overrides,
            };

            if dry_run {
                println!("circle update dry-run for {}", &args.circle);
                println!("  blobs: {}", bundle.blobs.len());
                for b in &bundle.blobs {
                    println!(
                        "    - {} key_id={} padding={} plaintext_sha256={}",
                        b.asset_path,
                        b.key_id,
                        b.padding_class.as_str(),
                        b.plaintext_hash_hex()
                    );
                }
                let current = circle_update::fetch_current_state_root(&ctx, &args.circle)
                    .await
                    .with_context(|| {
                        format!("dry-run: fetch current state-root for {}", &args.circle)
                    })?;
                match current {
                    Some(c) => {
                        let target = circle_update::compute_target_state_root(&c, &bundle)
                            .map_err(|e| anyhow::anyhow!("compute target state-root: {e}"))?;
                        let anchor = target
                            .anchor_hex()
                            .map_err(|e| anyhow::anyhow!("compute target anchor: {e}"))?;
                        println!("  current_anchor: {}", c.anchor_hex().unwrap_or_default());
                        println!("  target_anchor:  {anchor}");
                    }
                    None => {
                        println!("  current_anchor: <none — circle not yet registered>");
                    }
                }
                println!(
                    "  would submit: {} blob put(s) + 1 update_circle_state + 1 state-root.json put",
                    bundle.blobs.len()
                );
                println!("(dry-run; pass --commit to broadcast)");
                return Ok(());
            }

            match apply(&ctx, &creds, bundle).await {
                Ok(res) => {
                    println!("circle update: new_anchor = {}", res.new_anchor_hex);
                    for h in &res.blob_tx_hashes {
                        println!("  blob_tx: {h}");
                    }
                    if let Some(h) = &res.anchor_tx_hash {
                        println!("  anchor_tx: {h}");
                    }
                    Ok(())
                }
                Err(UpdateError::AnchorUpdateFailed {
                    target_anchor_hex,
                    blob_tx_hashes,
                    source,
                }) => {
                    eprintln!(
                        "anchor flip failed; blobs are committed. \
                         Re-run with: octravpn-node circle retry-anchor \
                         --circle {} --anchor {}",
                        &args.circle, target_anchor_hex
                    );
                    for h in &blob_tx_hashes {
                        eprintln!("  blob_tx (committed): {h}");
                    }
                    Err(anyhow::anyhow!(source))
                }
                Err(e) => Err(anyhow::anyhow!(e)),
            }
        }
        CircleCmd::ListOrphans(args) => {
            let creds = resolve_sealed_passphrase(args.passphrase.as_deref())?;
            let current = circle_update::fetch_current_state_root(&ctx, &args.circle)
                .await?
                .ok_or_else(|| anyhow::anyhow!("circle {} has no on-chain anchor", &args.circle))?;
            let orphans = list_orphaned_blobs(&ctx, &args.circle, &current, &creds).await?;
            if orphans.is_empty() {
                println!("no orphaned blobs detected");
            } else {
                println!("orphaned blob paths (not bound by current anchor):");
                for p in &orphans {
                    println!("  {p}");
                }
            }
            Ok(())
        }
        CircleCmd::RetryAnchor(args) => {
            let hash = retry_anchor(&ctx, &args.circle, &args.anchor).await?;
            println!("anchor re-committed: tx_hash = {hash}");
            Ok(())
        }
    }
}

/// Parse the `--blob <asset_path>:<file>:<key_id>:<padding>` spec.
fn parse_blob_specs(raw: &[String]) -> Result<Vec<circle_update::BlobUpdate>> {
    use octravpn_core::circle::PaddingClass;

    let mut out = Vec::with_capacity(raw.len());
    for spec in raw {
        let parts: Vec<&str> = spec.splitn(4, ':').collect();
        if parts.len() != 4 {
            anyhow::bail!(
                "blob spec must be <asset_path>:<file>:<key_id>:<padding>; got {spec:?}"
            );
        }
        let plaintext = std::fs::read(parts[1])
            .with_context(|| format!("read blob plaintext {}", parts[1]))?;
        let padding = PaddingClass::from_str_opt(parts[3])
            .ok_or_else(|| anyhow::anyhow!("unknown padding class {:?}", parts[3]))?;
        out.push(circle_update::BlobUpdate {
            asset_path: parts[0].to_string(),
            // Audit-3 H-2: plaintext is now wrapped in `Zeroizing<Vec<u8>>`
            // on `BlobUpdate` so the heap buffer is scrubbed on drop.
            plaintext: zeroize::Zeroizing::new(plaintext),
            key_id: parts[2].to_string(),
            padding_class: padding,
        });
    }
    Ok(out)
}

/// Resolve the sealed-asset passphrase: CLI value, then
/// `OCTRAVPN_SEALED_PASSPHRASE` env var, then error.
fn resolve_sealed_passphrase(
    explicit: Option<&str>,
) -> Result<circle_update::SealedAssetCreds> {
    if let Some(p) = explicit {
        return Ok(circle_update::SealedAssetCreds::new(p));
    }
    if let Ok(p) = std::env::var("OCTRAVPN_SEALED_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(circle_update::SealedAssetCreds::new(p));
        }
    }
    anyhow::bail!(
        "no sealed-asset passphrase: pass --passphrase or set \
         OCTRAVPN_SEALED_PASSPHRASE"
    )
}
