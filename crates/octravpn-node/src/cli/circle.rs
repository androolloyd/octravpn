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
    /// First anchor for a freshly deployed circle: seal + put
    /// `/state-root.json`, then `register_circle` (or re-anchor a circle
    /// that was registered without a readable state-root). Every other
    /// circle command (`update`, `auth allow`, `auth members`) needs this
    /// to have happened once.
    Bootstrap(CircleBootstrapArgs),
}

#[derive(clap::Args, Debug)]
pub(crate) struct CircleBootstrapArgs {
    /// Circle id (`oct…`), deployed beforehand (`octra cast circle deploy`).
    #[arg(long)]
    pub(crate) circle: String,
    /// Sealed-asset passphrase. Falls back to `$OCTRAVPN_SEALED_PASSPHRASE`.
    #[arg(long)]
    pub(crate) passphrase: Option<String>,
    /// Stake for `register_circle`. Defaults to `[chain].v3_initial_stake`,
    /// then the program minimum.
    #[arg(long)]
    pub(crate) stake: Option<u64>,
    /// Re-anchor even when the circle already has a readable state-root.
    /// This RESETS the anchored member/allow hashes — use `circle update`
    /// to rotate a live circle instead.
    #[arg(long)]
    pub(crate) force: bool,
    #[arg(long, default_value_t = true)]
    pub(crate) dry_run: bool,
    #[arg(long, conflicts_with = "dry_run")]
    pub(crate) commit: bool,
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
                let current = circle_update::fetch_current_state_root(&ctx, &args.circle, &creds)
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
            let current = circle_update::fetch_current_state_root(&ctx, &args.circle, &creds)
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
        CircleCmd::Bootstrap(args) => run_bootstrap(&cfg, &ctx, args).await,
    }
}

/// `circle bootstrap` — the state-root a fresh circle starts from, built
/// exactly the way `v3_boot` builds it at daemon boot (same policy, same
/// key derivation), sealed into the circle, then anchored on chain.
async fn run_bootstrap(
    cfg: &NodeConfig,
    ctx: &crate::chain_v3::ChainCtxV3,
    args: CircleBootstrapArgs,
) -> Result<()> {
    use crate::chain_v3::{RegisterCircleParams, MIN_CIRCLE_STAKE_DEFAULT};
    use octravpn_core::v3_state_root::StateRoot;
    use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

    let creds = resolve_sealed_passphrase(args.passphrase.as_deref())?;
    let circle = args.circle.as_str();
    let dry_run = args.dry_run && !args.commit;

    // Same derivation the Hub boots with (hub/boot.rs), so the anchored
    // wg_pubkey_hash is the one the daemon will attest later.
    let master = if cfg.chain.require_sealed_keys {
        *octravpn_core::util::read_secret_32_or_sealed(&cfg.tunnel.wg_secret_path, None)
            .with_context(|| {
                format!("strict-load wg master secret {}", cfg.tunnel.wg_secret_path)
            })?
    } else {
        octravpn_core::util::read_secret_32(&cfg.tunnel.wg_secret_path)
            .with_context(|| format!("load wg master secret {}", cfg.tunnel.wg_secret_path))?
    };
    let noise_sk = octravpn_core::util::derive_subkey(&master, octravpn_core::util::DOMAIN_NOISE);
    let receipt_sk =
        octravpn_core::util::derive_subkey(&master, octravpn_core::util::DOMAIN_RECEIPT_SIGN);
    let wg_pub = X25519Pub::from(&StaticSecret::from(noise_sk)).to_bytes();
    let receipt_kp = octravpn_core::sig::KeyPair::from_secret_bytes(&receipt_sk);
    let receipt_pubkey_b64 = octravpn_core::b64::encode(receipt_kp.public.0);

    let epoch = ctx.current_epoch().await.unwrap_or(0);
    let timestamp_secs = octravpn_core::util::now_unix_secs();
    let policy = crate::v3_boot::build_operator_policy_for_v3(
        cfg,
        &octravpn_core::b64::encode(wg_pub),
        epoch,
        timestamp_secs,
    );
    policy
        .validate()
        .map_err(|e| anyhow::anyhow!("operator-policy validation: {e}"))?;
    let policy_hash = policy
        .hash_hex()
        .map_err(|e| anyhow::anyhow!("operator-policy hash: {e}"))?;
    let state_root = StateRoot::new_v1(
        circle,
        policy_hash,
        crate::v3_boot::sha256_hex(&wg_pub),
        None,
        cfg.pricing.region.clone(),
        0,
        epoch,
        timestamp_secs,
    );
    state_root
        .validate()
        .map_err(|e| anyhow::anyhow!("state-root validation: {e}"))?;
    let anchor_hex = state_root
        .anchor_hex()
        .map_err(|e| anyhow::anyhow!("state-root anchor: {e}"))?;

    let active = ctx.get_circle_active(circle).await?;
    let on_chain = ctx.get_circle_state_root(circle).await?;
    // Readable = the sealed blob exists AND verifies against the anchor.
    // An error here (no blob, wrong passphrase) is exactly the state
    // bootstrap repairs, so it is reported, not propagated.
    let current = match on_chain {
        Some(_) => circle_update::fetch_current_state_root(ctx, circle, &creds)
            .await
            .ok()
            .flatten(),
        None => None,
    };
    println!("circle bootstrap for {circle}");
    println!("  registered:          {active}");
    println!(
        "  on-chain anchor:     {}",
        on_chain.as_deref().unwrap_or("<none>")
    );
    println!("  state-root readable: {}", current.is_some());
    println!("  new anchor:          {anchor_hex}");
    if current.is_some() && !args.force {
        println!(
            "circle already bootstrapped — use `circle update` to rotate, or --force to reset \
             the anchor (drops the anchored member/allow hashes)"
        );
        return Ok(());
    }
    if dry_run {
        println!("(dry-run; pass --commit to broadcast)");
        return Ok(());
    }
    let put_tx = circle_update::put_state_root(ctx, circle, &state_root, &creds)
        .await
        .context("put /state-root.json")?;
    println!("  state-root put:      tx {put_tx}");
    if !active {
        let stake = args
            .stake
            .or(cfg.chain.v3_initial_stake)
            .unwrap_or(MIN_CIRCLE_STAKE_DEFAULT);
        let fee = ctx.fee_or_fallback("contract_call").await;
        let params = RegisterCircleParams {
            circle_id: circle,
            state_root_hex: &anchor_hex,
            receipt_pubkey_b64: &receipt_pubkey_b64,
            stake_amount: stake,
            fee,
            nonce: 0,
        };
        let tx = ctx
            .submit_call(ctx.build_register_circle_call(&params))
            .await
            .context("register_circle")?;
        println!("  register_circle:     tx {tx} (stake {stake})");
    } else if on_chain.as_deref() != Some(anchor_hex.as_str()) {
        let tx = circle_update::retry_anchor(ctx, circle, &anchor_hex)
            .await
            .context("update_circle_state")?;
        println!("  update_circle_state: tx {tx}");
    } else {
        println!("  anchor already current; only the state-root blob was (re)written");
    }
    println!("submitted; the chain applies it at the next epoch (~10s)");
    Ok(())
}

/// Parse the `--blob <asset_path>:<file>:<key_id>:<padding>` spec.
fn parse_blob_specs(raw: &[String]) -> Result<Vec<circle_update::BlobUpdate>> {
    use octravpn_core::circle::PaddingClass;

    let mut out = Vec::with_capacity(raw.len());
    for spec in raw {
        let parts: Vec<&str> = spec.splitn(4, ':').collect();
        if parts.len() != 4 {
            anyhow::bail!("blob spec must be <asset_path>:<file>:<key_id>:<padding>; got {spec:?}");
        }
        let plaintext =
            std::fs::read(parts[1]).with_context(|| format!("read blob plaintext {}", parts[1]))?;
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
pub(crate) fn resolve_sealed_passphrase(
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
