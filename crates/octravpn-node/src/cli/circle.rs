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
    /// Public JSON from `octra-node vpn-identity --key PATH`.
    #[arg(long)]
    pub(crate) native_identity: Option<std::path::PathBuf>,
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeIdentityFile {
    operator: String,
    receipt_pubkey_b64: String,
    wg_pubkey_b64: String,
    transport: NativeTransport,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeTransport {
    kind: String,
}
struct BootstrapIdentity {
    operator: octravpn_core::Address,
    receipt: octravpn_core::sig::PublicKey,
    wireguard: [u8; 32],
}
fn native_identity(path: &std::path::Path) -> Result<BootstrapIdentity> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use std::io::Read;
    use x25519_dalek::{PublicKey, StaticSecret};
    let file = std::fs::File::open(path).context("open native public identity")?;
    let mut raw = Vec::new();
    file.take(4097).read_to_end(&mut raw)?;
    anyhow::ensure!(raw.len() <= 4096, "native identity exceeds byte limit");
    let descriptor: NativeIdentityFile =
        serde_json::from_slice(&raw).context("decode native public identity")?;
    anyhow::ensure!(
        descriptor.transport.kind == "wireguard",
        "native operator requires plain WireGuard transport"
    );
    let operator = octravpn_core::Address::try_from_display(&descriptor.operator)
        .context("invalid native operator address")?;
    anyhow::ensure!(
        operator.display() == descriptor.operator && operator.as_bytes().iter().any(|b| *b != 0),
        "noncanonical native operator address"
    );
    let decode = |encoded: &str, name: &str| -> Result<[u8; 32]> {
        let bytes = octravpn_core::b64::decode(encoded.as_bytes())
            .with_context(|| format!("invalid native {name}"))?;
        anyhow::ensure!(
            bytes.len() == 32 && octravpn_core::b64::encode(&bytes) == encoded,
            "native {name} must be a canonical 32-byte public key"
        );
        let key: [u8; 32] = bytes.as_slice().try_into()?;
        anyhow::ensure!(key.iter().any(|b| *b != 0), "native {name} is zero");
        Ok(key)
    };
    let receipt = decode(&descriptor.receipt_pubkey_b64, "receipt key")?;
    let point = CompressedEdwardsY(receipt)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("invalid native Ed25519 receipt key"))?;
    anyhow::ensure!(
        point.compress().0 == receipt && point.is_torsion_free() && !point.is_small_order(),
        "unsafe native Ed25519 receipt key"
    );
    ed25519_dalek::VerifyingKey::from_bytes(&receipt).context("invalid native receipt key")?;
    let wireguard = decode(&descriptor.wg_pubkey_b64, "WG key")?;
    let mut prime = [255; 32];
    prime[0] = 237;
    prime[31] = 127;
    anyhow::ensure!(
        wireguard.iter().rev().cmp(prime.iter().rev()).is_lt(),
        "noncanonical native X25519 public key"
    );
    anyhow::ensure!(
        StaticSecret::from([165; 32])
            .diffie_hellman(&PublicKey::from(wireguard))
            .was_contributory(),
        "unsafe native X25519 public key"
    );
    Ok(BootstrapIdentity {
        operator,
        receipt: octravpn_core::sig::PublicKey(receipt),
        wireguard,
    })
}

/// Publish both discovery resources before committing their application anchor.
async fn run_bootstrap(
    cfg: &NodeConfig,
    ctx: &crate::chain_v3::ChainCtxV3,
    args: CircleBootstrapArgs,
) -> Result<()> {
    use crate::chain_v3::{RegisterCircleParams, MIN_CIRCLE_STAKE_DEFAULT};
    use crate::v3_boot::publication;
    use octravpn_core::{
        circle::PaddingClass, v3_policy::OperatorPolicy, v3_state_root::StateRoot,
    };
    use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};
    let circle = args.circle.as_str();
    octravpn_core::parse_native_address(circle).context("invalid operator Circle address")?;
    octravpn_core::parse_native_address(&cfg.chain.program_addr)
        .context("invalid settlement application address")?;
    let dry_run = args.dry_run && !args.commit;
    let native = args.native_identity.is_some();
    let identity = if let Some(path) = &args.native_identity {
        native_identity(path)?
    } else {
        let master = zeroize::Zeroizing::new(if cfg.chain.require_sealed_keys {
            *octravpn_core::util::read_secret_32_or_sealed(&cfg.tunnel.wg_secret_path, None)
                .context("strict-load operator WG master secret")?
        } else {
            octravpn_core::util::read_secret_32(&cfg.tunnel.wg_secret_path)
                .context("load operator WG master secret")?
        });
        let noise = zeroize::Zeroizing::new(octravpn_core::util::derive_subkey(
            &master,
            octravpn_core::util::DOMAIN_NOISE,
        ));
        let receipt = zeroize::Zeroizing::new(octravpn_core::util::derive_subkey(
            &master,
            octravpn_core::util::DOMAIN_RECEIPT_SIGN,
        ));
        BootstrapIdentity {
            operator: ctx.wallet_addr.clone(),
            wireguard: X25519Pub::from(&StaticSecret::from(*noise)).to_bytes(),
            receipt: octravpn_core::sig::KeyPair::from_secret_bytes(&receipt).public,
        }
    };
    anyhow::ensure!(
        ctx.wallet_addr == identity.operator,
        "funding wallet differs from native operator identity"
    );
    let info = ctx
        .rpc
        .raw_call("circle_info", serde_json::json!([circle]))
        .await?;
    let public = match info
        .get("resource_mode")
        .and_then(serde_json::Value::as_str)
    {
        Some("public_resources" | "public_read") => true,
        Some("sealed_read") => false,
        _ => anyhow::bail!("operator Circle resource mode is unavailable"),
    };
    anyhow::ensure!(
        !native || public,
        "native discovery requires a public-resource operator Circle"
    );
    let creds = if public {
        None
    } else {
        Some(resolve_sealed_passphrase(args.passphrase.as_deref())?)
    };
    let epoch = ctx
        .current_epoch()
        .await
        .context("read committed chain epoch for bootstrap")?;
    let timestamp = octravpn_core::util::now_unix_secs();
    let wg_b64 = octravpn_core::b64::encode(identity.wireguard);
    let mut policy = if native {
        crate::v3_boot::transport_policy_with(
            cfg,
            &wg_b64,
            &identity.receipt,
            epoch,
            timestamp,
            octravpn_tun::amnezia::WireTransport::Wireguard,
        )?
    } else {
        crate::v3_boot::transport_policy(cfg, &wg_b64, &identity.receipt, epoch, timestamp)?
    };
    policy.unknown.insert(
        "operator".into(),
        serde_json::json!(identity.operator.display()),
    );
    policy.unknown.insert("receipt_domain".into(), serde_json::json!({"program_addr": cfg.chain.program_addr, "chain_id": cfg.chain.chain_id, "circle_id": circle}));
    policy.validate().context("operator policy validation")?;
    let mut state_root = StateRoot::new_v1(
        circle,
        policy.hash_hex()?,
        crate::v3_boot::sha256_hex(&identity.wireguard),
        None,
        cfg.pricing.region.clone(),
        0,
        epoch,
        timestamp,
    );
    state_root.validate().context("state-root validation")?;
    let mut anchor = state_root.anchor_hex()?;
    let receipt_b64 = octravpn_core::b64::encode(identity.receipt.0);
    anyhow::ensure!(
        !ctx.is_circle_slashed(circle).await?,
        "operator Circle is permanently slashed"
    );
    let active = ctx.get_circle_active(circle).await?;
    let on_chain = ctx.get_circle_state_root(circle).await?;
    if active || on_chain.is_some() {
        anyhow::ensure!(
            ctx.get_circle_receipt_pubkey(circle).await? == receipt_b64,
            "registered receipt key differs; rotate it before bootstrap"
        );
    }
    let current = if let Some(prior) = on_chain.as_deref() {
        let (prior_policy, root) = if public {
            publication::load(ctx, circle, prior).await?
        } else {
            let creds = creds.as_ref().context("sealed credentials unavailable")?;
            let root = circle_update::fetch_current_state_root(ctx, circle, creds)
                .await?
                .context("anchored state-root is unavailable; restore its immutable snapshot")?;
            let circle_update::SealedRead::Valid(policy_bytes) = circle_update::read_sealed_asset(
                ctx,
                circle,
                "/policy.json",
                "default",
                creds,
                &root.policy_hash,
            )
            .await?
            else {
                anyhow::bail!("anchored operator policy is unavailable or invalid; restore its immutable snapshot");
            };
            let prior_policy = OperatorPolicy::decode_lenient(&policy_bytes)?;
            anyhow::ensure!(
                prior_policy.hash_hex()? == root.policy_hash,
                "anchored operator policy hash differs"
            );
            (prior_policy, root)
        };
        anyhow::ensure!(
            root.circle_id == circle && root.anchor_hex()? == prior,
            "anchored state-root identity differs"
        );
        Some((prior_policy, root))
    } else {
        None
    };
    if let Some((prior_policy, prior_root)) = &current {
        if !args.force {
            let mut expected = policy.clone();
            expected.effective_epoch = prior_policy.effective_epoch;
            expected.timestamp_secs = prior_policy.timestamp_secs;
            for (key, value) in &prior_policy.unknown {
                expected
                    .unknown
                    .entry(key.clone())
                    .or_insert_with(|| value.clone());
            }
            anyhow::ensure!(&expected==prior_policy && prior_root.wg_pubkey_hash==crate::v3_boot::sha256_hex(&identity.wireguard),"existing operator discovery differs from requested configuration; use circle update or explicit --force");
            policy = prior_policy.clone();
            state_root = prior_root.clone();
            anchor = state_root.anchor_hex()?;
        }
    }
    println!("circle bootstrap for {circle}");
    println!("  operator: {}", identity.operator.display());
    println!("  registered: {active}");
    println!(
        "  on-chain anchor: {}",
        on_chain.as_deref().unwrap_or("<none>")
    );
    println!("  new anchor: {anchor}");
    if current.is_some() && active && !args.force {
        println!("verified existing policy and state-root; use circle update to rotate, or --force to reset membership hashes");
        return Ok(());
    }
    if dry_run {
        println!("dry-run; pass --commit to publish and anchor");
        return Ok(());
    }
    if public {
        publication::publish(ctx, circle, &policy, &state_root)
            .await
            .context("publish immutable discovery resources")?;
    } else {
        let creds = creds.as_ref().context("sealed credentials unavailable")?;
        for (path, bytes) in [
            ("/policy.json", policy.canonical_bytes()?),
            ("/state-root.json", state_root.canonical_bytes()?),
        ] {
            let blob = circle_update::BlobUpdate {
                asset_path: path.into(),
                plaintext: zeroize::Zeroizing::new(bytes),
                key_id: "default".into(),
                padding_class: PaddingClass::None,
            };
            circle_update::submit_sealed_put(ctx, circle, &blob, creds)
                .await
                .with_context(|| format!("publish immutable {path}"))?;
        }
    }
    if !active {
        let stake = args
            .stake
            .or(cfg.chain.v3_initial_stake)
            .unwrap_or(MIN_CIRCLE_STAKE_DEFAULT);
        let params = RegisterCircleParams {
            circle_id: circle,
            state_root_hex: &anchor,
            receipt_pubkey_b64: &receipt_b64,
            stake_amount: stake,
            fee: ctx.fee_or_fallback("contract_call").await,
            nonce: 0,
        };
        let hash = ctx
            .submit_call(ctx.build_register_circle_call(&params))
            .await
            .context("register_circle")?;
        println!("  register_circle: tx {hash} (stake {stake})");
    } else if on_chain.as_deref() != Some(anchor.as_str()) {
        let hash = circle_update::retry_anchor(ctx, circle, &anchor)
            .await
            .context("update_circle_state")?;
        println!("  update_circle_state: tx {hash}");
    }
    publication::await_anchor(ctx, circle, &anchor).await?;
    anyhow::ensure!(
        ctx.get_circle_receipt_pubkey(circle).await? == receipt_b64,
        "confirmed receipt key differs"
    );
    println!("confirmed policy, state-root and active registry anchor: {anchor}");
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
