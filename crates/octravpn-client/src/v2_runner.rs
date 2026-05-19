//! Dispatcher for the v2-flavored subcommands (`discover` + `connect-v2`).
//!
//! This is the thin glue between `main.rs` clap surface and the
//! `discover_v2` / `v2_cache` modules. The actual chain + sealed-policy
//! work lives there; here we just resolve config, decide which path
//! to print, and gate on the `protocol_version` flag.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde_json::json;
use tracing::info;

use crate::{
    config::ClientConfig,
    discover_v2::{
        self, render_row, resolve_passphrase, CircleListing, CirclePolicy, SessionClass,
    },
    runner::Client,
    v2_cache::{resolve_cache_dir, PolicyCache},
    DiscoverOp,
};

/// Top-level `discover ...` dispatch.
pub(crate) async fn dispatch_discover(
    client: &Arc<Client>,
    cfg: &Arc<ClientConfig>,
    op: DiscoverOp,
) -> Result<()> {
    require_v2(cfg)?;
    let cache_dir = resolve_cache_dir(&cfg.v2.cache_dir);
    let mut cache = PolicyCache::open(&cache_dir)
        .with_context(|| format!("open policy cache {}", cache_dir.display()))?;
    match op {
        DiscoverOp::V2 {
            tailnet_id,
            secret,
            refresh,
            json,
        } => {
            if refresh {
                cache.clear().ok();
            }
            run_discover_v2(client, cfg, tailnet_id, secret.as_deref(), &mut cache, json).await
        }
        DiscoverOp::Invalidate { circle_id, all } => {
            if all {
                cache.clear()?;
                println!("cleared all cached policy entries in {}", cache_dir.display());
                return Ok(());
            }
            let Some(cid) = circle_id else {
                bail!("--circle-id or --all required");
            };
            let removed = cache.invalidate(&cid)?;
            if removed {
                println!("invalidated cache entry for {cid}");
            } else {
                println!("no cached entry for {cid}");
            }
            Ok(())
        }
    }
}

/// Body of `discover v2` — prints one row per authorized circle.
async fn run_discover_v2(
    client: &Client,
    cfg: &ClientConfig,
    tailnet_id: u64,
    cli_secret: Option<&str>,
    cache: &mut PolicyCache,
    as_json: bool,
) -> Result<()> {
    let passphrase = resolve_passphrase(&cfg.v2, cli_secret);
    if passphrase.is_none() {
        eprintln!(
            "warning: no sealed-policy passphrase resolved — circles will appear as [opaque].\n\
             Set OCTRAVPN_SEALED_PASSPHRASE, pass --secret, or fill `[v2].sealed_passphrase`.",
        );
    }
    let listings = discover_v2::list(
        client,
        tailnet_id,
        &cfg.v2,
        passphrase.as_deref().map(String::as_str),
        cache,
    )
    .await?;
    if listings.is_empty() {
        println!(
            "no authorized circles found for tailnet {tailnet_id}.\n\
             hint: the v2 program needs `authorize_circle(tailnet_id, circle_addr)` from the tailnet owner.",
        );
        return Ok(());
    }
    if as_json {
        let arr: Vec<_> = listings
            .iter()
            .map(|l| match l {
                CircleListing::Open {
                    circle_id,
                    policy,
                    from_cache,
                } => json!({
                    "circle_id": circle_id,
                    "status": "open",
                    "from_cache": from_cache,
                    "policy": policy,
                }),
                CircleListing::Opaque { circle_id, reason } => json!({
                    "circle_id": circle_id,
                    "status": "opaque",
                    "reason": reason,
                }),
                CircleListing::Unpublished { circle_id } => json!({
                    "circle_id": circle_id,
                    "status": "unpublished",
                }),
                CircleListing::Error { circle_id, error } => json!({
                    "circle_id": circle_id,
                    "status": "error",
                    "error": error,
                }),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else {
        for l in &listings {
            println!("{}", render_row(l));
        }
    }
    Ok(())
}

/// Body of `connect-v2`. Resolves the circle, opens the session, and
/// prints the WG handoff. We deliberately stop short of bringing the
/// data plane up — same shape as the v1.1 `connect` which prints a WG
/// config block for the user (the boringtun side lives in
/// `octravpn-node`).
pub(crate) async fn connect_v2(
    client: &Arc<Client>,
    cfg: &Arc<ClientConfig>,
    tailnet_id: u64,
    circle_id_arg: Option<&str>,
    class_str: &str,
    deposit: u64,
    cli_secret: Option<&str>,
    refresh: bool,
) -> Result<()> {
    require_v2(cfg)?;
    let class = SessionClass::parse(class_str)?;
    let cache_dir = resolve_cache_dir(&cfg.v2.cache_dir);
    let mut cache = PolicyCache::open(&cache_dir)
        .with_context(|| format!("open policy cache {}", cache_dir.display()))?;
    if refresh {
        cache.clear().ok();
    }

    let passphrase = resolve_passphrase(&cfg.v2, cli_secret).ok_or_else(|| {
        anyhow::anyhow!(
            "no sealed-policy passphrase available — set OCTRAVPN_SEALED_PASSPHRASE, \
             pass --secret, or fill `[v2].sealed_passphrase`",
        )
    })?;

    // 1. Pick the circle. If the caller gave one explicitly, decrypt
    // just that one; otherwise fetch the full list and use the first
    // decryptable entry.
    let (chosen_id, policy) = if let Some(id) = circle_id_arg {
        let listing =
            discover_v2::fetch_one(client, id, &cfg.v2, Some(passphrase.as_str()), &mut cache).await;
        match listing {
            CircleListing::Open { circle_id, policy, .. } => (circle_id, policy),
            CircleListing::Opaque { reason, .. } => bail!("can't decrypt policy for {id}: {reason}"),
            CircleListing::Unpublished { .. } => bail!("circle {id} has no published policy yet"),
            CircleListing::Error { error, .. } => bail!("circle {id} fetch error: {error}"),
        }
    } else {
        pick_first_open(client, cfg, tailnet_id, passphrase.as_str(), &mut cache).await?
    };

    info!(
        tailnet_id,
        circle = chosen_id.as_str(),
        class = class.label(),
        deposit,
        policy_version = policy.policy_version,
        "opening v2 session"
    );
    let session_id =
        discover_v2::open_session_v2(client, tailnet_id, &chosen_id, class, deposit).await?;
    println!("session opened: id={session_id}");
    println!("  tailnet_id    = {tailnet_id}");
    println!("  circle        = {chosen_id}");
    println!("  class         = {} ({})", class.label(), class.as_int());
    println!("  policy ver    = {}", policy.policy_version);
    print_wg_handoff(&policy);
    Ok(())
}

async fn pick_first_open(
    client: &Client,
    cfg: &ClientConfig,
    tailnet_id: u64,
    passphrase: &str,
    cache: &mut PolicyCache,
) -> Result<(String, CirclePolicy)> {
    let listings = discover_v2::list(
        client,
        tailnet_id,
        &cfg.v2,
        Some(passphrase),
        cache,
    )
    .await?;
    for l in listings {
        if let CircleListing::Open { circle_id, policy, .. } = l {
            return Ok((circle_id, policy));
        }
    }
    bail!(
        "no decryptable authorized circles for tailnet {tailnet_id} \
         (no member access, or operators haven't published policy)",
    )
}

fn print_wg_handoff(policy: &CirclePolicy) {
    println!("---- WireGuard handoff (v2 sealed policy) ----");
    println!("[Peer]");
    println!("PublicKey  = {}", policy.wg_pubkey_b64);
    println!("Endpoint   = {}", policy.endpoint);
    println!("AllowedIPs = 0.0.0.0/0, ::/0");
    println!("# region        = {}", policy.region);
    println!(
        "# tariff shared = {} OU/MB",
        policy.price_per_mb_shared
    );
    println!(
        "# tariff intra  = {} OU/MB",
        policy.price_per_mb_internal
    );
    println!("----------------------------------------------");
}

fn require_v2(cfg: &ClientConfig) -> Result<()> {
    if cfg.is_v2() {
        return Ok(());
    }
    bail!(
        "v2 subcommands require `[chain].protocol_version = \"v2\"` in your client.toml \
         (currently `{}`)",
        cfg.chain.protocol_version,
    )
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

    fn cfg_v2() -> ClientConfig {
        let mut c = cfg_v1();
        c.chain.protocol_version = "v2".into();
        c
    }

    #[test]
    fn require_v2_rejects_v1() {
        let err = require_v2(&cfg_v1()).unwrap_err().to_string();
        assert!(err.contains("v2"));
    }

    #[test]
    fn require_v2_accepts_v2() {
        require_v2(&cfg_v2()).unwrap();
    }

    #[test]
    fn require_v2_accepts_case_insensitive() {
        let mut c = cfg_v2();
        c.chain.protocol_version = "V2".into();
        require_v2(&c).unwrap();
    }
}
