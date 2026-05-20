//! `Hub::new` internals: secret-file reads (plaintext or sealed-strict),
//! chain-context construction for v1.1 / v2 / v3, HKDF-derived receipt
//! and Noise subkeys, allowlist and metrics init, persistent
//! receipt-journal open, sealed-passphrase resolution, and the PVAC
//! sidecar spawn.
//!
//! Anything that runs **once** at boot and writes into the `Hub`
//! struct belongs here. New subsystem with background tasks: give it
//! its own `hub/<name>.rs` and call into it from `build_hub` + from
//! `hub::spawn`. Keep this file an orchestrator, not a kitchen sink.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use octravpn_core::{address::Address, rpc::RpcClient, sig::KeyPair};
use tracing::{info, warn};
use x25519_dalek::StaticSecret;

use super::Hub;
use crate::{
    chain::ChainCtx,
    chain_v2::ChainCtxV2,
    chain_v3::ChainCtxV3,
    config::NodeConfig,
    onion::OnionRouter,
};

/// Layered boot sequence. Each step has a comment block explaining
/// why it is ordered where it is.
pub(super) async fn build_hub(cfg: NodeConfig) -> Result<Hub> {
    let rpc = build_rpc(&cfg.chain)?;
    let validator_addr = Address::from_display(&cfg.chain.validator_addr);
    let program_addr = Address::from_display(&cfg.chain.program_addr);

    let wallet_secret = if cfg.chain.require_sealed_keys {
        *read_secret_32_strict(&cfg.chain.wallet_secret_path)
            .context("read wallet secret (strict, sealed-only)")?
    } else {
        read_secret_32(&cfg.chain.wallet_secret_path).context("read wallet secret")?
    };
    // KeyPair has no Clone (it zeroizes on drop); reconstruct the
    // same key from the on-disk secret twice — once for the v1.1
    // chain context and once for the v2 chain context. They sign
    // independently of each other.
    let wallet = KeyPair::from_secret_bytes(&wallet_secret);
    let wallet_v2 = KeyPair::from_secret_bytes(&wallet_secret);
    let wallet_v3 = KeyPair::from_secret_bytes(&wallet_secret);

    // v2 tx-envelope chain-id binding (P1-5b). The numeric
    // `cfg.chain.chain_id` (u32, e.g. `CHAIN_ID_DEVNET` 0x6F63_7464
    // = "octd") is exposed at the tx layer as the human-readable
    // strings the wallet + cast tooling already understand:
    // mainnet -> "octra-mainnet", devnet -> "octra-devnet". Other
    // values stringify to "octra-net-<hex>" so a future custom chain
    // works without code changes.
    let chain_id_str = chain_id_to_envelope_string(cfg.chain.chain_id);

    let chain = ChainCtx {
        rpc: rpc.clone(),
        program_addr: program_addr.clone(),
        validator_addr,
        wallet,
        chain_id: chain_id_str.clone(),
    };
    // v2 chain context shares the same RPC + program_addr (operators
    // run their v2 program on the same chain, just a different
    // deployed AML). The wallet addr is the deployer.
    let chain_v2 = ChainCtxV2::new_with_chain_id(
        rpc.clone(),
        program_addr.clone(),
        wallet_v2,
        chain_id_str.clone(),
    );
    // v3 chain context — same wallet, same RPC, talks to the v3
    // deployment configured under `program_addr`.
    let chain_v3 = ChainCtxV3::new_with_chain_id(rpc, program_addr, wallet_v3, chain_id_str);

    // The on-disk file holds a single 32-byte master secret. Two
    // independent subkeys are derived via HKDF-Expand with distinct
    // domain tags so we never use the same scalar across protocols:
    //
    //   master ---HKDF--> ed25519 receipt-signing secret (Tunn unused;
    //                                                     used only
    //                                                     for HTTP
    //                                                     control-plane
    //                                                     signatures)
    //          ---HKDF--> X25519 noise static secret (WG handshake)
    //
    // The wallet key (transaction signing) is a separate file already.
    let master = if cfg.chain.require_sealed_keys {
        *read_secret_32_strict(&cfg.tunnel.wg_secret_path)
            .context("read wg master secret (strict, sealed-only)")?
    } else {
        read_secret_32(&cfg.tunnel.wg_secret_path).context("read wg master secret")?
    };
    let receipt_sk =
        octravpn_core::util::derive_subkey(&master, octravpn_core::util::DOMAIN_RECEIPT_SIGN);
    let noise_sk = octravpn_core::util::derive_subkey(&master, octravpn_core::util::DOMAIN_NOISE);
    let wg_kp = Arc::new(KeyPair::from_secret_bytes(&receipt_sk));
    let wg_static_secret = StaticSecret::from(noise_sk);

    let view_pubkey = super::identity::wallet_view_pubkey(&wallet_secret);

    let allowlist = Arc::new(octravpn_core::bounded::BoundedMap::new(
        10_000,
        std::time::Duration::from_secs(3600),
    ));

    let metrics = Arc::new(crate::control::NodeMetrics::default());
    metrics.started_at_unix.store(
        octravpn_core::util::now_unix_secs(),
        std::sync::atomic::Ordering::Relaxed,
    );

    // P1-8/9: open the persistent receipt-seq journal at boot. The
    // journal is what stops a forced restart from letting the
    // daemon sign a fresh `seq=1` receipt for a session whose
    // last legitimate receipt was at seq=K. Default path is
    // `./state/receipts.bin`; operators on a system-managed
    // install should override to something under `/var/lib/octravpn/`.
    let journal_path: std::path::PathBuf = cfg
        .control
        .receipt_journal_path
        .clone()
        .map_or_else(|| "./state/receipts.bin".into(), std::path::PathBuf::from);
    let receipt_journal = Arc::new(
        octravpn_core::receipt_journal::ReceiptJournal::open(&journal_path)
            .with_context(|| format!("open receipt journal at {}", journal_path.display()))?,
    );

    // PVAC sidecar wiring. Opt-in (operator must set `[pvac].enabled
    // = true`); failure to spawn is *non-fatal* — we log a warning
    // and run without HFHE. Behaviour rationale:
    //
    //   - The HFHE path is still optional in v1.1/v2/v3 (placeholder
    //     blobs work end-to-end without it; see
    //     `hfhe_pubkey_placeholder` above).
    //   - Operators commonly deploy the node before the C++ sidecar
    //     toolchain lands on their host. Failing boot would force a
    //     rollback for what is, until claim_earnings is wired through
    //     the real PVAC, a no-op service.
    //   - When the binary IS present but later disappears (operator
    //     `make clean` in the source tree), the supervisor retries on
    //     its own back-off curve, so transient absences self-heal.
    let pvac = if cfg.pvac.enabled {
        match crate::pvac::PvacClient::spawn(cfg.pvac.to_runtime()).await {
            Ok(client) => {
                info!(
                    binary = %client.binary_path().display(),
                    "pvac sidecar spawned (HFHE path enabled)"
                );
                Some(Arc::new(client))
            }
            Err(e) => {
                warn!(
                    error = %e,
                    binary = %cfg.pvac.binary_path,
                    "pvac sidecar disabled: spawn failed — running without HFHE. \
                     Check `[pvac].binary_path` and that the binary is built \
                     (`cd pvac-sidecar && make`).",
                );
                None
            }
        }
    } else {
        None
    };

    Ok(Hub {
        cfg,
        chain,
        chain_v2,
        chain_v3,
        wg_kp,
        wg_static_secret,
        view_pubkey,
        router: Arc::new(OnionRouter::new()),
        allowlist,
        metrics,
        receipt_journal,
        pvac,
    })
}

pub(super) fn read_secret_32(path: &str) -> Result<[u8; 32]> {
    octravpn_core::util::read_secret_32(path).with_context(|| format!("load secret {path}"))
}

/// Strict variant used when `[chain].require_sealed_keys = true`. Returns
/// a `Zeroizing<[u8; 32]>` so the caller's intermediate copy is wiped
/// on drop. Plaintext on disk surfaces as
/// `CoreError::PlaintextKeyOnDisk` — anyhow renders the suggested
/// `octravpn-node seal-keys` invocation into the error message so the
/// operator sees a copy-pasteable next step. Threat model: P1-6.
pub(super) fn read_secret_32_strict(path: &str) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    octravpn_core::util::read_secret_32_or_sealed(path, None)
        .with_context(|| format!("strict-load secret {path}"))
}

/// Map the u32 `cfg.chain.chain_id` (P1-5 receipt-layer constant) to
/// the human-readable string the tx-envelope canonical bytes commit to
/// (P1-5b). Devnet and mainnet have stable names that match what
/// `octra cast send --chain-id` accepts; other values stringify to
/// `octra-net-<hex>` so an operator on a custom network doesn't have
/// to round-trip through this file to add a new constant.
pub(super) fn chain_id_to_envelope_string(id: u32) -> String {
    use octravpn_core::receipt::{CHAIN_ID_DEVNET, CHAIN_ID_MAINNET};
    if id == CHAIN_ID_DEVNET {
        "octra-devnet".to_string()
    } else if id == CHAIN_ID_MAINNET {
        "octra-mainnet".to_string()
    } else {
        format!("octra-net-{id:08x}")
    }
}

/// Build the RPC client honoring `[chain].pinned_root_paths` if any.
/// Empty / absent → system trust store (current behaviour). Set →
/// only the supplied PEM bundles are trusted, defeating
/// CA-compromise MITM on the chain endpoint. P0-2 from the v2 threat
/// model.
pub(super) fn build_rpc(chain: &crate::config::ChainCfg) -> Result<RpcClient> {
    let paths = chain
        .pinned_root_paths
        .as_ref()
        .map_or(&[][..], Vec::as_slice);
    if paths.is_empty() {
        return Ok(RpcClient::new(&chain.rpc_url));
    }
    let mut blobs = Vec::with_capacity(paths.len());
    for p in paths {
        let pem = std::fs::read(p).with_context(|| format!("read pinned root {p}"))?;
        blobs.push(pem);
    }
    RpcClient::new_with_pinned_roots(&chain.rpc_url, &blobs)
        .map_err(|e| anyhow::anyhow!("pinned tls: {e}"))
}

/// Resolve the v2 sealed-asset passphrase given the env var + config
/// field. Env-first (matches `octravpn-client::discover_v2::resolve_passphrase`)
/// so an operator can override the TOML without editing the file.
/// Empty / whitespace-only values are treated as unset.
///
/// Free function (no `&self`) so the precedence is unit-testable without
/// constructing a Hub. The wrapper method on `Hub` simply pulls live env
/// + config and delegates here.
pub(crate) fn resolve_sealed_passphrase(
    env: Option<&str>,
    cfg_field: Option<&str>,
) -> Result<zeroize::Zeroizing<String>> {
    if let Some(s) = env {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(zeroize::Zeroizing::new(trimmed.to_string()));
        }
    }
    if let Some(s) = cfg_field {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(zeroize::Zeroizing::new(trimmed.to_string()));
        }
    }
    Err(anyhow!(
        "v2 sealed-asset passphrase required: export OCTRAVPN_SEALED_PASSPHRASE \
         or set `[chain].sealed_passphrase` in the operator's TOML"
    ))
}

#[cfg(test)]
mod sealed_passphrase_tests {
    use super::resolve_sealed_passphrase;

    #[test]
    fn env_wins_over_cfg_field() {
        let got = resolve_sealed_passphrase(Some("env-val"), Some("cfg-val")).unwrap();
        assert_eq!(&*got, "env-val");
    }

    #[test]
    fn cfg_field_used_when_env_absent() {
        let got = resolve_sealed_passphrase(None, Some("cfg-val")).unwrap();
        assert_eq!(&*got, "cfg-val");
    }

    #[test]
    fn cfg_field_used_when_env_empty() {
        let got = resolve_sealed_passphrase(Some(""), Some("cfg-val")).unwrap();
        assert_eq!(&*got, "cfg-val");
    }

    #[test]
    fn cfg_field_used_when_env_whitespace() {
        let got = resolve_sealed_passphrase(Some("   "), Some("cfg-val")).unwrap();
        assert_eq!(&*got, "cfg-val");
    }

    #[test]
    fn error_when_both_unset() {
        assert!(resolve_sealed_passphrase(None, None).is_err());
    }

    #[test]
    fn error_when_both_empty() {
        assert!(resolve_sealed_passphrase(Some(""), Some("   ")).is_err());
    }

    #[test]
    fn values_are_trimmed() {
        let got = resolve_sealed_passphrase(Some("  spaced  "), None).unwrap();
        assert_eq!(&*got, "spaced");
    }
}
