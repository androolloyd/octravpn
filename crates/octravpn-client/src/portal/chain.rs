//! v3 chain context: a thin async fetcher for `circle_asset(circle_id, path)`.
//!
//! v3 is the plaintext-asset side of the v2 substrate: same chain RPC,
//! same `circle_asset_ciphertext_by_resource_key` view, but the bytes
//! delivered are content-addressed plaintext (`policy.json`, `state-root.json`,
//! arbitrary operator-published files). The portal renders these bytes.
//!
//! **Why we don't decrypt sealed v2 assets here.** Per the design doc
//! the portal is for plaintext bytes whose hash is anchored on chain.
//! If the operator chose to seal an asset, this code returns the raw
//! ciphertext envelope bytes; the portal's MIME sniffer will miss
//! (encrypted bytes have no plaintext magic), and the operator gets a
//! Save-As. Decryption stays in `discover_v2.rs` for `/policy.json` —
//! that's the connect path, not the browse path.
//!
//! **Decision log.**
//! * `protocol_version` accepted: `"v3"` (preferred) or `"v2"` (fallback,
//!   since v3 program isn't yet deployed). v1.1 is rejected — the
//!   portal refuses to start without a circle-aware substrate.
//! * `fetch_circle_asset_bytes` returns the *base64-decoded* ciphertext
//!   bytes of the v2 sealed envelope. When v3 ships a plaintext view,
//!   swap the RPC method name here; the caller surface is stable.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use octravpn_core::{circle::resource_key, rpc::RpcClient};
use serde_json::{json, Value};

use crate::config::ClientConfig;

/// Long-lived context the portal holds for chain RPC work. Cheaply
/// cloneable (`Arc`-shared `RpcClient` lives inside).
#[derive(Clone)]
pub(crate) struct PortalChain {
    rpc: Arc<RpcClient>,
    /// Configured program address — the v3 program once it lands; the
    /// v2 program in the interim. Not used for asset fetches (the RPC
    /// view is program-agnostic and indexes by `(circle_id, resource_key)`)
    /// but plumbed through so future signed calls have it.
    #[allow(dead_code)]
    program_addr: String,
    /// Configured chain id, for receipts the portal may eventually
    /// produce (currently read-only).
    #[allow(dead_code)]
    chain_id: u32,
}

impl PortalChain {
    /// Build a v3 context from the loaded `ClientConfig`. Refuses on
    /// v1.1; accepts v2 or v3.
    pub(crate) fn from_config(cfg: &ClientConfig) -> Result<Self> {
        Self::require_circle_substrate(cfg)?;
        // The portal itself doesn't sign anything (read-only over RPC),
        // so we don't load the wallet here. `connect_v3` performs the
        // wallet load separately when it actually needs to sign.
        let rpc = build_rpc(cfg)?;
        Ok(Self {
            rpc: Arc::new(rpc),
            program_addr: cfg.chain.program_addr.clone(),
            chain_id: cfg.chain.chain_id,
        })
    }

    /// Construct directly from a pre-built RPC client. Tests + the
    /// portal-integration harness use this so they can mock the chain
    /// without needing a real wallet file on disk.
    #[cfg(test)]
    pub(crate) fn from_rpc(rpc: RpcClient, program_addr: String, chain_id: u32) -> Self {
        Self {
            rpc: Arc::new(rpc),
            program_addr,
            chain_id,
        }
    }

    /// Returns `Ok` when the config selects a circle-aware substrate
    /// (`v2` or `v3`). Otherwise an error pointing at the config flag.
    pub(crate) fn require_circle_substrate(cfg: &ClientConfig) -> Result<()> {
        let v = cfg.chain.protocol_version.to_ascii_lowercase();
        if matches!(v.as_str(), "v2" | "2" | "v3" | "3") {
            Ok(())
        } else {
            Err(anyhow!(
                "oct:// portal requires `[chain].protocol_version = \"v3\"` (or v2) in your client.toml \
                 (currently `{}`)",
                cfg.chain.protocol_version,
            ))
        }
    }

    #[allow(dead_code)]
    pub(crate) fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    /// Fetch the bytes of `circle_asset(circle_id, path)`.
    ///
    /// Today this resolves to the v2 sealed-envelope RPC
    /// (`circle_asset_ciphertext_by_resource_key`) and returns the
    /// base64-decoded ciphertext. When the v3 program ships a plaintext
    /// `circle_asset_by_resource_key` view, replace the method name
    /// below — callers see the same `Vec<u8>` shape either way.
    pub(crate) async fn fetch_circle_asset_bytes(
        &self,
        circle_id: &str,
        path: &str,
    ) -> Result<Vec<u8>> {
        let path = canonical_path(path);
        let rkey = resource_key(circle_id, &path);
        let resp = self
            .rpc
            .raw_call(
                "circle_asset_ciphertext_by_resource_key",
                json!([circle_id, &rkey]),
            )
            .await
            .with_context(|| format!("fetch circle_asset {circle_id}{path}"))?;

        if resp.is_null() {
            return Err(anyhow!(
                "circle_asset {circle_id}{path}: no such asset (resource_key={rkey})"
            ));
        }

        let obj = resp
            .as_object()
            .ok_or_else(|| anyhow!("circle_asset {circle_id}{path}: unexpected RPC shape: {resp}"))?;

        // The v2 sealed envelope exposes the bytes under `ciphertext_b64`;
        // a future plaintext view would expose them under `bytes_b64`.
        // Accept either, in that preference order, so the portal works
        // on both substrates without a deploy-day code change.
        let b64 = obj
            .get("bytes_b64")
            .or_else(|| obj.get("ciphertext_b64"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!(
                    "circle_asset {circle_id}{path}: response missing bytes_b64/ciphertext_b64"
                )
            })?;

        let bytes = B64
            .decode(b64.as_bytes())
            .with_context(|| format!("decode base64 asset for {circle_id}{path}"))?;
        Ok(bytes)
    }
}

/// Normalize the path so the resource_key derivation matches the
/// canonical webcli definition. The webcli convention is: leading slash,
/// no `.`/`..`, no trailing slash (except root). We don't try to be
/// clever — the only guarantee we make is that bare `policy.json` and
/// `/policy.json` produce the same resource_key.
fn canonical_path(p: &str) -> String {
    let p = p.trim();
    if p.is_empty() || p == "/" {
        return "/".into();
    }
    if let Some(stripped) = p.strip_prefix('/') {
        format!("/{}", stripped.trim_start_matches('/'))
    } else {
        format!("/{p}")
    }
}

/// Mirror of `runner::build_rpc` but visible here without making the
/// runner pub. Pinned-root TLS plumbing is preserved.
fn build_rpc(cfg: &ClientConfig) -> Result<RpcClient> {
    let pinned: Vec<Vec<u8>> = match cfg.chain.pinned_root_paths.as_deref() {
        Some(paths) if !paths.is_empty() => paths
            .iter()
            .map(|p| {
                std::fs::read(p).with_context(|| format!("read pinned root {p}"))
            })
            .collect::<Result<Vec<_>>>()?,
        _ => Vec::new(),
    };
    if pinned.is_empty() {
        Ok(RpcClient::new(cfg.chain.rpc_url.clone()))
    } else {
        RpcClient::new_with_pinned_roots(cfg.chain.rpc_url.clone(), &pinned)
            .map_err(|e| anyhow!("pinned-root rpc client: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ChainCfg, V2Cfg, WalletCfg};

    fn cfg_with(version: &str) -> ClientConfig {
        ClientConfig {
            chain: ChainCfg {
                rpc_url: "http://127.0.0.1:1".into(),
                program_addr: "octPROG".into(),
                protocol_version: version.into(),
                chain_id: octravpn_core::receipt::CHAIN_ID_TEST,
                pinned_root_paths: None,
            },
            wallet: WalletCfg {
                addr: "oct".into(),
                secret_path: "/dev/null".into(),
            },
            v2: V2Cfg::default(),
            v3: crate::config::V3Cfg::default(),
        }
    }

    #[test]
    fn require_rejects_v11() {
        let err = PortalChain::require_circle_substrate(&cfg_with("v1.1")).unwrap_err();
        assert!(err.to_string().contains("v3"));
    }

    #[test]
    fn require_accepts_v3() {
        PortalChain::require_circle_substrate(&cfg_with("v3")).unwrap();
    }

    #[test]
    fn require_accepts_v2_fallback() {
        PortalChain::require_circle_substrate(&cfg_with("v2")).unwrap();
    }

    #[test]
    fn require_accepts_v3_case_insensitive() {
        PortalChain::require_circle_substrate(&cfg_with("V3")).unwrap();
    }

    #[test]
    fn canonical_path_normalizes() {
        assert_eq!(canonical_path("policy.json"), "/policy.json");
        assert_eq!(canonical_path("/policy.json"), "/policy.json");
        assert_eq!(canonical_path("//policy.json"), "/policy.json");
        assert_eq!(canonical_path(""), "/");
        assert_eq!(canonical_path("/"), "/");
    }
}
