//! Chain-side context for the `oct://` browser portal.
//!
//! Renders content-addressed circle assets. The chain's
//! `circle_asset_ciphertext_by_resource_key` view returns the v2 sealed
//! envelope (`OCRS1 || nonce[12] || AES-GCM(...)`); a future v3 program
//! is expected to expose a plaintext-view RPC at the same index. We
//! accept both shapes and **decrypt sealed envelopes here** so the MIME
//! sniffer downstream sees real plaintext bytes (otherwise an opaque
//! ciphertext would always fall to Save-As).
//!
//! # Module layout
//!
//! * [`cache`] — `AssetCache` (BoundedMap LRU+TTL), `CachedAsset`,
//!   capacity/TTL defaults, plus `canonical_path` / `looks_sealed`.
//! * [`errors`] — [`FetchAssetError`].
//! * [`fetch`] — `fetch_inner` (cache-bypass roundtrip + decrypt) +
//!   `fetch_cached` (cache wrapper) + `build_rpc`.
//! * [`decrypt`] — `try_decrypt_with_passphrase` (operator-supplied
//!   passphrase unseal). **Always bypasses the cache** — see the
//!   load-bearing invariant at the top of `decrypt.rs`.
//! * [`api`] — `fetch_with_source[_sniffed]` / `fetch_circle_asset_bytes`
//!   + `PassphraseSource` / `ConfigPassphrase`.
//!
//! # Decision log
//!
//! * `protocol_version`: `"v3"` (preferred) or `"v2"` (fallback). v1.1
//!   is rejected — the portal refuses to start without a circle-aware
//!   substrate.
//! * Passphrase resolved at boot via [`crate::discover_v2::resolve_passphrase`]
//!   (env > config), wrapped in [`zeroize::Zeroizing`] (P1-10 in
//!   docs/v2-threat-model.md).
//! * **One** passphrase, **one** decrypt attempt — multi-passphrase
//!   iteration would be an oracle vulnerability (see
//!   `docs/oct-url-handler.md` open question #4).
//! * Decrypt errors must not leak the passphrase or the ciphertext;
//!   [`FetchAssetError`] variants carry only an opaque reason.
//! * `plaintext_hash` mismatch inside `decrypt_sealed_bytes` surfaces
//!   as `DecryptFailed` — mismatch detection happens operator-side.
//! * Non-sealed bytes pass through verbatim, keeping us forward-compatible
//!   with a future plaintext-view RPC.

mod api;
mod cache;
mod decrypt;
mod errors;
mod fetch;

use std::sync::Arc;

use octravpn_core::{bounded::BoundedMap, rpc::RpcClient};
use zeroize::Zeroizing;

use crate::config::ClientConfig;

// ── Public-within-the-crate surface ─────────────────────────────────
//
// Every external caller (routes.rs, main.rs, commands/{fetch,open_url})
// reaches into `portal::chain::*` for these symbols, so they MUST stay
// visible at this path after the split.

pub(crate) use api::{ConfigPassphrase, PassphraseSource};
pub(crate) use cache::AssetCache;
#[allow(unused_imports)]
// preserved-surface re-exports: chain.rs exposed these at the crate-internal API path; the route layer references DEFAULT_ASSET_CACHE_* in doc comments and tests reach AssetCacheKey / CachedAsset through cache::*
pub(crate) use cache::{
    AssetCacheKey, CachedAsset, DEFAULT_ASSET_CACHE_CAPACITY, DEFAULT_ASSET_CACHE_TTL,
};
pub(crate) use errors::FetchAssetError;

/// Long-lived context the portal holds for chain RPC work. Cheaply
/// cloneable (`Arc`-shared `RpcClient` lives inside).
#[derive(Clone)]
pub(crate) struct PortalChain {
    pub(super) rpc: Arc<RpcClient>,
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
    /// Sealed-policy key id. Sticks with the v2 `[v2].key_id` config so
    /// derivation matches whatever the operator used when sealing.
    pub(super) key_id: String,
    /// Passphrase used to decrypt sealed envelopes. `None` means the
    /// portal still serves plaintext assets (forward-compat) but every
    /// sealed asset surfaces [`FetchAssetError::MissingPassphrase`].
    /// Wrapped in `Zeroizing` so the heap buffer wipes on drop.
    pub(super) passphrase: Option<Arc<Zeroizing<String>>>,
    /// Bounded LRU + TTL cache of decrypted plaintext bytes, keyed by
    /// `(circle_id, canonical_path)`. Avoids re-fetching + re-decrypting
    /// frequently-reloaded assets every time the operator's browser
    /// hits the portal. Invalidation is purely TTL-driven; if the chain
    /// anchor changes, the operator sees stale plaintext for up to the
    /// TTL window. See [`DEFAULT_ASSET_CACHE_CAPACITY`] /
    /// [`DEFAULT_ASSET_CACHE_TTL`] for the defaults.
    pub(super) asset_cache: Arc<AssetCache>,
}

impl PortalChain {
    /// Build a v3 context from the loaded `ClientConfig`. Refuses on
    /// v1.1; accepts v2 or v3. CA-bundle pinning only (no SPKI pin).
    pub(crate) fn from_config(cfg: &ClientConfig) -> anyhow::Result<Self> {
        Self::from_config_for_url(cfg, None)
    }

    /// Same as [`Self::from_config`] but with an optional `oct://`
    /// URL. When the URL carries an `?spki=<base64>` parameter, the
    /// chain RPC client is built with
    /// [`octravpn_core::spki_verifier::SpkiPinVerifier`] active so the
    /// TLS handshake is gated on the leaf cert's SPKI sha256 matching
    /// one of the pinned values (audit-1 H-1). Without the parameter
    /// the build path is identical to `from_config` (CA-pin or
    /// system trust). The split exists so the `open_url` command
    /// can pass the URL through verbatim; long-running flows
    /// (`portal`, `connect-v3`) use the CA-only path.
    pub(crate) fn from_config_for_url(
        cfg: &ClientConfig,
        oct_url: Option<&str>,
    ) -> anyhow::Result<Self> {
        Self::require_circle_substrate(cfg)?;
        // The portal itself doesn't sign anything (read-only over RPC),
        // so we don't load the wallet here. `connect_v3` performs the
        // wallet load separately when it actually needs to sign.
        let rpc = fetch::build_rpc_for_oct_url(cfg, oct_url)?;
        // Resolve the sealed-asset passphrase once at boot. We reuse
        // discover_v2's resolver so env > config precedence stays the
        // same as the v2 connect path. CLI override doesn't apply here
        // (the `portal` subcommand has no `--secret` flag yet).
        let passphrase = crate::discover_v2::resolve_passphrase(&cfg.v2, None).map(Arc::new);
        if passphrase.is_none() {
            tracing::warn!(
                "octravpn portal: no sealed-asset passphrase configured \
                 (set OCTRAVPN_SEALED_PASSPHRASE or [v2].sealed_passphrase). \
                 Sealed circle assets will surface as 412 errors until configured."
            );
        }
        Ok(Self {
            rpc: Arc::new(rpc),
            program_addr: cfg.chain.program_addr.clone(),
            chain_id: cfg.chain.chain_id,
            key_id: cfg.v2.key_id.clone(),
            passphrase,
            asset_cache: Arc::new(BoundedMap::new(
                DEFAULT_ASSET_CACHE_CAPACITY,
                DEFAULT_ASSET_CACHE_TTL,
            )),
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
            key_id: "default".into(),
            passphrase: None,
            asset_cache: Arc::new(BoundedMap::new(
                DEFAULT_ASSET_CACHE_CAPACITY,
                DEFAULT_ASSET_CACHE_TTL,
            )),
        }
    }

    /// Test-only setter for the sealed-asset passphrase. Used by the
    /// unit tests + the integration harness to drive the decrypt path.
    #[cfg(test)]
    pub(crate) fn with_passphrase(mut self, pp: impl Into<String>) -> Self {
        self.passphrase = Some(Arc::new(Zeroizing::new(pp.into())));
        self
    }

    /// Test-only setter for the sealed-asset key id (default `"default"`).
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = key_id.into();
        self
    }

    /// Returns `Ok` when the config selects a circle-aware substrate
    /// (`v2` or `v3`). Otherwise an error pointing at the config flag.
    pub(crate) fn require_circle_substrate(cfg: &ClientConfig) -> anyhow::Result<()> {
        let v = cfg.chain.protocol_version.to_ascii_lowercase();
        if matches!(v.as_str(), "v2" | "2" | "v3" | "3") {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
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

    /// Returns `true` if a sealed-asset passphrase is configured. Used
    /// by tests / diagnostics; not load-bearing on the render path.
    #[allow(dead_code)]
    pub(crate) fn has_passphrase(&self) -> bool {
        self.passphrase.is_some()
    }

    /// Returns a clone of the boot-time configured passphrase, if any.
    /// The portal uses this as the fallback inside its cache-aware
    /// [`PassphraseSource`] impl.
    pub(crate) fn configured_passphrase(&self) -> Option<Arc<Zeroizing<String>>> {
        self.passphrase.clone()
    }

    /// Returns an `Arc` to the shared asset cache. `PortalState`
    /// surfaces this on its public `asset_cache` field so HTTP handlers
    /// can inspect the cache (e.g. a future `/api/cache/stats`).
    pub(crate) fn asset_cache(&self) -> Arc<AssetCache> {
        Arc::clone(&self.asset_cache)
    }

    /// Test-only constructor that swaps in a custom cache (different
    /// capacity / TTL than the production defaults). Used by the cache
    /// unit tests so they don't have to wait 30s for a TTL miss.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn with_asset_cache(mut self, cache: Arc<AssetCache>) -> Self {
        self.asset_cache = cache;
        self
    }
}

// ── Shared test fixtures ────────────────────────────────────────────
//
// Each submodule's `#[cfg(test)] mod tests` pulls these in. Kept in
// one place so we don't duplicate the mock-RPC plumbing across files.

#[cfg(test)]
pub(super) mod tests_common {
    use std::{
        net::SocketAddr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use axum::{routing::post, Json, Router};
    use octravpn_core::{
        circle::{encrypt_sealed_bytes, PaddingClass},
        rpc::RpcClient,
    };
    use serde_json::{json, Value};

    use super::{AssetCache, PortalChain};

    /// Bind a router on a loopback port, spawn it, sleep briefly to let
    /// the bind settle, and return the socket address.
    async fn serve(app: Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        addr
    }

    /// Spawn a stub axum RPC for `circle_asset_ciphertext_by_resource_key`.
    /// When `counter` is supplied it ticks on every matched call (used by
    /// hit/miss assertions). Non-matching methods return JSON-RPC -32601.
    async fn spawn_asset_rpc(result: Value, counter: Option<Arc<AtomicUsize>>) -> SocketAddr {
        let result_arc = Arc::new(result);
        let app: Router = Router::new().route(
            "/",
            post(move |Json(req): Json<Value>| {
                let result = Arc::clone(&result_arc);
                let counter = counter.clone();
                async move {
                    let id = req.get("id").cloned().unwrap_or(json!(1));
                    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                    if method == "circle_asset_ciphertext_by_resource_key" {
                        if let Some(c) = &counter {
                            c.fetch_add(1, Ordering::SeqCst);
                        }
                        Json(json!({"jsonrpc":"2.0","id":id,"result":(*result).clone()}))
                    } else {
                        Json(json!({
                            "jsonrpc":"2.0","id":id,
                            "error": { "code": -32601, "message": "method not found" },
                        }))
                    }
                }
            }),
        );
        serve(app).await
    }

    /// Non-counting stub. Returns `result` for every asset call.
    pub(crate) async fn spawn_mock_rpc(result: Value) -> SocketAddr {
        spawn_asset_rpc(result, None).await
    }

    /// Counting variant. Caller polls the returned `AtomicUsize` to
    /// count hit/miss roundtrips.
    pub(crate) async fn spawn_counting_rpc(result: Value) -> (SocketAddr, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let addr = spawn_asset_rpc(result, Some(Arc::clone(&counter))).await;
        (addr, counter)
    }

    /// Spawn an RPC that returns a JSON-RPC `error` for every call.
    /// Drives the `FetchAssetError::Rpc` branch.
    pub(crate) async fn spawn_error_rpc(message: &str) -> SocketAddr {
        let msg = message.to_string();
        let app: Router = Router::new().route(
            "/",
            post(move |Json(req): Json<Value>| {
                let msg = msg.clone();
                async move {
                    let id = req.get("id").cloned().unwrap_or(json!(1));
                    Json(json!({
                        "jsonrpc":"2.0","id":id,
                        "error": { "code": -32000, "message": msg },
                    }))
                }
            }),
        );
        serve(app).await
    }

    /// Build a sealed-envelope fixture at runtime (no committed binary).
    pub(crate) fn build_sealed_fixture(
        circle_id: &str,
        key_id: &str,
        passphrase: &str,
        plaintext: &[u8],
    ) -> (String, String) {
        encrypt_sealed_bytes(circle_id, key_id, passphrase, plaintext, PaddingClass::None)
            .expect("encrypt fixture")
    }

    /// Build a chain wired to `addr` with the given cache injected.
    pub(crate) fn chain_with_cache(addr: SocketAddr, cache: Arc<AssetCache>) -> PortalChain {
        let rpc = RpcClient::new(format!("http://{addr}/"));
        PortalChain::from_rpc(rpc, "octPROG".into(), 0).with_asset_cache(cache)
    }

    /// Wrap raw `plaintext` bytes into the canonical RPC payload shape
    /// (`{ciphertext_b64, plaintext_hash, key_id}`). Most cache tests
    /// don't care about the hash — they exercise the plaintext-passthrough
    /// branch — so this defaults to a 64-zero hash.
    pub(crate) fn plaintext_payload(plaintext: &[u8]) -> Value {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        json!({
            "ciphertext_b64": B64.encode(plaintext),
            "plaintext_hash": "0".repeat(64),
            "key_id": "default",
        })
    }

    /// Wrap a pre-sealed `(ct_b64, plaintext_hash_hex)` pair into the
    /// canonical RPC payload shape. Used by tests that exercise the
    /// decrypt branch.
    pub(crate) fn sealed_payload(ct_b64: &str, plaintext_hash_hex: &str) -> Value {
        json!({
            "ciphertext_b64": ct_b64,
            "plaintext_hash": plaintext_hash_hex,
            "key_id": "default",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ChainCfg, V2Cfg, V3Cfg, WalletCfg};

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
            v3: V3Cfg::default(),
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
    fn portal_chain_with_key_id_overrides_default() {
        let rpc = RpcClient::new("http://127.0.0.1:1");
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0).with_key_id("custom-key");
        assert_eq!(chain.key_id, "custom-key");
    }
}
