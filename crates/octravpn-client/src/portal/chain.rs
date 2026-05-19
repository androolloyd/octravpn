//! Chain-side context for the `oct://` browser portal.
//!
//! The portal renders content-addressed circle assets. Today the chain's
//! `circle_asset_ciphertext_by_resource_key` view returns the v2 sealed
//! envelope (`OCRS1 || nonce[12] || AES-GCM(...)`); a future v3 program
//! is expected to expose a plaintext-view RPC at the same `(circle_id,
//! resource_key)` index. We accept both shapes and **decrypt sealed
//! envelopes here** so the MIME sniffer downstream sees real plaintext
//! bytes instead of an opaque ciphertext (which would always fall to
//! Save-As).
//!
//! **Decision log.**
//! * `protocol_version` accepted: `"v3"` (preferred) or `"v2"` (fallback,
//!   since v3 program isn't yet deployed). v1.1 is rejected — the
//!   portal refuses to start without a circle-aware substrate.
//! * Sealed-asset decryption is bounded by the per-tailnet passphrase
//!   resolved at portal startup via [`crate::discover_v2::resolve_passphrase`]
//!   (env > config). The passphrase lives in [`zeroize::Zeroizing`] so
//!   the heap buffer wipes on drop (P1-10 in docs/v2-threat-model.md).
//! * We do **not** try multiple passphrases — that would be a
//!   passphrase-oracle vulnerability (see `docs/oct-url-handler.md`
//!   open question #4). One configured passphrase, one decrypt attempt.
//! * Decrypt errors must not leak the passphrase or the ciphertext.
//!   The structured [`FetchAssetError`] variants carry only an opaque
//!   reason; the underlying `decrypt_sealed_bytes` error string is
//!   discarded at the boundary.
//! * If the plaintext hash check inside `decrypt_sealed_bytes` fails,
//!   that surfaces as `DecryptFailed` — the operator's commitment is
//!   anchored on chain via `plaintext_hash`; mismatch detection happens
//!   operator-side, not in the renderer.
//! * Non-sealed bytes (no OCRS1 magic) pass through verbatim, which
//!   keeps us forward-compatible with the future plaintext-view RPC.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use octravpn_core::{
    bounded::BoundedMap,
    circle::{decrypt_sealed_bytes, resource_key},
    rpc::RpcClient,
};
use serde_json::{json, Value};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    config::ClientConfig,
    portal::mime::{sniff, SniffedMime},
};

/// Default LRU capacity for the per-`(circle_id, path)` plaintext cache.
/// Tuned for portal sessions that re-browse the same handful of circles
/// (a few dozen circles x a few asset paths each).
pub(crate) const DEFAULT_ASSET_CACHE_CAPACITY: usize = 256;

/// Default TTL for cached plaintext assets. Keeps reads cheap during a
/// browse session while bounding staleness if the chain anchor moves.
pub(crate) const DEFAULT_ASSET_CACHE_TTL: Duration = Duration::from_secs(30);

/// One cache entry: the decrypted plaintext + the sniffed MIME (so we
/// don't re-sniff on every hit) + the moment we materialised it.
///
/// `bytes` is wrapped in `Arc` so cache hits clone an Arc instead of the
/// full payload. Callers that need owned `Vec<u8>` clone once at the
/// boundary — still avoids the RPC + KDF round-trip.
#[derive(Clone)]
pub(crate) struct CachedAsset {
    pub bytes: Arc<Vec<u8>>,
    pub mime: SniffedMime,
    #[allow(dead_code)] // surfaced for future /api/cache/stats
    pub fetched_at: Instant,
}

/// Key into the asset cache: `(circle_id, canonical_path)`. The path is
/// the canonicalised form (`canonical_path()`), so `policy.json` and
/// `/policy.json` collapse to the same entry.
pub(crate) type AssetCacheKey = (String, String);

/// Concrete cache type the portal threads through `PortalState` and
/// `PortalChain`. Wrapped in `Arc` upstream so a single cache is shared
/// by every clone (the `PortalState` and the per-request handler clones
/// must all see the same hit set).
pub(crate) type AssetCache = BoundedMap<AssetCacheKey, CachedAsset>;

/// Resolve the sealed-asset passphrase to try for a given `circle_id`.
///
/// The portal binds an implementation that consults its per-circle
/// unseal cache first (interactive unseal flow), falling back to the
/// boot-time configured passphrase. CLI / non-portal callers use the
/// default ([`ConfigPassphrase`]) which is circle-agnostic.
///
/// Returning `None` means "no passphrase available" — the fetch path
/// will surface [`FetchAssetError::MissingPassphrase`].
pub(crate) trait PassphraseSource: Send + Sync {
    fn passphrase_for(&self, circle_id: &str) -> Option<Arc<Zeroizing<String>>>;
}

/// Circle-agnostic source backed by a single configured passphrase
/// resolved at boot. Used by the CLI `fetch` / `open-url` paths.
#[derive(Clone, Default)]
pub(crate) struct ConfigPassphrase {
    inner: Option<Arc<Zeroizing<String>>>,
}

impl ConfigPassphrase {
    pub(crate) fn new(pp: Option<Arc<Zeroizing<String>>>) -> Self {
        Self { inner: pp }
    }
}

impl PassphraseSource for ConfigPassphrase {
    fn passphrase_for(&self, _circle_id: &str) -> Option<Arc<Zeroizing<String>>> {
        self.inner.clone()
    }
}

/// Sealed-asset envelope magic prefix. Must match `octra-core::circle`.
/// Duplicated here as a small constant rather than re-exported so this
/// module stays self-contained for the magic sniff.
const SEALED_MAGIC: &[u8; 5] = b"OCRS1";

/// Structured error returned from [`PortalChain::fetch_circle_asset_bytes`].
///
/// Distinguishing the variants matters at the route layer: a generic
/// transport failure renders the existing "tunnel down" 502 page, while
/// the two decrypt-related variants render a dedicated 412 with
/// passphrase-configuration guidance.
#[derive(Debug, Error)]
pub(crate) enum FetchAssetError {
    /// JSON-RPC transport or response-shape problem. Carries the
    /// underlying anyhow chain for diagnostics — safe to render because
    /// it never touched the ciphertext bytes or the passphrase.
    #[error("chain RPC failed for {circle_id}{path}: {source}")]
    Rpc {
        circle_id: String,
        path: String,
        #[source]
        source: anyhow::Error,
    },
    /// The RPC returned `null` for this `(circle_id, resource_key)`.
    #[error("asset not published: {circle_id}{path} (resource_key={resource_key})")]
    NotPublished {
        circle_id: String,
        path: String,
        resource_key: String,
    },
    /// The bytes look sealed (OCRS1 magic) but no passphrase is
    /// configured. The portal can still start; per-asset decrypt just
    /// surfaces this distinct error so the route layer can render the
    /// 412 passphrase-config page.
    #[error("sealed asset {circle_id}{path}: no passphrase configured")]
    MissingPassphrase { circle_id: String, path: String },
    /// The bytes look sealed and we have a passphrase, but decrypt
    /// failed. The underlying error string is deliberately discarded so
    /// the passphrase / ciphertext bytes cannot leak through Display.
    #[error("sealed asset {circle_id}{path}: could not decrypt (wrong passphrase, wrong key_id, or corrupt envelope)")]
    DecryptFailed { circle_id: String, path: String },
}

impl FetchAssetError {
    #[allow(dead_code)] // accessor — used by future error-page renderers
    pub(crate) fn circle_id(&self) -> &str {
        match self {
            Self::Rpc { circle_id, .. }
            | Self::NotPublished { circle_id, .. }
            | Self::MissingPassphrase { circle_id, .. }
            | Self::DecryptFailed { circle_id, .. } => circle_id,
        }
    }

    #[allow(dead_code)] // accessor — used by future error-page renderers
    pub(crate) fn path(&self) -> &str {
        match self {
            Self::Rpc { path, .. }
            | Self::NotPublished { path, .. }
            | Self::MissingPassphrase { path, .. }
            | Self::DecryptFailed { path, .. } => path,
        }
    }
}

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
    /// Sealed-policy key id. Sticks with the v2 `[v2].key_id` config so
    /// derivation matches whatever the operator used when sealing.
    key_id: String,
    /// Passphrase used to decrypt sealed envelopes. `None` means the
    /// portal still serves plaintext assets (forward-compat) but every
    /// sealed asset surfaces [`FetchAssetError::MissingPassphrase`].
    /// Wrapped in `Zeroizing` so the heap buffer wipes on drop.
    passphrase: Option<Arc<Zeroizing<String>>>,
    /// Bounded LRU + TTL cache of decrypted plaintext bytes, keyed by
    /// `(circle_id, canonical_path)`. Avoids re-fetching + re-decrypting
    /// frequently-reloaded assets every time the operator's browser
    /// hits the portal. Invalidation is purely TTL-driven; if the chain
    /// anchor changes, the operator sees stale plaintext for up to the
    /// TTL window. See [`DEFAULT_ASSET_CACHE_CAPACITY`] /
    /// [`DEFAULT_ASSET_CACHE_TTL`] for the defaults.
    asset_cache: Arc<AssetCache>,
}

impl PortalChain {
    /// Build a v3 context from the loaded `ClientConfig`. Refuses on
    /// v1.1; accepts v2 or v3.
    pub(crate) fn from_config(cfg: &ClientConfig) -> anyhow::Result<Self> {
        Self::require_circle_substrate(cfg)?;
        // The portal itself doesn't sign anything (read-only over RPC),
        // so we don't load the wallet here. `connect_v3` performs the
        // wallet load separately when it actually needs to sign.
        let rpc = build_rpc(cfg)?;
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

    /// Fetch + decrypt a circle asset using an explicit
    /// [`PassphraseSource`]. The portal uses this to consult its
    /// per-circle unseal cache; CLI callers wire a [`ConfigPassphrase`].
    ///
    /// Consults the `(circle_id, path)` plaintext cache before going
    /// to the chain — a hit skips the RPC + KDF entirely.
    pub(crate) async fn fetch_with_source(
        &self,
        circle_id: &str,
        path: &str,
        source: &dyn PassphraseSource,
    ) -> Result<Vec<u8>, FetchAssetError> {
        self.fetch_cached(circle_id, path, |cid| source.passphrase_for(cid))
            .await
            .map(|c| (*c.bytes).clone())
    }

    /// Cache-aware variant of [`fetch_with_source`] that returns the
    /// sniffed MIME alongside the bytes, so callers (the routes layer)
    /// avoid re-sniffing per request. Cache hits share the same
    /// `SniffedMime` that was stored on first miss.
    pub(crate) async fn fetch_with_source_sniffed(
        &self,
        circle_id: &str,
        path: &str,
        source: &dyn PassphraseSource,
    ) -> Result<CachedAsset, FetchAssetError> {
        self.fetch_cached(circle_id, path, |cid| source.passphrase_for(cid))
            .await
    }

    /// One-shot attempt to decrypt the asset at `(circle_id, path)`
    /// with an alternate `passphrase`. Used by `POST /unseal` to
    /// validate operator-supplied passphrases against the canonical
    /// circle-resource-key fixture. Same single-attempt semantics — no
    /// oracle iteration; the caller is responsible for rate-limiting
    /// submissions.
    ///
    /// **Does NOT consult or populate the asset cache.** Unseal must
    /// always re-fetch + re-decrypt with the operator-supplied
    /// passphrase; serving cached bytes here would let a stale entry
    /// satisfy a wrong-passphrase submission (false-positive
    /// validation).
    pub(crate) async fn try_decrypt_with_passphrase(
        &self,
        circle_id: &str,
        path: &str,
        passphrase: Arc<Zeroizing<String>>,
    ) -> Result<Vec<u8>, FetchAssetError> {
        self.fetch_inner(circle_id, path, |_| Some(passphrase.clone()))
            .await
    }

    /// Fetch the bytes of `circle_asset(circle_id, path)`.
    ///
    /// Behaviour:
    ///   * Calls `circle_asset_ciphertext_by_resource_key`. Accepts
    ///     either `bytes_b64` (forward-compat plaintext view) or
    ///     `ciphertext_b64` (today's sealed view).
    ///   * If the decoded bytes start with the OCRS1 magic, attempts
    ///     decryption with the configured passphrase. On success
    ///     returns the plaintext; on failure returns a structured
    ///     [`FetchAssetError`] (no passphrase / decrypt failed) so the
    ///     route layer can render a passphrase-config error page.
    ///   * If the bytes don't have the magic, returns them verbatim —
    ///     forward-compatible with a future plaintext RPC view.
    pub(crate) async fn fetch_circle_asset_bytes(
        &self,
        circle_id: &str,
        path: &str,
    ) -> Result<Vec<u8>, FetchAssetError> {
        let pp = self.passphrase.clone();
        self.fetch_cached(circle_id, path, |_| pp.clone())
            .await
            .map(|c| (*c.bytes).clone())
    }

    /// Cache wrapper around [`Self::fetch_inner`]. On hit, returns the
    /// stored plaintext + sniffed MIME without touching the chain RPC
    /// or running a KDF. On miss, performs the fetch + decrypt, sniffs
    /// the result once, and inserts a [`CachedAsset`] for subsequent
    /// callers. Errors are never cached — every error path re-attempts
    /// on the next call so transient chain failures don't pin a
    /// negative result.
    async fn fetch_cached<F>(
        &self,
        circle_id: &str,
        path: &str,
        pick_passphrase: F,
    ) -> Result<CachedAsset, FetchAssetError>
    where
        F: Fn(&str) -> Option<Arc<Zeroizing<String>>>,
    {
        let key: AssetCacheKey = (circle_id.to_string(), canonical_path(path));
        if let Some(hit) = self.asset_cache.get(&key) {
            return Ok(hit);
        }
        let bytes = self.fetch_inner(circle_id, path, pick_passphrase).await?;
        let mime = sniff(&bytes);
        let entry = CachedAsset {
            bytes: Arc::new(bytes),
            mime,
            fetched_at: Instant::now(),
        };
        // `insert` evicts the oldest entry when at capacity. Concurrent
        // misses for the same key will both fetch then both insert —
        // the second insert wins and replaces the first, which is fine
        // (same plaintext modulo a chain anchor change inside the
        // race window).
        self.asset_cache.insert(key, entry.clone());
        Ok(entry)
    }

    /// Common fetch + decrypt pipeline. The `pick_passphrase` closure
    /// is consulted only after the OCRS1 magic confirms the bytes are
    /// sealed; plaintext-passthrough never asks for a passphrase.
    ///
    /// This is the **cache-bypass** path. Routes that want caching
    /// should go through [`Self::fetch_cached`] instead.
    async fn fetch_inner<F>(
        &self,
        circle_id: &str,
        path: &str,
        pick_passphrase: F,
    ) -> Result<Vec<u8>, FetchAssetError>
    where
        F: Fn(&str) -> Option<Arc<Zeroizing<String>>>,
    {
        let path = canonical_path(path);
        let rkey = resource_key(circle_id, &path);

        let resp = match self
            .rpc
            .raw_call(
                "circle_asset_ciphertext_by_resource_key",
                json!([circle_id, &rkey]),
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                // `RpcClient::call_once` flattens a `null` JSON-RPC
                // result into an "empty result" error and surfaces
                // "not found" for the node's explicit miss. Both mean
                // the asset isn't published — distinct from a wire
                // failure that we'd render as 502.
                let msg = e.to_string();
                if msg.contains("empty result") || msg.contains("not found") || msg.contains("no such") {
                    return Err(FetchAssetError::NotPublished {
                        circle_id: circle_id.to_string(),
                        path,
                        resource_key: rkey,
                    });
                }
                return Err(FetchAssetError::Rpc {
                    circle_id: circle_id.to_string(),
                    path: path.clone(),
                    source: anyhow::Error::new(e)
                        .context(format!("fetch circle_asset {circle_id}{path}")),
                });
            }
        };

        if resp.is_null() {
            return Err(FetchAssetError::NotPublished {
                circle_id: circle_id.to_string(),
                path,
                resource_key: rkey,
            });
        }

        let obj = resp.as_object().ok_or_else(|| FetchAssetError::Rpc {
            circle_id: circle_id.to_string(),
            path: path.clone(),
            source: anyhow::anyhow!("unexpected RPC shape: {resp}"),
        })?;

        // Pick the best-available field. Prefer `bytes_b64` (a future
        // plaintext view) over `ciphertext_b64` (today's sealed view)
        // so a deploy-day plaintext-RPC swap requires no code change.
        let b64 = if let Some(s) = obj.get("bytes_b64").and_then(Value::as_str) {
            s
        } else if let Some(s) = obj.get("ciphertext_b64").and_then(Value::as_str) {
            s
        } else {
            return Err(FetchAssetError::Rpc {
                circle_id: circle_id.to_string(),
                path: path.clone(),
                source: anyhow::anyhow!("response missing bytes_b64/ciphertext_b64"),
            });
        };

        let bytes = B64
            .decode(b64.as_bytes())
            .map_err(|e| FetchAssetError::Rpc {
                circle_id: circle_id.to_string(),
                path: path.clone(),
                source: anyhow::anyhow!("decode base64 asset: {e}"),
            })?;

        // Sealed-envelope sniff. We check the magic regardless of which
        // field name carried the payload — a future plaintext-view RPC
        // could in principle still ship a pre-sealed asset, and we'd
        // rather decrypt than render ciphertext. (Cost: 5-byte cmp.)
        if !looks_sealed(&bytes) {
            return Ok(bytes);
        }

        // From here on, bytes are a sealed envelope. We need a
        // passphrase + the plaintext_hash the chain published.
        let Some(pp) = pick_passphrase(circle_id) else {
            return Err(FetchAssetError::MissingPassphrase {
                circle_id: circle_id.to_string(),
                path,
            });
        };

        let plaintext_hash = obj
            .get("plaintext_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| FetchAssetError::Rpc {
                circle_id: circle_id.to_string(),
                path: path.clone(),
                source: anyhow::anyhow!("sealed asset response missing plaintext_hash"),
            })?;
        let key_id = obj
            .get("key_id")
            .and_then(Value::as_str)
            .unwrap_or(&self.key_id);

        // One decrypt attempt. We deliberately drop the inner error
        // string — exposing it through Display could leak fragments of
        // the ciphertext envelope or, in some future codepath, the
        // passphrase. The route layer turns this into a "passphrase
        // mismatch" page; the operator can re-check their config.
        match decrypt_sealed_bytes(circle_id, key_id, pp.as_str(), b64, plaintext_hash) {
            Ok(plain) => Ok(plain),
            Err(_) => Err(FetchAssetError::DecryptFailed {
                circle_id: circle_id.to_string(),
                path,
            }),
        }
    }
}

/// Detect the OCRS1 sealed-envelope magic on raw envelope bytes (post
/// base64-decode).
fn looks_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= SEALED_MAGIC.len() && &bytes[..SEALED_MAGIC.len()] == SEALED_MAGIC
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
fn build_rpc(cfg: &ClientConfig) -> anyhow::Result<RpcClient> {
    use anyhow::Context as _;
    let pinned: Vec<Vec<u8>> = match cfg.chain.pinned_root_paths.as_deref() {
        Some(paths) if !paths.is_empty() => paths
            .iter()
            .map(|p| std::fs::read(p).with_context(|| format!("read pinned root {p}")))
            .collect::<anyhow::Result<Vec<_>>>()?,
        _ => Vec::new(),
    };
    if pinned.is_empty() {
        Ok(RpcClient::new(cfg.chain.rpc_url.clone()))
    } else {
        RpcClient::new_with_pinned_roots(cfg.chain.rpc_url.clone(), &pinned)
            .map_err(|e| anyhow::anyhow!("pinned-root rpc client: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ChainCfg, V2Cfg, V3Cfg, WalletCfg};
    use axum::{routing::post, Json, Router};
    use octravpn_core::circle::{encrypt_sealed_bytes, PaddingClass};
    use std::net::SocketAddr;

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
    fn canonical_path_normalizes() {
        assert_eq!(canonical_path("policy.json"), "/policy.json");
        assert_eq!(canonical_path("/policy.json"), "/policy.json");
        assert_eq!(canonical_path("//policy.json"), "/policy.json");
        assert_eq!(canonical_path(""), "/");
        assert_eq!(canonical_path("/"), "/");
    }

    #[test]
    fn looks_sealed_recognises_ocrs1_magic() {
        assert!(looks_sealed(b"OCRS1\x00\x01"));
        assert!(!looks_sealed(b"OCRS"));
        assert!(!looks_sealed(b"plain"));
        assert!(!looks_sealed(b""));
    }

    /// Spawn a stub axum RPC that returns the given `result` JSON for
    /// every `circle_asset_ciphertext_by_resource_key` call. Returns the
    /// listening loopback address.
    async fn spawn_mock_rpc(result: serde_json::Value) -> SocketAddr {
        let result_arc = std::sync::Arc::new(result);
        let app: Router = Router::new().route(
            "/",
            post(move |Json(req): Json<serde_json::Value>| {
                let result = std::sync::Arc::clone(&result_arc);
                async move {
                    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                    let id = req.get("id").cloned().unwrap_or(json!(1));
                    if method == "circle_asset_ciphertext_by_resource_key" {
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": (*result).clone(),
                        }))
                    } else {
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": { "code": -32601, "message": "method not found" },
                        }))
                    }
                }
            }),
        );
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

    /// Build a sealed-envelope fixture at runtime so we don't commit a
    /// binary blob. Matches the operator-side sealing path.
    fn build_sealed_fixture(
        circle_id: &str,
        key_id: &str,
        passphrase: &str,
        plaintext: &[u8],
    ) -> (String, String) {
        encrypt_sealed_bytes(circle_id, key_id, passphrase, plaintext, PaddingClass::None)
            .expect("encrypt fixture")
    }

    #[tokio::test]
    async fn decrypts_sealed_envelope_with_passphrase() {
        let plaintext = br#"{"endpoint":"vpn.example:51820","region":"us-east"}"#;
        let (ct_b64, ph_hex) =
            build_sealed_fixture("octCIRCLE_T1", "default", "correct-passphrase", plaintext);
        let addr = spawn_mock_rpc(json!({
            "ciphertext_b64": ct_b64,
            "plaintext_hash": ph_hex,
            "key_id": "default",
        }))
        .await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0)
            .with_passphrase("correct-passphrase");

        let got = chain
            .fetch_circle_asset_bytes("octCIRCLE_T1", "/policy.json")
            .await
            .expect("decrypt should succeed");
        assert_eq!(got, plaintext);
    }

    #[tokio::test]
    async fn passes_plaintext_bytes_through() {
        // Mock RPC returns base64 of NON-sealed bytes (no OCRS1 magic).
        // No passphrase needed — fetcher returns the bytes verbatim.
        let plaintext = b"plain text from the chain RPC";
        let b64 = B64.encode(plaintext);
        let addr = spawn_mock_rpc(json!({
            "ciphertext_b64": b64,
            "plaintext_hash": "0".repeat(64),
            "key_id": "default",
        }))
        .await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);

        let got = chain
            .fetch_circle_asset_bytes("octCIRCLE_T2", "/asset.txt")
            .await
            .expect("plaintext passthrough should succeed");
        assert_eq!(got, plaintext);
    }

    #[tokio::test]
    async fn wrong_passphrase_returns_structured_error() {
        let plaintext = br#"{"k":"v"}"#;
        let (ct_b64, ph_hex) =
            build_sealed_fixture("octCIRCLE_T3", "default", "operator-secret", plaintext);
        let addr = spawn_mock_rpc(json!({
            "ciphertext_b64": ct_b64,
            "plaintext_hash": ph_hex,
            "key_id": "default",
        }))
        .await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0)
            .with_passphrase("WRONG-passphrase");

        let err = chain
            .fetch_circle_asset_bytes("octCIRCLE_T3", "/policy.json")
            .await
            .expect_err("wrong passphrase must fail");
        assert!(
            matches!(err, FetchAssetError::DecryptFailed { .. }),
            "expected DecryptFailed, got: {err:?}",
        );
        // The error Display must not leak the passphrase or the
        // ciphertext bytes.
        let msg = err.to_string();
        assert!(!msg.contains("WRONG-passphrase"));
        assert!(!msg.contains(&ct_b64));
    }

    #[tokio::test]
    async fn no_passphrase_returns_structured_error() {
        let plaintext = br#"{"k":"v"}"#;
        let (ct_b64, ph_hex) =
            build_sealed_fixture("octCIRCLE_T4", "default", "operator-secret", plaintext);
        let addr = spawn_mock_rpc(json!({
            "ciphertext_b64": ct_b64,
            "plaintext_hash": ph_hex,
            "key_id": "default",
        }))
        .await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        // No passphrase configured.
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);

        let err = chain
            .fetch_circle_asset_bytes("octCIRCLE_T4", "/policy.json")
            .await
            .expect_err("missing passphrase must fail");
        assert!(
            matches!(err, FetchAssetError::MissingPassphrase { .. }),
            "expected MissingPassphrase, got: {err:?}",
        );
    }

    #[tokio::test]
    async fn not_published_returns_structured_error() {
        let addr = spawn_mock_rpc(serde_json::Value::Null).await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let err = chain
            .fetch_circle_asset_bytes("octCIRCLE_T5", "/missing.json")
            .await
            .expect_err("null result must be NotPublished");
        assert!(
            matches!(err, FetchAssetError::NotPublished { .. }),
            "got: {err:?}",
        );
    }

    // ─── asset-cache tests  ───────────────────────────────────────────
    //
    // These exercise the bounded LRU + TTL cache layered on
    // `fetch_circle_asset_bytes` / `fetch_with_source[_sniffed]`. The
    // shared infrastructure: a counting mock RPC that lets us assert
    // "this call did NOT hit the chain" (cache hit) vs "this call
    // produced a fresh roundtrip" (cache miss).

    /// Spawn a stub RPC that returns `result` for every call and
    /// increments `counter` on each invocation. Returned `addr` is the
    /// loopback bind; the counter is shared with the caller for
    /// hit/miss assertions.
    async fn spawn_counting_rpc(
        result: serde_json::Value,
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_app = Arc::clone(&counter);
        let result_arc = Arc::new(result);
        let app: Router = Router::new().route(
            "/",
            post(move |Json(req): Json<serde_json::Value>| {
                let result = Arc::clone(&result_arc);
                let counter = Arc::clone(&counter_for_app);
                async move {
                    let id = req.get("id").cloned().unwrap_or(json!(1));
                    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                    if method == "circle_asset_ciphertext_by_resource_key" {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": (*result).clone(),
                        }))
                    } else {
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": { "code": -32601, "message": "method not found" },
                        }))
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        (addr, counter)
    }

    /// Build a chain wired to `addr` with the given cache injected.
    fn chain_with_cache(addr: SocketAddr, cache: Arc<AssetCache>) -> PortalChain {
        let rpc = RpcClient::new(format!("http://{addr}/"));
        PortalChain::from_rpc(rpc, "octPROG".into(), 0).with_asset_cache(cache)
    }

    #[tokio::test]
    async fn cache_hit_returns_same_bytes_without_rpc_call() {
        use std::sync::atomic::Ordering;
        let plaintext = b"plaintext for cache hit";
        let b64 = B64.encode(plaintext);
        let (addr, count) = spawn_counting_rpc(json!({
            "ciphertext_b64": b64,
            "plaintext_hash": "0".repeat(64),
            "key_id": "default",
        }))
        .await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(16, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));

        // First call: miss → one RPC roundtrip.
        let got1 = chain
            .fetch_circle_asset_bytes("circHIT", "/policy.json")
            .await
            .expect("first call fetches");
        assert_eq!(got1, plaintext);
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Second + third call: hit → counter stays at 1.
        let got2 = chain
            .fetch_circle_asset_bytes("circHIT", "/policy.json")
            .await
            .expect("second call is cached");
        let got3 = chain
            .fetch_circle_asset_bytes("circHIT", "/policy.json")
            .await
            .expect("third call is cached");
        assert_eq!(got2, plaintext);
        assert_eq!(got3, plaintext);
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "cache hits must not generate new RPC calls",
        );
    }

    #[tokio::test]
    async fn cache_ttl_expiry_forces_refetch() {
        use std::sync::atomic::Ordering;
        let plaintext = b"ttl-expiry bytes";
        let b64 = B64.encode(plaintext);
        let (addr, count) = spawn_counting_rpc(json!({
            "ciphertext_b64": b64,
            "plaintext_hash": "0".repeat(64),
            "key_id": "default",
        }))
        .await;
        // Short TTL so the test isn't slow. `BoundedMap::sweep` is what
        // implements eviction — `get` itself doesn't lazily expire, so
        // we drive sweep explicitly to model a periodic sweep task.
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(16, Duration::from_millis(20)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));

        let _ = chain
            .fetch_circle_asset_bytes("circTTL", "/policy.json")
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Wait past TTL + sweep → entry is gone.
        tokio::time::sleep(Duration::from_millis(40)).await;
        let evicted = cache.sweep();
        assert_eq!(evicted, 1, "ttl sweep should evict the stale entry");

        // Next fetch must hit the RPC again.
        let _ = chain
            .fetch_circle_asset_bytes("circTTL", "/policy.json")
            .await
            .unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "post-eviction fetch must re-roundtrip",
        );
    }

    #[tokio::test]
    async fn cache_bounded_capacity_evicts_oldest() {
        use std::sync::atomic::Ordering;
        let plaintext = b"capacity test bytes";
        let b64 = B64.encode(plaintext);
        let (addr, count) = spawn_counting_rpc(json!({
            "ciphertext_b64": b64,
            "plaintext_hash": "0".repeat(64),
            "key_id": "default",
        }))
        .await;
        // Cap = 2; insert 3 distinct keys → the first is evicted.
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(2, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));

        let _ = chain
            .fetch_circle_asset_bytes("circCAP", "/a.json")
            .await
            .unwrap();
        let _ = chain
            .fetch_circle_asset_bytes("circCAP", "/b.json")
            .await
            .unwrap();
        let _ = chain
            .fetch_circle_asset_bytes("circCAP", "/c.json")
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 3, "three distinct keys, three RPCs");
        assert_eq!(cache.len(), 2, "capacity must cap at 2");

        // /a.json was the oldest; refetching must miss + roundtrip.
        // After this insert, the cache holds /c.json + /a.json (the
        // re-insert of /a.json evicted /b.json — the new oldest).
        let _ = chain
            .fetch_circle_asset_bytes("circCAP", "/a.json")
            .await
            .unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            4,
            "evicted oldest entry re-fetches",
        );

        // /c.json was still cached → no new roundtrip.
        let _ = chain
            .fetch_circle_asset_bytes("circCAP", "/c.json")
            .await
            .unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            4,
            "/c.json was still in cache; no new RPC",
        );
    }

    #[tokio::test]
    async fn cache_key_isolates_circles_and_paths() {
        use std::sync::atomic::Ordering;
        let plaintext = b"isolation test bytes";
        let b64 = B64.encode(plaintext);
        let (addr, count) = spawn_counting_rpc(json!({
            "ciphertext_b64": b64,
            "plaintext_hash": "0".repeat(64),
            "key_id": "default",
        }))
        .await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(16, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));

        // Different circles, same path → distinct keys → two RPCs.
        let _ = chain
            .fetch_circle_asset_bytes("circA", "/policy.json")
            .await
            .unwrap();
        let _ = chain
            .fetch_circle_asset_bytes("circB", "/policy.json")
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2, "circle id isolates cache");

        // Same circle, different paths → distinct keys → two more RPCs.
        let _ = chain
            .fetch_circle_asset_bytes("circA", "/state-root.json")
            .await
            .unwrap();
        let _ = chain
            .fetch_circle_asset_bytes("circA", "/members.json")
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 4, "path isolates cache");

        // Canonical-path collapse: `policy.json` and `/policy.json`
        // share a key, so the second hits the cache.
        let _ = chain
            .fetch_circle_asset_bytes("circA", "policy.json")
            .await
            .unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            4,
            "canonical path collapses leading-slash variants to the same entry",
        );
    }

    #[tokio::test]
    async fn cache_concurrent_access_does_not_re_roundtrip() {
        // Concurrent misses for the same key may both hit the RPC
        // before either inserts (we don't have inflight de-duplication;
        // `fetch_cached` calls that out). But after the cache is warm,
        // every subsequent concurrent request must be served from
        // cache. This test asserts the post-warmup invariant: 100
        // concurrent gets on a warm cache produce zero new RPCs.
        use std::sync::atomic::Ordering;
        let plaintext = b"concurrent access bytes";
        let b64 = B64.encode(plaintext);
        let (addr, count) = spawn_counting_rpc(json!({
            "ciphertext_b64": b64,
            "plaintext_hash": "0".repeat(64),
            "key_id": "default",
        }))
        .await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(16, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));

        // Warm up the cache (single fetch).
        let _ = chain
            .fetch_circle_asset_bytes("circCONC", "/policy.json")
            .await
            .unwrap();
        let baseline = count.load(Ordering::SeqCst);
        assert_eq!(baseline, 1);

        // Fan out 100 concurrent reads of the same key.
        let mut handles = Vec::with_capacity(100);
        for _ in 0..100 {
            let chain = chain.clone();
            handles.push(tokio::spawn(async move {
                chain
                    .fetch_circle_asset_bytes("circCONC", "/policy.json")
                    .await
                    .unwrap()
            }));
        }
        for h in handles {
            let bytes = h.await.unwrap();
            assert_eq!(bytes, plaintext);
        }
        assert_eq!(
            count.load(Ordering::SeqCst),
            baseline,
            "warm-cache concurrent reads must not generate new RPCs",
        );
    }

    #[tokio::test]
    async fn cache_errors_are_not_stored() {
        // A failed fetch must not poison the cache — the next call
        // re-attempts. Drive this via NotPublished (RPC returns null).
        use std::sync::atomic::Ordering;
        let (addr, count) = spawn_counting_rpc(serde_json::Value::Null).await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(16, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));

        let err1 = chain
            .fetch_circle_asset_bytes("circERR", "/missing.json")
            .await
            .expect_err("null result must be NotPublished");
        assert!(matches!(err1, FetchAssetError::NotPublished { .. }));
        let after_first = count.load(Ordering::SeqCst);

        // Second call: must also roundtrip — not satisfied from cache.
        let err2 = chain
            .fetch_circle_asset_bytes("circERR", "/missing.json")
            .await
            .expect_err("still not published");
        assert!(matches!(err2, FetchAssetError::NotPublished { .. }));
        assert!(
            count.load(Ordering::SeqCst) > after_first,
            "failed fetches must not be cached",
        );
        assert_eq!(cache.len(), 0, "cache stays empty when fetches fail");
    }

    #[tokio::test]
    async fn try_decrypt_with_passphrase_bypasses_cache() {
        // The unseal flow uses `try_decrypt_with_passphrase`, which
        // must NEVER serve from cache — serving a previously-cached
        // plaintext would let a wrong passphrase validate successfully.
        use std::sync::atomic::Ordering;
        let plaintext = b"unseal bypass bytes";
        let (ct_b64, ph_hex) =
            build_sealed_fixture("circBYPASS", "default", "right-pp", plaintext);
        let (addr, count) = spawn_counting_rpc(json!({
            "ciphertext_b64": ct_b64,
            "plaintext_hash": ph_hex,
            "key_id": "default",
        }))
        .await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(16, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache)).with_passphrase("right-pp");

        // Warm the cache via the read path.
        let _ = chain
            .fetch_circle_asset_bytes("circBYPASS", "/policy.json")
            .await
            .unwrap();
        let warmed = count.load(Ordering::SeqCst);
        assert_eq!(warmed, 1);

        // Now call `try_decrypt_with_passphrase` — it must NOT serve
        // from cache; we expect an additional RPC roundtrip.
        let pp = Arc::new(Zeroizing::new("right-pp".to_string()));
        let _ = chain
            .try_decrypt_with_passphrase("circBYPASS", "/policy.json", pp)
            .await
            .unwrap();
        assert!(
            count.load(Ordering::SeqCst) > warmed,
            "try_decrypt_with_passphrase must always hit the chain",
        );
    }
}
