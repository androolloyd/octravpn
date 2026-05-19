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

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use octravpn_core::{
    circle::{decrypt_sealed_bytes, resource_key},
    rpc::RpcClient,
};
use serde_json::{json, Value};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::ClientConfig;

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
    pub(crate) fn circle_id(&self) -> &str {
        match self {
            Self::Rpc { circle_id, .. }
            | Self::NotPublished { circle_id, .. }
            | Self::MissingPassphrase { circle_id, .. }
            | Self::DecryptFailed { circle_id, .. } => circle_id,
        }
    }

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
        let Some(pp) = self.passphrase.as_ref() else {
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
}
