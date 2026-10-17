//! Chain-RPC fetch pipeline for circle assets.
//!
//! * `fetch_inner` — **cache-bypass** roundtrip + sealed-envelope
//!   decrypt. Calls `circle_asset_ciphertext_by_resource_key`, accepts
//!   `bytes_b64` (future plaintext) or `ciphertext_b64` (today's sealed
//!   view), and decrypts on the OCRS1 magic.
//! * `fetch_cached` — LRU+TTL wrapper used by the read path. Errors
//!   are never cached.
//! * `build_rpc` — construct an `RpcClient` from a `ClientConfig`,
//!   wiring pinned-root TLS when configured.
//!
//! The unseal path in `decrypt.rs` calls `fetch_inner` directly so it
//! always bypasses the cache.

use octravpn_core::{
    circle::{decrypt_sealed_bytes, resource_key},
    rpc::RpcClient,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Instant};
use zeroize::Zeroizing;

use crate::{
    config::ClientConfig,
    portal::{
        chain::{
            cache::{canonical_path, looks_sealed, AssetCacheKey, CachedAsset},
            errors::FetchAssetError,
            PortalChain,
        },
        mime::sniff,
    },
};

impl PortalChain {
    /// Cache wrapper around [`Self::fetch_inner`]. On hit, returns the
    /// stored plaintext + sniffed MIME without touching the chain RPC
    /// or running a KDF. On miss, performs the fetch + decrypt, sniffs
    /// the result once, and inserts a [`CachedAsset`] for subsequent
    /// callers. Errors are never cached — every error path re-attempts
    /// on the next call so transient chain failures don't pin a
    /// negative result.
    pub(super) async fn fetch_cached<F>(
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
    pub(super) async fn fetch_inner<F>(
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
                if msg.contains("empty result")
                    || msg.contains("not found")
                    || msg.contains("no such")
                {
                    if let Some(public) = self.fetch_public_asset(circle_id, &path, &rkey).await {
                        return public;
                    }
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
            if let Some(public) = self.fetch_public_asset(circle_id, &path, &rkey).await {
                return public;
            }
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

        let bytes =
            octravpn_core::b64::decode(b64.as_bytes()).map_err(|e| FetchAssetError::Rpc {
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

    /// The resource-key RPC intentionally hides sealed paths. Only disclose
    /// a plaintext path after the chain reports a public Circle and public
    /// resource mode. A miss or failure to establish that mode keeps the
    /// original resource-key result.
    async fn fetch_public_asset(
        &self,
        circle_id: &str,
        path: &str,
        resource_key: &str,
    ) -> Option<Result<Vec<u8>, FetchAssetError>> {
        let info = self
            .rpc
            .raw_call("circle_info", json!([circle_id]))
            .await
            .ok()?;
        if info.get("circle_id").and_then(Value::as_str) != Some(circle_id)
            || info.get("privacy_class").and_then(Value::as_str) != Some("public")
            || info.get("resource_mode").and_then(Value::as_str) != Some("public_resources")
        {
            return None;
        }

        Some(
            self.fetch_public_asset_confirmed(circle_id, path, resource_key)
                .await,
        )
    }

    async fn fetch_public_asset_confirmed(
        &self,
        circle_id: &str,
        path: &str,
        resource_key: &str,
    ) -> Result<Vec<u8>, FetchAssetError> {
        let response = self
            .rpc
            .raw_call("circle_asset", json!([circle_id, path]))
            .await
            .map_err(|source| FetchAssetError::Rpc {
                circle_id: circle_id.to_string(),
                path: path.to_string(),
                source: anyhow::Error::new(source).context("fetch public circle_asset"),
            })?;
        if response.is_null() {
            return Err(FetchAssetError::NotPublished {
                circle_id: circle_id.to_string(),
                path: path.to_string(),
                resource_key: resource_key.to_string(),
            });
        }
        let invalid = |reason| FetchAssetError::Rpc {
            circle_id: circle_id.to_string(),
            path: path.to_string(),
            source: anyhow::anyhow!("invalid public circle_asset response: {reason}"),
        };
        if response.get("circle_id").and_then(Value::as_str) != Some(circle_id)
            || response.get("canonical_path").and_then(Value::as_str) != Some(path)
            || response.get("resource_key").and_then(Value::as_str) != Some(resource_key)
            || response.get("resource_mode").and_then(Value::as_str) != Some("public_resources")
        {
            return Err(invalid("identity or mode mismatch"));
        }
        let body_b64 = response
            .get("body_b64")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing body_b64"))?;
        let bytes = octravpn_core::b64::decode(body_b64.as_bytes())
            .map_err(|_| invalid("invalid body_b64"))?;
        let declared_size = response
            .get("size_bytes")
            .and_then(|value| value.as_str().and_then(|s| s.parse::<usize>().ok()))
            .ok_or_else(|| invalid("invalid size_bytes"))?;
        if bytes.len() != declared_size {
            return Err(invalid("size mismatch"));
        }
        let expected_hash = response
            .get("blob_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing blob_hash"))?;
        if hex::encode(Sha256::digest(&bytes)) != expected_hash {
            return Err(invalid("blob hash mismatch"));
        }
        Ok(bytes)
    }
}

/// Mirror of `runner::build_rpc` but visible here without making the
/// runner pub. Pinned-root TLS plumbing is preserved; SPKI pinning is
/// applied on top when a `oct://...?spki=<base64>` URL is provided to
/// [`build_rpc_for_oct_url`] (audit-1 H-1).
#[allow(dead_code)] // legacy callsite kept for back-compat; new code uses build_rpc_for_oct_url
pub(super) fn build_rpc(cfg: &ClientConfig) -> anyhow::Result<RpcClient> {
    build_rpc_for_oct_url(cfg, None)
}

/// Same as [`build_rpc`] but, when `oct_url` carries an `?spki=…`
/// parameter, installs a [`SpkiPinVerifier`] that gates every TLS
/// handshake on the leaf cert's `sha256(SubjectPublicKeyInfo)`
/// matching one of the pinned values. The pin set may carry multiple
/// entries (comma-separated) for rotation grace; see
/// `crates/octravpn-core/src/spki_verifier.rs`.
///
/// Falls back to the regular CA-pinned path when:
///   * `oct_url` is `None`
///   * the URL has no `?spki=` parameter
///   * the `spki=` value fails to parse (returns `None` from
///     [`SpkiPinVerifier::parse_pins_from_oct_url`])
///
/// This is intentional: a v1 oct:// URL minted before the SPKI-pin
/// rollout still works against the same chain RPC — operators can
/// upgrade the chain RPC's TLS cert and old URLs continue to function
/// (with the original CA-only protection). Once an operator regenerates
/// URLs with the new pin, the protection upgrades.
pub(super) fn build_rpc_for_oct_url(
    cfg: &ClientConfig,
    oct_url: Option<&str>,
) -> anyhow::Result<RpcClient> {
    use anyhow::Context as _;
    use octravpn_core::spki_verifier::SpkiPinVerifier;
    let pinned: Vec<Vec<u8>> = match cfg.chain.pinned_root_paths.as_deref() {
        Some(paths) if !paths.is_empty() => paths
            .iter()
            .map(|p| std::fs::read(p).with_context(|| format!("read pinned root {p}")))
            .collect::<anyhow::Result<Vec<_>>>()?,
        _ => Vec::new(),
    };
    // SPKI pin path — only when the caller passed an oct:// URL AND
    // the URL has `?spki=<b64>` AND it parses cleanly. Anything else
    // falls back to CA pinning so legacy URLs keep working.
    let spki_pins = oct_url.and_then(SpkiPinVerifier::parse_pins_from_oct_url);
    if let Some(pins) = spki_pins {
        let pem_roots: Option<&[Vec<u8>]> = if pinned.is_empty() {
            None
        } else {
            Some(&pinned)
        };
        return RpcClient::new_with_pinned_spki(cfg.chain.rpc_url.clone(), pem_roots, pins)
            .map_err(|e| anyhow::anyhow!("spki-pinned rpc client: {e}"));
    }
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
    use crate::portal::chain::tests_common::{
        build_sealed_fixture, plaintext_payload, sealed_payload, spawn_error_rpc, spawn_mock_rpc,
    };
    use crate::portal::chain::PortalChain;
    use axum::{routing::post, Json, Router};
    use std::{
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    async fn spawn_public_circle_rpc(
        resource_mode: &'static str,
        valid_hash: bool,
    ) -> (SocketAddr, Arc<AtomicUsize>) {
        let asset_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&asset_calls);
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let calls = Arc::clone(&calls);
                async move {
                    let circle = "octPUBLIC";
                    let path = "/index.html";
                    let body = b"<html>public Circle</html>";
                    let resource_key = resource_key(circle, path);
                    let result = match request["method"].as_str().unwrap_or_default() {
                        "circle_info" => Some(json!({
                            "circle_id": circle,
                            "privacy_class": if resource_mode == "public_resources" { "public" } else { "sealed" },
                            "resource_mode": resource_mode,
                        })),
                        "circle_asset" => {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Some(json!({
                                "circle_id": circle,
                                "canonical_path": path,
                                "resource_key": resource_key,
                                "resource_mode": resource_mode,
                                "body_b64": octravpn_core::b64::encode(body),
                                "size_bytes": body.len().to_string(),
                                "blob_hash": if valid_hash { hex::encode(Sha256::digest(body)) } else { "0".repeat(64) },
                            }))
                        }
                        _ => None,
                    };
                    let id = request.get("id").cloned().unwrap_or(json!(1));
                    match result {
                        Some(result) => Json(json!({"jsonrpc":"2.0","id":id,"result":result})),
                        None => Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":112,"message":"not found"}})),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (address, asset_calls)
    }

    #[tokio::test]
    async fn public_circle_falls_back_to_verified_plaintext_asset() {
        let (address, calls) = spawn_public_circle_rpc("public_resources", true).await;
        let chain = PortalChain::from_rpc(
            RpcClient::new(format!("http://{address}/")),
            "octPROG".into(),
            0,
        );
        let bytes = chain
            .fetch_circle_asset_bytes("octPUBLIC", "/index.html")
            .await
            .unwrap();
        assert_eq!(bytes, b"<html>public Circle</html>");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn sealed_circle_never_discloses_plaintext_path_on_miss() {
        let (address, calls) = spawn_public_circle_rpc("sealed_read", true).await;
        let chain = PortalChain::from_rpc(
            RpcClient::new(format!("http://{address}/")),
            "octPROG".into(),
            0,
        );
        assert!(matches!(
            chain
                .fetch_circle_asset_bytes("octPUBLIC", "/index.html")
                .await,
            Err(FetchAssetError::NotPublished { .. })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn public_circle_rejects_mismatched_asset_hash() {
        let (address, _) = spawn_public_circle_rpc("public_resources", false).await;
        let chain = PortalChain::from_rpc(
            RpcClient::new(format!("http://{address}/")),
            "octPROG".into(),
            0,
        );
        assert!(matches!(
            chain
                .fetch_circle_asset_bytes("octPUBLIC", "/index.html")
                .await,
            Err(FetchAssetError::Rpc { .. })
        ));
    }

    #[tokio::test]
    async fn decrypts_sealed_envelope_with_passphrase() {
        let plaintext = br#"{"endpoint":"vpn.example:51820","region":"us-east"}"#;
        let (ct_b64, ph_hex) =
            build_sealed_fixture("octCIRCLE_T1", "default", "correct-passphrase", plaintext);
        let addr = spawn_mock_rpc(sealed_payload(&ct_b64, &ph_hex)).await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain =
            PortalChain::from_rpc(rpc, "octPROG".into(), 0).with_passphrase("correct-passphrase");

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
        let addr = spawn_mock_rpc(plaintext_payload(plaintext)).await;
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
        let addr = spawn_mock_rpc(sealed_payload(&ct_b64, &ph_hex)).await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain =
            PortalChain::from_rpc(rpc, "octPROG".into(), 0).with_passphrase("WRONG-passphrase");

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
        let addr = spawn_mock_rpc(sealed_payload(&ct_b64, &ph_hex)).await;
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

    #[tokio::test]
    async fn rpc_not_found_maps_to_not_published() {
        let addr = spawn_error_rpc("not found").await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let err = chain
            .fetch_circle_asset_bytes("circNF", "/missing.json")
            .await
            .expect_err("not found must map to NotPublished");
        assert!(matches!(err, FetchAssetError::NotPublished { .. }));
    }

    #[tokio::test]
    async fn rpc_empty_result_maps_to_not_published() {
        let addr = spawn_error_rpc("empty result").await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let err = chain
            .fetch_circle_asset_bytes("circEMPTY", "/x.json")
            .await
            .expect_err("empty result must map to NotPublished");
        assert!(matches!(err, FetchAssetError::NotPublished { .. }));
    }

    #[tokio::test]
    async fn rpc_no_such_method_maps_to_not_published() {
        let addr = spawn_error_rpc("no such method").await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let err = chain
            .fetch_circle_asset_bytes("circNS", "/x.json")
            .await
            .expect_err("no such must map to NotPublished");
        assert!(matches!(err, FetchAssetError::NotPublished { .. }));
    }

    #[tokio::test]
    async fn rpc_generic_failure_maps_to_rpc_error() {
        let addr = spawn_error_rpc("internal server error").await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let err = chain
            .fetch_circle_asset_bytes("circGEN", "/x.json")
            .await
            .expect_err("generic error must map to Rpc");
        match err {
            FetchAssetError::Rpc { .. } => {}
            other => panic!("expected Rpc, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rpc_connection_refused_maps_to_rpc_error() {
        // Point the chain at a port that's almost certainly closed.
        let rpc = RpcClient::new("http://127.0.0.1:1/");
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let err = chain
            .fetch_circle_asset_bytes("circDOWN", "/x.json")
            .await
            .expect_err("connect refused must produce an error");
        // Wire-level error: not `NotPublished` (the message doesn't
        // include those magic phrases) → Rpc variant.
        match err {
            FetchAssetError::Rpc { .. } => {}
            other => panic!("expected Rpc, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_rpc_payload_missing_bytes_field_maps_to_rpc() {
        // Object response with neither `bytes_b64` nor `ciphertext_b64`.
        let addr = spawn_mock_rpc(json!({
            "plaintext_hash": "00".repeat(32),
            "key_id": "default",
        }))
        .await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let err = chain
            .fetch_circle_asset_bytes("circBAD", "/x.json")
            .await
            .expect_err("missing bytes field must map to Rpc");
        match err {
            FetchAssetError::Rpc { source, .. } => {
                let msg = source.to_string();
                assert!(
                    msg.contains("missing bytes_b64") || msg.contains("ciphertext_b64"),
                    "got: {msg}"
                );
            }
            other => panic!("expected Rpc, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_rpc_payload_non_object_maps_to_rpc() {
        // RPC returns a bare string, not an object.
        let addr = spawn_mock_rpc(json!("not an object")).await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let err = chain
            .fetch_circle_asset_bytes("circStr", "/x.json")
            .await
            .expect_err("non-object must map to Rpc");
        assert!(matches!(err, FetchAssetError::Rpc { .. }));
    }

    #[tokio::test]
    async fn malformed_base64_payload_maps_to_rpc() {
        // ciphertext_b64 isn't valid base64.
        let addr = spawn_mock_rpc(json!({
            "ciphertext_b64": "!!!not-base64@@@",
            "plaintext_hash": "0".repeat(64),
            "key_id": "default",
        }))
        .await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let err = chain
            .fetch_circle_asset_bytes("circB64", "/x.json")
            .await
            .expect_err("invalid base64 must map to Rpc");
        match err {
            FetchAssetError::Rpc { source, .. } => {
                assert!(source.to_string().contains("base64"));
            }
            other => panic!("expected Rpc, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sealed_asset_missing_plaintext_hash_maps_to_rpc() {
        // Sealed envelope but the response is missing plaintext_hash.
        let plaintext = b"x";
        let (ct_b64, _ph) = build_sealed_fixture("circNOPH", "default", "pp", plaintext);
        let addr = spawn_mock_rpc(json!({
            "ciphertext_b64": ct_b64,
            "key_id": "default",
        }))
        .await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0).with_passphrase("pp");
        let err = chain
            .fetch_circle_asset_bytes("circNOPH", "/x.json")
            .await
            .expect_err("missing plaintext_hash must map to Rpc");
        match err {
            FetchAssetError::Rpc { source, .. } => {
                assert!(source.to_string().contains("plaintext_hash"));
            }
            other => panic!("expected Rpc, got {other:?}"),
        }
    }
}
