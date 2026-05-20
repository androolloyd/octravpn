//! Operator-supplied passphrase unseal path.
//!
//! # Load-bearing cache-bypass invariant
//!
//! [`PortalChain::try_decrypt_with_passphrase`] **MUST always bypass
//! the asset cache.** `POST /unseal` validates the operator-supplied
//! passphrase by calling this method and treating success as proof
//! the passphrase is correct. Serving a cached plaintext — decrypted
//! under a *previous* passphrase — would satisfy the call even when
//! the freshly-submitted passphrase is wrong, collapsing the unseal
//! flow into a false-positive validation oracle.
//!
//! To preserve the invariant this method calls
//! [`PortalChain::fetch_inner`] (the cache-bypass pipeline) directly,
//! never `fetch_cached`, and never writes back into the cache.
//!
//! Same single-attempt semantics as the read path: one decrypt, no
//! oracle iteration. Callers rate-limit submissions.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::portal::chain::{errors::FetchAssetError, PortalChain};

impl PortalChain {
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
    /// validation). See the module-level invariant.
    pub(crate) async fn try_decrypt_with_passphrase(
        &self,
        circle_id: &str,
        path: &str,
        passphrase: Arc<Zeroizing<String>>,
    ) -> Result<Vec<u8>, FetchAssetError> {
        self.fetch_inner(circle_id, path, |_| Some(passphrase.clone()))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::chain::{
        cache::{AssetCache, CachedAsset},
        tests_common::{
            build_sealed_fixture, chain_with_cache, plaintext_payload, sealed_payload,
            spawn_counting_rpc, spawn_mock_rpc,
        },
    };
    use crate::portal::mime::sniff;
    use octravpn_core::{bounded::BoundedMap, rpc::RpcClient};
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn try_decrypt_with_passphrase_bypasses_cache() {
        // The unseal flow uses `try_decrypt_with_passphrase`, which
        // must NEVER serve from cache — serving a previously-cached
        // plaintext would let a wrong passphrase validate successfully.
        use std::sync::atomic::Ordering;
        let plaintext = b"unseal bypass bytes";
        let (ct_b64, ph_hex) = build_sealed_fixture("circBYPASS", "default", "right-pp", plaintext);
        let (addr, count) = spawn_counting_rpc(sealed_payload(&ct_b64, &ph_hex)).await;
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

    #[tokio::test]
    async fn try_decrypt_with_wrong_passphrase_returns_decrypt_failed() {
        let plaintext = b"unseal test";
        let (ct_b64, ph_hex) = build_sealed_fixture("circWP", "default", "right-pp", plaintext);
        let addr = spawn_mock_rpc(sealed_payload(&ct_b64, &ph_hex)).await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let pp = Arc::new(Zeroizing::new("wrong-pp".to_string()));
        let err = chain
            .try_decrypt_with_passphrase("circWP", "/x.json", pp)
            .await
            .expect_err("wrong pp must fail");
        assert!(matches!(err, FetchAssetError::DecryptFailed { .. }));
    }

    #[tokio::test]
    async fn try_decrypt_does_not_populate_cache() {
        use std::sync::atomic::Ordering;
        let plaintext = b"do not cache me";
        let (ct_b64, ph_hex) = build_sealed_fixture("circNOC", "default", "pp", plaintext);
        let (addr, count) = spawn_counting_rpc(sealed_payload(&ct_b64, &ph_hex)).await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(16, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));
        let pp = Arc::new(Zeroizing::new("pp".to_string()));
        // First call via try_decrypt: should not insert into cache.
        let _ = chain
            .try_decrypt_with_passphrase("circNOC", "/x.json", Arc::clone(&pp))
            .await
            .unwrap();
        assert_eq!(cache.len(), 0, "try_decrypt must not populate cache");
        // Second call also re-roundtrips.
        let before = count.load(Ordering::SeqCst);
        let _ = chain
            .try_decrypt_with_passphrase("circNOC", "/x.json", pp)
            .await
            .unwrap();
        assert!(count.load(Ordering::SeqCst) > before);
    }

    #[tokio::test]
    async fn try_decrypt_on_not_published_returns_not_published() {
        let addr = spawn_mock_rpc(serde_json::Value::Null).await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let pp = Arc::new(Zeroizing::new("pp".to_string()));
        let err = chain
            .try_decrypt_with_passphrase("circDEC_NP", "/missing.json", pp)
            .await
            .expect_err("null result must be NotPublished");
        assert!(matches!(err, FetchAssetError::NotPublished { .. }));
    }

    #[tokio::test]
    async fn try_decrypt_on_plaintext_passthrough_returns_bytes() {
        // Non-sealed bytes: the OCRS1 sniff says "not sealed" so we
        // return the bytes verbatim regardless of the supplied
        // passphrase.
        let plain = b"plain bytes, no sealing";
        let addr = spawn_mock_rpc(plaintext_payload(plain)).await;
        let rpc = RpcClient::new(format!("http://{addr}/"));
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let pp = Arc::new(Zeroizing::new("ignored".to_string()));
        let got = chain
            .try_decrypt_with_passphrase("circDEC_PLAIN", "/x.json", pp)
            .await
            .unwrap();
        assert_eq!(got, plain);
    }

    #[tokio::test]
    async fn try_decrypt_correct_pp_works_even_with_stale_cache() {
        // Pre-populate the cache with bogus bytes under the same key.
        // try_decrypt must ignore the cache and re-fetch.
        let plaintext = b"freshly decrypted";
        let (ct_b64, ph_hex) = build_sealed_fixture("circSTALE", "default", "good-pp", plaintext);
        let addr = spawn_mock_rpc(sealed_payload(&ct_b64, &ph_hex)).await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(16, Duration::from_secs(60)));
        let stale = CachedAsset {
            bytes: Arc::new(b"STALE BYTES".to_vec()),
            mime: sniff(b"STALE BYTES"),
            fetched_at: Instant::now(),
        };
        cache.insert(("circSTALE".to_string(), "/x.json".to_string()), stale);
        let chain = chain_with_cache(addr, Arc::clone(&cache));
        let pp = Arc::new(Zeroizing::new("good-pp".to_string()));
        let got = chain
            .try_decrypt_with_passphrase("circSTALE", "/x.json", pp)
            .await
            .unwrap();
        assert_eq!(got, plaintext, "must NOT return cached stale bytes");
    }
}
