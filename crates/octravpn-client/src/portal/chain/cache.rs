//! Bounded LRU + TTL plaintext-asset cache for the portal chain layer.
//!
//! Keys are `(circle_id, canonical_path)`; values are decrypted bytes
//! plus the sniffed MIME so cache hits skip both the RPC roundtrip and
//! the MIME re-sniff. `Arc<BoundedMap>` upstream gives every clone the
//! same backing map.
//!
//! `canonical_path()` collapses `policy.json` and `/policy.json` to
//! the same key so the cache and resource_key derivation agree.
//!
//! Cache-bypass invariant lives in `decrypt.rs`: the unseal path MUST
//! always bypass this cache, otherwise a stale entry could
//! false-positive a wrong-passphrase submission.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use octravpn_core::bounded::BoundedMap;

use crate::portal::mime::SniffedMime;

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

/// Sealed-asset envelope magic prefix. Must match `octra-core::circle`.
/// Duplicated here as a small constant rather than re-exported so this
/// module stays self-contained for the magic sniff.
pub(super) const SEALED_MAGIC: &[u8; 5] = b"OCRS1";

/// Detect the OCRS1 sealed-envelope magic on raw envelope bytes (post
/// base64-decode).
pub(super) fn looks_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= SEALED_MAGIC.len() && &bytes[..SEALED_MAGIC.len()] == SEALED_MAGIC
}

/// Normalize the path so the resource_key derivation matches the
/// canonical webcli definition. The webcli convention is: leading slash,
/// no `.`/`..`, no trailing slash (except root). We don't try to be
/// clever — the only guarantee we make is that bare `policy.json` and
/// `/policy.json` produce the same resource_key.
pub(super) fn canonical_path(p: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::chain::tests_common::{
        chain_with_cache, plaintext_payload, spawn_counting_rpc, spawn_mock_rpc,
    };
    use crate::portal::chain::PortalChain;
    use octravpn_core::rpc::RpcClient;

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

    #[tokio::test]
    async fn cache_hit_returns_same_bytes_without_rpc_call() {
        use std::sync::atomic::Ordering;
        let plaintext = b"plaintext for cache hit";
        let (addr, count) = spawn_counting_rpc(plaintext_payload(plaintext)).await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(16, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));

        // First call: miss → one RPC roundtrip.
        let got1 = chain
            .fetch_circle_asset_bytes("circHIT", "/policy.json")
            .await
            .unwrap();
        assert_eq!(got1, plaintext);
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Second + third call: hit → counter stays at 1.
        let got2 = chain
            .fetch_circle_asset_bytes("circHIT", "/policy.json")
            .await
            .unwrap();
        let got3 = chain
            .fetch_circle_asset_bytes("circHIT", "/policy.json")
            .await
            .unwrap();
        assert_eq!(got2, plaintext);
        assert_eq!(got3, plaintext);
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "cache hits must not generate new RPC calls"
        );
    }

    #[tokio::test]
    async fn cache_ttl_expiry_forces_refetch() {
        use std::sync::atomic::Ordering;
        let plaintext = b"ttl-expiry bytes";
        let (addr, count) = spawn_counting_rpc(plaintext_payload(plaintext)).await;
        // Short TTL so the test isn't slow. `BoundedMap::sweep` is what
        // implements eviction — `get` itself doesn't lazily expire, so
        // we drive sweep explicitly to model a periodic sweep task.
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(16, Duration::from_millis(20)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));

        chain
            .fetch_circle_asset_bytes("circTTL", "/policy.json")
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Wait past TTL + sweep → entry is gone.
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(cache.sweep(), 1, "ttl sweep should evict the stale entry");

        // Next fetch must hit the RPC again.
        chain
            .fetch_circle_asset_bytes("circTTL", "/policy.json")
            .await
            .unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "post-eviction fetch must re-roundtrip"
        );
    }

    #[tokio::test]
    async fn cache_bounded_capacity_evicts_oldest() {
        use std::sync::atomic::Ordering;
        let plaintext = b"capacity test bytes";
        let (addr, count) = spawn_counting_rpc(plaintext_payload(plaintext)).await;
        // Cap = 2; insert 3 distinct keys → the first is evicted.
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(2, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));

        for p in ["/a.json", "/b.json", "/c.json"] {
            chain.fetch_circle_asset_bytes("circCAP", p).await.unwrap();
        }
        assert_eq!(
            count.load(Ordering::SeqCst),
            3,
            "three distinct keys, three RPCs"
        );
        assert_eq!(cache.len(), 2, "capacity must cap at 2");

        // /a.json was the oldest; refetching must miss + roundtrip.
        // After this insert, the cache holds /c.json + /a.json (the
        // re-insert of /a.json evicted /b.json — the new oldest).
        chain
            .fetch_circle_asset_bytes("circCAP", "/a.json")
            .await
            .unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            4,
            "evicted oldest entry re-fetches"
        );

        // /c.json was still cached → no new roundtrip.
        chain
            .fetch_circle_asset_bytes("circCAP", "/c.json")
            .await
            .unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            4,
            "/c.json was still in cache; no new RPC"
        );
    }

    #[tokio::test]
    async fn cache_key_isolates_circles_and_paths() {
        use std::sync::atomic::Ordering;
        let plaintext = b"isolation test bytes";
        let (addr, count) = spawn_counting_rpc(plaintext_payload(plaintext)).await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(16, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));

        // Different circles, same path → distinct keys → two RPCs.
        chain
            .fetch_circle_asset_bytes("circA", "/policy.json")
            .await
            .unwrap();
        chain
            .fetch_circle_asset_bytes("circB", "/policy.json")
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2, "circle id isolates cache");

        // Same circle, different paths → distinct keys → two more RPCs.
        chain
            .fetch_circle_asset_bytes("circA", "/state-root.json")
            .await
            .unwrap();
        chain
            .fetch_circle_asset_bytes("circA", "/members.json")
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 4, "path isolates cache");

        // Canonical-path collapse: `policy.json` and `/policy.json`
        // share a key, so the second hits the cache.
        chain
            .fetch_circle_asset_bytes("circA", "policy.json")
            .await
            .unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            4,
            "canonical path collapses leading-slash variants to the same entry"
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
        let (addr, count) = spawn_counting_rpc(plaintext_payload(plaintext)).await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(16, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));

        // Warm up the cache (single fetch).
        chain
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
            assert_eq!(h.await.unwrap(), plaintext);
        }
        assert_eq!(
            count.load(Ordering::SeqCst),
            baseline,
            "warm-cache concurrent reads must not generate new RPCs"
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

        use crate::portal::chain::FetchAssetError;
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
            "failed fetches must not be cached"
        );
        assert_eq!(cache.len(), 0, "cache stays empty when fetches fail");
    }

    #[tokio::test]
    async fn cache_257_distinct_entries_evicts_first() {
        // Stress the cap-256 behaviour: 257 distinct keys → only 256 stay.
        use std::sync::atomic::Ordering;
        let plain = b"X";
        let (addr, count) = spawn_counting_rpc(plaintext_payload(plain)).await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(
            DEFAULT_ASSET_CACHE_CAPACITY,
            Duration::from_secs(60),
        ));
        let chain = chain_with_cache(addr, Arc::clone(&cache));
        for i in 0..257 {
            let path = format!("/asset-{i}.bin");
            chain
                .fetch_circle_asset_bytes("circ257", &path)
                .await
                .unwrap();
        }
        assert_eq!(count.load(Ordering::SeqCst), 257);
        assert_eq!(
            cache.len(),
            DEFAULT_ASSET_CACHE_CAPACITY,
            "cache must clip to its capacity",
        );
        // The very first key was evicted.
        assert!(
            cache
                .get(&("circ257".to_string(), "/asset-0.bin".to_string()))
                .is_none(),
            "asset-0 must have been evicted as the oldest"
        );
    }

    #[tokio::test]
    async fn cache_concurrent_writers_and_readers_do_not_panic() {
        // 100 readers + 10 writers fanning over a few keys. Ensures
        // BoundedMap's internal locks are correct under fan-out.
        let plain = b"concurrent";
        let (addr, _count) = spawn_counting_rpc(plaintext_payload(plain)).await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(32, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));
        // Pre-warm a few keys so reader hits aren't all misses.
        for i in 0..4 {
            chain
                .fetch_circle_asset_bytes("circCONC", &format!("/p{i}.bin"))
                .await
                .unwrap();
        }
        let mut handles = Vec::new();
        // 100 readers over the warm keys.
        for i in 0..100 {
            let c = chain.clone();
            let path = format!("/p{}.bin", i % 4);
            handles.push(tokio::spawn(async move {
                c.fetch_circle_asset_bytes("circCONC", &path).await
            }));
        }
        // 10 writers under fresh keys (forces inserts + possible eviction).
        for i in 0..10 {
            let c = chain.clone();
            let path = format!("/w-{i}.bin");
            handles.push(tokio::spawn(async move {
                c.fetch_circle_asset_bytes("circCONC", &path).await
            }));
        }
        for h in handles {
            let r = h.await.expect("task panicked");
            r.expect("fetch failed in concurrent test");
        }
        // Cap is enforced.
        assert!(cache.len() <= 32);
    }

    #[tokio::test]
    async fn cache_hit_preserves_sniffed_mime_through_repeated_reads() {
        // Hits should carry the same SniffedMime as the first miss.
        // The PNG magic prefix is rare in JSON payloads, so this is a
        // good cross-check.
        let png = b"\x89PNG\r\n\x1a\nIHDR-rest-of-bytes";
        let addr = spawn_mock_rpc(plaintext_payload(png)).await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(8, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));
        let pp_src = crate::portal::chain::ConfigPassphrase::new(None);
        let a = chain
            .fetch_with_source_sniffed("circPNG", "/img.png", &pp_src)
            .await
            .unwrap();
        let b = chain
            .fetch_with_source_sniffed("circPNG", "/img.png", &pp_src)
            .await
            .unwrap();
        assert_eq!(a.mime, b.mime);
        assert_eq!(a.mime, SniffedMime::Png);
    }

    #[tokio::test]
    async fn cache_two_circles_same_path_isolated() {
        // Confirm that the (circle, path) tuple isolates entries.
        use std::sync::atomic::Ordering;
        let plain = b"X";
        let (addr, count) = spawn_counting_rpc(plaintext_payload(plain)).await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(8, Duration::from_secs(60)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));
        chain
            .fetch_circle_asset_bytes("circLEFT", "/p.bin")
            .await
            .unwrap();
        chain
            .fetch_circle_asset_bytes("circRIGHT", "/p.bin")
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert_eq!(cache.len(), 2);
    }

    #[tokio::test]
    async fn cache_does_not_serve_after_ttl_sweep() {
        // Stronger variant of the existing ttl_expiry test — asserts
        // that a `get` after `sweep` returns None.
        let plain = b"ttl-via-sweep";
        let addr = spawn_mock_rpc(plaintext_payload(plain)).await;
        let cache: Arc<AssetCache> = Arc::new(BoundedMap::new(8, Duration::from_millis(15)));
        let chain = chain_with_cache(addr, Arc::clone(&cache));
        chain
            .fetch_circle_asset_bytes("circTTL2", "/p.bin")
            .await
            .unwrap();
        assert_eq!(cache.len(), 1);
        tokio::time::sleep(Duration::from_millis(40)).await;
        let evicted = cache.sweep();
        assert!(evicted >= 1);
        assert!(
            cache
                .get(&("circTTL2".to_string(), "/p.bin".to_string()))
                .is_none(),
            "post-sweep get must miss"
        );
    }

    #[test]
    fn canonical_path_strips_only_first_redundant_slash() {
        // `//foo` → `/foo` (collapses), `/foo/` retained, `////` → `/`.
        assert_eq!(canonical_path("/foo"), "/foo");
        assert_eq!(canonical_path("//foo"), "/foo");
        assert_eq!(canonical_path("///foo"), "/foo");
        assert_eq!(canonical_path("//"), "/");
    }

    #[test]
    fn canonical_path_preserves_trailing_slash() {
        // We don't strip trailing slashes; the resource_key derivation
        // is exact-match.
        assert_eq!(canonical_path("/foo/"), "/foo/");
        assert_eq!(canonical_path("foo/"), "/foo/");
    }

    #[test]
    fn canonical_path_trims_whitespace() {
        assert_eq!(canonical_path("  /foo  "), "/foo");
        assert_eq!(canonical_path("\t/foo\n"), "/foo");
    }

    #[test]
    fn looks_sealed_exact_magic_match() {
        assert!(looks_sealed(b"OCRS1"));
        assert!(looks_sealed(b"OCRS1\xff\xff\xff"));
    }

    #[test]
    fn looks_sealed_rejects_partial_magic() {
        assert!(!looks_sealed(b"OCRS")); // too short
        assert!(!looks_sealed(b"OCR")); // way too short
        assert!(!looks_sealed(b"ocrs1")); // case-sensitive
    }

    #[test]
    fn portal_chain_with_asset_cache_returns_arc() {
        let rpc = RpcClient::new("http://127.0.0.1:1");
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let cache = chain.asset_cache();
        assert!(Arc::strong_count(&cache) >= 2);
    }
}
