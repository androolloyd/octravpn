//! Cache-aware portal API surface.
//!
//! `portal::routes` calls these to render the `oct://` browser portal:
//! a single fetch + decrypt + sniff shape parameterised on a
//! [`PassphraseSource`] so the portal can consult its per-circle
//! unseal cache while CLI callers use a boot-time configured
//! passphrase.
//!
//! All three entry points go through `fetch_cached`, so they share the
//! same LRU + TTL layer. The cache-bypass unseal path lives in
//! [`super::decrypt`].

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::portal::chain::{cache::CachedAsset, errors::FetchAssetError, PortalChain};

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

impl PortalChain {
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

    /// Cache-aware variant of [`Self::fetch_with_source`] that returns the
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_passphrase_source_returns_configured_value() {
        let pp = Arc::new(Zeroizing::new("my-secret".to_string()));
        let src = ConfigPassphrase::new(Some(Arc::clone(&pp)));
        let got = src.passphrase_for("any-circle").unwrap();
        assert_eq!(got.as_str(), "my-secret");
        // Different circle id → same value (circle-agnostic source).
        let got2 = src.passphrase_for("other-circle").unwrap();
        assert_eq!(got2.as_str(), "my-secret");
    }

    #[test]
    fn config_passphrase_source_returns_none_when_unset() {
        let src = ConfigPassphrase::new(None);
        assert!(src.passphrase_for("anything").is_none());
    }

    #[test]
    fn has_passphrase_toggles_with_with_passphrase() {
        use octravpn_core::rpc::RpcClient;
        let rpc = RpcClient::new("http://127.0.0.1:1");
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        assert!(!chain.has_passphrase());
        let chain2 = chain.with_passphrase("hi");
        assert!(chain2.has_passphrase());
        assert!(chain2.configured_passphrase().is_some());
    }
}
