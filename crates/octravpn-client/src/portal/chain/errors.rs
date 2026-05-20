//! Structured error type for the portal asset-fetch pipeline.
//!
//! [`FetchAssetError`] is returned from every `PortalChain::fetch_*` /
//! `try_decrypt_with_passphrase`. The route layer matches on variants
//! to choose status codes: `Rpc` → 502, `MissingPassphrase` /
//! `DecryptFailed` → 412 (passphrase-config page).
//!
//! Privacy invariant: variants must never embed the passphrase or
//! ciphertext in their Display strings — the underlying decrypt error
//! is discarded at the boundary. Tests enforce the no-leak property.

use thiserror::Error;

/// Structured error returned from [`super::PortalChain::fetch_circle_asset_bytes`].
///
/// Distinguishing the variants matters at the route layer: a generic
/// transport failure renders the existing "tunnel down" 502 page, while
/// the two decrypt-related variants render a dedicated 412 with
/// passphrase-configuration guidance.
#[derive(Debug, Error)]
#[non_exhaustive]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_asset_error_accessors_carry_circle_and_path() {
        let e = FetchAssetError::NotPublished {
            circle_id: "circA".into(),
            path: "/policy".into(),
            resource_key: "rk".into(),
        };
        assert_eq!(e.circle_id(), "circA");
        assert_eq!(e.path(), "/policy");
        let e = FetchAssetError::MissingPassphrase {
            circle_id: "circB".into(),
            path: "/p2".into(),
        };
        assert_eq!(e.circle_id(), "circB");
        assert_eq!(e.path(), "/p2");
        let e = FetchAssetError::DecryptFailed {
            circle_id: "circC".into(),
            path: "/p3".into(),
        };
        assert_eq!(e.circle_id(), "circC");
        assert_eq!(e.path(), "/p3");
        let e = FetchAssetError::Rpc {
            circle_id: "circD".into(),
            path: "/p4".into(),
            source: anyhow::anyhow!("boom"),
        };
        assert_eq!(e.circle_id(), "circD");
        assert_eq!(e.path(), "/p4");
    }

    #[test]
    fn fetch_asset_error_display_does_not_leak_passphrase() {
        // No passphrase ever flows into FetchAssetError construction;
        // double-check the Display strings.
        let e = FetchAssetError::DecryptFailed {
            circle_id: "circD".into(),
            path: "/p".into(),
        };
        let s = e.to_string();
        assert!(!s.contains("passphrase=") && !s.to_lowercase().contains("secret"));
    }
}
