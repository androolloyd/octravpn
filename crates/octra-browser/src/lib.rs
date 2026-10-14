//! Browser services consume a fixed read capability. An optional application
//! host receives allowlisted reads and explicitly reviewed transaction intents.
//! Wallet loading, chain execution and signing remain host responsibilities.
pub mod url;
pub mod render;
pub mod http;
pub mod application;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
pub use url::OctUrl;

pub const MAX_ASSET_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotIdentity {
    pub chain_id: String,
    pub genesis_root: String,
    pub epoch: u64,
    pub state_root: String,
    pub ledger_root: String,
    pub irmin_commit: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    Canonical(SnapshotIdentity),
    /// An RPC response without a verified immutable read cursor.
    UnpinnedRpc,
}
impl Provenance {
    pub fn id(&self) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(serde_json::to_vec(self).expect("provenance serialization")))
    }
}

#[derive(Clone, Debug)]
pub struct Asset {
    pub bytes: Arc<[u8]>,
    pub content_type: String,
    pub provenance: Provenance,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error("Circle asset is not published")]
    NotFound,
    #[error("Circle requires local approval")]
    ApprovalRequired { approval_url: String },
    #[error("Circle asset requires an authorized decryption capability")]
    Sealed,
    #[error("asset exceeds browser resource limit")]
    TooLarge,
    #[error("resolver returned a different snapshot")]
    SnapshotChanged,
    #[error("Circle asset resolution failed: {0}")]
    Unavailable(String),
}

/// A resolver instance is bound to one immutable snapshot, or explicitly reports
/// unpinned RPC provenance. A server never replaces this capability in place.
/// The HTTP viewer currently serves published public assets. A private resolver
/// requires a separate request authorization boundary before being mounted there.
#[async_trait]
pub trait AssetResolver: Send + Sync {
    fn provenance(&self) -> Provenance;
    async fn resolve(&self, url: &OctUrl) -> Result<Asset, Error>;
}
