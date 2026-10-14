//! Circle reads from an immutable committed tree. Native storage decoding is
//! separate from the browser's bounded, public-resource serving policy.
use crate::{canonical::CanonicalStore, circle_view, state_batch::Snapshot};
use async_trait::async_trait;
use octra_browser::{
    Asset, AssetResolver, Error, OctUrl, Provenance, SnapshotIdentity, MAX_ASSET_BYTES,
};
use octra_node_protocol::{
    circles::{
        self, policy_bool, policy_integer, AssetMeta, AssetPolicy, Error as StoreError,
        LocatorMode, MetadataMode, ResourceMode,
    },
    native_integer::parse_int64,
    native_json::{Document, Value},
    transaction::decode_base64,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub struct StoredAsset<'a> {
    pub canonical_path: String,
    pub path_key: String,
    pub browser_mode: &'a [u8],
    pub resource_mode: &'a [u8],
    pub meta: AssetMeta,
    pub body_b64: &'a [u8],
}
/// Equivalent to Store_irmin.get_circle_public_asset_at. This is a storage
/// primitive; callers must enforce their own disclosure and execution policy.
pub fn public_asset<'a>(
    state: &'a Snapshot,
    circle: &[u8],
    path: &[u8],
    max_bytes: i64,
) -> Result<StoredAsset<'a>, StoreError> {
    let missing = || StoreError("circle asset missing".into());
    if max_bytes < 0 {
        return Err(StoreError("circle asset size exceeds limit".into()));
    }
    let canonical_path = circles::normalize_path(path)?;
    let path_key = circles::path_key(canonical_path.as_bytes());
    let browser_mode = state
        .get(&[b"circles", circle, b"browser", b"mode"])
        .ok_or_else(missing)?;
    let resource_mode = state
        .get(&[b"circles", circle, b"resources", b"mode"])
        .ok_or_else(missing)?;
    let get = |name| {
        state.get(&[
            b"circles",
            circle,
            b"assets",
            b"by_hash",
            path_key.as_bytes(),
            name,
        ])
    };
    let meta = AssetMeta::parse(get(b"meta").ok_or_else(missing)?)?;
    if meta.size_bytes < 0 || meta.size_bytes > max_bytes {
        return Err(StoreError("circle asset size exceeds limit".into()));
    }
    if meta.path_key != path_key.as_bytes() || meta.canonical_path != canonical_path.as_bytes() {
        return Err(StoreError("circle asset metadata differs".into()));
    }
    let body_b64 = get(b"body_b64").ok_or_else(missing)?;
    Ok(StoredAsset {
        canonical_path,
        path_key,
        browser_mode,
        resource_mode,
        meta,
        body_b64,
    })
}

#[derive(Clone)]
pub struct CanonicalAssets {
    state: Snapshot,
    identity: SnapshotIdentity,
}
impl CanonicalAssets {
    /// Immutable state captured with this published browser identity.
    pub fn snapshot(&self) -> &Snapshot {
        &self.state
    }

    pub fn identity(&self) -> &SnapshotIdentity {
        &self.identity
    }

    /// Capture only the published head. Speculative snapshots cannot acquire
    /// canonical browser provenance through this API.
    pub async fn capture(store: &CanonicalStore) -> Result<Self, Error> {
        let (head, state) = store.snapshot().await.map_err(unavailable)?;
        if state.get(&[b"meta", b"last_epoch"]).and_then(parse_int64)
            != i64::try_from(head.cursor.epoch.0).ok()
        {
            return Err(Error::Unavailable(
                "committed Circle snapshot epoch differs".into(),
            ));
        }
        Ok(Self {
            state: state.snapshot(),
            identity: SnapshotIdentity {
                chain_id: store.chain().chain_id.clone(),
                genesis_root: hex::encode(store.chain().genesis_root.0),
                epoch: head.cursor.epoch.0,
                state_root: hex::encode(head.cursor.state_root.0),
                ledger_root: head.ledger_root,
                irmin_commit: head.irmin_commit,
            },
        })
    }

    fn read(&self, url: &OctUrl) -> Result<Asset, Error> {
        let circle = url.circle_id.as_bytes();
        let key = circles::path_key(url.path.as_bytes());
        // Limit metadata before allocating the native JSON arena. This is a
        // browser resource limit, not a change to native storage semantics.
        if self
            .state
            .get(&[
                b"circles",
                circle,
                b"assets",
                b"by_hash",
                key.as_bytes(),
                b"meta",
            ])
            .is_some_and(|raw| raw.len() > 64 * 1024)
        {
            return Err(Error::TooLarge);
        }
        // OctUrl already decoded once; encode it before the native raw-path API.
        let raw_path = octra_browser::url::encode_path(&url.path);
        let asset = public_asset(
            &self.state,
            circle,
            raw_path.as_bytes(),
            MAX_ASSET_BYTES as i64,
        )
        .map_err(|e| match e.0.as_slice() {
            b"circle asset missing" => Error::NotFound,
            b"circle asset size exceeds limit" => Error::TooLarge,
            _ => unavailable(e),
        })?;
        if asset.browser_mode != b"gateway_allowed"
            || asset.resource_mode != b"public_resources"
            || asset.meta.body_mode != ResourceMode::Public
            || asset.meta.locator_mode != LocatorMode::Path
            || asset.meta.metadata_mode != MetadataMode::Reveal
            || asset.meta.key_id.is_some()
        {
            return Err(Error::Sealed);
        }
        if !self.visible(circle, &asset.meta)? {
            return Err(Error::NotFound);
        }
        if asset.meta.encoding != b"identity" {
            return Err(Error::Invalid("unsupported Circle asset encoding".into()));
        }
        // Reject inflated encodings before Base64 allocates a decoded body.
        let size = usize::try_from(asset.meta.size_bytes).map_err(|_| Error::TooLarge)?;
        if asset.body_b64.len() > size.div_ceil(3) * 4 {
            return Err(Error::TooLarge);
        }
        let bytes = decode_base64(asset.body_b64)
            .map_err(|_| Error::Invalid("invalid Circle asset body encoding".into()))?;
        if bytes.len() != size
            || hex::encode(Sha256::digest(&bytes)).as_bytes() != asset.meta.blob_hash
        {
            return Err(Error::Invalid("Circle asset body binding mismatch".into()));
        }
        let content_type = std::str::from_utf8(&asset.meta.content_type)
            .map_err(|_| Error::Invalid("invalid Circle asset content type".into()))?
            .to_owned();
        Ok(Asset {
            bytes: Arc::from(bytes),
            content_type,
            provenance: self.provenance(),
        })
    }

    fn visible(&self, circle: &[u8], meta: &AssetMeta) -> Result<bool, Error> {
        let key = String::from_utf8_lossy(&meta.path_key);
        let read = |suffix| {
            self.policy(
                circle,
                &format!("slot_policy:{key}:{suffix}"),
                &format!("mailbox:{key}:{suffix}"),
            )
        };
        let policy = AssetPolicy {
            activate_after_epoch: read("activate_after_epoch")?
                .as_deref()
                .and_then(policy_integer),
            expire_after_epoch: read("expire_after_epoch")?
                .as_deref()
                .and_then(policy_integer),
            tombstone: read("tombstone")?.as_deref().is_some_and(policy_bool),
            revoked: read("revoked")?.as_deref().is_some_and(policy_bool),
        };
        let epoch = circle_view::epoch(
            self.state.get(&[b"meta", b"last_epoch"]),
            circle_view::ReadKind::Policy,
        )
        .map_err(unavailable)?;
        Ok(policy.visible_at(epoch, meta))
    }

    fn policy(&self, circle: &[u8], first: &str, legacy: &str) -> Result<Option<Vec<u8>>, Error> {
        for key in [first, legacy] {
            let hash = circles::stable_key(key.as_bytes());
            let Some(raw) =
                self.state
                    .get(&[b"circles", circle, b"stable", b"by_hash", hash.as_bytes()])
            else {
                continue;
            };
            if raw.len() > 64 * 1024 {
                return Err(Error::TooLarge);
            }
            let doc = Document::parse(raw).map_err(unavailable)?;
            let string = |object, name| match doc.field(object, name) {
                Some(Value::String(v)) => Some(v.as_slice()),
                _ => None,
            };
            let Some(raw_key) = string(doc.root(), b"raw_key") else {
                continue;
            };
            if string(doc.root(), b"key_hash").is_none() {
                continue;
            }
            let Some(value) = doc.field(doc.root(), b"value") else {
                continue;
            };
            match string(value, b"value_kind") {
                Some(b"inline") if raw_key == key.as_bytes() => {
                    if let Some(value) = string(value, b"value_inline") {
                        return Ok(Some(value.to_vec()));
                    }
                }
                Some(b"blob_ref")
                    if string(value, b"value_blob_hash").is_some()
                        && string(value, b"value_size")
                            .is_some_and(|size| parse_int64(size).is_none()) =>
                {
                    return Err(Error::Unavailable(
                        "Circle policy blob size is invalid".into(),
                    ));
                }
                _ => (),
            }
        }
        Ok(None)
    }
}
fn unavailable(error: impl std::fmt::Display) -> Error {
    Error::Unavailable(error.to_string())
}
#[async_trait]
impl AssetResolver for CanonicalAssets {
    fn provenance(&self) -> Provenance {
        Provenance::Canonical(self.identity.clone())
    }
    async fn resolve(&self, url: &OctUrl) -> Result<Asset, Error> {
        self.read(url)
    }
}
