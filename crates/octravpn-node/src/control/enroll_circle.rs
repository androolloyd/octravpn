//! Circle-backed enrollment storage.
//!
//! Two layers:
//! - [`CircleStore`] — circle-asset access shared by enrollment: the
//!   on-chain `state-root` anchor, sealed read/write, and the admission
//!   **allowlist**. It carries no `ip_salt`, so the operator allowlist CLI
//!   (`octravpn-node auth`) builds one directly without fabricating a
//!   member-set salt it never uses.
//! - [`CircleEnrollStore`] — a [`CircleStore`] plus the member-set salt;
//!   the production [`EnrollStore`]. It reads the allowlist + member set
//!   under a **single** anchor fetch ([`CircleEnrollStore::load_enroll_state`]).
//!
//! Both halves of the private-mesh membership live in the operator's
//! circle, each sealed + anchored under its own `circle_state_root` slot,
//! so every operator node reads the same record and any edit is
//! tamper-evident:
//!
//! | asset                | anchor slot         | role                              |
//! |----------------------|---------------------|-----------------------------------|
//! | `/auth/allowed.json` | `auth_allowed_hash` | who *may* enroll (admission gate) |
//! | `/auth/members.json` | `auth_members_hash` | who *has* (devices + WG keys)     |
//!
//! Reads verify the sealed ciphertext against the on-chain anchor (so a
//! tampered blob fails closed); writes re-seal the asset and flip the
//! anchor in one `circle_update::apply` two-step. This is the private-mesh
//! path only — the public **paid-exit** flow is gated by `open_session`
//! escrow, never by this allowlist.
//!
//! Precondition: the operator circle must already be registered
//! (`register_circle`) so it has a `state-root.json` anchor; enrollment
//! rotations build on it. A circle with no anchor yet surfaces a clear
//! "register first" error from `apply`. The full RPC round-trip is
//! exercised by the stage-5 integration test against `octra-mock-rpc`.

use std::sync::Arc;

use async_trait::async_trait;
use octravpn_core::{circle::PaddingClass, v3_members::TailnetMembers, v3_state_root::StateRoot};

use super::enroll::{AllowList, EnrollError, EnrollState, EnrollStore};
use crate::chain_v3::ChainCtxV3;
use crate::circle_update::{
    self, AnchorOverrides, BlobUpdate, SealedAssetCreds, SealedRead, UpdateBundle,
};

/// Sealed, anchored asset holding the enrolled member set (`TailnetMembers`).
const MEMBERS_PATH: &str = "/auth/members.json";
/// Sealed, anchored asset holding the admission allowlist (`AllowList`).
const ALLOWED_PATH: &str = "/auth/allowed.json";
/// Sealed-asset key id — matches the operator circle's default key.
const KEY_ID: &str = "default";
/// Pad sealed blobs to 16 KiB so observers can't read the member /
/// allowlist size off the on-chain ciphertext length.
const PADDING: PaddingClass = PaddingClass::K16;

/// Circle-asset access common to enrollment: `state-root` anchor + sealed
/// read/write + the admission allowlist. No `ip_salt` — see module docs.
pub(crate) struct CircleStore {
    ctx: Arc<ChainCtxV3>,
    creds: SealedAssetCreds,
    circle_id: String,
}

impl CircleStore {
    pub(crate) fn new(
        ctx: Arc<ChainCtxV3>,
        creds: SealedAssetCreds,
        circle_id: impl Into<String>,
    ) -> Self {
        Self {
            ctx,
            creds,
            circle_id: circle_id.into(),
        }
    }

    /// Current on-chain anchor decoded back into a `StateRoot`, or `None`
    /// if the circle has no anchor yet.
    async fn current_state_root(&self) -> Result<Option<StateRoot>, EnrollError> {
        circle_update::fetch_current_state_root(&self.ctx, &self.circle_id)
            .await
            .map_err(|e| EnrollError::Store(e.to_string()))
    }

    /// Fetch + decrypt a sealed asset, verifying its plaintext against the
    /// `expected_hash`. `Ok(None)` when absent; a hash/decrypt mismatch is
    /// a hard `Store` error — fail closed.
    async fn load_sealed(
        &self,
        path: &str,
        expected_hash: &str,
    ) -> Result<Option<Vec<u8>>, EnrollError> {
        match circle_update::read_sealed_asset(
            &self.ctx,
            &self.circle_id,
            path,
            KEY_ID,
            &self.creds,
            expected_hash,
        )
        .await
        .map_err(|e| EnrollError::Store(e.to_string()))?
        {
            SealedRead::Valid(bytes) => Ok(Some(bytes)),
            SealedRead::Absent => Ok(None),
            SealedRead::Corrupt => Err(EnrollError::Store(format!(
                "sealed asset {path} failed hash/decrypt verification"
            ))),
        }
    }

    /// Seal `plaintext` under `path` and flip the bound anchor slot in one
    /// `apply` two-step. Returns the new `circle_state_version`.
    async fn commit_sealed(&self, path: &str, plaintext: Vec<u8>) -> Result<u64, EnrollError> {
        let blob = BlobUpdate {
            asset_path: path.to_string(),
            plaintext: zeroize::Zeroizing::new(plaintext),
            key_id: KEY_ID.to_string(),
            padding_class: PADDING,
        };
        let bundle = UpdateBundle {
            circle_id: self.circle_id.clone(),
            blobs: vec![blob],
            anchor_overrides: AnchorOverrides::default(),
        };
        circle_update::apply(&self.ctx, &self.creds, bundle)
            .await
            .map_err(|e| EnrollError::Store(e.to_string()))?;
        self.ctx
            .get_circle_state_version(&self.circle_id)
            .await
            .map_err(|e| EnrollError::Store(e.to_string()))
    }

    /// Decode the allowlist from an already-fetched anchor (no extra
    /// round-trip). Empty — **default-deny** — when no `auth_allowed_hash`
    /// is anchored yet.
    async fn load_allowlist_at(&self, sr: Option<&StateRoot>) -> Result<AllowList, EnrollError> {
        let Some(expected) = sr.and_then(|s| s.auth_allowed_hash.as_deref()) else {
            return Ok(AllowList::default());
        };
        let Some(plain) = self.load_sealed(ALLOWED_PATH, expected).await? else {
            return Ok(AllowList::default());
        };
        serde_json::from_slice(&plain)
            .map_err(|e| EnrollError::Store(format!("decode allowed.json: {e}")))
    }

    /// Load the admission allowlist (fetches the anchor). Operator-CLI
    /// facing (`octravpn-node auth list/allow/revoke`).
    pub(crate) async fn load_allowlist(&self) -> Result<AllowList, EnrollError> {
        let sr = self.current_state_root().await?;
        self.load_allowlist_at(sr.as_ref()).await
    }

    /// Seal + anchor a new admission allowlist. Used by the operator CLI,
    /// not the enrollment hot path.
    pub(crate) async fn commit_allowlist(&self, allowed: &AllowList) -> Result<u64, EnrollError> {
        let bytes = serde_json::to_vec(allowed)
            .map_err(|e| EnrollError::Store(format!("encode allowed.json: {e}")))?;
        self.commit_sealed(ALLOWED_PATH, bytes).await
    }
}

/// Production [`EnrollStore`]: a [`CircleStore`] plus the member-set salt.
#[allow(dead_code)] // prod EnrollStore; wired by the Hub when an operator hosts a tailnet
pub(crate) struct CircleEnrollStore {
    base: CircleStore,
    /// 64-hex salt seeded into a freshly-created member set so per-wallet
    /// IPs are derivable. Inherited from the tailnet's `members.json`.
    ip_salt: String,
}

#[allow(dead_code)] // constructed by the Hub; see CircleEnrollStore
impl CircleEnrollStore {
    pub(crate) fn new(
        ctx: Arc<ChainCtxV3>,
        creds: SealedAssetCreds,
        circle_id: impl Into<String>,
        ip_salt: impl Into<String>,
    ) -> Self {
        Self {
            base: CircleStore::new(ctx, creds, circle_id),
            ip_salt: ip_salt.into(),
        }
    }

    /// Decode the member set from an already-fetched anchor (no extra
    /// round-trip). Returns an empty v1 set when none is anchored yet.
    async fn load_members_at(
        &self,
        sr: Option<&StateRoot>,
        tailnet_id: u64,
    ) -> Result<TailnetMembers, EnrollError> {
        let empty = || TailnetMembers::new_v1(tailnet_id, self.ip_salt.clone(), vec![], 0, 0);
        let Some(expected) = sr.and_then(|s| s.auth_members_hash.as_deref()) else {
            return Ok(empty());
        };
        let Some(plain) = self.base.load_sealed(MEMBERS_PATH, expected).await? else {
            return Ok(empty());
        };
        TailnetMembers::decode_lenient(&plain).map_err(EnrollError::Members)
    }
}

#[async_trait]
impl EnrollStore for CircleEnrollStore {
    async fn load_enroll_state(&self, tailnet_id: u64) -> Result<EnrollState, EnrollError> {
        // One anchor fetch feeds both reads.
        let sr = self.base.current_state_root().await?;
        Ok(EnrollState {
            allowlist: self.base.load_allowlist_at(sr.as_ref()).await?,
            members: self.load_members_at(sr.as_ref(), tailnet_id).await?,
        })
    }

    async fn commit_members(
        &self,
        _tailnet_id: u64,
        members: &TailnetMembers,
    ) -> Result<u64, EnrollError> {
        let bytes = members.canonical_bytes().map_err(EnrollError::Members)?;
        self.base.commit_sealed(MEMBERS_PATH, bytes).await
    }
}
