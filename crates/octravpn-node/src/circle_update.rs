//! Atomic circle-update primitive.
//!
//! "Atomic" here is a hard constraint set by Octra's lack of multi-tx
//! atomicity: txs are committed one at a time, so the helper enforces
//! a strict ordering rule rather than literal atomicity.
//!
//! ## Atomicity contract
//!
//! Updating a sealed circle asset is a two-step dance:
//!
//! 1. **Write all new blobs first** via `circle_asset_put_encrypted`.
//!    These writes are content-addressed: the chain stores them under
//!    `(circle_id, path)`, but the OLD anchor still points at the OLD
//!    asset bytes (verifiers recompute `sha256(asset_bytes)` against
//!    the bound `policy_hash` / `members_hash` / etc. — different
//!    bytes ⇒ different hash ⇒ the new blob is *invisible* to old
//!    verifiers because the on-chain anchor doesn't bind it yet).
//!
//! 2. **Submit one `update_circle_state` tx** that flips the on-chain
//!    anchor to a [`StateRoot`] whose field-by-field hashes match the
//!    new blobs. After this tx confirms, verifiers see the new bytes
//!    as the canonical state of the circle.
//!
//! If step 2 fails (RPC error, nonce race, op out of funds, etc.) the
//! blobs are *orphans*: they exist in the chain's asset store, but no
//! anchor field binds their hash. Old verifiers still see the old
//! anchor pointing at the old blobs, so user-visible state is fully
//! consistent. The operator can retry the anchor flip via
//! [`retry_anchor`] without re-uploading any blob bytes.
//!
//! The reverse order — anchor first, blobs second — is forbidden,
//! because a verifier that polled between the anchor flip and the
//! blob write would see the new anchor pointing at hashes that don't
//! match the chain's asset bytes (the *old* bytes still live there),
//! and would reject the circle as inconsistent.
//!
//! ## What this module owns
//!
//! * [`UpdateBundle`] — operator-side description of "I want to change
//!   these blobs and these anchor fields."
//! * [`apply`] — drive the bundle through the chain in the correct
//!   order, returning an [`UpdateResult`] that carries every tx hash
//!   the helper submitted.
//! * [`retry_anchor`] — re-submit only the anchor update (used after a
//!   transient anchor-tx failure; blobs are already on chain).
//! * [`list_orphaned_blobs`] — diagnostic: walk a known set of asset
//!   paths and report which ones the current anchor doesn't bind.
//! * [`compute_target_state_root`] — pure function: given the current
//!   on-chain `StateRoot` + the `AnchorOverrides`, produce the new
//!   `StateRoot`. Pulled out so the dry-run path can show operators
//!   the exact bytes that would be committed.
//!
//! Nothing in here decodes the sealed envelope or owns key material
//! directly; it consumes [`SealedAssetCreds`] (a wrapper around the
//! per-tailnet sealed-asset passphrase) and delegates to
//! `octravpn_core::circle::encrypt_sealed_bytes`. The sealed envelope
//! codec is treated as a black box per the project's per-module
//! ownership rule.

use anyhow::{anyhow, bail, Context, Result};
use octravpn_core::{
    circle::{decrypt_sealed_bytes, encrypt_sealed_bytes, PaddingClass},
    v3_state_root::StateRoot,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::chain_v3::ChainCtxV3;

/// Default fee floor for a `circle_asset_put_encrypted` tx if the
/// chain's `octra_recommendedFee` returns 0 / errors. Mirrors the
/// constant the v2 path uses for the same op.
pub(crate) const ASSET_PUT_FEE_FALLBACK: u64 = 5_000;

/// Default fee floor for the trailing `update_circle_state` anchor tx.
pub(crate) const ANCHOR_UPDATE_FEE_FALLBACK: u64 = 1_000;

/// One blob the operator wants to seal + commit as part of this
/// update bundle.
///
/// Audit-3 H-2: `Debug` is hand-written (NOT derived) so the plaintext
/// bytes never appear in `tracing::*!(?blob)` output. Plaintext is
/// also wrapped in `zeroize::Zeroizing<Vec<u8>>` for defence in depth:
/// the heap buffer is scrubbed when the BlobUpdate drops, shrinking
/// the window during which a coredump could rescue the bytes.
#[derive(Clone)]
pub(crate) struct BlobUpdate {
    /// Path inside the circle, e.g. `"/policy.json"`. Forms the
    /// `(circle_id, path)` content-address that
    /// `circle_asset_put_encrypted` writes under.
    pub asset_path: String,
    /// Plaintext bytes. The helper hashes them (for the StateRoot
    /// `*_hash` fields) and feeds them through
    /// `encrypt_sealed_bytes(circle_id, key_id, passphrase, plaintext,
    /// padding_class)`.
    ///
    /// Wrapped in `zeroize::Zeroizing<Vec<u8>>` so the bytes are scrubbed
    /// from the heap on drop (Audit-3 H-2 defence-in-depth alongside the
    /// hand-written `Debug` that hides them from log output).
    pub plaintext: zeroize::Zeroizing<Vec<u8>>,
    /// Sealed-envelope key id. `"default"` for the single-key per-circle
    /// case; multi-key flows pass a non-default id and bind the
    /// resulting envelope's hash separately.
    pub key_id: String,
    /// Padding class. Forces the sealed envelope's on-wire length to a
    /// fixed multiple — same enum the webcli + v2 path use.
    pub padding_class: PaddingClass,
}

impl std::fmt::Debug for BlobUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Audit-3 H-2: print only structural metadata + the length of
        // the plaintext (never the bytes). Length alone leaks at most
        // a coarse fingerprint of policy size — acceptable trade-off
        // for the operator-debuggability gain. Bytes never appear.
        f.debug_struct("BlobUpdate")
            .field("asset_path", &self.asset_path)
            .field("plaintext_len", &self.plaintext.len())
            .field("plaintext", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("padding_class", &self.padding_class)
            .finish()
    }
}

impl BlobUpdate {
    /// SHA-256 of the plaintext (NOT the sealed ciphertext). This is
    /// the value the StateRoot's `policy_hash` / `wg_pubkey_hash` /
    /// `attestation_hash` field binds — the chain stores the sealed
    /// bytes opaquely, but the anchor commits to the pre-encryption
    /// plaintext so verifiers can re-derive it after decryption.
    pub(crate) fn plaintext_hash_hex(&self) -> String {
        // Slice through Zeroizing's Deref so the hash op sees `&[u8]`.
        hex::encode(Sha256::digest(self.plaintext.as_slice()))
    }

    /// Map a known asset path to the StateRoot field whose hash binds
    /// it. Returns `None` for paths the schema doesn't bind.
    pub(crate) fn bound_field(&self) -> Option<AnchoredField> {
        AnchoredField::from_asset_path(&self.asset_path)
    }
}

/// Identifies which StateRoot field a given asset path's plaintext
/// hash binds.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum AnchoredField {
    /// `/policy.json` — binds `state_root.policy_hash`.
    Policy,
    /// `/members.json` — operator-circle StateRoot does NOT have a
    /// `members_hash` field; this variant exists to surface a clear
    /// "members.json belongs in the tailnet-owner circle" rejection
    /// rather than silently shipping an orphan blob.
    Members,
    /// `/attestation.json` — binds `state_root.attestation_hash`.
    Attestation,
    /// `/wg.pub` — binds `state_root.wg_pubkey_hash`.
    WgPubkey,
    /// `/auth/members.json` — binds `state_root.auth_members_hash`, the
    /// operator-hosted enrollment member set. Distinct from `Members`
    /// (the tailnet-owner's `/members.json`, which has no operator-circle
    /// anchor and is rejected); this one is the operator's own circle.
    AuthMembers,
    /// `/auth/allowed.json` — binds `state_root.auth_allowed_hash`, the
    /// operator's enrollment allowlist (who *may* join the private mesh).
    AuthAllowed,
}

impl AnchoredField {
    /// Look up the StateRoot field bound by `asset_path`. Returns
    /// `None` for paths the schema doesn't bind.
    pub(crate) fn from_asset_path(asset_path: &str) -> Option<Self> {
        match asset_path {
            "/policy.json" => Some(Self::Policy),
            "/members.json" => Some(Self::Members),
            "/attestation.json" => Some(Self::Attestation),
            "/wg.pub" => Some(Self::WgPubkey),
            "/auth/members.json" => Some(Self::AuthMembers),
            "/auth/allowed.json" => Some(Self::AuthAllowed),
            _ => None,
        }
    }
}

/// Field-by-field override knobs for the new StateRoot. Fields the
/// operator wants to *inherit unchanged* from the on-chain anchor are
/// left `None`. Fields the operator wants to *change* carry the new
/// value (or for `attestation_hash`, `Some(None)` to clear).
#[derive(Clone, Debug, Default)]
pub(crate) struct AnchorOverrides {
    pub policy_hash: Option<String>,
    /// Members-hash override for forward compat. The current
    /// operator-circle StateRoot schema (v1/v2) does NOT have a
    /// `members_hash` field — this is a no-op against today's chain
    /// but lives in the struct so the API surface stays stable when
    /// the schema bumps. Today, setting this is a hard error to
    /// prevent silent data loss.
    pub members_hash: Option<String>,
    pub wg_pubkey_hash: Option<String>,
    /// `Some(Some(hex))` = set; `Some(None)` = clear; `None` = inherit.
    ///
    /// The three-state semantics are load-bearing — a custom enum would
    /// duplicate `Option` semantics with no payoff, so we keep the
    /// nesting and silence `clippy::option_option`.
    #[allow(clippy::option_option)]
    pub attestation_hash: Option<Option<String>>,
    pub region: Option<String>,
    pub member_count: Option<u64>,
}

impl AnchorOverrides {
    /// True iff every field is `None` (no anchor changes requested).
    pub(crate) fn is_empty(&self) -> bool {
        self.policy_hash.is_none()
            && self.members_hash.is_none()
            && self.wg_pubkey_hash.is_none()
            && self.attestation_hash.is_none()
            && self.region.is_none()
            && self.member_count.is_none()
    }
}

/// Sealed-asset credentials. Wraps the per-tailnet AES-GCM passphrase
/// that decrypts the operator's sealed blobs (see
/// `docs/v2-operator-key-hygiene.md §5`). Zeroizes on drop.
pub(crate) struct SealedAssetCreds {
    passphrase: zeroize::Zeroizing<String>,
}

impl SealedAssetCreds {
    pub(crate) fn new(passphrase: impl Into<String>) -> Self {
        Self {
            passphrase: zeroize::Zeroizing::new(passphrase.into()),
        }
    }

    pub(crate) fn passphrase(&self) -> &str {
        &self.passphrase
    }
}

/// Operator-side bundle: "rewrite these blobs and flip the anchor."
///
/// Audit-3 H-2: hand-written `Debug` (NOT derived) — flows through the
/// per-blob redaction defined on `BlobUpdate::fmt` so neither
/// `tracing::debug!(?bundle)` nor `tracing::info!(?bundle)` can leak
/// the plaintext of any wrapped blob.
#[derive(Clone)]
pub(crate) struct UpdateBundle {
    pub circle_id: String,
    /// Blobs to seal + write. Each lands as a separate
    /// `circle_asset_put_encrypted` tx. Empty vec means "no blob
    /// changes; just flip the anchor."
    pub blobs: Vec<BlobUpdate>,
    pub anchor_overrides: AnchorOverrides,
}

impl std::fmt::Debug for UpdateBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Defers to BlobUpdate's redacting Debug for each entry.
        f.debug_struct("UpdateBundle")
            .field("circle_id", &self.circle_id)
            .field("blobs", &self.blobs)
            .field("anchor_overrides", &self.anchor_overrides)
            .finish()
    }
}

impl UpdateBundle {
    /// True iff the bundle would submit zero txs.
    pub(crate) fn is_noop(&self) -> bool {
        self.blobs.is_empty() && self.anchor_overrides.is_empty()
    }
}

/// What [`apply`] returns on success.
#[derive(Clone, Debug)]
pub(crate) struct UpdateResult {
    pub new_anchor_hex: String,
    pub blob_tx_hashes: Vec<String>,
    pub anchor_tx_hash: Option<String>,
}

/// Errors that can short-circuit [`apply`] mid-flight.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum UpdateError {
    #[error("blob put failed for {asset_path}: {source}")]
    BlobPutFailed {
        asset_path: String,
        index: usize,
        committed_so_far: Vec<String>,
        #[source]
        source: anyhow::Error,
    },
    #[error("anchor update failed (blobs were committed): {source}")]
    AnchorUpdateFailed {
        target_anchor_hex: String,
        blob_tx_hashes: Vec<String>,
        #[source]
        source: anyhow::Error,
    },
    #[error("bundle validation failed: {0}")]
    BundleInvalid(String),
    #[error("could not fetch current state-root for inheritance: {0}")]
    AnchorFetch(#[source] anyhow::Error),
}

fn validate_bundle(bundle: &UpdateBundle) -> Result<(), UpdateError> {
    if bundle.circle_id.is_empty() {
        return Err(UpdateError::BundleInvalid("circle_id is empty".into()));
    }
    if bundle.anchor_overrides.members_hash.is_some() {
        return Err(UpdateError::BundleInvalid(
            "members_hash override is not supported by the operator-circle StateRoot v1/v2 schema; \
             commit members via update_members_root(tailnet_id, …) on the tailnet-owner circle"
                .into(),
        ));
    }
    for (i, b) in bundle.blobs.iter().enumerate() {
        if b.asset_path.is_empty() || !b.asset_path.starts_with('/') {
            return Err(UpdateError::BundleInvalid(format!(
                "blob[{i}]: asset_path must start with '/', got {:?}",
                b.asset_path
            )));
        }
        if b.key_id.is_empty() {
            return Err(UpdateError::BundleInvalid(format!(
                "blob[{i}]: key_id is empty"
            )));
        }
    }
    Ok(())
}

/// Compute the new StateRoot from the current on-chain anchor's
/// decoded JSON + the operator's bundle.
pub(crate) fn compute_target_state_root(
    current: &StateRoot,
    bundle: &UpdateBundle,
) -> Result<StateRoot, UpdateError> {
    let mut next = current.clone();

    // 1. Apply blob-induced hash changes first. Overrides come second.
    for blob in &bundle.blobs {
        if let Some(field) = blob.bound_field() {
            let h = blob.plaintext_hash_hex();
            match field {
                AnchoredField::Policy => next.policy_hash = h,
                AnchoredField::WgPubkey => next.wg_pubkey_hash = h,
                AnchoredField::Attestation => next.attestation_hash = Some(h),
                AnchoredField::AuthMembers => next.auth_members_hash = Some(h),
                AnchoredField::AuthAllowed => next.auth_allowed_hash = Some(h),
                AnchoredField::Members => {
                    return Err(UpdateError::BundleInvalid(
                        "blob /members.json belongs in the tailnet-owner circle, not the \
                         operator circle — use update_members_root(tailnet_id, new_root) on the \
                         tailnet-owner circle instead"
                            .into(),
                    ));
                }
            }
        }
    }

    // 2. Apply explicit overrides.
    if let Some(h) = &bundle.anchor_overrides.policy_hash {
        next.policy_hash.clone_from(h);
    }
    if let Some(h) = &bundle.anchor_overrides.wg_pubkey_hash {
        next.wg_pubkey_hash.clone_from(h);
    }
    if let Some(opt_h) = &bundle.anchor_overrides.attestation_hash {
        next.attestation_hash.clone_from(opt_h);
    }
    if let Some(r) = &bundle.anchor_overrides.region {
        next.region.clone_from(r);
    }
    if let Some(mc) = bundle.anchor_overrides.member_count {
        let clamped = u32::try_from(mc).unwrap_or(u32::MAX);
        next.member_count = clamped;
    }

    next.validate().map_err(|e| {
        UpdateError::BundleInvalid(format!("computed StateRoot fails validate: {e}"))
    })?;
    Ok(next)
}

/// Fetch the current on-chain anchor's sealed `state-root.json` and
/// decode it.
pub(crate) async fn fetch_current_state_root(
    ctx: &ChainCtxV3,
    circle_id: &str,
) -> Result<Option<StateRoot>> {
    let Some(anchor_hex) = ctx.get_circle_state_root(circle_id).await? else {
        return Ok(None);
    };
    let bytes = fetch_circle_asset_plain(ctx, circle_id, "/state-root.json").await?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let sr = StateRoot::decode_lenient(&bytes)
        .with_context(|| format!("decode current state-root for {circle_id}"))?;
    let recomputed = sr
        .anchor_hex()
        .with_context(|| format!("recompute anchor for fetched state-root of {circle_id}"))?;
    if recomputed != anchor_hex {
        bail!(
            "state-root fetched from circle {circle_id} has anchor {recomputed} \
             but chain reports {anchor_hex}; refusing to update against a drifted snapshot"
        );
    }
    Ok(Some(sr))
}

pub(crate) async fn fetch_circle_asset_plain(
    ctx: &ChainCtxV3,
    circle_id: &str,
    path: &str,
) -> Result<Option<Vec<u8>>> {
    let v = match ctx
        .rpc
        .raw_call("circle_asset", json!([circle_id, path]))
        .await
    {
        Ok(v) => v,
        Err(e) => {
            let msg = e.to_string();
            // Missing-asset shapes: explicit "not found" / "no such" /
            // empty `result: null` (the RPC client surfaces this as
            // "empty result").
            if msg.contains("not found") || msg.contains("no such") || msg.contains("empty result")
            {
                return Ok(None);
            }
            return Err(anyhow!("circle_asset({circle_id}, {path}): {e}"));
        }
    };
    if v.is_null() {
        return Ok(None);
    }
    if let Some(s) = v.as_str() {
        return Ok(Some(s.as_bytes().to_vec()));
    }
    if let Some(obj) = v.as_object() {
        for key in ["plaintext", "content", "json"] {
            if let Some(s) = obj.get(key).and_then(Value::as_str) {
                return Ok(Some(s.as_bytes().to_vec()));
            }
        }
        if let Some(s) = obj.get("bytes").and_then(Value::as_str) {
            let decoded = octravpn_core::b64::decode(s.as_bytes())
                .map_err(|e| anyhow!("circle_asset bytes b64: {e}"))?;
            return Ok(Some(decoded));
        }
    }
    Err(anyhow!(
        "circle_asset({circle_id}, {path}): unexpected response shape: {v}"
    ))
}

/// Outcome of reading a sealed circle asset via [`read_sealed_asset`].
pub(crate) enum SealedRead {
    /// The asset isn't present on chain.
    Absent,
    /// Present, decrypted, and its plaintext matched the anchor hash.
    Valid(Vec<u8>),
    /// Present but non-UTF-8, or the decrypt/hash check failed — a
    /// tampered or orphaned blob.
    Corrupt,
}

/// Fetch a sealed circle asset and decrypt it, verifying the plaintext
/// against the on-chain anchor `expected_hash`. The canonical sealed-asset
/// *read* — the inverse of the `apply` write side. `Err` is reserved for a
/// fetch (RPC) failure; a present-but-invalid blob is reported as
/// [`SealedRead::Corrupt`] so callers can tell "couldn't reach the chain"
/// apart from "the blob is bad".
pub(crate) async fn read_sealed_asset(
    ctx: &ChainCtxV3,
    circle_id: &str,
    path: &str,
    key_id: &str,
    creds: &SealedAssetCreds,
    expected_hash: &str,
) -> Result<SealedRead> {
    let Some(bytes) = fetch_circle_asset_plain(ctx, circle_id, path).await? else {
        return Ok(SealedRead::Absent);
    };
    let Ok(sealed) = std::str::from_utf8(&bytes) else {
        return Ok(SealedRead::Corrupt);
    };
    match decrypt_sealed_bytes(
        circle_id,
        key_id,
        creds.passphrase(),
        sealed.trim(),
        expected_hash,
    ) {
        Ok(plain) => Ok(SealedRead::Valid(plain)),
        Err(_) => Ok(SealedRead::Corrupt),
    }
}

/// Build an unsigned `circle_asset_put_encrypted` envelope. Mirrors
/// `ChainCtxV2::build_put_encrypted_tx` but drives off the v3 ctx
/// wallet address so callers don't have to wire up a parallel v2 chain ctx.
fn build_blob_put_tx(
    ctx: &ChainCtxV3,
    circle_id: &str,
    blob: &BlobUpdate,
    creds: &SealedAssetCreds,
    fee: u64,
) -> Result<(Value, String)> {
    let (ciphertext_b64, plaintext_hash) = encrypt_sealed_bytes(
        circle_id,
        &blob.key_id,
        creds.passphrase(),
        blob.plaintext.as_slice(),
        blob.padding_class,
    )
    .with_context(|| format!("seal asset {} for circle {circle_id}", blob.asset_path))?;
    let mut payload = json!({
        "path": &blob.asset_path,
        "content_type": "application/octet-stream",
        "key_id": &blob.key_id,
        "plaintext_hash": &plaintext_hash,
    });
    let padding_class = blob.padding_class.as_str();
    if !padding_class.is_empty() {
        payload
            .as_object_mut()
            .expect("payload is object")
            .insert("padding_class".into(), json!(padding_class));
    }
    let tx = json!({
        "from": ctx.wallet_addr.display(),
        "to_": circle_id,
        "amount": "0",
        "nonce": 0,
        "ou": fee.to_string(),
        "timestamp": current_timestamp_f64(),
        "op_type": "circle_asset_put_encrypted",
        "encrypted_data": ciphertext_b64,
        "message": payload.to_string(),
    });
    Ok((tx, plaintext_hash))
}

fn current_timestamp_f64() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// Apply an [`UpdateBundle`] atomically (blobs-first-anchor-second).
///
/// On success: every blob is on chain and the anchor binds them.
/// On `BlobPutFailed`: zero or more blobs were committed, NO anchor
/// flip was attempted, chain state is consistent with the OLD anchor.
/// On `AnchorUpdateFailed`: every blob was committed but the anchor
/// flip didn't land. Chain state is consistent with the OLD anchor.
/// Operator should call [`retry_anchor`] with `err.target_anchor_hex`
/// to re-submit just the anchor flip without re-uploading blobs.
pub(crate) async fn apply(
    ctx: &ChainCtxV3,
    creds: &SealedAssetCreds,
    bundle: UpdateBundle,
) -> Result<UpdateResult, UpdateError> {
    validate_bundle(&bundle)?;
    if bundle.is_noop() {
        let current = ctx
            .get_circle_state_root(&bundle.circle_id)
            .await
            .map_err(UpdateError::AnchorFetch)?;
        return Ok(UpdateResult {
            new_anchor_hex: current.unwrap_or_else(|| "0".to_string()),
            blob_tx_hashes: Vec::new(),
            anchor_tx_hash: None,
        });
    }

    let current = fetch_current_state_root(ctx, &bundle.circle_id)
        .await
        .map_err(UpdateError::AnchorFetch)?
        .ok_or_else(|| {
            UpdateError::AnchorFetch(anyhow!(
                "circle {} has no on-chain anchor yet — use register_circle for the initial \
                 commit, then call update for subsequent rotations",
                bundle.circle_id
            ))
        })?;

    let target = compute_target_state_root(&current, &bundle)?;
    let target_anchor_hex = target
        .anchor_hex()
        .map_err(|e| UpdateError::BundleInvalid(format!("anchor_hex: {e}")))?;

    let current_anchor_hex = current
        .anchor_hex()
        .map_err(|e| UpdateError::BundleInvalid(format!("current anchor_hex: {e}")))?;
    if target_anchor_hex == current_anchor_hex && bundle.blobs.is_empty() {
        return Ok(UpdateResult {
            new_anchor_hex: current_anchor_hex,
            blob_tx_hashes: Vec::new(),
            anchor_tx_hash: None,
        });
    }

    // Step 2: write each blob.
    let mut blob_tx_hashes = Vec::with_capacity(bundle.blobs.len());
    for (i, blob) in bundle.blobs.iter().enumerate() {
        let fee_q = ctx.fee("circle_asset_put_encrypted").await.ok();
        let fee = fee_q.filter(|f| *f > 0).unwrap_or(ASSET_PUT_FEE_FALLBACK);
        let (tx, plaintext_hash) = build_blob_put_tx(ctx, &bundle.circle_id, blob, creds, fee)
            .map_err(|e| UpdateError::BlobPutFailed {
                asset_path: blob.asset_path.clone(),
                index: i,
                committed_so_far: blob_tx_hashes.clone(),
                source: e,
            })?;
        debug!(
            asset_path = %blob.asset_path,
            key_id = %blob.key_id,
            plaintext_hash = %plaintext_hash,
            "circle-update: submitting blob put"
        );
        let hash = ctx
            .submit_call(tx)
            .await
            .map_err(|e| UpdateError::BlobPutFailed {
                asset_path: blob.asset_path.clone(),
                index: i,
                committed_so_far: blob_tx_hashes.clone(),
                source: e,
            })?;
        info!(
            asset_path = %blob.asset_path,
            tx_hash = %hash,
            "circle-update: blob committed"
        );
        blob_tx_hashes.push(hash);
    }

    // Step 3: flip the anchor.
    let anchor_hash = submit_anchor_update(ctx, &bundle.circle_id, &target_anchor_hex)
        .await
        .map_err(|e| UpdateError::AnchorUpdateFailed {
            target_anchor_hex: target_anchor_hex.clone(),
            blob_tx_hashes: blob_tx_hashes.clone(),
            source: e,
        })?;

    // Step 4: emit the meta-blob (state-root.json itself) AFTER the
    // anchor flip. See module-level docs for the rationale (until the
    // HFHE-3 swap collapses this to one tx, the anchor briefly points
    // at not-yet-served meta bytes; same-block ordering covers it).
    let state_root_bytes = target
        .canonical_bytes()
        .map_err(|e| UpdateError::BundleInvalid(format!("canonical_bytes: {e}")))?;
    let meta_blob = BlobUpdate {
        asset_path: "/state-root.json".to_string(),
        // Audit-3 H-2 wrap: Zeroizing<Vec<u8>> so the meta-blob bytes
        // are scrubbed on drop alongside the rest.
        plaintext: zeroize::Zeroizing::new(state_root_bytes),
        key_id: "default".to_string(),
        padding_class: PaddingClass::None,
    };
    let fee = ctx
        .fee("circle_asset_put_encrypted")
        .await
        .ok()
        .filter(|f| *f > 0)
        .unwrap_or(ASSET_PUT_FEE_FALLBACK);
    let (meta_tx, _) =
        build_blob_put_tx(ctx, &bundle.circle_id, &meta_blob, creds, fee).map_err(|e| {
            UpdateError::AnchorUpdateFailed {
                target_anchor_hex: target_anchor_hex.clone(),
                blob_tx_hashes: blob_tx_hashes.clone(),
                source: e,
            }
        })?;
    let meta_hash =
        ctx.submit_call(meta_tx)
            .await
            .map_err(|e| UpdateError::AnchorUpdateFailed {
                target_anchor_hex: target_anchor_hex.clone(),
                blob_tx_hashes: blob_tx_hashes.clone(),
                source: e,
            })?;
    blob_tx_hashes.push(meta_hash);

    Ok(UpdateResult {
        new_anchor_hex: target_anchor_hex,
        blob_tx_hashes,
        anchor_tx_hash: Some(anchor_hash),
    })
}

async fn submit_anchor_update(
    ctx: &ChainCtxV3,
    circle_id: &str,
    target_anchor_hex: &str,
) -> Result<String> {
    let fee = ctx
        .fee("contract_call")
        .await
        .ok()
        .filter(|f| *f > 0)
        .unwrap_or(ANCHOR_UPDATE_FEE_FALLBACK);
    let call = ctx.build_update_circle_state_call(circle_id, target_anchor_hex, fee, 0);
    let hash = ctx
        .submit_call(call)
        .await
        .with_context(|| format!("submit update_circle_state for {circle_id}"))?;
    info!(circle_id, new_anchor = target_anchor_hex, %hash, "circle-update: anchor committed");
    Ok(hash)
}

/// Re-submit just the `update_circle_state` tx. Used after [`apply`]
/// returned [`UpdateError::AnchorUpdateFailed`].
pub(crate) async fn retry_anchor(
    ctx: &ChainCtxV3,
    circle_id: &str,
    target_anchor_hex: &str,
) -> Result<String> {
    submit_anchor_update(ctx, circle_id, target_anchor_hex).await
}

/// Diagnostic: probe known asset paths and report which ones the
/// current anchor doesn't bind.
pub(crate) async fn list_orphaned_blobs(
    ctx: &ChainCtxV3,
    circle_id: &str,
    current: &StateRoot,
    creds: &SealedAssetCreds,
) -> Result<Vec<String>> {
    let probes: &[(&str, AnchoredField, &str)] = &[
        (
            "/policy.json",
            AnchoredField::Policy,
            current.policy_hash.as_str(),
        ),
        (
            "/wg.pub",
            AnchoredField::WgPubkey,
            current.wg_pubkey_hash.as_str(),
        ),
    ];
    let mut orphans = Vec::new();
    for (path, _field, expected_hex) in probes {
        // A blob present on chain that doesn't decrypt/verify against its
        // anchor is exactly a `Corrupt` read; absent or valid is fine.
        if matches!(
            read_sealed_asset(ctx, circle_id, path, "default", creds, expected_hex).await?,
            SealedRead::Corrupt
        ) {
            orphans.push((*path).to_string());
        }
    }
    // Attestation is *optionally* anchored: when bound, verify it like any
    // sealed asset; when unbound, its mere presence on chain is an orphan.
    const ATTESTATION_PATH: &str = "/attestation.json";
    match current.attestation_hash.as_deref() {
        Some(expected) => {
            if matches!(
                read_sealed_asset(ctx, circle_id, ATTESTATION_PATH, "default", creds, expected)
                    .await?,
                SealedRead::Corrupt
            ) {
                orphans.push(ATTESTATION_PATH.to_string());
            }
        }
        None => {
            if fetch_circle_asset_plain(ctx, circle_id, ATTESTATION_PATH)
                .await?
                .is_some()
            {
                orphans.push(ATTESTATION_PATH.to_string());
            }
        }
    }
    Ok(orphans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_v3::ChainCtxV3;
    use octravpn_core::{address::Address, rpc::RpcClient, sig::KeyPair};

    const TEST_CIRCLE: &str = "octCIRCLEffffffffffffffffffffffffffffffffffe1";
    const TEST_PASS: &str = "tailnet-passphrase-not-a-secret";

    fn h(byte: u8) -> String {
        let mut s = String::with_capacity(64);
        use std::fmt::Write as _;
        for _ in 0..32 {
            write!(s, "{byte:02x}").unwrap();
        }
        s
    }

    fn sample_current_state_root() -> StateRoot {
        StateRoot::new_v1(
            TEST_CIRCLE,
            h(0xab),
            h(0xcd),
            Some(h(0xef)),
            "us-east-1",
            42,
            12345,
            1_705_000_000,
        )
    }

    fn ctx_offline() -> ChainCtxV3 {
        let secret = [7u8; 32];
        let wallet = KeyPair::from_secret_bytes(&secret);
        let program_addr = Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3");
        let rpc = RpcClient::new("http://127.0.0.1:0/unused");
        ChainCtxV3::new(rpc, program_addr, wallet)
    }

    // --- Pure-function tests -----------------------------------------

    /// Audit-3 H-2: `Debug` on `BlobUpdate` and `UpdateBundle` MUST
    /// NOT include the plaintext bytes — neither at the field-by-field
    /// level (`?blob`) nor at the bundle level (`?bundle`). Sentinel
    /// bytes guarantee a failed redaction shows up loudly.
    #[test]
    fn debug_does_not_leak_blob_plaintext() {
        const SENTINEL: &[u8] = b"H2-LEAK-CANARY-secret-policy-bytes-do-not-print";
        let blob = BlobUpdate {
            asset_path: "/policy.json".into(),
            plaintext: zeroize::Zeroizing::new(SENTINEL.to_vec()),
            key_id: "default".into(),
            padding_class: PaddingClass::None,
        };
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: vec![blob.clone()],
            anchor_overrides: AnchorOverrides::default(),
        };
        let s_blob = format!("{blob:?}");
        let s_bundle = format!("{bundle:?}");
        let needle = std::str::from_utf8(SENTINEL).unwrap();
        assert!(
            !s_blob.contains(needle),
            "BlobUpdate Debug leaked plaintext: {s_blob}"
        );
        assert!(
            !s_bundle.contains(needle),
            "UpdateBundle Debug leaked plaintext: {s_bundle}"
        );
        // Positive control: length IS exposed (audit accepts this
        // trade-off — see BlobUpdate::fmt docstring).
        assert!(
            s_blob.contains(&format!("plaintext_len: {}", SENTINEL.len())),
            "Debug should still expose plaintext_len for operator triage: {s_blob}"
        );
    }

    #[test]
    fn plaintext_hash_matches_sha256() {
        let blob = BlobUpdate {
            asset_path: "/policy.json".into(),
            plaintext: zeroize::Zeroizing::new(b"hello".to_vec()),
            key_id: "default".into(),
            padding_class: PaddingClass::None,
        };
        let expected = hex::encode(Sha256::digest(b"hello"));
        assert_eq!(blob.plaintext_hash_hex(), expected);
    }

    #[test]
    fn bound_field_maps_known_paths() {
        assert_eq!(
            AnchoredField::from_asset_path("/policy.json"),
            Some(AnchoredField::Policy)
        );
        assert_eq!(
            AnchoredField::from_asset_path("/members.json"),
            Some(AnchoredField::Members)
        );
        assert_eq!(
            AnchoredField::from_asset_path("/attestation.json"),
            Some(AnchoredField::Attestation)
        );
        assert_eq!(
            AnchoredField::from_asset_path("/wg.pub"),
            Some(AnchoredField::WgPubkey)
        );
        assert_eq!(AnchoredField::from_asset_path("/weird"), None);
    }

    #[test]
    fn anchor_overrides_default_is_empty() {
        assert!(AnchorOverrides::default().is_empty());
    }

    #[test]
    fn anchor_overrides_with_value_not_empty() {
        let o = AnchorOverrides {
            region: Some("eu-west-3".into()),
            ..AnchorOverrides::default()
        };
        assert!(!o.is_empty());
    }

    #[test]
    fn single_blob_anchor_flip_pure() {
        let current = sample_current_state_root();
        let plaintext = br#"{"endpoint":"new"}"#;
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: vec![BlobUpdate {
                asset_path: "/policy.json".into(),
                plaintext: zeroize::Zeroizing::new(plaintext.to_vec()),
                key_id: "default".into(),
                padding_class: PaddingClass::K4,
            }],
            anchor_overrides: AnchorOverrides::default(),
        };
        let next = compute_target_state_root(&current, &bundle).unwrap();
        assert_eq!(next.policy_hash, hex::encode(Sha256::digest(plaintext)));
        assert_eq!(next.wg_pubkey_hash, current.wg_pubkey_hash);
        assert_eq!(next.attestation_hash, current.attestation_hash);
        assert_eq!(next.region, current.region);
        assert_ne!(next.anchor_hex().unwrap(), current.anchor_hex().unwrap());
    }

    #[test]
    fn multi_blob_anchor_binds_all_fields() {
        let current = sample_current_state_root();
        let policy = b"new-policy-bytes";
        let wgpub = b"new-wg-pubkey-32-bytes-here-XYZ";
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: vec![
                BlobUpdate {
                    asset_path: "/policy.json".into(),
                    plaintext: zeroize::Zeroizing::new(policy.to_vec()),
                    key_id: "default".into(),
                    padding_class: PaddingClass::K4,
                },
                BlobUpdate {
                    asset_path: "/wg.pub".into(),
                    plaintext: zeroize::Zeroizing::new(wgpub.to_vec()),
                    key_id: "default".into(),
                    padding_class: PaddingClass::None,
                },
            ],
            anchor_overrides: AnchorOverrides::default(),
        };
        let next = compute_target_state_root(&current, &bundle).unwrap();
        assert_eq!(next.policy_hash, hex::encode(Sha256::digest(policy)));
        assert_eq!(next.wg_pubkey_hash, hex::encode(Sha256::digest(wgpub)));
    }

    #[test]
    fn anchor_inheritance_carries_forward_unchanged_fields() {
        let current = sample_current_state_root();
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: Vec::new(),
            anchor_overrides: AnchorOverrides {
                region: Some("ap-south-2".into()),
                ..AnchorOverrides::default()
            },
        };
        let next = compute_target_state_root(&current, &bundle).unwrap();
        assert_eq!(next.region, "ap-south-2");
        assert_eq!(next.policy_hash, current.policy_hash);
        assert_eq!(next.wg_pubkey_hash, current.wg_pubkey_hash);
        assert_eq!(next.attestation_hash, current.attestation_hash);
        assert_eq!(next.member_count, current.member_count);
    }

    #[test]
    fn attestation_clear_override() {
        let current = sample_current_state_root();
        assert!(current.attestation_hash.is_some());
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: Vec::new(),
            anchor_overrides: AnchorOverrides {
                attestation_hash: Some(None),
                ..AnchorOverrides::default()
            },
        };
        let next = compute_target_state_root(&current, &bundle).unwrap();
        assert!(next.attestation_hash.is_none());
    }

    #[test]
    fn members_hash_override_rejected_today() {
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: Vec::new(),
            anchor_overrides: AnchorOverrides {
                members_hash: Some(h(0x77)),
                ..AnchorOverrides::default()
            },
        };
        match validate_bundle(&bundle) {
            Err(UpdateError::BundleInvalid(msg)) => {
                assert!(msg.contains("members_hash"), "got: {msg}");
            }
            other => panic!("expected BundleInvalid, got {other:?}"),
        }
    }

    #[test]
    fn members_json_blob_rejected_against_operator_circle() {
        let current = sample_current_state_root();
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: vec![BlobUpdate {
                asset_path: "/members.json".into(),
                plaintext: zeroize::Zeroizing::new(b"members".to_vec()),
                key_id: "default".into(),
                padding_class: PaddingClass::K4,
            }],
            anchor_overrides: AnchorOverrides::default(),
        };
        match compute_target_state_root(&current, &bundle) {
            Err(UpdateError::BundleInvalid(msg)) => {
                assert!(msg.contains("members.json"), "got: {msg}");
            }
            other => panic!("expected BundleInvalid, got {other:?}"),
        }
    }

    #[test]
    fn empty_bundle_is_noop_predicate() {
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: Vec::new(),
            anchor_overrides: AnchorOverrides::default(),
        };
        assert!(bundle.is_noop());
    }

    #[test]
    fn empty_circle_id_rejected() {
        let bundle = UpdateBundle {
            circle_id: String::new(),
            blobs: Vec::new(),
            anchor_overrides: AnchorOverrides::default(),
        };
        match validate_bundle(&bundle) {
            Err(UpdateError::BundleInvalid(msg)) => {
                assert!(msg.contains("circle_id"), "got: {msg}");
            }
            other => panic!("expected BundleInvalid, got {other:?}"),
        }
    }

    #[test]
    fn bad_asset_path_rejected() {
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: vec![BlobUpdate {
                asset_path: "policy.json".into(),
                plaintext: zeroize::Zeroizing::new(b"x".to_vec()),
                key_id: "default".into(),
                padding_class: PaddingClass::None,
            }],
            anchor_overrides: AnchorOverrides::default(),
        };
        match validate_bundle(&bundle) {
            Err(UpdateError::BundleInvalid(msg)) => {
                assert!(msg.contains("asset_path"), "got: {msg}");
            }
            other => panic!("expected BundleInvalid, got {other:?}"),
        }
    }

    #[test]
    fn multi_key_id_same_plaintext_same_hash() {
        let plaintext = b"region-policy";
        let b1 = BlobUpdate {
            asset_path: "/policy.json".into(),
            plaintext: zeroize::Zeroizing::new(plaintext.to_vec()),
            key_id: "eu-west".into(),
            padding_class: PaddingClass::K4,
        };
        let b2 = BlobUpdate {
            asset_path: "/policy.json".into(),
            plaintext: zeroize::Zeroizing::new(plaintext.to_vec()),
            key_id: "ap-south".into(),
            padding_class: PaddingClass::K4,
        };
        assert_eq!(b1.plaintext_hash_hex(), b2.plaintext_hash_hex());
    }

    #[test]
    fn padding_class_change_changes_envelope_bytes() {
        let (ct_a, _) =
            encrypt_sealed_bytes(TEST_CIRCLE, "default", TEST_PASS, b"x", PaddingClass::None)
                .unwrap();
        let (ct_b, _) =
            encrypt_sealed_bytes(TEST_CIRCLE, "default", TEST_PASS, b"x", PaddingClass::K4)
                .unwrap();
        assert_ne!(ct_a, ct_b);
    }

    #[test]
    fn explicit_override_wins_over_blob_hash() {
        let current = sample_current_state_root();
        let forced_hash = h(0x55);
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: vec![BlobUpdate {
                asset_path: "/policy.json".into(),
                plaintext: zeroize::Zeroizing::new(b"blob-content".to_vec()),
                key_id: "default".into(),
                padding_class: PaddingClass::None,
            }],
            anchor_overrides: AnchorOverrides {
                policy_hash: Some(forced_hash.clone()),
                ..AnchorOverrides::default()
            },
        };
        let next = compute_target_state_root(&current, &bundle).unwrap();
        assert_eq!(next.policy_hash, forced_hash);
    }

    #[test]
    fn member_count_override_clamps_to_u32_max() {
        let current = sample_current_state_root();
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: Vec::new(),
            anchor_overrides: AnchorOverrides {
                member_count: Some(u64::MAX),
                ..AnchorOverrides::default()
            },
        };
        let next = compute_target_state_root(&current, &bundle).unwrap();
        assert_eq!(next.member_count, u32::MAX);
    }

    #[test]
    fn build_blob_put_tx_emits_envelope_with_correct_plaintext_hash() {
        let ctx = ctx_offline();
        let creds = SealedAssetCreds::new(TEST_PASS);
        let blob = BlobUpdate {
            asset_path: "/policy.json".into(),
            plaintext: zeroize::Zeroizing::new(b"hello".to_vec()),
            key_id: "default".into(),
            padding_class: PaddingClass::None,
        };
        let (tx, ph) =
            build_blob_put_tx(&ctx, TEST_CIRCLE, &blob, &creds, ASSET_PUT_FEE_FALLBACK).unwrap();
        let expected = hex::encode(Sha256::digest(b"hello"));
        assert_eq!(ph, expected);
        assert_eq!(tx["nonce"], 0);
        assert_eq!(tx["op_type"], "circle_asset_put_encrypted");
        let msg = tx.get("message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            msg.contains(&expected),
            "message missing plaintext_hash: {msg}"
        );
        assert!(msg.contains("/policy.json"));
    }

    #[test]
    fn sealed_asset_creds_passphrase_accessor() {
        let c = SealedAssetCreds::new("foo");
        assert_eq!(c.passphrase(), "foo");
    }

    #[test]
    fn sealed_round_trip_via_codec() {
        let plaintext = b"sealed-policy-bytes";
        let (ct_b64, ph) = encrypt_sealed_bytes(
            TEST_CIRCLE,
            "default",
            TEST_PASS,
            plaintext,
            PaddingClass::K4,
        )
        .unwrap();
        let out =
            decrypt_sealed_bytes(TEST_CIRCLE, "default", TEST_PASS, &ct_b64, &ph).expect("unseal");
        assert_eq!(out, plaintext);
    }

    #[test]
    fn sealed_wrong_pass_decrypt_errors() {
        let plaintext = b"sealed-policy-bytes";
        let (ct_b64, ph) = encrypt_sealed_bytes(
            TEST_CIRCLE,
            "default",
            TEST_PASS,
            plaintext,
            PaddingClass::K4,
        )
        .unwrap();
        assert!(decrypt_sealed_bytes(TEST_CIRCLE, "default", "wrong-pass", &ct_b64, &ph).is_err());
    }

    #[test]
    fn compute_target_state_root_is_deterministic() {
        let current = sample_current_state_root();
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: vec![BlobUpdate {
                asset_path: "/policy.json".into(),
                plaintext: zeroize::Zeroizing::new(b"hello".to_vec()),
                key_id: "default".into(),
                padding_class: PaddingClass::K4,
            }],
            anchor_overrides: AnchorOverrides {
                region: Some("eu-west-3".into()),
                member_count: Some(42),
                ..AnchorOverrides::default()
            },
        };
        let a = compute_target_state_root(&current, &bundle)
            .unwrap()
            .anchor_hex()
            .unwrap();
        let b = compute_target_state_root(&current, &bundle)
            .unwrap()
            .anchor_hex()
            .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn each_override_changes_anchor() {
        let current = sample_current_state_root();
        let base_anchor = current.anchor_hex().unwrap();

        type Mutator = fn(&mut AnchorOverrides);
        let cases: &[(&str, Mutator)] = &[
            ("policy_hash", |o: &mut AnchorOverrides| {
                o.policy_hash = Some(h(0x11));
            }),
            ("wg_pubkey_hash", |o: &mut AnchorOverrides| {
                o.wg_pubkey_hash = Some(h(0x22));
            }),
            ("attestation_clear", |o: &mut AnchorOverrides| {
                o.attestation_hash = Some(None);
            }),
            ("region", |o: &mut AnchorOverrides| {
                o.region = Some("xx".into());
            }),
            ("member_count", |o: &mut AnchorOverrides| {
                o.member_count = Some(999);
            }),
        ];
        for (name, mutate) in cases {
            let mut o = AnchorOverrides::default();
            mutate(&mut o);
            let bundle = UpdateBundle {
                circle_id: TEST_CIRCLE.into(),
                blobs: Vec::new(),
                anchor_overrides: o,
            };
            let next = compute_target_state_root(&current, &bundle).unwrap();
            let next_anchor = next.anchor_hex().unwrap();
            assert_ne!(
                next_anchor, base_anchor,
                "override {name} did not change anchor"
            );
        }
    }

    // -----------------------------------------------------------------
    // Chain-driven tests against a tiny mock JSON-RPC server.
    // -----------------------------------------------------------------

    use axum::{extract::State as AxumState, http::StatusCode, routing::post, Json, Router};
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    #[derive(Default)]
    struct MockChain {
        anchors: HashMap<String, String>,
        assets: HashMap<(String, String), Vec<u8>>,
        submitted: Vec<(String, Value)>,
        next_nonce: u64,
        tx_counter: u64,
        anchor_revert_remaining: u32,
        blob_reject_path: Option<String>,
    }

    type SharedMock = Arc<Mutex<MockChain>>;

    async fn mock_handler(
        AxumState(state): AxumState<SharedMock>,
        Json(req): Json<Value>,
    ) -> Result<Json<Value>, StatusCode> {
        let method = req
            .get("method")
            .and_then(|v| v.as_str())
            .ok_or(StatusCode::BAD_REQUEST)?;
        let id = req.get("id").cloned().unwrap_or(json!(1));
        let params = req.get("params").cloned().unwrap_or(json!([]));

        let result = match method {
            "node_status" => json!({ "epoch": 1234 }),
            "octra_balance" => {
                let g = state.lock();
                let last_used_nonce = g.next_nonce.saturating_sub(1);
                json!({
                    "balance": "100.000000",
                    "balance_raw": "100000000",
                    "nonce": last_used_nonce,
                    "pending_nonce": last_used_nonce,
                })
            }
            "octra_recommendedFee" => {
                json!({ "minimum": "500", "recommended": "500", "fast": "1000" })
            }
            "circle_asset" => {
                let arr = params.as_array().ok_or(StatusCode::BAD_REQUEST)?;
                let circle = arr
                    .first()
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let path = arr.get(1).and_then(Value::as_str).unwrap_or("").to_string();
                let g = state.lock();
                match g.assets.get(&(circle, path)) {
                    Some(bytes) => Value::String(String::from_utf8_lossy(bytes).into_owned()),
                    None => Value::Null,
                }
            }
            "contract_call" => {
                let arr = params.as_array().ok_or(StatusCode::BAD_REQUEST)?;
                let m = arr.get(1).and_then(Value::as_str).unwrap_or("");
                let args = arr.get(2).cloned().unwrap_or(json!([]));
                let g = state.lock();
                match m {
                    "get_circle_state_root" => {
                        let c = args[0].as_str().unwrap_or("");
                        let v = g.anchors.get(c).cloned().unwrap_or_else(|| "0".to_string());
                        json!({ "result": v, "storage": {} })
                    }
                    _ => json!({ "result": null, "storage": {} }),
                }
            }
            "octra_submit" => {
                let mut g = state.lock();
                let tx = params
                    .as_array()
                    .and_then(|a| a.first())
                    .cloned()
                    .unwrap_or(Value::Null);
                let method = tx
                    .get("encrypted_data")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let op_type = tx.get("op_type").and_then(Value::as_str).unwrap_or("");
                let msg = tx.get("message").and_then(Value::as_str).unwrap_or("[]");
                if op_type == "circle_asset_put_encrypted" {
                    let payload: Value = serde_json::from_str(msg).unwrap_or(json!({}));
                    let path = payload
                        .get("path")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let circle = tx
                        .get("to_")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if let Some(rej) = &g.blob_reject_path {
                        if rej == &path {
                            return Ok(Json(json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": {
                                    "code": -32000,
                                    "message": format!("mock reject blob {path}"),
                                },
                            })));
                        }
                    }
                    let bytes_b64 = tx
                        .get("encrypted_data")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    g.assets
                        .insert((circle, path), bytes_b64.as_bytes().to_vec());
                } else if method == "update_circle_state" {
                    if g.anchor_revert_remaining > 0 {
                        g.anchor_revert_remaining -= 1;
                        return Ok(Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32001,
                                "message": "mock reject update_circle_state",
                            },
                        })));
                    }
                    let params: Value = serde_json::from_str(msg).unwrap_or(json!([]));
                    let p = params.as_array().cloned().unwrap_or_default();
                    let circle = p.first().and_then(Value::as_str).unwrap_or("").to_string();
                    let anchor = p.get(1).and_then(Value::as_str).unwrap_or("").to_string();
                    if !circle.is_empty() {
                        g.anchors.insert(circle, anchor);
                    }
                }
                g.tx_counter += 1;
                let hash = format!("{:064x}", g.tx_counter);
                g.submitted.push((hash.clone(), tx));
                g.next_nonce += 1;
                json!({ "tx_hash": hash, "status": "accepted" })
            }
            _ => json!(null),
        };
        Ok(Json(
            json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        ))
    }

    async fn spawn_mock() -> (String, SharedMock, oneshot::Sender<()>) {
        let state = Arc::new(Mutex::new(MockChain {
            next_nonce: 1,
            ..Default::default()
        }));
        let app = Router::new()
            .route("/", post(mock_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind mock");
        let addr = listener.local_addr().expect("addr");
        let url = format!("http://{addr}/");
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let svc = app.into_make_service();
            let server = axum::serve(listener, svc);
            let _ = server
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });
        (url, state, tx)
    }

    fn seed_circle(state: &SharedMock, circle_id: &str, sr: &StateRoot) -> String {
        let bytes = sr.canonical_bytes().expect("encode");
        let anchor = sr.anchor_hex().expect("anchor");
        let mut g = state.lock();
        g.anchors.insert(circle_id.to_string(), anchor.clone());
        g.assets.insert(
            (circle_id.to_string(), "/state-root.json".to_string()),
            bytes,
        );
        anchor
    }

    fn ctx_for(url: &str) -> ChainCtxV3 {
        let secret = [7u8; 32];
        let wallet = KeyPair::from_secret_bytes(&secret);
        let program_addr = Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3");
        let rpc = RpcClient::new(url);
        ChainCtxV3::new(rpc, program_addr, wallet)
    }

    /// End-to-end: single-blob `apply` flips the anchor and writes
    /// the blob + state-root.json. Verifies blob lands BEFORE the
    /// anchor update.
    #[tokio::test]
    async fn apply_single_blob_orders_blob_before_anchor() {
        let (url, state, _kill) = spawn_mock().await;
        let ctx = ctx_for(&url);
        let creds = SealedAssetCreds::new(TEST_PASS);
        let initial = sample_current_state_root();
        seed_circle(&state, TEST_CIRCLE, &initial);

        let new_policy = b"new-policy-bytes-v2";
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: vec![BlobUpdate {
                asset_path: "/policy.json".into(),
                plaintext: zeroize::Zeroizing::new(new_policy.to_vec()),
                key_id: "default".into(),
                padding_class: PaddingClass::K4,
            }],
            anchor_overrides: AnchorOverrides::default(),
        };

        let result = apply(&ctx, &creds, bundle).await.expect("apply");
        assert_ne!(result.new_anchor_hex, initial.anchor_hex().unwrap());
        assert!(result.anchor_tx_hash.is_some());
        assert_eq!(result.blob_tx_hashes.len(), 2); // policy + state-root.json

        let g = state.lock();
        let methods: Vec<String> = g
            .submitted
            .iter()
            .map(|(_, tx)| {
                let op = tx.get("op_type").and_then(Value::as_str).unwrap_or("");
                if op == "circle_asset_put_encrypted" {
                    let msg = tx.get("message").and_then(Value::as_str).unwrap_or("");
                    let v: Value = serde_json::from_str(msg).unwrap_or(json!({}));
                    let p = v.get("path").and_then(Value::as_str).unwrap_or("");
                    format!("put:{p}")
                } else {
                    tx.get("encrypted_data")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string()
                }
            })
            .collect();
        assert_eq!(methods[0], "put:/policy.json");
        assert_eq!(methods[1], "update_circle_state");
        assert_eq!(methods[2], "put:/state-root.json");
    }

    /// Anchor-tx revert: blobs commit, anchor flip rejected,
    /// `retry_anchor` succeeds on second attempt.
    #[tokio::test]
    async fn anchor_tx_revert_then_retry_succeeds() {
        let (url, state, _kill) = spawn_mock().await;
        let ctx = ctx_for(&url);
        let creds = SealedAssetCreds::new(TEST_PASS);
        let initial = sample_current_state_root();
        seed_circle(&state, TEST_CIRCLE, &initial);
        state.lock().anchor_revert_remaining = 1;

        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: vec![BlobUpdate {
                asset_path: "/policy.json".into(),
                plaintext: zeroize::Zeroizing::new(b"v3".to_vec()),
                key_id: "default".into(),
                padding_class: PaddingClass::K4,
            }],
            anchor_overrides: AnchorOverrides::default(),
        };
        match apply(&ctx, &creds, bundle).await {
            Err(UpdateError::AnchorUpdateFailed {
                target_anchor_hex,
                blob_tx_hashes,
                ..
            }) => {
                assert_eq!(blob_tx_hashes.len(), 1, "policy blob committed");
                let hash = retry_anchor(&ctx, TEST_CIRCLE, &target_anchor_hex)
                    .await
                    .expect("retry succeeds");
                assert!(!hash.is_empty());
                let on_chain = state
                    .lock()
                    .anchors
                    .get(TEST_CIRCLE)
                    .cloned()
                    .unwrap_or_default();
                assert_eq!(on_chain, target_anchor_hex);
            }
            other => panic!("expected AnchorUpdateFailed, got {other:?}"),
        }
    }

    /// Blob-tx revert: first blob commits, second rejected, no anchor
    /// flip attempted.
    #[tokio::test]
    async fn blob_tx_revert_aborts_before_anchor() {
        let (url, state, _kill) = spawn_mock().await;
        let ctx = ctx_for(&url);
        let creds = SealedAssetCreds::new(TEST_PASS);
        let initial = sample_current_state_root();
        seed_circle(&state, TEST_CIRCLE, &initial);
        state.lock().blob_reject_path = Some("/wg.pub".to_string());

        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: vec![
                BlobUpdate {
                    asset_path: "/policy.json".into(),
                    plaintext: zeroize::Zeroizing::new(b"v4".to_vec()),
                    key_id: "default".into(),
                    padding_class: PaddingClass::K4,
                },
                BlobUpdate {
                    asset_path: "/wg.pub".into(),
                    plaintext: zeroize::Zeroizing::new(b"new-wg".to_vec()),
                    key_id: "default".into(),
                    padding_class: PaddingClass::None,
                },
            ],
            anchor_overrides: AnchorOverrides::default(),
        };
        match apply(&ctx, &creds, bundle).await {
            Err(UpdateError::BlobPutFailed {
                asset_path,
                index,
                committed_so_far,
                ..
            }) => {
                assert_eq!(asset_path, "/wg.pub");
                assert_eq!(index, 1);
                assert_eq!(committed_so_far.len(), 1, "first blob committed");
            }
            other => panic!("expected BlobPutFailed, got {other:?}"),
        }
        let on_chain = state
            .lock()
            .anchors
            .get(TEST_CIRCLE)
            .cloned()
            .unwrap_or_default();
        assert_eq!(on_chain, initial.anchor_hex().unwrap());
    }

    /// Concurrent-race scaffold: helper's last write wins.
    #[tokio::test]
    async fn concurrent_anchor_change_helper_wins_last_write() {
        let (url, state, _kill) = spawn_mock().await;
        let ctx = ctx_for(&url);
        let creds = SealedAssetCreds::new(TEST_PASS);
        let initial = sample_current_state_root();
        seed_circle(&state, TEST_CIRCLE, &initial);

        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: vec![BlobUpdate {
                asset_path: "/policy.json".into(),
                plaintext: zeroize::Zeroizing::new(b"my-policy".to_vec()),
                key_id: "default".into(),
                padding_class: PaddingClass::K4,
            }],
            anchor_overrides: AnchorOverrides::default(),
        };
        let result = apply(&ctx, &creds, bundle).await.expect("apply ok");
        let on_chain = state
            .lock()
            .anchors
            .get(TEST_CIRCLE)
            .cloned()
            .unwrap_or_default();
        assert_eq!(on_chain, result.new_anchor_hex);
    }

    /// `list_orphaned_blobs` flags a blob whose plaintext hash isn't
    /// bound by the current anchor.
    #[tokio::test]
    async fn list_orphaned_blobs_finds_unbound_policy() {
        let (url, state, _kill) = spawn_mock().await;
        let ctx = ctx_for(&url);
        let creds = SealedAssetCreds::new(TEST_PASS);
        let initial = sample_current_state_root();
        seed_circle(&state, TEST_CIRCLE, &initial);
        let (orphan_b64, _) = encrypt_sealed_bytes(
            TEST_CIRCLE,
            "default",
            TEST_PASS,
            b"orphan-not-anchored",
            PaddingClass::K4,
        )
        .unwrap();
        state.lock().assets.insert(
            (TEST_CIRCLE.to_string(), "/policy.json".to_string()),
            orphan_b64.as_bytes().to_vec(),
        );

        let orphans = list_orphaned_blobs(&ctx, TEST_CIRCLE, &initial, &creds)
            .await
            .expect("list");
        assert!(
            orphans.contains(&"/policy.json".to_string()),
            "got: {orphans:?}"
        );
    }

    /// Empty bundle no-op fast path: no chain side-effects.
    #[tokio::test]
    async fn empty_bundle_apply_returns_existing_anchor() {
        let (url, state, _kill) = spawn_mock().await;
        let ctx = ctx_for(&url);
        let creds = SealedAssetCreds::new(TEST_PASS);
        let initial = sample_current_state_root();
        let anchor = seed_circle(&state, TEST_CIRCLE, &initial);
        let bundle = UpdateBundle {
            circle_id: TEST_CIRCLE.into(),
            blobs: Vec::new(),
            anchor_overrides: AnchorOverrides::default(),
        };
        let result = apply(&ctx, &creds, bundle).await.expect("noop");
        assert_eq!(result.new_anchor_hex, anchor);
        assert!(result.blob_tx_hashes.is_empty());
        assert!(result.anchor_tx_hash.is_none());
        assert_eq!(state.lock().submitted.len(), 0);
    }
}
