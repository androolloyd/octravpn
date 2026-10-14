// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Validate the native spawn/asset effects before staging any of their writes.
use crate::{
    circle::CircleRuntime, circle_call::Context, circle_code, circle_store::Info,
    circle_transaction::Rules, state_batch::StateBatch,
};
use octra_node_protocol::{
    circle_program::{self, Deploy},
    circle_storage::StorageTable,
    circle_wasm::{
        receipt::{Asset, EncryptedAsset, Receipt, Spawn, SpawnOwner},
        Error,
    },
    circles::{self, AssetMeta, LocatorMode, MetadataMode, ResourceMode},
    native_integer::parse_int64,
    native_json::Document,
    transaction::decode_base64,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const RAW_CAP: usize = 1_048_576;
const ENCODED_CAP: usize = RAW_CAP.div_ceil(3) * 4;

/// Effects shared by OCTB and WASM, authorized only after successful execution.
pub(crate) struct Effects {
    pub storage: StorageTable,
    pub spawns: Vec<Spawn>,
    pub assets: Vec<Asset>,
    pub encrypted_assets: Vec<EncryptedAsset>,
}
impl From<Receipt> for Effects {
    fn from(receipt: Receipt) -> Self {
        Self {
            storage: receipt.storage,
            spawns: receipt.spawns,
            assets: receipt.assets,
            encrypted_assets: receipt.encrypted_assets,
        }
    }
}
fn rejected(reason: impl AsRef<[u8]>) -> Error {
    Error::Rejected(reason.as_ref().to_vec())
}
fn unavailable(reason: impl std::fmt::Display) -> Error {
    Error::Unavailable(reason.to_string().into_bytes())
}
fn sha(raw: &[u8]) -> Vec<u8> {
    hex::encode(Sha256::digest(raw)).into_bytes()
}
struct Child {
    source: Spawn,
    payload: Deploy,
    hash: Vec<u8>,
    owner: Vec<u8>,
}
struct Write {
    target: Vec<u8>,
    meta: AssetMeta,
    body: Vec<u8>,
    usage: i64,
}
pub(crate) struct Prepared {
    children: Vec<Child>,
    assets: Vec<Write>,
    calls: bool,
}

impl Prepared {
    pub(crate) fn check(
        runtime: &CircleRuntime,
        state: &StateBatch,
        info: &Info,
        ctx: &Context,
        receipt: &Effects,
    ) -> Result<Self, Error> {
        if receipt.spawns.len() > 4 {
            return Err(rejected("circle spawn cap exceeded"));
        }
        let mut seen = BTreeSet::new();
        for spawn in &receipt.spawns {
            if !seen.insert(&spawn.circle_id) {
                return Err(rejected(
                    [b"duplicate circle spawn id ".as_slice(), &spawn.circle_id].concat(),
                ));
            }
        }
        let rules = Rules {
            wasm: ctx.profile,
            manifest: ctx.manifest,
            inspect: ctx.inspect,
            update_policy: ctx.update_policy,
            storage_proof: ctx.storage_proof,
            fhe_work: ctx.fhe_work,
        };
        let mut checked = Vec::new();
        // Native mapi_s completes admission of each child before selecting the
        // first ordinary refusal. An unavailable host still aborts immediately.
        for (index, source) in receipt.spawns.iter().enumerate() {
            let result = (|| {
                if source.nonce != index as i64 {
                    return Err(rejected("circle spawn nonce mismatch"));
                }
                if source.payload_json.len() > 2_097_152 {
                    return Err(rejected("circle spawn payload exceeds max size"));
                }
                let document =
                    Document::parse(&source.payload_json).map_err(|error| match error {
                        octra_node_protocol::native_json::Error::Allocation => unavailable(error),
                        octra_node_protocol::native_json::Error::Syntax(_) => {
                            rejected("circle deploy payload is invalid")
                        }
                    })?;
                let payload = Deploy::from_document(&document).map_err(|e| {
                    if e.tag == "malformed_transaction_exception" {
                        rejected("circle deploy payload is invalid")
                    } else {
                        rejected(e.reason)
                    }
                })?;
                let (mode, owner) = match source.owner {
                    SpawnOwner::Caller => (b"caller".as_slice(), ctx.caller.as_bytes()),
                    SpawnOwner::Parent => (b"parent".as_slice(), info.circle_id.as_slice()),
                };
                if circle_program::spawn_id(
                    &info.circle_id,
                    ctx.caller.as_bytes(),
                    ctx.tx_hash.as_bytes(),
                    source.nonce,
                    mode,
                    &source.payload_json,
                ) != source.circle_id
                {
                    return Err(rejected("circle spawn id mismatch"));
                }
                let hash =
                    circle_code::check_deploy(runtime, rules, state, &source.circle_id, &payload)
                        .map_err(circle_code::Failure::effect)?;
                Ok(Child {
                    source: source.clone(),
                    payload,
                    hash,
                    owner: owner.to_vec(),
                })
            })();
            match result {
                Err(error @ Error::Unavailable(_)) => return Err(error),
                other => checked.push(other),
            }
        }
        let children = checked.into_iter().collect::<Result<Vec<_>, _>>()?;
        if receipt.assets.len() + receipt.encrypted_assets.len() > 4 {
            return Err(rejected("circle asset effect cap exceeded"));
        }
        let mut check = Assets {
            state,
            info,
            ctx,
            children: &children,
            seen: BTreeSet::new(),
            usage: BTreeMap::new(),
        };
        let mut assets = Vec::new();
        for asset in &receipt.assets {
            assets.push(check.public(asset)?);
        }
        for asset in &receipt.encrypted_assets {
            assets.push(check.encrypted(asset)?);
        }
        let calls = ctx.profile.proof_exec
            && state.get(&[b"circles", &info.circle_id, b"call_code"])
                == Some(info.code_hash.as_slice());
        Ok(Self {
            children,
            assets,
            calls,
        })
    }
    pub(crate) fn apply(
        self,
        state: &mut StateBatch,
        parent: &[u8],
        ctx: &Context,
    ) -> Result<(), Error> {
        for child in self.children {
            let id = child.source.circle_id.as_slice();
            circle_code::install(
                state,
                id,
                &child.owner,
                &child.hash,
                &child.payload,
                self.calls,
            )
            .map_err(circle_code::Failure::effect)?;
            for (key, value) in [
                (b"kind".as_slice(), b"spawn".to_vec()),
                (b"parent", parent.to_vec()),
                (b"caller", ctx.caller.as_bytes().to_vec()),
                (b"tx_hash", ctx.tx_hash.as_bytes().to_vec()),
                (b"spawn_nonce", child.source.nonce.to_string().into_bytes()),
                (
                    b"owner_mode",
                    match child.source.owner {
                        SpawnOwner::Caller => b"caller".to_vec(),
                        SpawnOwner::Parent => b"parent".to_vec(),
                    },
                ),
            ] {
                state
                    .set(&[b"circles", id, b"origin", key], value)
                    .map_err(unavailable)?;
            }
        }
        for asset in self.assets {
            let id = asset.target.as_slice();
            let key = asset.meta.path_key.as_slice();
            state
                .set(
                    &[b"circles", id, b"assets", b"by_hash", key, b"meta"],
                    asset.meta.to_json_bytes(),
                )
                .map_err(unavailable)?;
            let field = if asset.meta.body_mode == ResourceMode::Public {
                b"body_b64".as_slice()
            } else {
                b"ciphertext_b64".as_slice()
            };
            state
                .set(
                    &[b"circles", id, b"assets", b"by_hash", key, field],
                    asset.body,
                )
                .map_err(unavailable)?;
            state
                .set(
                    &[
                        b"circles",
                        id,
                        b"assets",
                        b"resource_keys",
                        &asset.meta.resource_key,
                    ],
                    key.to_vec(),
                )
                .map_err(unavailable)?;
            state
                .set(
                    &[b"circles", id, b"assets", b"usage_bytes"],
                    asset.usage.to_string().into_bytes(),
                )
                .map_err(unavailable)?;
            let root = state
                .snapshot()
                .hash_at(&[b"circles", id, b"assets", b"by_hash"])
                .map_err(unavailable)?
                .map_or_else(|| "0".repeat(64), hex::encode);
            state
                .set(&[b"circles", id, b"assets_root"], root.into_bytes())
                .map_err(unavailable)?;
        }
        Ok(())
    }
}

struct Assets<'a> {
    state: &'a StateBatch,
    info: &'a Info,
    ctx: &'a Context,
    children: &'a [Child],
    seen: BTreeSet<Vec<u8>>,
    usage: BTreeMap<Vec<u8>, i64>,
}
impl Assets<'_> {
    fn target(&self, target: &[u8], encrypted: bool) -> Result<i64, Error> {
        let prefix = if encrypted {
            "circle encrypted asset"
        } else {
            "circle asset"
        };
        let (owner, resource, limit) = if target == self.info.circle_id {
            (&self.info.owner, &self.info.resource, self.info.limits[1])
        } else {
            let child = self
                .children
                .iter()
                .find(|c| c.source.circle_id == target)
                .ok_or_else(|| rejected(format!("{prefix} target not in call scope")))?;
            (
                &child.owner,
                &child.payload.resource,
                child.payload.limits[1],
            )
        };
        if owner != self.ctx.caller.as_bytes()
            && !(target != self.info.circle_id && owner == &self.info.circle_id)
        {
            return Err(rejected(format!("{prefix} owner authorization failed")));
        }
        if encrypted && resource != b"sealed_read" {
            return Err(rejected(
                "encrypted asset effects require sealed_read circles",
            ));
        }
        if !encrypted && resource == b"sealed_read" {
            return Err(rejected(
                "sealed_read circles require encrypted asset effects",
            ));
        }
        Ok(limit)
    }
    fn public(&mut self, asset: &Asset) -> Result<Write, Error> {
        let limit = self.target(&asset.circle_id, false)?;
        if asset.body_b64.len() > ENCODED_CAP {
            return Err(rejected(
                "circle asset effect body exceeds max encoded size",
            ));
        }
        if asset.content_type.is_empty() {
            return Err(rejected("circle asset content_type must not be empty"));
        }
        let path = circles::normalize_path(&asset.path)
            .map_err(|e| rejected(e.0))?
            .into_bytes();
        let key = circles::path_key(&path).into_bytes();
        let (raw, usage) = self.body(&asset.circle_id, &key, &asset.body_b64, limit, false)?;
        let meta = AssetMeta {
            path_key: key,
            resource_key: circles::resource_key(&asset.circle_id, &path).into_bytes(),
            canonical_path: path,
            content_type: asset.content_type.clone(),
            encoding: asset
                .encoding
                .clone()
                .unwrap_or_else(|| b"identity".to_vec()),
            size_bytes: raw.len() as i64,
            blob_hash: sha(&raw),
            body_mode: ResourceMode::Public,
            plaintext_hash: Some(sha(&raw)),
            key_id: None,
            padding_class: None,
            locator_mode: LocatorMode::Path,
            slot_ref: None,
            activate_after_epoch: None,
            expire_after_epoch: None,
            metadata_mode: MetadataMode::Reveal,
        };
        Ok(Write {
            target: asset.circle_id.clone(),
            meta,
            body: asset.body_b64.clone(),
            usage,
        })
    }
    fn encrypted(&mut self, asset: &EncryptedAsset) -> Result<Write, Error> {
        let limit = self.target(&asset.circle_id, true)?;
        if asset.ciphertext_b64.len() > ENCODED_CAP {
            return Err(rejected(
                "circle encrypted asset effect body exceeds max encoded size",
            ));
        }
        if asset.content_type.is_empty() {
            return Err(rejected(
                "circle encrypted asset content_type must not be empty",
            ));
        }
        if asset.key_id.is_empty() {
            return Err(rejected("circle encrypted asset key_id must not be empty"));
        }
        if asset.plaintext_hash.len() != 64
            || !asset.plaintext_hash.iter().all(u8::is_ascii_hexdigit)
        {
            return Err(rejected(
                "circle encrypted asset plaintext_hash must be a 64-char hex string",
            ));
        }
        if let (Some(a), Some(e)) = (asset.activate_after_epoch, asset.expire_after_epoch) {
            if e <= a {
                return Err(rejected("circle encrypted asset expire_after_epoch must be greater than activate_after_epoch"));
            }
        }
        let (path, key, resource, locator, slot) = locator(asset)?;
        let (raw, usage) = self.body(&asset.circle_id, &key, &asset.ciphertext_b64, limit, true)?;
        let meta = AssetMeta {
            path_key: key,
            resource_key: resource,
            canonical_path: path,
            content_type: asset.content_type.clone(),
            encoding: asset
                .encoding
                .clone()
                .unwrap_or_else(|| b"identity".to_vec()),
            size_bytes: raw.len() as i64,
            blob_hash: sha(&raw),
            body_mode: ResourceMode::Sealed,
            plaintext_hash: Some(asset.plaintext_hash.clone()),
            key_id: Some(asset.key_id.clone()),
            padding_class: asset.padding_class.clone(),
            locator_mode: locator,
            slot_ref: slot,
            activate_after_epoch: asset.activate_after_epoch,
            expire_after_epoch: asset.expire_after_epoch,
            metadata_mode: asset.metadata_mode.unwrap_or(MetadataMode::Reveal),
        };
        Ok(Write {
            target: asset.circle_id.clone(),
            meta,
            body: asset.ciphertext_b64.clone(),
            usage,
        })
    }
    fn body(
        &mut self,
        target: &[u8],
        key: &[u8],
        body: &[u8],
        limit: i64,
        encrypted: bool,
    ) -> Result<(Vec<u8>, i64), Error> {
        if !self.seen.insert([target, b":", key].concat()) {
            return Err(rejected("duplicate circle asset effect"));
        }
        let kind = if encrypted {
            "encrypted asset"
        } else {
            "asset"
        };
        let raw = decode_base64(body).map_err(|e| {
            rejected(format!(
                "invalid circle {kind} body: Invalid_argument(\"{e}\")"
            ))
        })?;
        if raw.len() > RAW_CAP {
            return Err(rejected(format!(
                "circle {kind} effect body exceeds max raw size"
            )));
        }
        let size = raw.len() as i64;
        if size > limit {
            return Err(rejected(format!("{kind} exceeds circle asset limit")));
        }
        let mut old = 0;
        if target == self.info.circle_id {
            if let Some(meta) = self
                .state
                .get(&[b"circles", target, b"assets", b"by_hash", key, b"meta"])
            {
                Document::parse(meta).map_err(unavailable)?;
                match AssetMeta::parse(meta) {
                    Ok(meta) => old = meta.size_bytes,
                    Err(e) if e.0 == b"circle asset metadata integer refused" => {
                        return Err(unavailable(e))
                    }
                    Err(_) => (),
                }
            }
        }
        let usage = self.usage.entry(target.to_vec()).or_insert_with(|| {
            if target == self.info.circle_id {
                self.state
                    .get(&[b"circles", target, b"assets", b"usage_bytes"])
                    .and_then(parse_int64)
                    .unwrap_or(0)
            } else {
                0
            }
        });
        let next = usage.wrapping_sub(old).wrapping_add(size);
        if next > limit {
            return Err(rejected(format!(
                "{kind} update exceeds circle asset budget"
            )));
        }
        *usage = next;
        Ok((raw, next))
    }
}
type Locator = (Vec<u8>, Vec<u8>, Vec<u8>, LocatorMode, Option<Vec<u8>>);
fn locator(asset: &EncryptedAsset) -> Result<Locator, Error> {
    match (
        asset.path.as_deref(),
        asset.slot_ref.as_deref(),
        asset.state_ref.as_deref(),
    ) {
        (None, None, None) => Err(rejected("path, slot_ref, or state_ref is required")),
        (Some(path), None, None) => {
            let path = circles::normalize_path(path)
                .map_err(|e| rejected(e.0))?
                .into_bytes();
            Ok((
                path.clone(),
                circles::path_key(&path).into_bytes(),
                circles::resource_key(&asset.circle_id, &path).into_bytes(),
                LocatorMode::Path,
                None,
            ))
        }
        (None, Some(raw), None) | (None, None, Some(raw)) => {
            let slot = asset.slot_ref.is_some();
            let label = if slot { "slot_ref" } else { "state_ref" };
            let space = |b: &u8| matches!(b, b' ' | b'\n' | b'\r' | b'\t' | 12);
            let start = raw.iter().position(|b| !space(b)).unwrap_or(raw.len());
            let end = raw.iter().rposition(|b| !space(b)).map_or(start, |i| i + 1);
            let normalized = raw[start..end].to_ascii_lowercase();
            if normalized.len() != 64 || !normalized.iter().all(u8::is_ascii_hexdigit) {
                return Err(rejected(format!("{label} must be a 64-char hex string")));
            }
            let path = [
                if slot {
                    b"/_slots/".as_slice()
                } else {
                    b"/_state/".as_slice()
                },
                &normalized,
            ]
            .concat();
            let key = circles::domain_hash(
                if slot {
                    b"octra:asset_path:v1"
                } else {
                    b"octra:asset_state_path:v1"
                },
                &[&path],
            )
            .into_bytes();
            let resource = circles::domain_hash(
                if slot {
                    b"octra:circle_resource_key:slot:v1"
                } else {
                    b"octra:circle_resource_key:state:v1"
                },
                &[&asset.circle_id, if slot { &normalized } else { raw }],
            )
            .into_bytes();
            Ok((
                path,
                key,
                resource,
                if slot {
                    LocatorMode::Slot
                } else {
                    LocatorMode::State
                },
                slot.then_some(normalized),
            ))
        }
        _ => Err(rejected(
            "provide exactly one of path, slot_ref, or state_ref",
        )),
    }
}
