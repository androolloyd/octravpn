// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Direct native resource operations. VM effects keep their distinct validation
//! rules while sharing locator and asset storage primitives with this host.
use crate::{
    circle_error::{self, refused, unavailable, Failure},
    circle_operation::{debit, document, owned as info},
    circle_store,
    execution::{Completion, Error},
    state_batch::StateBatch,
};
use octra_node_protocol::{
    circle_resources::{self as resources, EncryptedAsset, Locator, PublicAsset, SlotPolicy},
    circle_state,
    circles::{AssetMeta, LocatorMode, MetadataMode, ResourceMode},
    native_integer::parse_int64,
    native_json::Document,
    state::Ledger,
    transaction::{decode_base64, OpType, Transaction},
};
use sha2::{Digest, Sha256};
type Result<T> = std::result::Result<T, Failure>;
fn descriptor(tx: &Transaction, ledger: &mut Ledger, state: &mut StateBatch) -> Result<()> {
    let payload = circle_state::Payload::parse(&document(tx)?)?;
    let info = info(state, tx, b"state descriptors")?;
    if info.resource != b"sealed_read" {
        return Err(refused(
            "circle_mode_invalid",
            b"state descriptor updates require sealed_read circle mode",
        ));
    }
    payload.resolve()?;
    let locator = Locator::sealed(&tx.to, None, Some(&payload.state))?;
    debit(ledger, tx)?;
    crate::circle_operation::save_policy(state, tx, &info, payload.snapshot(&locator.key))
}
fn body(tx: &Transaction) -> Result<(&[u8], Vec<u8>)> {
    let encoded = tx
        .encrypted_data
        .as_deref()
        .ok_or_else(|| refused("malformed_transaction", b"circle asset body missing"))?;
    if encoded.len() > resources::MAX_ENCODED_BODY {
        return Err(refused(
            "malformed_transaction",
            b"circle asset body exceeds max encoded size",
        ));
    }
    let raw = decode_base64(encoded).map_err(|e| {
        refused(
            "malformed_transaction_exception",
            octra_node_protocol::native_exception::string_argument(
                b"Invalid_argument",
                e.to_string().as_bytes(),
            ),
        )
    })?;
    Ok((encoded, raw))
}
fn next_usage(
    state: &StateBatch,
    tx: &Transaction,
    key: &[u8],
    size: i64,
    limit: i64,
    sealed_object: bool,
) -> Result<i64> {
    let next = usage(state, &tx.to, key, size)?;
    if next > limit {
        return Err(refused(
            "circle_assets_limit_exceeded",
            if sealed_object {
                b"sealed slot update exceeds circle asset budget".as_slice()
            } else {
                b"asset update exceeds circle asset budget"
            },
        ));
    }
    Ok(next)
}
pub(crate) fn usage(state: &StateBatch, circle: &[u8], key: &[u8], size: i64) -> Result<i64> {
    let old = match state.get(&[b"circles", circle, b"assets", b"by_hash", key, b"meta"]) {
        None => 0,
        Some(raw) => {
            Document::parse(raw).map_err(unavailable)?;
            match AssetMeta::parse(raw) {
                Ok(meta) => meta.size_bytes,
                Err(error) if error.0 == b"circle asset metadata integer refused" => {
                    return Err(unavailable(error))
                }
                Err(_) => 0,
            }
        }
    };
    let usage = state
        .get(&[b"circles", circle, b"assets", b"usage_bytes"])
        .and_then(parse_int64)
        .unwrap_or(0);
    Ok(usage.wrapping_sub(old).wrapping_add(size))
}
fn public(tx: &Transaction, ledger: &mut Ledger, state: &mut StateBatch) -> Result<()> {
    let payload = PublicAsset::parse(&document(tx)?)?;
    let (encoded, raw) = body(tx)?;
    let info = info(state, tx, b"assets")?;
    if info.resource == b"sealed_read" {
        return Err(refused(
            "circle_mode_invalid",
            b"sealed_read circles require encrypted asset updates",
        ));
    }
    let locator = Locator::path(&tx.to, &payload.path)?;
    let size = raw.len() as i64;
    if size > info.limits[1] {
        return Err(refused(
            "circle_asset_too_large",
            b"asset exceeds circle asset limit",
        ));
    }
    if payload.content_type.is_empty() {
        return Err(refused(
            "invalid_circle_content_type",
            b"content_type must not be empty",
        ));
    }
    let usage = next_usage(state, tx, &locator.key, size, info.limits[1], false)?;
    debit(ledger, tx)?;
    let digest = hex::encode(Sha256::digest(&raw)).into_bytes();
    let meta = AssetMeta {
        path_key: locator.key,
        canonical_path: locator.path,
        resource_key: locator.resource,
        content_type: payload.content_type,
        encoding: payload.encoding.unwrap_or_else(|| b"identity".to_vec()),
        size_bytes: size,
        blob_hash: digest.clone(),
        body_mode: ResourceMode::Public,
        plaintext_hash: Some(digest),
        key_id: None,
        padding_class: None,
        locator_mode: LocatorMode::Path,
        slot_ref: None,
        activate_after_epoch: None,
        expire_after_epoch: None,
        metadata_mode: MetadataMode::Reveal,
    };
    circle_store::save_asset(state, &tx.to, &meta, encoded, usage).map_err(unavailable)
}
fn encrypted(
    tx: &Transaction,
    ledger: &mut Ledger,
    state: &mut StateBatch,
    sealed_object: bool,
) -> Result<()> {
    let payload = EncryptedAsset::parse(&document(tx)?, sealed_object)?;
    let (encoded, raw) = body(tx)?;
    let info = info(
        state,
        tx,
        if sealed_object {
            b"sealed slots"
        } else {
            b"assets"
        },
    )?;
    if info.resource != b"sealed_read" {
        return Err(refused(
            "circle_mode_invalid",
            if sealed_object {
                b"sealed slot updates require sealed_read circle mode".as_slice()
            } else {
                b"encrypted asset updates require sealed_read circle mode"
            },
        ));
    }
    let locator = if sealed_object {
        Locator::sealed(
            &tx.to,
            payload.slot_ref.as_deref(),
            payload.state_ref.as_deref(),
        )?
    } else {
        Locator::encrypted(
            &tx.to,
            payload.path.as_deref(),
            payload.slot_ref.as_deref(),
            payload.state_ref.as_deref(),
        )?
    };
    let size = raw.len() as i64;
    if size > info.limits[1] {
        return Err(refused(
            "circle_asset_too_large",
            if sealed_object {
                b"sealed slot payload exceeds circle asset limit".as_slice()
            } else {
                b"asset exceeds circle asset limit"
            },
        ));
    }
    if payload.content_type.is_empty() {
        return Err(refused(
            "invalid_circle_content_type",
            b"content_type must not be empty",
        ));
    }
    if payload.key_id.is_empty() {
        return Err(refused(
            "invalid_circle_key_id",
            b"key_id must not be empty",
        ));
    }
    // Direct native writes check length here. VM effects additionally require
    // hexadecimal bytes; do not silently strengthen the transaction rule.
    if payload.plaintext_hash.len() != 64 {
        return Err(refused(
            "invalid_circle_plaintext_hash",
            b"plaintext_hash must be a 64-char hex string",
        ));
    }
    if matches!((payload.activate_after_epoch, payload.expire_after_epoch), (Some(a), Some(e)) if e <= a)
    {
        return Err(refused(
            "invalid_circle_access_window",
            b"expire_after_epoch must be greater than activate_after_epoch",
        ));
    }
    let usage = next_usage(state, tx, &locator.key, size, info.limits[1], sealed_object)?;
    debit(ledger, tx)?;
    let meta = AssetMeta {
        path_key: locator.key,
        canonical_path: locator.path,
        resource_key: locator.resource,
        content_type: payload.content_type,
        encoding: payload.encoding.unwrap_or_else(|| b"identity".to_vec()),
        size_bytes: size,
        blob_hash: hex::encode(Sha256::digest(raw)).into_bytes(),
        body_mode: ResourceMode::Sealed,
        plaintext_hash: Some(payload.plaintext_hash),
        key_id: Some(payload.key_id),
        padding_class: payload.padding_class,
        locator_mode: locator.mode,
        slot_ref: locator.slot,
        activate_after_epoch: payload.activate_after_epoch,
        expire_after_epoch: payload.expire_after_epoch,
        metadata_mode: payload.metadata_mode.unwrap_or(if sealed_object {
            MetadataMode::Opaque
        } else {
            MetadataMode::Reveal
        }),
    };
    circle_store::save_asset(state, &tx.to, &meta, encoded, usage).map_err(unavailable)
}
fn slot_policy(tx: &Transaction, ledger: &mut Ledger, state: &mut StateBatch) -> Result<()> {
    let payload = SlotPolicy::parse(&document(tx)?)?;
    let info = info(state, tx, b"slot policy")?;
    if info.resource != b"sealed_read" {
        return Err(refused(
            "circle_mode_invalid",
            b"slot policy updates require sealed_read circle mode",
        ));
    }
    let locator = Locator::sealed(
        &tx.to,
        payload.slot_ref.as_deref(),
        payload.state_ref.as_deref(),
    )?;
    if payload.delivery_key_id.as_ref().is_some_and(Vec::is_empty) {
        return Err(refused(
            "invalid_circle_delivery_key_id",
            b"delivery_key_id must not be empty",
        ));
    }
    if matches!((payload.activate_after_epoch, payload.expire_after_epoch), (Some(a), Some(e)) if e <= a)
    {
        return Err(refused(
            "invalid_circle_access_window",
            b"expire_after_epoch must be greater than activate_after_epoch",
        ));
    }
    debit(ledger, tx)?;
    let mut storage = circle_store::load_storage(&state.snapshot(), &tx.to, None)
        .map_err(|e| refused("circle_stable_storage_invalid", e.0))?;
    let prefix = if locator.mode == LocatorMode::State {
        b"state_policy:".as_slice()
    } else {
        b"slot_policy:"
    };
    for (suffix, value) in [
        (b"delivery_key_id".as_slice(), payload.delivery_key_id),
        (
            b"activate_after_epoch",
            payload
                .activate_after_epoch
                .map(|v| v.to_string().into_bytes()),
        ),
        (
            b"expire_after_epoch",
            payload
                .expire_after_epoch
                .map(|v| v.to_string().into_bytes()),
        ),
        (b"tombstone", payload.tombstone.then(|| b"true".to_vec())),
        (b"revoked", payload.revoked.then(|| b"true".to_vec())),
    ] {
        let key = [prefix, &locator.key, b":", suffix].concat();
        match value {
            Some(value) => storage.replace(key, value),
            None => storage.remove(&key),
        }
    }
    for suffix in [
        b"activate_after_epoch".as_slice(),
        b"expire_after_epoch",
        b"tombstone",
        b"revoked",
    ] {
        storage.remove(&[b"mailbox:".as_slice(), &locator.key, b":", suffix].concat());
    }
    circle_store::save_storage(state, &tx.to, &storage, info.limits[0], info.limits[2])
        .map_err(|e| refused("circle_stable_storage_invalid", e.0))?;
    Ok(())
}
pub(crate) fn execute(
    tx: &Transaction,
    ledger: &mut Ledger,
    state: &mut StateBatch,
) -> std::result::Result<Completion, Error> {
    circle_error::completion(match tx.op_type {
        OpType::CircleAssetPut => public(tx, ledger, state),
        OpType::CircleAssetPutEncrypted => encrypted(tx, ledger, state, false),
        OpType::CircleSealedSlotPut => encrypted(tx, ledger, state, true),
        OpType::CircleSlotPolicyPut => slot_policy(tx, ledger, state),
        OpType::CircleStateDescriptorPut => descriptor(tx, ledger, state),
        _ => Err(unavailable("Circle resource operation host unavailable")),
    })
}
