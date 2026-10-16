// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{circle_store, circles, policy, unavailable, AssetMeta, Fault, Object, Snapshot};
use crate::circle_store::Info;
use octra_node_protocol::circles::MetadataMode;
pub(super) fn plaintext(
    circle: &[u8],
    path: &[u8],
    key: &[u8],
    info: &Info,
    meta: &AssetMeta,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Object::new();
    out.string(b"circle_id", circle)
        .string(b"canonical_path", path)
        .string(b"path_key", key)
        .string(b"content_type", &meta.content_type)
        .string(b"encoding", &meta.encoding)
        .string(b"size_bytes", meta.size_bytes.to_string().as_bytes())
        .string(b"blob_hash", &meta.blob_hash)
        .string(b"resource_key", &meta.resource_key)
        .string(b"browser_mode", &info.browser)
        .string(b"resource_mode", &info.resource)
        .string(b"body_b64", body);
    out.finish()
}
pub(super) struct Ciphertext<'a> {
    pub state: &'a Snapshot,
    pub circle: &'a [u8],
    pub path: &'a [u8],
    pub path_key: &'a [u8],
    pub info: &'a Info,
    pub meta: &'a AssetMeta,
    pub body: &'a [u8],
    pub epoch: i64,
    pub reveal: bool,
}
// Preserve the native owned-input and typed diagnostic interface.
#[allow(clippy::needless_pass_by_value)]
pub(super) fn ciphertext(input: Ciphertext<'_>) -> Result<Vec<u8>, Fault> {
    let Ciphertext {
        state,
        circle,
        path,
        path_key,
        info,
        meta,
        body,
        epoch,
        reveal,
    } = input;
    let mut out = Object::new();
    out.string(b"circle_id", circle)
        .string(b"ciphertext_b64", body)
        .string(b"content_type", &meta.content_type)
        .string(b"encoding", &meta.encoding);
    if meta.metadata_mode == MetadataMode::Reveal {
        out.string(b"size_bytes", meta.size_bytes.to_string().as_bytes())
            .string(b"body_mode", meta.body_mode.as_bytes())
            .string(b"locator_mode", meta.locator_mode.as_bytes());
    }
    out.string(b"metadata_mode", meta.metadata_mode.as_bytes());
    if reveal {
        out.optional(b"slot_ref", meta.slot_ref.as_deref())
            .optional(
                b"state_ref",
                circles::state_ref_from_path(&meta.canonical_path).as_deref(),
            )
            .epoch(b"activate_after_epoch", meta.activate_after_epoch)
            .epoch(b"expire_after_epoch", meta.expire_after_epoch)
            .optional(b"plaintext_hash", meta.plaintext_hash.as_deref())
            .optional(b"key_id", meta.key_id.as_deref())
            .optional(b"padding_class", meta.padding_class.as_deref());
    }
    if meta.metadata_mode == MetadataMode::Reveal {
        out.string(b"browser_mode", &info.browser)
            .string(b"resource_mode", &info.resource);
    }
    if reveal {
        let policy = circle_store::resource_policy(state, circle, path_key, meta.locator_mode)
            .map_err(unavailable)?;
        policy::delivery_fields(
            &mut out,
            state,
            circle,
            policy.delivery_key.as_deref().or(meta.key_id.as_deref()),
            epoch,
            false,
        )?;
        if circles::state_ref_from_path(&meta.canonical_path).is_some() {
            let descriptor =
                circle_store::descriptor(state, circle, &meta.path_key).map_err(unavailable)?;
            out.boolean(b"state_descriptor_materialized", descriptor.is_some())
                .raw(
                    b"state_descriptor",
                    &descriptor.unwrap_or_default().encode(),
                );
        }
    }
    if meta.metadata_mode == MetadataMode::Reveal {
        out.string(b"canonical_path", path)
            .string(b"path_key", path_key)
            .string(b"blob_hash", &meta.blob_hash)
            .string(b"resource_key", &meta.resource_key);
    }
    Ok(out.finish())
}
