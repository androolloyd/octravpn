// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native asset reads: RPC projections are separate from the browser's bounded
//! public-serving policy. Ciphertext never passes through a plaintext decoder.
use super::{error, load, policy, wire::Object};
use crate::{circle_store, circle_view, state_batch::Snapshot};
use octra_node_protocol::{
    circle_auth::{self, Auth, Gate},
    circle_policy::key,
    circles::{self, AssetMeta, Locator, ResourceMode},
    native_json::{Document, Value},
    rpc::{param_id, require_string, Fault},
};
mod render;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Plain,
    Path,
    Resource,
    Slot,
    State,
}
#[derive(Clone, Copy)]
pub struct Route {
    kind: Kind,
    authenticated: bool,
    primary: &'static [u8],
}
const ROUTES: &[(Kind, &[u8], &[u8])] = &[
    (Kind::Plain, b"circle_asset", b"octra_circleAsset"),
    (
        Kind::Path,
        b"circle_asset_ciphertext",
        b"octra_circleAssetCiphertext",
    ),
    (
        Kind::Resource,
        b"circle_asset_ciphertext_by_resource_key",
        b"octra_circleAssetCiphertextByResourceKey",
    ),
    (
        Kind::Slot,
        b"circle_asset_ciphertext_by_slot_ref",
        b"octra_circleAssetCiphertextBySlotRef",
    ),
    (
        Kind::State,
        b"circle_asset_ciphertext_by_state_ref",
        b"octra_circleAssetCiphertextByStateRef",
    ),
];
pub fn route(method: &[u8]) -> Option<Route> {
    ROUTES.iter().find_map(|&(kind, primary, alias)| {
        if method == primary || method == alias {
            Some(Route {
                kind,
                authenticated: false,
                primary,
            })
        } else if kind != Kind::Plain
            && (method.strip_suffix(b"_auth") == Some(primary)
                || method.strip_suffix(b"Auth") == Some(alias))
        {
            Some(Route {
                kind,
                authenticated: true,
                primary,
            })
        } else {
            None
        }
    })
}
pub struct Plan {
    route: Route,
    document: Document,
    params: Value,
    circle: usize,
    subject: usize,
    locator: Option<Locator>,
}
impl Route {
    pub fn prepare(self, doc: &Document, params: &Value) -> Result<Plan, Fault> {
        require_string(doc, params, 0, "circle_id")?;
        let field = match self.kind {
            Kind::Plain | Kind::Path => "path",
            Kind::Resource => "resource_key",
            Kind::Slot => "slot_ref",
            Kind::State => "state_ref",
        };
        let raw = require_string(doc, params, 1, field)?;
        let locator = match self.kind {
            Kind::Plain | Kind::Path => {
                let path = circles::normalize_path(raw).map_err(|e| Fault::invalid(&e.0))?;
                Some(Locator {
                    path_key: circles::path_key(path.as_bytes()),
                    canonical_path: path.into_bytes(),
                })
            }
            Kind::Slot => Some(circles::slot_locator(raw).map_err(|e| Fault::invalid(&e.0))?),
            Kind::State => Some(circles::state_locator(raw).map_err(|e| Fault::invalid(&e.0))?),
            Kind::Resource => None,
        };
        Ok(Plan {
            route: self,
            document: doc.clone(),
            params: params.clone(),
            circle: param_id(params, 0).expect("circle string"),
            subject: param_id(params, 1).expect("subject string"),
            locator,
        })
    }
}
impl Plan {
    fn bytes(&self, index: usize) -> &[u8] {
        let Some(Value::String(value)) = self.document.get(index) else {
            unreachable!("validated immutable arena string")
        };
        value
    }
    pub fn read(self, state: &Snapshot) -> Result<Vec<u8>, Fault> {
        let circle = self.bytes(self.circle);
        let raw_subject = self.bytes(self.subject);
        let epoch = if self.route.kind == Kind::Plain {
            0
        } else {
            circle_view::epoch(
                state.get(&[b"meta", b"last_epoch"]),
                circle_view::ReadKind::Policy,
            )
            .map_err(|e| error(e.to_string().as_bytes()))?
        };
        let info = if self.route.authenticated || self.route.kind != Kind::Resource {
            Some(load(state, circle)?)
        } else {
            None
        };
        if self.route.authenticated {
            let info = info.as_ref().expect("authenticated circle loaded");
            let (kind, subject) = match self.route.kind {
                Kind::Path => (
                    b"path".as_slice(),
                    self.locator
                        .as_ref()
                        .expect("path locator")
                        .canonical_path
                        .as_slice(),
                ),
                Kind::Resource => (b"resource_key".as_slice(), raw_subject),
                Kind::Slot => (b"slot_ref".as_slice(), raw_subject),
                Kind::State => (b"state_ref".as_slice(), raw_subject),
                Kind::Plain => unreachable!("no authenticated plaintext route"),
            };
            let subject = circle_auth::asset_subject(kind, subject);
            let op = [b"octra_".as_slice(), self.route.primary].concat();
            Auth::parse(&self.document, &self.params, [2, 3, 4])?.authorize(
                &info.privacy,
                &info.owner,
                Gate::Owner,
                &op,
                circle,
                &subject,
            )?;
        }
        let (path, path_key) = if let Some(locator) = &self.locator {
            (
                locator.canonical_path.clone(),
                locator.path_key.as_bytes().to_vec(),
            )
        } else {
            let key = state
                .get(&[b"circles", circle, b"assets", b"resource_keys", raw_subject])
                .ok_or_else(|| missing(b"circle ciphertext asset not found"))?;
            let meta = metadata(state, circle, key)?
                .ok_or_else(|| missing(b"circle ciphertext asset not found"))?;
            (meta.canonical_path, key.to_vec())
        };
        let info = match info {
            Some(info) => info,
            None => load(state, circle)?,
        };
        let meta = metadata(state, circle, &path_key)?;
        if self.route.kind == Kind::Plain {
            let meta = meta.ok_or_else(|| missing(b"circle asset not found"))?;
            if meta.body_mode == ResourceMode::Sealed || info.resource == b"sealed_read" {
                return Err(Fault::invalid(
                    b"circle asset is sealed; use circle_asset_ciphertext",
                ));
            }
            let body = state
                .get(&[
                    b"circles",
                    circle,
                    b"assets",
                    b"by_hash",
                    &path_key,
                    b"body_b64",
                ])
                .ok_or_else(|| missing(b"circle asset not found"))?;
            return Ok(render::plaintext(
                circle, &path, &path_key, &info, &meta, body,
            ));
        }
        let body = state.get(&[
            b"circles",
            circle,
            b"assets",
            b"by_hash",
            &path_key,
            b"ciphertext_b64",
        ]);
        let (Some(meta), Some(body)) = (meta, body) else {
            return Err(missing(b"circle ciphertext asset not found"));
        };
        if !visible(state, circle, &meta, epoch)? {
            return Err(missing(b"circle ciphertext asset not found"));
        }
        render::ciphertext(render::Ciphertext {
            state,
            circle,
            path: &path,
            path_key: &path_key,
            info: &info,
            meta: &meta,
            body,
            epoch,
            reveal: self.route.authenticated,
        })
    }
}
pub(super) fn missing(message: &[u8]) -> Fault {
    Fault::new(112, b"not found").string_data(message)
}
pub(super) fn unavailable(_: impl std::fmt::Display) -> Fault {
    Fault::new(110, b"service unavailable")
}
pub(super) fn metadata(
    state: &Snapshot,
    circle: &[u8],
    key: &[u8],
) -> Result<Option<AssetMeta>, Fault> {
    circle_store::asset_meta(state, circle, key).map_err(unavailable)
}
pub(super) fn visible(
    state: &Snapshot,
    circle: &[u8],
    meta: &AssetMeta,
    epoch: i64,
) -> Result<bool, Fault> {
    let policy = circle_store::resource_policy(state, circle, &meta.path_key, meta.locator_mode)
        .map_err(unavailable)?;
    // Resolve the key even when another flag already hides the resource, as
    // upstream does; a corrupt key read cannot turn into a committed absence.
    let delivery = policy::key_state(
        state,
        circle,
        policy.delivery_key.as_deref().or(meta.key_id.as_deref()),
        epoch,
    )?;
    let activate = policy
        .visibility
        .activate_after_epoch
        .or(meta.activate_after_epoch);
    let expire = policy
        .visibility
        .expire_after_epoch
        .or(meta.expire_after_epoch);
    Ok(!policy.visibility.tombstone
        && !policy.visibility.revoked
        && activate.is_none_or(|start| epoch >= start)
        && expire.is_none_or(|end| epoch < end)
        && delivery == key::State::Live)
}
pub(super) fn private_cell(
    out: &mut Object,
    state: &Snapshot,
    circle: &[u8],
    locator: &Locator,
    reference: &[u8],
    kind: octra_node_protocol::circle_records::Kind,
    epoch: i64,
) -> Result<(), Fault> {
    let not_found = if matches!(kind, octra_node_protocol::circle_records::Kind::BalanceCell) {
        b"circle balance cell not found".as_slice()
    } else {
        b"circle register cell not found"
    };
    let meta = metadata(state, circle, locator.path_key.as_bytes())?;
    let body = state.get(&[
        b"circles",
        circle,
        b"assets",
        b"by_hash",
        locator.path_key.as_bytes(),
        b"ciphertext_b64",
    ]);
    let (Some(meta), Some(body)) = (meta, body) else {
        return Err(missing(not_found));
    };
    if !visible(state, circle, &meta, epoch)? {
        return Err(missing(not_found));
    }
    let descriptor = circle_store::descriptor(state, circle, locator.path_key.as_bytes())
        .map_err(unavailable)?;
    let policy = circle_store::resource_policy(
        state,
        circle,
        locator.path_key.as_bytes(),
        circles::LocatorMode::State,
    )
    .map_err(unavailable)?;
    let policy_json = policy::encode(state, circle, &policy, epoch)?;
    let cell = circle_store::record(state, circle, kind, locator.path_key.as_bytes())
        .map_err(unavailable)?;
    out.string(b"state_ref", reference)
        .string(b"canonical_path", &locator.canonical_path)
        .string(b"path_key", locator.path_key.as_bytes())
        .string(b"ciphertext_b64", body)
        .string(b"content_type", &meta.content_type)
        .string(b"encoding", &meta.encoding)
        .string(b"size_bytes", meta.size_bytes.to_string().as_bytes())
        .string(b"metadata_mode", meta.metadata_mode.as_bytes())
        .optional(b"key_id", meta.key_id.as_deref())
        .optional(b"plaintext_hash", meta.plaintext_hash.as_deref())
        .optional(b"padding_class", meta.padding_class.as_deref())
        .boolean(b"descriptor_materialized", descriptor.is_some())
        .raw(b"descriptor", &descriptor.unwrap_or_default().encode())
        .raw(b"state_policy", &policy_json)
        .raw(kind.prefix(), &cell.encode())
        .boolean(
            &[kind.prefix(), b"_materialized"].concat(),
            cell.materialized(),
        );
    Ok(())
}
