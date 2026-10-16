// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Owner-authorized native reads. Public aliases validate shape and refuse
//! before touching private state; all authenticated work uses one snapshot.
use super::objects::Read as ObjectRead;
use super::{error, load, optional};
use crate::{circle_store, circle_transport_store, circle_view, state_batch::Snapshot};
use octra_node_protocol::{
    circle_auth::{Auth, Gate},
    circle_policy::key,
    circle_records::Kind,
    circles::{self, Locator},
    native_json::{Document, Value},
    rpc::{require_string, Fault},
    transaction::json_string,
};
#[derive(Clone, Copy)]
enum Read {
    Transport,
    Hfhe,
    Key,
    Storage,
    Dump,
    Slot,
    State,
    Descriptor,
    OutboxClaim,
    OutboxIntent,
    OutboxStatus,
    Ingress,
    Record(Kind),
    Object(ObjectRead),
    Cell(Kind),
}
pub struct Route {
    read: Read,
    primary: &'static [u8],
    alias: &'static [u8],
    field: Option<&'static str>,
    epoch: bool,
    denial: &'static [u8],
}
const ROUTES: &[Route] = &[
    Route {
        read: Read::Cell(Kind::BalanceCell),
        primary: b"circle_balance_cell",
        alias: b"octra_circleBalanceCell",
        field: Some("state_ref"),
        epoch: true,
        denial: b"authenticated circle balance cell read required",
    },
    Route {
        read: Read::Cell(Kind::RegisterCell),
        primary: b"circle_register_cell",
        alias: b"octra_circleRegisterCell",
        field: Some("state_ref"),
        epoch: true,
        denial: b"authenticated circle register cell read required",
    },
    Route {
        read: Read::Object(ObjectRead::Summary),
        primary: b"circle_object_summary",
        alias: b"octra_circleObjectSummary",
        field: Some("object_ref"),
        epoch: false,
        denial: b"authenticated circle object summary read required",
    },
    Route {
        read: Read::Object(ObjectRead::Members),
        primary: b"circle_object_members",
        alias: b"octra_circleObjectMembers",
        field: Some("object_ref"),
        epoch: false,
        denial: b"authenticated circle object members read required",
    },
    Route {
        read: Read::Object(ObjectRead::Detail),
        primary: b"circle_object_detail",
        alias: b"octra_circleObjectDetail",
        field: Some("object_ref"),
        epoch: false,
        denial: b"authenticated circle object detail read required",
    },
    Route {
        read: Read::Object(ObjectRead::Member),
        primary: b"circle_object_member",
        alias: b"octra_circleObjectMember",
        field: Some("object_ref"),
        epoch: false,
        denial: b"authenticated circle object member read required",
    },
    Route {
        read: Read::Object(ObjectRead::Refs),
        primary: b"circle_object_refs",
        alias: b"octra_circleObjectRefs",
        field: None,
        epoch: false,
        denial: b"authenticated circle object refs read required",
    },
    Route {
        read: Read::Object(ObjectRead::List),
        primary: b"circle_object_list",
        alias: b"octra_circleObjectList",
        field: None,
        epoch: false,
        denial: b"authenticated circle object list read required",
    },
    Route {
        read: Read::Record(Kind::BalanceBinding),
        primary: b"circle_balance_binding",
        alias: b"octra_circleBalanceBinding",
        field: Some("subject_addr"),
        epoch: false,
        denial: b"authenticated circle balance binding read required",
    },
    Route {
        read: Read::Record(Kind::RegisterBinding),
        primary: b"circle_register_binding",
        alias: b"octra_circleRegisterBinding",
        field: Some("register_ref"),
        epoch: false,
        denial: b"authenticated circle register binding read required",
    },
    Route {
        read: Read::Record(Kind::BalanceWorkflow),
        primary: b"circle_balance_workflow",
        alias: b"octra_circleBalanceWorkflow",
        field: Some("workflow_ref"),
        epoch: false,
        denial: b"authenticated circle balance workflow read required",
    },
    Route {
        read: Read::Record(Kind::RegisterWorkflow),
        primary: b"circle_register_workflow",
        alias: b"octra_circleRegisterWorkflow",
        field: Some("workflow_ref"),
        epoch: false,
        denial: b"authenticated circle register workflow read required",
    },
    Route {
        read: Read::Transport,
        primary: b"circle_transport_policy",
        alias: b"octra_circleTransportPolicy",
        field: None,
        epoch: false,
        denial: b"authenticated circle transport policy read required",
    },
    Route {
        read: Read::Hfhe,
        primary: b"circle_hfhe_policy",
        alias: b"octra_circleHfhePolicy",
        field: None,
        epoch: false,
        denial: b"authenticated circle hfhe policy read required",
    },
    Route {
        read: Read::Key,
        primary: b"circle_key_policy",
        alias: b"octra_circleKeyPolicy",
        field: Some("key_id"),
        epoch: true,
        denial: b"authenticated circle key policy read required",
    },
    Route {
        read: Read::Storage,
        primary: b"circle_storage",
        alias: b"octra_circleStorage",
        field: Some("key"),
        epoch: false,
        denial: b"authenticated circle storage read required",
    },
    Route {
        read: Read::Dump,
        primary: b"circle_storage_dump",
        alias: b"octra_circleStorageDump",
        field: None,
        epoch: false,
        denial: b"authenticated circle storage dump required",
    },
    Route {
        read: Read::Slot,
        primary: b"circle_slot_policy",
        alias: b"octra_circleSlotPolicy",
        field: Some("slot_ref"),
        epoch: true,
        denial: b"authenticated circle slot policy read required",
    },
    Route {
        read: Read::State,
        primary: b"circle_state_policy",
        alias: b"octra_circleStatePolicy",
        field: Some("state_ref"),
        epoch: true,
        denial: b"authenticated circle state policy read required",
    },
    Route {
        read: Read::Descriptor,
        primary: b"circle_state_descriptor",
        alias: b"octra_circleStateDescriptor",
        field: Some("state_ref"),
        epoch: false,
        denial: b"authenticated circle state descriptor read required",
    },
    Route {
        read: Read::OutboxClaim,
        primary: b"circle_outbox_claim",
        alias: b"octra_circleOutboxClaim",
        field: Some("intent_id"),
        epoch: true,
        denial: b"authenticated circle outbox read required",
    },
    Route {
        read: Read::OutboxIntent,
        primary: b"circle_outbox_intent",
        alias: b"octra_circleOutboxIntent",
        field: Some("intent_id"),
        epoch: false,
        denial: b"authenticated circle outbox read required",
    },
    Route {
        read: Read::OutboxStatus,
        primary: b"circle_outbox_status",
        alias: b"octra_circleOutboxStatus",
        field: Some("intent_id"),
        epoch: true,
        denial: b"authenticated circle outbox read required",
    },
    Route {
        read: Read::Ingress,
        primary: b"circle_ingress_packet",
        alias: b"octra_circleIngressPacket",
        field: Some("intent_id"),
        epoch: false,
        denial: b"authenticated circle ingress read required",
    },
];
pub fn find(method: &[u8]) -> Option<(&'static Route, bool)> {
    ROUTES.iter().find_map(|route| {
        if method == route.primary || method == route.alias {
            Some((route, false))
        } else if method.strip_suffix(b"_auth") == Some(route.primary)
            || method.strip_suffix(b"Auth") == Some(route.alias)
        {
            Some((route, true))
        } else {
            None
        }
    })
}
impl Route {
    pub fn deny(&self, doc: &Document, params: &Value) -> Fault {
        match self
            .parameters(doc, params)
            .and_then(|_| self.member_parameter(doc, params))
        {
            Ok(_) => error(self.denial),
            Err(error) => error,
        }
    }
    fn member_parameter<'a>(
        &self,
        doc: &'a Document,
        params: &Value,
    ) -> Result<Option<&'a [u8]>, Fault> {
        if matches!(self.read, Read::Object(ObjectRead::Member)) {
            require_string(doc, params, 2, "member_ref").map(Some)
        } else {
            Ok(None)
        }
    }
    fn parameters<'a>(
        &self,
        doc: &'a Document,
        params: &Value,
    ) -> Result<(&'a [u8], &'a [u8]), Fault> {
        let circle = require_string(doc, params, 0, "circle_id")?;
        let subject = self.field.map_or(Ok(b"".as_slice()), |field| {
            require_string(doc, params, 1, field)
        })?;
        Ok((circle, subject))
    }
    pub fn read(&self, state: &Snapshot, doc: &Document, params: &Value) -> Result<Vec<u8>, Fault> {
        let epoch = if self.epoch {
            circle_view::epoch(
                state.get(&[b"meta", b"last_epoch"]),
                circle_view::ReadKind::Policy,
            )
            .map_err(|reason| error(reason.to_string().as_bytes()))?
        } else {
            0
        };
        let (circle, subject) = self.parameters(doc, params)?;
        let member = self.member_parameter(doc, params)?;
        let normalized = match self.read {
            Read::Record(kind) => Some(
                kind.normalize_subject(subject)
                    .map_err(|reason| Fault::invalid(&reason.0))?,
            ),
            Read::Object(_) if self.field.is_some() => Some(
                Kind::ObjectBinding
                    .normalize_subject(subject)
                    .map_err(|reason| Fault::invalid(&reason.0))?,
            ),
            _ => None,
        };
        let subject = normalized.as_deref().unwrap_or(subject);
        let member = member
            .map(octra_node_protocol::circle_object::query::validate_member_ref)
            .transpose()
            .map_err(|reason| Fault::invalid(&reason.0))?;
        let locator = match self.read {
            Read::Slot => Some(circles::slot_locator(subject)),
            Read::State | Read::Descriptor | Read::Cell(_) => Some(circles::state_locator(subject)),
            _ => None,
        }
        .transpose()
        .map_err(|reason| Fault::invalid(&reason.0))?;
        let info = load(state, circle)?;
        let first = if member.is_some() {
            3
        } else if self.field.is_some() {
            2
        } else {
            1
        };
        let op = [b"octra_".as_slice(), self.primary].concat();
        let member_subject = member
            .as_ref()
            .map(|member| [subject, b"|", member].concat());
        Auth::parse(doc, params, [first, first + 1, first + 2])?.authorize(
            &info.privacy,
            &info.owner,
            Gate::Owner,
            &op,
            circle,
            member_subject.as_deref().unwrap_or(subject),
        )?;
        let mut out = base(circle);
        match self.read {
            Read::Cell(kind) => {
                let mut cell = super::wire::Object::new();
                cell.string(b"circle_id", circle);
                super::assets::private_cell(
                    &mut cell,
                    state,
                    circle,
                    locator.as_ref().expect("validated state locator"),
                    subject,
                    kind,
                    epoch,
                )?;
                return Ok(cell.finish());
            }
            Read::Transport => {
                let policy = circle_transport_store::policy(state, circle).map_err(unavailable)?;
                field(&mut out, b"policy", &policy.encode());
            }
            Read::Hfhe => {
                let policy = circle_store::hfhe_policy(state, circle).map_err(|_| resources())?;
                field(&mut out, b"policy", &policy.encode());
            }
            Read::Key => {
                let policy = circle_transport_store::key_policy(state, circle, subject)
                    .map_err(unavailable)?;
                let status = policy.state(epoch);
                string(&mut out, b"key_id", subject);
                string(&mut out, b"current_epoch", epoch.to_string().as_bytes());
                field(&mut out, b"live", boolean(status == key::State::Live));
                string(&mut out, b"state", status.as_bytes());
                field(&mut out, b"policy", &policy.encode(subject));
            }
            Read::Storage => {
                let value =
                    circle_store::inline(state, circle, subject).map_err(|_| resources())?;
                string(&mut out, b"key", subject);
                out.extend_from_slice(b",\"value\":");
                optional(&mut out, value.as_deref());
            }
            Read::Dump => storage_page(&mut out, state, circle)?,
            Read::Object(kind) => {
                super::objects::read(&mut out, state, circle, kind, subject, member.as_deref())?;
            }
            Read::Record(kind) => super::records::read(&mut out, state, circle, kind, subject)?,
            Read::OutboxClaim => super::outbox::claims(&mut out, state, circle, subject, epoch)?,
            Read::OutboxIntent => super::outbox::intent(&mut out, state, circle, subject)?,
            Read::OutboxStatus => super::outbox::status(&mut out, state, circle, subject, epoch)?,
            Read::Ingress => super::outbox::packet(&mut out, state, circle, subject)?,
            Read::Slot | Read::State => locator_policy(
                &mut out,
                state,
                circle,
                self.field.expect("locator field").as_bytes(),
                subject,
                locator.as_ref().expect("validated locator"),
                epoch,
                matches!(self.read, Read::State),
            )?,
            Read::Descriptor => {
                let locator = locator.expect("validated state locator");
                let descriptor =
                    circle_store::descriptor(state, circle, locator.path_key.as_bytes())
                        .map_err(|_| resources())?;
                string(&mut out, b"state_ref", subject);
                string(&mut out, b"canonical_path", &locator.canonical_path);
                string(&mut out, b"path_key", locator.path_key.as_bytes());
                field(&mut out, b"materialized", boolean(descriptor.is_some()));
                field(
                    &mut out,
                    b"descriptor",
                    &descriptor.unwrap_or_default().encode(),
                );
            }
        }
        out.push(b'}');
        Ok(out)
    }
}
fn resources() -> Fault {
    Fault::new(110, b"service unavailable")
}
pub(super) fn unavailable(reason: crate::circle_error::Failure) -> Fault {
    match reason.effect() {
        octra_node_protocol::circle_wasm::Error::Rejected(reason) => error(reason),
        octra_node_protocol::circle_wasm::Error::Unavailable(_) => resources(),
    }
}
pub(super) fn base(circle: &[u8]) -> Vec<u8> {
    let mut out = b"{\"circle_id\":".to_vec();
    json_string(&mut out, circle);
    out
}
pub(super) fn field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(b',');
    json_string(out, name);
    out.push(b':');
    out.extend_from_slice(value);
}
pub(super) fn string(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(b',');
    json_string(out, name);
    out.push(b':');
    json_string(out, value);
}
pub(super) fn boolean(value: bool) -> &'static [u8] {
    if value {
        b"true"
    } else {
        b"false"
    }
}
fn storage_page(out: &mut Vec<u8>, state: &Snapshot, circle: &[u8]) -> Result<(), Fault> {
    let page = circle_store::storage_page(state, circle, 128).map_err(|reason| {
        if reason.0 == b"circle stable storage contains non-inline values" {
            error(&reason.0)
        } else {
            resources()
        }
    })?;
    out.extend_from_slice(b",\"storage\":{");
    for (index, (key, value)) in page.entries.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        json_string(out, key);
        out.push(b':');
        json_string(out, value);
    }
    out.extend_from_slice(b"},\"storage_sizes\":{");
    for (index, (key, value)) in page.entries.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        json_string(out, key);
        out.push(b':');
        out.extend_from_slice(value.len().to_string().as_bytes());
    }
    out.extend_from_slice(
        format!(
            "}},\"count\":{},\"total\":{},\"has_more\":{}",
            page.entries.len(),
            page.total,
            page.entries.len() < page.total
        )
        .as_bytes(),
    );
    Ok(())
}
#[allow(clippy::too_many_arguments)] // Native locator response and captured epoch.
fn locator_policy(
    out: &mut Vec<u8>,
    state: &Snapshot,
    circle: &[u8],
    name: &[u8],
    subject: &[u8],
    locator: &Locator,
    epoch: i64,
    state_locator: bool,
) -> Result<(), Fault> {
    let mode = if state_locator {
        circles::LocatorMode::State
    } else {
        circles::LocatorMode::Slot
    };
    let policy = circle_store::resource_policy(state, circle, locator.path_key.as_bytes(), mode)
        .map_err(|_| resources())?;
    string(out, name, subject);
    string(out, b"canonical_path", &locator.canonical_path);
    string(out, b"path_key", locator.path_key.as_bytes());
    let fields = super::policy::encode(state, circle, &policy, epoch)?;
    // This trusted object has the native ordered policy fields, flattened into
    // the locator response rather than nested under a second policy member.
    out.push(b',');
    out.extend_from_slice(&fields[1..fields.len() - 1]);
    Ok(())
}
