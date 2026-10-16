// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    error,
    private::{base, boolean, field, string},
};
use crate::{circle_store, state_batch::Snapshot};
use octra_node_protocol::{
    circle_object::query::{Query, Summary},
    rpc::Fault,
    transaction::json_string,
};
#[derive(Clone, Copy)]
pub(super) enum Read {
    Summary,
    Members,
    Detail,
    Member,
    Refs,
    List,
}
fn strings(values: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![b'['];
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        json_string(&mut out, value);
    }
    out.push(b']');
    out
}
fn summary_fields(out: &mut Vec<u8>, summary: &Summary) {
    string(out, b"object_ref", &summary.object);
    field(
        out,
        b"binding_materialized",
        boolean(summary.binding.materialized()),
    );
    field(out, b"binding", &summary.binding.encode());
    field(
        out,
        b"policy_materialized",
        boolean(summary.policy.is_some()),
    );
    field(
        out,
        b"policy",
        &summary.policy.as_ref().map_or_else(
            || b"null".to_vec(),
            octra_node_protocol::circle_records::Record::encode,
        ),
    );
    field(
        out,
        b"active_member_count",
        summary.members.len().to_string().as_bytes(),
    );
    field(out, b"member_refs", &strings(&summary.members));
}
fn summary_json(circle: &[u8], summary: &Summary) -> Vec<u8> {
    let mut out = base(circle);
    summary_fields(&mut out, summary);
    out.push(b'}');
    out
}
pub(super) fn read(
    out: &mut Vec<u8>,
    state: &Snapshot,
    circle: &[u8],
    kind: Read,
    object: &[u8],
    member: Option<&[u8]>,
) -> Result<(), Fault> {
    let storage = circle_store::load_storage(state, circle, None).map_err(|reason| {
        if reason.0 == b"circle stable storage contains non-inline values" {
            error(&reason.0)
        } else {
            Fault::new(110, b"service unavailable")
        }
    })?;
    let query = Query::new(&storage);
    match kind {
        Read::Summary => summary_fields(out, &query.summary(object)),
        Read::Members => {
            let members = query.members(object);
            string(out, b"object_ref", object);
            field(out, b"member_count", members.len().to_string().as_bytes());
            out.extend_from_slice(b",\"members\":[");
            for (index, member) in members.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(b"{\"member_ref\":");
                json_string(out, &member.reference);
                field(out, b"member_state", &member.state.encode());
                out.push(b'}');
            }
            out.push(b']');
        }
        Read::Detail => {
            let detail = query.detail(object);
            string(out, b"object_ref", object);
            field(out, b"summary", &summary_json(circle, &detail.summary));
            field(
                out,
                b"current_state_descriptor_materialized",
                boolean(detail.current_descriptor.is_some()),
            );
            field(
                out,
                b"current_state_descriptor",
                &detail.current_descriptor.as_ref().map_or_else(
                    || b"null".to_vec(),
                    octra_node_protocol::circle_state::Descriptor::encode,
                ),
            );
            field(
                out,
                b"last_transition_materialized",
                boolean(detail.last_transition.is_some()),
            );
            field(
                out,
                b"last_transition",
                &detail.last_transition.as_ref().map_or_else(
                    || b"null".to_vec(),
                    octra_node_protocol::circle_records::Record::encode,
                ),
            );
        }
        Read::Member => {
            let member = query.member(object, member.expect("validated member parameter"));
            string(out, b"object_ref", object);
            string(out, b"member_ref", &member.reference);
            field(out, b"materialized", boolean(member.state.materialized()));
            field(out, b"member_state", &member.state.encode());
            field(
                out,
                b"descriptor_materialized",
                boolean(member.descriptor.is_some()),
            );
            field(
                out,
                b"descriptor",
                &member.descriptor.as_ref().map_or_else(
                    || b"null".to_vec(),
                    octra_node_protocol::circle_state::Descriptor::encode,
                ),
            );
        }
        Read::Refs => {
            let references = query.references();
            field(
                out,
                b"object_count",
                references.len().to_string().as_bytes(),
            );
            field(out, b"object_refs", &strings(&references));
        }
        Read::List => {
            let summaries = query.summaries();
            field(out, b"object_count", summaries.len().to_string().as_bytes());
            out.extend_from_slice(b",\"objects\":[");
            for (index, summary) in summaries.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(&summary_json(circle, summary));
            }
            out.push(b']');
        }
    }
    Ok(())
}
