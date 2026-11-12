// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Source metadata jobs hold their verification lease through publication.
//! Immutable hash-keyed records cannot become metadata for an upgraded program.
use super::{compile, Arc, Context, Document, Fault, Value};
use octra_node_protocol::{aml::rpc::verification, program_record::Record, rpc::require_address};
use octra_node_runtime::{
    canonical::RecordError,
    program::{source_read, store},
};
use std::sync::OnceLock;
static SOURCE_READER: OnceLock<source_read::Reader> = OnceLock::new();

fn projected(error: compile::Error) -> Fault {
    match error {
        compile::Error::Rpc(fault) => fault,
        compile::Error::Unavailable(_) => Fault::new(110, b"service unavailable"),
    }
}
fn record_error(error: RecordError) -> Fault {
    match error {
        RecordError::Conflict => {
            let mut fault = Fault::new(-32000, b"program record differs");
            fault.data = Some(b"{\"reason\":\"record_conflict\"}".to_vec());
            fault
        }
        RecordError::Invalid(reason) => Fault::new(-32000, reason),
        RecordError::Unavailable(_) => Fault::new(110, b"service unavailable"),
    }
}
fn source_entry(meta: Option<&store::Meta>) -> bool {
    meta.is_some_and(|meta| meta.admission == b"source")
}
pub(super) async fn verify(
    host: Arc<Context>,
    doc: Arc<Document>,
    params: Value,
) -> std::result::Result<Vec<u8>, Fault> {
    let prepared = verification::prepare(&doc, &params).map_err(projected)?;
    let lease: crate::executor::VerificationLease = host.executor.begin_verification()?;
    // Detach the complete protected job, including its final hash recheck and
    // auxiliary write. Cancelling an HTTP future cannot strand a held lease.
    tokio::spawn(async move {
        let _scope = lease.clone();
        let material = prepared.materialize(&doc).map_err(projected)?;
        let address = material.address().to_vec();
        let view = host
            .node
            .snapshot()
            .map_err(|_| Fault::new(110, b"service unavailable"))?;
        let encoded = view
            .state()
            .get(&[b"contracts", &address, b"bytecode"])
            .ok_or_else(|| {
                Fault::new(112, b"not found").string_data(b"contract not found or no bytecode")
            })?
            .to_vec();
        let meta = store::meta(view.state(), &address)
            .map_err(|_| Fault::new(110, b"service unavailable"))?;
        let verified = host
            .executor
            .verify_record(lease, material, source_entry(meta.as_ref()), encoded)
            .await?;
        let current = host
            .node
            .snapshot()
            .map_err(|_| Fault::new(110, b"service unavailable"))?;
        let meta = store::meta(current.state(), &address)
            .map_err(|_| Fault::new(110, b"service unavailable"))?
            .ok_or_else(|| Fault::new(112, b"not found").string_data(b"program not found"))?;
        if meta.code_hash != verified.record().code_hash {
            return Err(Fault::new(-32000, b"program changed during verification"));
        }
        let saved = committed_record(current.state(), &address, &meta.code_hash)?;
        let committed = saved
            .as_ref()
            .is_some_and(|record| record.matches_verification(verified.record()));
        let published = if committed {
            true
        } else if saved.is_some() || !source_entry(Some(&meta)) {
            false
        } else {
            host.node
                .program_records()
                .save(&verified)
                .await
                .map_err(record_error)?;
            true
        };
        let epoch = i64::try_from(current.head().cursor.epoch.0)
            .unwrap_or((1_i64 << 62) - 1)
            .saturating_add(1)
            .min((1_i64 << 62) - 1);
        let metered = octra_node_protocol::rules::program_inputs_at(
            host.node.chain().chain_id.as_bytes(),
            epoch,
        ) == octra_node_protocol::transaction::RuleMode::Active;
        verified
            .response_with(published, committed, metered)
            .map_err(projected)
    })
    .await
    .unwrap_or_else(|_| Err(Fault::new(110, b"service unavailable")))
}
fn committed_record(
    state: &octra_node_runtime::state_batch::Snapshot,
    address: &[u8],
    hash: &[u8],
) -> std::result::Result<Option<Record>, Fault> {
    let Some(raw) = state.get(&[b"contracts", address, b"record"]) else {
        return Ok(None);
    };
    if raw.len() > octra_node_protocol::program_record::source::MAX_BYTES {
        return Err(Fault::new(-32000, b"program record too large"));
    }
    let record = Record::decode(raw).map_err(|error| Fault::new(-32000, error.to_string()))?;
    Ok((record.code_hash == hash).then_some(record))
}
async fn current(
    host: &Context,
    address: &[u8],
) -> std::result::Result<(crate::Committed, Option<Record>, bool), Fault> {
    let view = host
        .node
        .snapshot()
        .map_err(|_| Fault::new(110, b"service unavailable"))?;
    let Some(meta) =
        store::meta(view.state(), address).map_err(|_| Fault::new(110, b"service unavailable"))?
    else {
        return Ok((view, None, false));
    };
    if let Some(record) = committed_record(view.state(), address, &meta.code_hash)? {
        return Ok((view, Some(record), true));
    }
    let record = host
        .node
        .program_records()
        .get(address, &meta.code_hash)
        .await
        .map_err(record_error)?;
    Ok((view, record, false))
}
pub(super) async fn source(
    host: &Context,
    doc: &Document,
    params: &Value,
) -> std::result::Result<Vec<u8>, Fault> {
    let address = require_address(doc, params, 0, "address")?;
    let (view, record, committed) = current(host, address).await?;
    let Some(mut record) = record else {
        return verification::source_response(None).map_err(projected);
    };
    let stored = view
        .state()
        .get(&[b"contracts", address, b"bytecode"])
        .map(<[u8]>::to_vec);
    let checked = SOURCE_READER
        .get_or_init(source_read::Reader::default)
        .query(stored, record.clone())
        .await;
    let mut extra = Vec::new();
    match checked {
        source_read::Outcome::Failed => {
            return Err(Fault::new(-32000, b"program source check unavailable"))
        }
        source_read::Outcome::Pending | source_read::Outcome::Different => {
            record.report = None;
            record.certificate = None;
            extra.extend_from_slice(b",\"verified\":false,\"verification_status\":");
            octra_node_protocol::transaction::json_string(
                &mut extra,
                if checked == source_read::Outcome::Pending {
                    b"pending"
                } else {
                    b"scope_unproven"
                },
            );
            extra.extend_from_slice(b",\"code_hash\":");
            octra_node_protocol::transaction::json_string(&mut extra, &record.code_hash);
        }
        source_read::Outcome::Checked => (),
    }
    let response = verification::source_response(Some(&record)).map_err(projected)?;
    let mut out = format!("{{\"committed\":{committed},").into_bytes();
    out.extend_from_slice(&response[1..response.len() - 1]);
    out.extend_from_slice(&extra);
    out.push(b'}');
    Ok(out)
}
pub(super) async fn abi(
    host: &Context,
    doc: &Document,
    params: &Value,
) -> std::result::Result<Vec<u8>, Fault> {
    let address = require_address(doc, params, 0, "address")?;
    let (view, record, _) = current(host, address).await?;
    if let Some(raw) = verification::abi_response(address, record.as_ref()).map_err(projected)? {
        return Ok(raw);
    }
    let epoch = i64::try_from(view.head().cursor.epoch.0)
        .ok()
        .filter(|epoch| *epoch < 1_i64 << 62)
        .ok_or_else(|| Fault::new(110, b"service unavailable"))?;
    let state = view.state().clone();
    let native = host.executor.clone();
    let address = address.to_vec();
    host.executor
        .read(move || native.program_abi(&state, &address, epoch))
        .await
}
