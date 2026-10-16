// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Source metadata jobs hold their verification lease through publication.
//! Immutable hash-keyed records cannot become metadata for an upgraded program.
use super::{compile, Arc, Context, Document, Fault, Value};
use octra_node_protocol::{aml::rpc::verification, program_record::Record, rpc::require_address};
use octra_node_runtime::{canonical::RecordError, program::store};

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
        if !verified.publishable() {
            return verified.response(false).map_err(projected);
        }
        if !source_entry(Some(&meta)) {
            return Err(Fault::new(-32000, b"program changed during verification"));
        }
        host.node
            .program_records()
            .save(&verified)
            .await
            .map_err(record_error)?;
        verified.response(true).map_err(projected)
    })
    .await
    .unwrap_or_else(|_| Err(Fault::new(110, b"service unavailable")))
}
async fn current(
    host: &Context,
    address: &[u8],
) -> std::result::Result<(crate::Committed, Option<Record>), Fault> {
    let first = host
        .node
        .snapshot()
        .map_err(|_| Fault::new(110, b"service unavailable"))?;
    let meta =
        store::meta(first.state(), address).map_err(|_| Fault::new(110, b"service unavailable"))?;
    let Some(meta) = meta.filter(|meta| source_entry(Some(meta))) else {
        return Ok((first, None));
    };
    let record = host
        .node
        .program_records()
        .get(address, &meta.code_hash)
        .await
        .map_err(record_error)?;
    let next = host
        .node
        .snapshot()
        .map_err(|_| Fault::new(110, b"service unavailable"))?;
    match store::meta(next.state(), address).map_err(|_| Fault::new(110, b"service unavailable"))? {
        Some(current) if current.code_hash == meta.code_hash && source_entry(Some(&current)) => {
            Ok((next, record))
        }
        Some(_) => Err(Fault::new(-32000, b"program changed during metadata read")),
        None => Err(Fault::new(
            -32000,
            b"program disappeared during metadata read",
        )),
    }
}
pub(super) async fn source(
    host: &Context,
    doc: &Document,
    params: &Value,
) -> std::result::Result<Vec<u8>, Fault> {
    let address = require_address(doc, params, 0, "address")?;
    let (_, record) = current(host, address).await?;
    verification::source_response(record.as_ref()).map_err(projected)
}
pub(super) async fn abi(
    host: &Context,
    doc: &Document,
    params: &Value,
) -> std::result::Result<Vec<u8>, Fault> {
    let address = require_address(doc, params, 0, "address")?;
    let (view, record) = current(host, address).await?;
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
