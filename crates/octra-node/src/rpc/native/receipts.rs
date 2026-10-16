// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Context, Document, Fault, Value};
use octra_node_protocol::{native_json::ReadError, rpc::require_hash, transaction::json_string};

pub(super) async fn read(
    host: &Context,
    doc: &Document,
    params: &Value,
) -> std::result::Result<Vec<u8>, Fault> {
    let hash = require_hash(doc, params, 0, "hash")?;
    let snapshot = host
        .node
        .snapshot()
        .map_err(|_| Fault::new(110, b"service unavailable"))?;
    let raw = host
        .node
        .vm_receipt(snapshot.head(), hash)
        .await
        .map_err(|_| Fault::new(110, b"service unavailable"))?
        .ok_or_else(|| Fault::new(112, b"not found").string_data(b"receipt not found"))?;
    // Match Safe JSON projection, including the legacy raw-string fallback.
    host.executor
        .read(move || {
            match Document::parse_native(&raw, octra_node_protocol::native_json::ReadMode::Safe) {
                Ok(document) => document
                    .write(document.root(), false)
                    .map_err(|_| Fault::new(110, b"service unavailable")),
                Err(ReadError::Json { .. }) => {
                    let mut out = Vec::new();
                    json_string(&mut out, &raw);
                    Ok(out)
                }
                Err(ReadError::Unavailable(_)) => Err(Fault::new(110, b"service unavailable")),
            }
        })
        .await
}
