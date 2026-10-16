// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native writes use exactly the authenticated, durable queue intake used by
//! proposal construction. An accepted row is not a finalized receipt.
use super::{Arc, Context, Document, Fault, Value};
use octra_node_protocol::{submit_rpc as wire, transaction::json_string};
use octra_node_runtime::admission;

fn failure(error: admission::Error, private: bool) -> Fault {
    match error {
        admission::Error::Rejected(error) if private => {
            Fault::new(-32000, format!("{}: {}", error.tag, error.reason))
        }
        admission::Error::Rejected(error) => wire::refusal(error.tag, &error.reason),
        admission::Error::Unavailable(_) => Fault::new(110, b"service unavailable"),
    }
}
async fn accepted(
    host: &Context,
    tx: octra_node_protocol::transaction::Transaction,
) -> std::result::Result<Vec<u8>, admission::Error> {
    let hash = host.submit_native(tx).await?;
    // Durable admission has succeeded even if the peer queue is temporarily full.
    let _ = host.announce(hash.clone(), None).await;
    Ok(hash)
}
pub(super) async fn write(
    host: &Arc<Context>,
    method: &[u8],
    doc: Arc<Document>,
    params: Value,
) -> std::result::Result<Vec<u8>, Fault> {
    if method == b"octra_recommendedFee" {
        let pending = host.pending.clone();
        let fees = host.fees.clone();
        return host
            .executor
            .read(move || {
                use rand::Rng;
                let (total, size) = pending
                    .inspect(|pool| (pool.total_ou().clone(), pool.len()))
                    .map_err(|_| Fault::new(110, b"service unavailable"))?;
                Ok(fees.response(&doc, &params, &total, size, |range| {
                    rand::thread_rng().gen_range(0..range)
                }))
            })
            .await;
    }
    if method == b"octra_submitBatch" {
        let transactions = host
            .executor
            .read(move || {
                let entries = wire::batch(&doc, &params)?;
                Ok(entries
                    .iter()
                    .map(|id| {
                        doc.get(*id)
                            .ok_or_else(|| "invalid tx".into())
                            .and_then(|value| wire::decode(&doc, value))
                    })
                    .collect::<Vec<_>>())
            })
            .await?;
        let total = transactions.len();
        let mut count = 0;
        let mut rows = Vec::with_capacity(total);
        for tx in transactions {
            let row = match tx {
                Err(reason) => wire::batch_row(Err(&reason), None),
                Ok(tx) => {
                    let nonce = tx.nonce;
                    match accepted(host, tx).await {
                        Ok(hash) => {
                            count += 1;
                            wire::batch_row(Ok(&hash), Some(nonce))
                        }
                        Err(admission::Error::Rejected(error)) => {
                            wire::batch_row(Err(&error.reason), Some(nonce))
                        }
                        Err(admission::Error::Unavailable(_)) => {
                            wire::batch_row(Err("service unavailable"), Some(nonce))
                        }
                    }
                }
            };
            rows.push(row);
        }
        let mut out = format!(
            "{{\"total\":{total},\"accepted\":{count},\"rejected\":{},\"results\":[",
            total - count
        )
        .into_bytes();
        for (index, row) in rows.into_iter().enumerate() {
            if index != 0 {
                out.push(b',');
            }
            out.extend(row);
        }
        out.extend_from_slice(b"]}");
        return Ok(out);
    }
    let private = method == b"octra_privateTransfer";
    let tx = host
        .executor
        .read(move || {
            if private {
                wire::private_transfer(&doc, &params)
            } else {
                wire::submit(&doc, &params)
            }
        })
        .await?;
    let hash = accepted(host, tx.clone())
        .await
        .map_err(|error| failure(error, private))?;
    if private {
        let mut out = b"{\"tx_hash\":".to_vec();
        json_string(&mut out, &hash);
        out.extend_from_slice(b",\"status\":\"pending\"}");
        Ok(out)
    } else {
        Ok(wire::accepted(&hash, &tx, &host.fees.stealth_minimum))
    }
}
