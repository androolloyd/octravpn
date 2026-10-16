//! Rest_read_rpc projections over the native queue and a captured committed tree.
use super::{
    account_store, array, balance, boolean, counter, fields, fields_with_message, is_valid_address,
    message, number, object, rpc, string, unavailable, Arc, BigInt, Context, Document, Fault,
    StateBatch, Value,
};
use octra_node_protocol::{
    native_integer::parse_int63, native_table::Table, network::endpoint::native_trim,
};
use octra_node_runtime::staging::{public_cost, Pool, MAX_OU};

fn epoch_list(doc: &Document, params: &Value, epoch: i64) -> std::result::Result<Vec<u8>, Fault> {
    let integer = |key: &[u8], index, default| match params {
        Value::Object(_) => match doc.field(params, key) {
            Some(Value::Int(value)) => value.get(),
            _ => default,
        },
        _ => rpc::param_int(doc, params, index).unwrap_or(default),
    };
    let limit = integer(b"limit", 0, 25).min(100);
    let offset = integer(b"offset", 1, 0);
    let start = counter(counter(epoch.wrapping_sub(1)).wrapping_sub(offset));
    let count = limit.min(counter(start.wrapping_add(1)).max(0));
    // Native List.init rejects a negative length; do not silently clamp a
    // malformed request into a successful, apparently complete empty page.
    if count < 0 {
        return Err(Fault::new(-32603, b"internal error"));
    }
    Ok(object(&[
        ("total", number(epoch)),
        (
            "epochs",
            array((0..count).map(|index| number(counter(start.wrapping_sub(index))))),
        ),
        ("has_more", boolean(counter(start.wrapping_sub(limit)) >= 0)),
    ]))
}
fn staging(pool: &Pool, method: &[u8]) -> std::result::Result<Vec<u8>, Fault> {
    let size = pool.len();
    let total = pool.total_ou();
    if method == b"staging_view" {
        let rows = pool
            .recent(64)
            .map(|entry| {
                let message_size = entry.tx.message.as_ref().map_or(0, Vec::len);
                let truncated = message_size > 4096;
                let mut row = vec![
                    ("hash", string(&entry.hash)),
                    ("message_size", number(message_size)),
                    ("message_truncated", boolean(truncated)),
                ];
                row.extend(fields_with_message(
                    &entry.tx,
                    if truncated {
                        b"null".to_vec()
                    } else {
                        message(&entry.tx)?
                    },
                )?);
                Ok(object(&row))
            })
            .collect::<std::result::Result<Vec<_>, Fault>>()?;
        return Ok(object(&[
            ("count", number(rows.len())),
            ("total", number(size)),
            ("truncated", boolean(rows.len() < size)),
            ("transactions", array(rows)),
        ]));
    }
    let sample = pool.sample(256).collect::<Vec<_>>();
    let sample_size = sample.len();
    if method == b"staging_stats" {
        let mut senders = Table::<(usize, BigInt)>::new(50);
        for entry in sample {
            let (count, value) = senders
                .get(&entry.tx.from)
                .cloned()
                .unwrap_or((0, 0.into()));
            senders.replace(
                entry.tx.from.clone(),
                (count + 1, value + public_cost(&entry.tx)),
            );
        }
        let mut rows = senders
            .iter()
            .map(|(address, (count, value))| {
                object(&[
                    ("address", string(address)),
                    ("tx_count", number(count)),
                    ("total_value", string(balance(value))),
                ])
            })
            .collect::<Vec<_>>();
        rows.reverse(); // Native Hashtbl.fold conses each row onto the result.
        return Ok(object(&[
            ("total_transactions", number(size)),
            ("sample_size", number(sample_size)),
            ("sample_truncated", boolean(sample_size < size)),
            ("total_ou", string(total.to_string())),
            ("max_ou", string(MAX_OU.to_string())),
            (
                "ou_remaining",
                string((BigInt::from(MAX_OU) - total).to_string()),
            ),
            ("by_sender", array(rows)),
        ]));
    }
    let mut fees = sample
        .iter()
        .map(|entry| entry.tx.ou.clone())
        .collect::<Vec<_>>();
    fees.sort();
    let percentile = |n: usize| {
        fees.get((n * sample_size / 100).min(sample_size.saturating_sub(1)))
            .map_or_else(|| "0".into(), ToString::to_string)
    };
    Ok(object(&[
        ("staging_size", number(size)),
        ("sample_size", number(sample_size)),
        ("sample_truncated", boolean(sample_size < size)),
        ("p50", string(percentile(50))),
        ("p75", string(percentile(75))),
        ("p95", string(percentile(95))),
        (
            "recommended",
            string(if sample_size < 10 {
                "1000".into()
            } else {
                percentile(60)
            }),
        ),
        ("staging_ou", string(total.to_string())),
        ("epoch_capacity", string(MAX_OU.to_string())),
    ]))
}
pub(in super::super) async fn read(
    host: &Arc<Context>,
    method: &[u8],
    doc: Arc<Document>,
    params: Value,
) -> std::result::Result<Vec<u8>, Fault> {
    match method {
        b"epoch_current" | b"epoch_list" => {
            let status = host.node.legacy_status().map_err(unavailable)?;
            if method == b"epoch_current" {
                Ok(object(&[
                    ("epoch_id", number(status.epoch)),
                    ("roots", number(status.roots)),
                ]))
            } else {
                epoch_list(&doc, &params, status.epoch)
            }
        }
        b"staging_view" | b"staging_stats" | b"staging_estimateOu" => {
            let pending = host.pending.clone();
            let method = method.to_vec();
            host.executor
                .read(move || {
                    pending
                        .inspect(|pool| staging(pool, &method))
                        .map_err(unavailable)?
                })
                .await
        }
        b"octra_search" => search(host, doc, params).await,
        _ => Err(Fault::missing(method)),
    }
}
async fn search(
    host: &Arc<Context>,
    doc: Arc<Document>,
    params: Value,
) -> std::result::Result<Vec<u8>, Fault> {
    let query = native_trim(rpc::require_string(&doc, &params, 0, "query")?).to_vec();
    if query.len() < 3 {
        return Err(Fault::invalid(b"query too short (min 3 chars)"));
    }
    if query.len() == 64
        && query
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        let pending = host.pending.clone();
        let hash = query.clone();
        let response = host
            .executor
            .read(move || {
                pending
                    .inspect(|pool| {
                        pool.find(&hash)
                            .map(|tx| {
                                Ok(object(&[
                                    ("type", string(b"transaction")),
                                    ("status", string(b"pending")),
                                    ("hash", string(&hash)),
                                    ("data", object(&fields(tx)?)),
                                ]))
                            })
                            .transpose()
                    })
                    .map_err(unavailable)?
            })
            .await?;
        if let Some(response) = response {
            return Ok(response);
        }
        let head = host.node.head().await.map_err(unavailable)?;
        if let Some((head, _)) = host
            .node
            .reader()
            .transaction(&head, &query, i64::MAX as usize - 1)
            .await
            .map_err(unavailable)?
        {
            return Ok(object(&[
                ("type", string(b"transaction")),
                ("status", string(b"confirmed")),
                ("hash", string(query)),
                ("epoch", number(head.cursor.epoch.0)),
            ]));
        }
        return Err(Fault::new(112, b"not found").string_data(b"no match"));
    }
    if is_valid_address(&query) {
        let view = host.node.snapshot().map_err(unavailable)?;
        return host
            .executor
            .read(move || {
                let account =
                    account_store::load(&StateBatch::from_snapshot(view.state().clone()), &query)
                        .map_err(unavailable)?
                        .ok_or_else(|| {
                            Fault::new(112, b"not found").string_data(b"address not found")
                        })?;
                Ok(object(&[
                    ("type", string(b"account")),
                    ("address", string(query)),
                    ("balance", string(balance(&account.balance))),
                    ("nonce", number(account.nonce.get())),
                ]))
            })
            .await;
    }
    if let Some(epoch) = parse_int63(&query) {
        let head = host.node.head().await.map_err(unavailable)?;
        if host
            .node
            .epoch_summary(&head, epoch)
            .await
            .map_err(unavailable)?
            .is_some()
        {
            return Ok(object(&[
                ("type", string(b"epoch")),
                ("epoch_id", number(epoch)),
            ]));
        }
        return Err(Fault::new(112, b"not found").string_data(b"epoch not found"));
    }
    Err(Fault::new(112, b"not found").string_data(b"no match"))
}
