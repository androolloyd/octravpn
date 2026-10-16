//! Native history projections over authenticated, bounded local archive reads.
use super::{
    array, balance, boolean, display_from, display_to, float, load, number, object, rpc, string,
    unavailable, Arc, Context, Document, DropReason, Fault, OpType, Transaction, Value,
};
use octra_exex::native_history::NativeTransaction;
use octra_node_runtime::canonical::{
    Head, HistoryPage, HistoryQuery, HistoryReadError, RejectionPage, RejectionRecord,
};
mod projection;
use projection::summary;

#[derive(Clone, Copy)]
struct Page {
    limit: usize,
    offset: u64,
}
#[derive(Clone, Copy)]
enum Projection {
    Summary,
    Recent,
    Account,
    Transactions,
}
struct ConfirmedRow {
    hash: String,
    from: Vec<u8>,
    to: Vec<u8>,
    json: Vec<u8>,
}
type ConfirmedPage = HistoryPage<ConfirmedRow>;
struct RejectedRow {
    hash: String,
    json: Vec<u8>,
}
type RejectedPage = RejectionPage<RejectedRow>;
#[derive(Clone, Copy)]
enum RejectedProjection {
    Summary,
    Account,
    Lookup,
}
fn history_fault(error: HistoryReadError<Fault>) -> Fault {
    match error {
        HistoryReadError::Canonical(error) => unavailable(error),
        HistoryReadError::Projection(error) => error,
        HistoryReadError::ResponseLimit => Fault::response_limit(),
    }
}
fn project(
    head: &Head,
    record: NativeTransaction,
    projection: Projection,
) -> std::result::Result<(ConfirmedRow, usize), Fault> {
    let tx =
        Transaction::from_document(&Document::parse(&record.transaction).map_err(unavailable)?)
            .map_err(unavailable)?;
    let json = match projection {
        Projection::Summary => summary(head, &record)?,
        Projection::Recent => projection::prefix(head, &record)?,
        Projection::Account => hash_summary(head.cursor.epoch.0, &record.hash),
        Projection::Transactions => object(&[
            ("hash", string(&record.hash)),
            ("epoch", number(head.cursor.epoch.0)),
        ]),
    };
    let size = json.len().saturating_add(1);
    Ok((
        ConfirmedRow {
            hash: record.hash,
            from: tx.from,
            to: tx.to,
            json,
        },
        size,
    ))
}
fn page(doc: &Document, params: &Value, index: usize, maximum: i64, default: usize) -> Page {
    Page {
        limit: rpc::param_int(doc, params, index)
            .map_or(default, |value| value.clamp(0, maximum) as usize),
        offset: rpc::param_int(doc, params, index + 1).unwrap_or(0).max(0) as u64,
    }
}
async fn confirmed(
    host: &Arc<Context>,
    head: &Head,
    query: &HistoryQuery,
    page: Page,
) -> std::result::Result<ConfirmedPage, Fault> {
    confirmed_as(host, head, query, page, Projection::Summary).await
}
async fn confirmed_as(
    host: &Arc<Context>,
    head: &Head,
    query: &HistoryQuery,
    page: Page,
    projection: Projection,
) -> std::result::Result<ConfirmedPage, Fault> {
    host.node
        .reader()
        .transactions_projected(
            head,
            query,
            page.limit,
            page.offset,
            rpc::MAX_SINGLE,
            move |head, record| std::future::ready(project(&head, record, projection)),
        )
        .await
        .map_err(history_fault)
}
async fn address_confirmed(
    host: &Arc<Context>,
    head: &Head,
    query: &HistoryQuery,
    page: Page,
    strict: bool,
    projection: Projection,
) -> std::result::Result<ConfirmedPage, Fault> {
    let address = query.address.as_deref().expect("address history");
    let total = confirmed(
        host,
        head,
        query,
        Page {
            limit: 0,
            offset: 0,
        },
    )
    .await?
    .total;
    let scan = (page.limit.saturating_mul(4).max(64) as u64).min(total.saturating_sub(page.offset));
    let mut result = confirmed_as(
        host,
        head,
        query,
        Page {
            limit: scan as usize,
            offset: page.offset,
        },
        projection,
    )
    .await?;
    let mut rows = Vec::new();
    for row in result.rows {
        if row.from == address || row.to == address {
            rows.push(row);
        }
    }
    result.total = if page.offset == 0 && scan == total {
        rows.len() as u64
    } else {
        total
    };
    let needed = (page.limit as u64).min(result.total.saturating_sub(page.offset)) as usize;
    rows.truncate(needed);
    if strict && rows.len() != needed {
        let mut fault = Fault::new(116, b"history index incomplete");
        fault.data = Some(object(&[
            (
                "detail",
                string([b"address history incomplete for ".as_slice(), address].concat()),
            ),
            ("address", string(address)),
            ("offset", number(page.offset)),
            ("limit", number(page.limit)),
            ("missing", number(0)),
        ]));
        return Err(fault);
    }
    result.rows = rows;
    Ok(result)
}
async fn rejected(
    host: &Arc<Context>,
    head: &Head,
    query: &HistoryQuery,
    page: Page,
) -> std::result::Result<RejectedPage, Fault> {
    rejected_as(host, head, query, page, RejectedProjection::Summary).await
}
async fn rejected_as(
    host: &Arc<Context>,
    head: &Head,
    query: &HistoryQuery,
    page: Page,
    projection: RejectedProjection,
) -> std::result::Result<RejectedPage, Fault> {
    // Sorted history needs only its current epoch's authenticated partition.
    // Never retain all private receipt payloads across a large public page.
    let cache = Arc::new(std::sync::Mutex::new(
        None::<(
            Head,
            Vec<octra_node_protocol::transaction_outcome::Rejection>,
        )>,
    ));
    host.node
        .reader()
        .rejections_projected(
            head,
            query,
            page.limit,
            page.offset,
            rpc::MAX_SINGLE,
            move |row| {
                let host = host.clone();
                let cache = cache.clone();
                async move {
                    let saved = {
                        let cache = cache.lock().map_err(unavailable)?;
                        cache
                            .as_ref()
                            .filter(|(head, _)| head == &row.head)
                            .map(|(_, items)| items.contains(&row.rejection))
                    };
                    let matched = if let Some(matched) = saved {
                        matched
                    } else {
                        let record = host
                            .finality
                            .record(row.head.cursor.sequence)
                            .await
                            .map_err(unavailable)?;
                        if record.epoch_id != row.head.cursor.epoch.0 as i64
                            || record.state_root != row.head.cursor.state_root.0
                        {
                            return Err(unavailable("rejection finality head differs"));
                        }
                        let partition = octra_node_protocol::transaction_outcome::split(
                            &record.receipts_json,
                            false,
                        )
                        .map_err(unavailable)?;
                        let matched = partition.rejections.contains(&row.rejection);
                        *cache.lock().map_err(unavailable)? =
                            Some((row.head.clone(), partition.rejections));
                        matched
                    };
                    if !matched {
                        return Err(unavailable("rejection receipt differs"));
                    }
                    let hash = hex::encode(row.rejection.tx.hash().map_err(unavailable)?);
                    let json = match projection {
                        RejectedProjection::Summary => rejection_summary(&row)?,
                        RejectedProjection::Account => hash_summary(row.head.cursor.epoch.0, &hash),
                        RejectedProjection::Lookup => rejection_lookup(&row, hash.as_bytes())?,
                    };
                    let size = json.len().saturating_add(1);
                    Ok((RejectedRow { hash, json }, size))
                }
            },
        )
        .await
        .map_err(history_fault)
}
fn rejection_summary(row: &RejectionRecord) -> std::result::Result<Vec<u8>, Fault> {
    let tx = &row.rejection.tx;
    let hash = hex::encode(tx.hash().map_err(unavailable)?);
    let time = row
        .observed_at
        .ok_or_else(|| Fault::new(110, b"service unavailable"))?;
    Ok(object(&[
        ("hash", string(hash)),
        ("epoch", number(row.head.cursor.epoch.0)),
        ("from", string(&tx.from)),
        ("to", string(&tx.to)),
        ("amount", string(tx.amount.to_string())),
        ("nonce", number(tx.nonce.get())),
        ("error_type", string(&row.rejection.error_type)),
        ("reason", string(&row.rejection.reason)),
        ("timestamp", float(time)?),
        ("type", string(b"rejected")),
    ]))
}
pub(super) async fn rejected_hash(
    host: &Arc<Context>,
    head: &Head,
    hash: &[u8],
) -> std::result::Result<Option<Vec<u8>>, Fault> {
    let query = HistoryQuery {
        hash: Some(hash.to_vec()),
        ..HistoryQuery::default()
    };
    let result = rejected_as(
        host,
        head,
        &query,
        Page {
            limit: 1,
            offset: 0,
        },
        RejectedProjection::Lookup,
    )
    .await?;
    Ok(result.rows.into_iter().next().map(|row| row.json))
}
fn rejection_lookup(row: &RejectionRecord, hash: &[u8]) -> std::result::Result<Vec<u8>, Fault> {
    let tx = &row.rejection.tx;
    let time = row
        .observed_at
        .ok_or_else(|| Fault::new(110, b"service unavailable"))?;
    // Native rejection projections preserve stored addresses; unlike confirmed
    // summaries they do not carry an op_type field for mask_stealth_rows.
    Ok(object(&[
        ("status", string(b"rejected")),
        ("tx_hash", string(hash)),
        ("epoch", number(row.head.cursor.epoch.0)),
        (
            "error",
            object(&[
                ("type", string(&row.rejection.error_type)),
                ("reason", string(&row.rejection.reason)),
            ]),
        ),
        ("from", string(&tx.from)),
        ("to", string(&tx.to)),
        ("amount", string(tx.amount.to_string())),
        ("nonce", number(tx.nonce.get())),
        ("rejected_at", float(time)?),
        ("source", string(b"rejected_txs")),
    ]))
}
#[allow(clippy::unnecessary_wraps)] // Keep the shared fallible history projection interface.
fn summaries(page: &ConfirmedPage) -> std::result::Result<Vec<Vec<u8>>, Fault> {
    Ok(page.rows.iter().map(|row| row.json.clone()).collect())
}
#[allow(clippy::unnecessary_wraps)] // Keep the shared fallible history projection interface.
fn rejection_summaries(page: &RejectedPage) -> std::result::Result<Vec<Vec<u8>>, Fault> {
    Ok(page.rows.iter().map(|row| row.json.clone()).collect())
}
fn hash_summary(epoch: u64, hash: impl AsRef<[u8]>) -> Vec<u8> {
    object(&[("epoch", number(epoch)), ("hash", string(hash))])
}
async fn dropped_by_address(
    host: &Arc<Context>,
    head: &Head,
    address: &[u8],
    page: Page,
    rows: &ConfirmedPage,
    rejections: &RejectedPage,
) -> std::result::Result<(Vec<Vec<u8>>, bool), Fault> {
    let pending = host.pending.clone();
    let addr = address.to_vec();
    let drops = host
        .executor
        .read(move || pending.drops(&addr).map_err(unavailable))
        .await;
    let Ok(mut drops) = drops else {
        return Ok((Vec::new(), false));
    };
    drops.sort_by(|a, b| {
        b.timestamp
            .partial_cmp(&a.timestamp)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.hash.cmp(&a.hash))
    });
    let mut result = Vec::new();
    for row in drops
        .into_iter()
        .skip(usize::try_from(page.offset).unwrap_or(usize::MAX))
        .take(page.limit)
    {
        if matches!(row.operation, OpType::Stealth | OpType::Claim) {
            continue;
        }
        if rows
            .rows
            .iter()
            .any(|record| record.hash.as_bytes() == row.hash)
            || rejections
                .rows
                .iter()
                .any(|record| record.hash.as_bytes() == row.hash)
        {
            continue;
        }
        let query = row.hash.clone();
        let pending = host.pending.clone();
        if host
            .executor
            .read(move || {
                pending
                    .inspect(|pool| pool.find(&query).is_some())
                    .map_err(unavailable)
            })
            .await?
        {
            continue;
        }
        if host
            .node
            .reader()
            .transaction(head, &row.hash, i64::MAX as usize - 1)
            .await
            .map_err(unavailable)?
            .is_some()
        {
            continue;
        }
        let query = HistoryQuery {
            hash: Some(row.hash.clone()),
            ..HistoryQuery::default()
        };
        if rejected(
            host,
            head,
            &query,
            Page {
                limit: 1,
                offset: 0,
            },
        )
        .await?
        .total
            != 0
        {
            continue;
        }
        result.push(object(&[
            ("hash", string(&row.hash)),
            ("tx_hash", string(&row.hash)),
            ("status", string(b"dropped")),
            ("from", string(&row.from)),
            ("to", string(&row.to)),
            ("to_", string(&row.to)),
            ("nonce", number(row.nonce.get())),
            ("ou", string(row.ou.to_string())),
            ("op_type", string(row.operation.as_str())),
            (
                "reason",
                string(match row.reason {
                    DropReason::Evicted => b"evicted".as_slice(),
                    DropReason::Expired => b"expired",
                }),
            ),
            ("detail", string(&row.detail)),
            ("dropped_at", float(row.timestamp)?),
            ("timestamp", float(row.timestamp)?),
        ]));
    }
    Ok((result, true))
}
pub(super) async fn read(
    host: &Arc<Context>,
    method: &[u8],
    doc: &Document,
    params: &Value,
) -> std::result::Result<Vec<u8>, Fault> {
    let address = if matches!(
        method,
        b"octra_account"
            | b"octra_transactionsByAddress"
            | b"octra_tokenTransfersByAddress"
            | b"octra_rejectedByAddress"
    ) {
        Some(rpc::require_address(doc, params, 0, "address")?.to_vec())
    } else {
        None
    };
    let epoch = if method == b"octra_transactionsByEpoch" {
        Some(
            rpc::param_int(doc, params, 0)
                .ok_or_else(|| Fault::invalid(b"missing required param: epoch_id (index 0)"))?,
        )
    } else if method == b"octra_transactions" {
        rpc::param_int(doc, params, 0)
    } else {
        None
    };
    let captured = host.node.snapshot().map_err(unavailable)?;
    let head = captured.head().clone();
    if method == b"octra_account" {
        let account_address = address.clone().expect("account address");
        let account = host
            .executor
            .read(move || load(&captured, &account_address))
            .await?;
        let limit = rpc::param_int(doc, params, 1).map_or(10, |limit| limit.clamp(0, 50) as usize);
        let query = HistoryQuery {
            address: address.clone(),
            ..HistoryQuery::default()
        };
        let transactions = address_confirmed(
            host,
            &head,
            &query,
            Page { limit, offset: 0 },
            false,
            Projection::Account,
        )
        .await?;
        let query = HistoryQuery {
            ascending: true,
            ..query
        };
        let rejections = rejected_as(
            host,
            &head,
            &query,
            Page { limit, offset: 0 },
            RejectedProjection::Account,
        )
        .await?;
        let recent = transactions.rows.iter().map(|row| row.json.clone());
        let rejected = rejections.rows.iter().map(|row| row.json.clone());
        return Ok(object(&[
            (
                "address",
                string(address.as_deref().expect("account address")),
            ),
            ("balance", string(balance(&account.balance))),
            ("balance_raw", string(account.balance.to_string())),
            ("nonce", number(account.nonce.get())),
            ("has_public_key", boolean(account.public_key.is_some())),
            (
                "has_encrypted_balance",
                boolean(
                    account
                        .encrypted_balance
                        .as_deref()
                        .is_some_and(|value| value != b"0"),
                ),
            ),
            ("tx_count", number(transactions.total)),
            ("recent_txs", array(recent)),
            ("rejected_txs", array(rejected)),
        ]));
    }
    if method == b"octra_transactions" {
        let limit = rpc::param_int(doc, params, 1)
            .unwrap_or(20)
            .clamp(0, 10_000) as usize;
        let mut result = Vec::new();
        let epochs = match epoch {
            Some(epoch) => vec![epoch],
            None => (0..5)
                .filter_map(|offset| head.cursor.epoch.0.checked_sub(offset))
                .map(|epoch| epoch as i64)
                .collect(),
        };
        for epoch in epochs {
            // Missing/future epochs return an empty page; retained history gaps
            // and checkpoint-only archives stay explicit availability failures.
            if epoch < 0 || epoch as u64 > head.cursor.epoch.0 {
                continue;
            }
            let query = HistoryQuery {
                epoch: Some(epoch),
                ascending: true,
                ..HistoryQuery::default()
            };
            let page = confirmed_as(
                host,
                &head,
                &query,
                Page {
                    limit: limit.saturating_sub(result.len()),
                    offset: 0,
                },
                Projection::Transactions,
            )
            .await?;
            result.extend(page.rows.into_iter().map(|row| row.json));
        }
        return Ok(object(&[
            ("count", number(result.len())),
            ("transactions", array(result)),
        ]));
    }
    let page = if method == b"octra_recentTransactions" {
        page(doc, params, 0, 100, 15)
    } else if method == b"octra_transactionsByEpoch" {
        page(
            doc,
            params,
            1,
            host.history_epoch_limit,
            50.min(host.history_epoch_limit as usize),
        )
    } else {
        page(doc, params, 1, 500, 50)
    };
    let query = HistoryQuery {
        address: address.clone(),
        epoch,
        token_only: method == b"octra_tokenTransfersByAddress",
        ascending: method == b"octra_transactionsByEpoch",
        ..HistoryQuery::default()
    };
    if method == b"octra_tokenTransfersByAddress" {
        let coverage = HistoryQuery {
            token_only: false,
            ..query.clone()
        };
        let count = confirmed(
            host,
            &head,
            &coverage,
            Page {
                limit: 0,
                offset: 0,
            },
        )
        .await?
        .total;
        if count > 4096 {
            let address = address.as_deref().expect("token address");
            let mut fault = Fault::new(116, b"history index incomplete");
            fault.data = Some(object(&[
                (
                    "detail",
                    string(
                        [
                            b"token transfer history incomplete for ".as_slice(),
                            address,
                        ]
                        .concat(),
                    ),
                ),
                ("address", string(address)),
                ("offset", number(page.offset)),
                ("limit", number(page.limit)),
                ("missing", number(0)),
            ]));
            return Err(fault);
        }
    }
    if method == b"octra_rejectedByAddress" {
        let result = rejected(host, &head, &query, page).await?;
        let count = result.rows.len();
        return Ok(object(&[
            (
                "address",
                string(address.as_deref().expect("history address")),
            ),
            ("total", number(result.total)),
            ("count", number(count)),
            ("offset", number(page.offset)),
            ("limit", number(page.limit)),
            (
                "has_more",
                boolean(page.offset.saturating_add(count as u64) < result.total),
            ),
            ("rejected", array(rejection_summaries(&result)?)),
        ]));
    }
    let result = if method == b"octra_transactionsByAddress" {
        address_confirmed(host, &head, &query, page, true, Projection::Summary).await?
    } else if method == b"octra_recentTransactions" {
        confirmed_as(host, &head, &query, page, Projection::Recent).await?
    } else {
        confirmed(host, &head, &query, page).await?
    };
    let rows = summaries(&result)?;
    let count = rows.len();
    match method {
        b"octra_recentTransactions" => Ok(object(&[
            ("count", number(count)),
            ("transactions", array(rows)),
            ("rejected", array([])),
        ])),
        b"octra_tokenTransfersByAddress" => Ok(object(&[
            (
                "address",
                string(address.as_deref().expect("history address")),
            ),
            ("total", number(result.total)),
            ("count", number(count)),
            ("offset", number(page.offset)),
            ("limit", number(page.limit)),
            (
                "has_more",
                boolean(page.offset.saturating_add(count as u64) < result.total),
            ),
            ("incoming", number(result.incoming)),
            ("outgoing", number(result.outgoing)),
            ("transactions", array(rows)),
        ])),
        b"octra_transactionsByAddress" => {
            let rejected = rejected(host, &head, &query, page).await?;
            let (dropped, drops_ready) = dropped_by_address(
                host,
                &head,
                address.as_deref().expect("history address"),
                page,
                &result,
                &rejected,
            )
            .await?;
            Ok(object(&[
                (
                    "dropped_status",
                    string(if drops_ready {
                        b"ready".as_slice()
                    } else {
                        b"unavailable"
                    }),
                ),
                (
                    "address",
                    string(address.as_deref().expect("history address")),
                ),
                ("total", number(result.total)),
                ("count", number(count)),
                ("offset", number(page.offset)),
                ("limit", number(page.limit)),
                (
                    "has_more",
                    boolean(page.offset.saturating_add(count as u64) < result.total),
                ),
                ("transactions", array(rows)),
                ("rejected", array(rejection_summaries(&rejected)?)),
                ("dropped", array(dropped)),
            ]))
        }
        b"octra_transactionsByEpoch" => {
            let rejected = rejected(host, &head, &query, page).await?;
            let rejected_count = rejected.rows.len();
            Ok(object(&[
                ("epoch_id", number(epoch.expect("epoch history"))),
                ("count", number(count + rejected_count)),
                ("confirmed_count", number(count)),
                ("expected_confirmed_count", number(result.total)),
                ("rejected_count", number(rejected_count)),
                ("offset", number(page.offset)),
                ("limit", number(page.limit)),
                (
                    "has_more",
                    boolean(count == page.limit || rejected_count == page.limit),
                ),
                ("transactions", array(rows)),
                ("rejected", array(rejection_summaries(&rejected)?)),
            ]))
        }
        _ => Err(Fault::missing(method)),
    }
}
