//! Bounded native epoch summaries and anchored forward pages.
use super::{rpc, Arc, Context, Document, Fault, Value};
use octra_node_protocol::{epoch_journal, epoch_page};
static PAGE_READ: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
fn unavailable(reason: impl std::fmt::Display) -> Fault {
    Fault::new(-32012, reason.to_string().as_bytes())
}
fn inconsistent(_: impl std::fmt::Display) -> Fault {
    epoch_journal::unavailable()
}
#[allow(clippy::suspicious_operation_groupings)] // The native request interval is bounded by the authenticated anchor epoch.
pub(super) async fn read(
    host: &Arc<Context>,
    method: &[u8],
    doc: &Document,
    params: &Value,
) -> std::result::Result<Vec<u8>, Fault> {
    let request = if method == b"octra_epochPage" {
        Some(epoch_page::Request::parse(doc, params)?)
    } else {
        None
    };
    let _lease = if request.is_some() {
        Some(
            PAGE_READ
                .try_lock()
                .map_err(|_| Fault::new(107, b"epoch page reader is busy; retry"))?,
        )
    } else {
        None
    };
    let head = host
        .node
        .head()
        .await
        .map_err(|_| unavailable("committed head is unavailable"))?;
    let reader = host.node.reader();
    if let Some(request) = request {
        let current = epoch_page::Anchor {
            chain: reader.chain().chain_id.as_bytes().to_vec(),
            epoch: i64::try_from(head.cursor.epoch.0).map_err(unavailable)?,
            root: hex::encode(head.cursor.state_root.0).into_bytes(),
        };
        if !current.valid() {
            return Err(unavailable("committed head is invalid"));
        }
        let anchor = request.anchor.unwrap_or_else(|| current.clone());
        if anchor.chain != current.chain
            || anchor.epoch > current.epoch
            || request.start > anchor.epoch
        {
            return Err(Fault::invalid(
                "anchor or start differs from committed history",
            ));
        }
        let mut budget = epoch_page::MAX_BYTES;
        if anchor.epoch == current.epoch {
            if anchor.root != current.root {
                return Err(unavailable("anchor root differs"));
            }
        } else {
            let Some((row, bytes)) = reader
                .epoch_page_row(&head, anchor.epoch)
                .await
                .map_err(inconsistent)?
            else {
                return Err(unavailable("anchor is unavailable in local history"));
            };
            budget = reserve(budget, bytes)?;
            if row.root != anchor.root {
                return Err(unavailable("anchor root differs"));
            }
        }
        let mut next = request.start;
        let mut previous = request.previous;
        let mut tx_start = None;
        let mut rows = Vec::new();
        let stop = loop {
            if next > anchor.epoch {
                break "complete";
            }
            if rows.len() == request.limit {
                break "more";
            }
            tokio::task::yield_now().await;
            let Some((row, bytes)) = reader
                .epoch_page_row(&head, next)
                .await
                .map_err(inconsistent)?
            else {
                break "gap";
            };
            budget = reserve(budget, bytes)?;
            if (!previous.is_empty() && row.previous != previous)
                || tx_start.is_some_and(|start| row.tx_start != start)
                || (next == anchor.epoch && row.root != anchor.root)
            {
                return Err(unavailable("epoch chain is inconsistent"));
            }
            previous.clone_from(&row.root);
            tx_start = Some(
                row.tx_start
                    .checked_add(row.tx_count)
                    .ok_or_else(|| unavailable("epoch transaction index exhausted"))?,
            );
            rows.push(row);
            next += 1;
        };
        return epoch_page::encode(&anchor, &rows, next, stop);
    }
    if method == b"epoch_get" {
        let epoch = rpc::require_int(doc, params, 0, "epoch_id")?;
        let raw = reader
            .epoch_summary(&head, epoch)
            .await
            .map_err(inconsistent)?
            .ok_or_else(|| Fault::new(112, b"not found").string_data(b"epoch not found"))?;
        if raw.len() > rpc::MAX_SINGLE {
            return Err(Fault::response_limit());
        }
        return Ok(raw);
    }
    let mut raw = vec![b'['];
    for epoch in epoch_journal::summary_ids(doc, params) {
        if let Some(row) = reader
            .epoch_summary(&head, epoch)
            .await
            .map_err(inconsistent)?
        {
            if raw.len().saturating_add(row.len()).saturating_add(2) > rpc::MAX_SINGLE {
                return Err(Fault::response_limit());
            }
            if raw.len() > 1 {
                raw.push(b',');
            }
            raw.extend(row);
        }
    }
    raw.push(b']');
    Ok(raw)
}
fn reserve(budget: usize, bytes: usize) -> std::result::Result<usize, Fault> {
    if bytes > budget.min(epoch_page::MAX_RECORD) {
        return Err(Fault::new(107, b"epoch record exceeds read limit"));
    }
    Ok(budget - bytes)
}
