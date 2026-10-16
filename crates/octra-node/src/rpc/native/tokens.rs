use super::{rpc, Context, Document, Fault, Value};
pub(super) async fn read(
    host: &Context,
    doc: &Document,
    params: &Value,
) -> std::result::Result<Vec<u8>, Fault> {
    let holder = rpc::require_address(doc, params, 0, "address")?.to_vec();
    let offset = rpc::param_int(doc, params, 1).unwrap_or(0);
    let limit = rpc::param_int(doc, params, 2)
        .unwrap_or(octra_node_protocol::token_rpc::MAX_PAGE_ROWS as i64);
    if !(0..=octra_node_protocol::token_rpc::MAX_SCAN_PROGRAMS as i64).contains(&offset) {
        return Err(Fault::invalid(b"token offset outside read limit"));
    }
    if limit <= 0 || limit > octra_node_protocol::token_rpc::MAX_PAGE_ROWS as i64 {
        return Err(Fault::invalid(b"token page size outside read limit"));
    }
    let snapshot = host
        .node
        .snapshot()
        .map_err(|_| Fault::new(110, b"service unavailable"))?;
    host.tokens
        .as_ref()
        .ok_or_else(|| Fault::new(110, b"service unavailable"))?
        .query(snapshot.state().clone(), holder, offset, limit)
        .await
        .map_err(|e| match e {
            octra_node_runtime::token_rpc::Error::Busy => {
                Fault::new(-32005, b"Program token read busy")
            }
            octra_node_runtime::token_rpc::Error::Stopped => {
                Fault::new(110, b"service unavailable")
            }
            octra_node_runtime::token_rpc::Error::ReadFailed => {
                Fault::new(-32000, b"Program token read failed")
            }
        })
}
pub(super) fn save_abi() -> Fault {
    Fault::new(
        -32601,
        b"program ABI writes are disabled; use program verification",
    )
}
