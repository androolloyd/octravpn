// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Common direct-operation boundaries. Authorization and fee order remain in
//! each operation; these helpers never open or publish a transaction.
use crate::{
    circle_error::{refused, unavailable, Failure},
    circle_store::{self, Info},
    state_batch::StateBatch,
};
use octra_node_protocol::{
    circle_policy,
    native_json::{Document, ReadMode},
    state::Ledger,
    transaction::Transaction,
};
pub(crate) type Result<T> = std::result::Result<T, Failure>;
pub(crate) fn document(tx: &Transaction) -> Result<Document> {
    document_with_mode(tx, ReadMode::Tree)
}
pub(crate) fn document_with_mode(tx: &Transaction, mode: ReadMode) -> Result<Document> {
    let message = tx.message.as_deref().ok_or_else(|| {
        refused(
            "malformed_transaction",
            format!("{} requires message payload", tx.op_type.as_str()).into_bytes(),
        )
    })?;
    parse(message, mode)
}
pub(crate) fn parse(raw: &[u8], mode: ReadMode) -> Result<Document> {
    Document::parse_native(raw, mode).map_err(|error| match error.exception() {
        Some(exception) => refused("malformed_transaction_exception", exception),
        None => unavailable(error.legacy()),
    })
}
pub(crate) fn owned(state: &StateBatch, tx: &Transaction, action: &[u8]) -> Result<Info> {
    let info = info(state, tx)?;
    if info.owner != tx.from {
        return Err(refused(
            "circle_access_denied",
            [b"only the owner can modify circle ".as_slice(), action].concat(),
        ));
    }
    Ok(info)
}
pub(crate) fn info(state: &StateBatch, tx: &Transaction) -> Result<Info> {
    circle_store::info(&state.snapshot(), &tx.to)
        .map_err(unavailable)?
        .ok_or_else(|| refused("circle_not_found", b"circle does not exist"))
}
pub(crate) fn debit(ledger: &mut Ledger, tx: &Transaction) -> Result<()> {
    ledger
        .debit(&tx.from, &tx.ou, tx.nonce, None)
        .map_err(|e| refused("insufficient_balance", e.0.into_bytes()))
}
pub(crate) fn save_policy(
    state: &mut StateBatch,
    tx: &Transaction,
    info: &Info,
    snapshot: circle_policy::Snapshot,
) -> Result<()> {
    let mut storage = circle_store::load_storage(&state.snapshot(), &tx.to, None)
        .map_err(|e| refused("circle_stable_storage_invalid", e.0))?;
    for (key, value) in snapshot.0 {
        match value {
            Some(value) => storage.replace(key, value),
            None => storage.remove(&key),
        }
    }
    circle_store::save_storage(state, &tx.to, &storage, info.limits[0], info.limits[2])
        .map_err(|e| refused("circle_stable_storage_invalid", e.0))?;
    Ok(())
}
