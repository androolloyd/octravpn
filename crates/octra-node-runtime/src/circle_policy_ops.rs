// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Owner-authorized native policies and key lifecycle operations.
use crate::{
    circle_error::{completion, refused, unavailable},
    circle_operation::{self as host, Result},
    circle_transport_store as outbox,
    execution::{Completion, Error},
    state_batch::StateBatch,
};
use octra_node_protocol::{
    circle_policy::{hfhe, key, transport},
    state::Ledger,
    transaction::{is_valid_address, OpType, Transaction},
};
fn transport(tx: &Transaction, ledger: &mut Ledger, state: &mut StateBatch) -> Result<()> {
    let policy = transport::Policy::parse(&host::document(tx)?)?;
    let info = host::owned(state, tx, b"transport policy")?;
    policy.validate()?;
    host::debit(ledger, tx)?;
    host::save_policy(state, tx, &info, policy.snapshot())
}
fn hfhe(tx: &Transaction, ledger: &mut Ledger, state: &mut StateBatch) -> Result<()> {
    let policy = hfhe::Policy::parse(&host::document(tx)?)?;
    let info = host::owned(state, tx, b"hfhe policy")?;
    if policy
        .pk_allowlist
        .as_ref()
        .is_some_and(|ids| !ids.iter().all(|id| is_valid_address(id)))
    {
        return Err(refused(
            "invalid_circle_hfhe_allowlist",
            b"invalid_circle_hfhe_allowlist must contain valid octra addresses",
        ));
    }
    host::debit(ledger, tx)?;
    host::save_policy(state, tx, &info, policy.snapshot())
}
fn key(tx: &Transaction, ledger: &mut Ledger, state: &mut StateBatch, epoch: i64) -> Result<()> {
    let operation = match tx.op_type {
        OpType::CircleKeyPolicyPut => "put",
        OpType::CircleKeyGrant => "grant",
        OpType::CircleKeyExtend => "extend",
        OpType::CircleKeyRevoke => "revoke",
        _ => "erase",
    };
    let payload = key::Payload::parse(&host::document(tx)?, operation)?;
    let info = host::owned(state, tx, b"key policy")?;
    if payload.key_id.is_empty() {
        return Err(refused(
            "invalid_circle_key_id",
            b"key_id must not be empty",
        ));
    }
    // Put validates its window before the debit. Lifecycle operations debit
    // first, then resolve the old policy and perform their transition.
    let next = if let key::Operation::Put(policy) = payload.operation {
        key::validate_window(policy.activate, policy.expire)?;
        host::debit(ledger, tx)?;
        policy
    } else {
        host::debit(ledger, tx)?;
        outbox::key_policy(&state.snapshot(), &tx.to, &payload.key_id)?
            .apply(&payload.operation, epoch)?
    };
    host::save_policy(state, tx, &info, next.snapshot(&payload.key_id))?;
    outbox::shutdown(state, &tx.to, &payload.key_id, epoch, next)
}
pub(crate) fn execute(
    tx: &Transaction,
    ledger: &mut Ledger,
    state: &mut StateBatch,
    epoch: i64,
) -> std::result::Result<Completion, Error> {
    completion(match tx.op_type {
        OpType::CircleTransportPolicyPut => transport(tx, ledger, state),
        OpType::CircleHfhePolicyPut => hfhe(tx, ledger, state),
        OpType::CircleKeyPolicyPut
        | OpType::CircleKeyGrant
        | OpType::CircleKeyExtend
        | OpType::CircleKeyRevoke
        | OpType::CircleKeyErase => key(tx, ledger, state, epoch),
        _ => Err(unavailable("Circle policy operation host unavailable")),
    })
}
