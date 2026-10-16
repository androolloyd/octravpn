// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native signed outbox and relay operations, staged until canonical commit.
use crate::{
    circle_error::{completion, refused, unavailable},
    circle_operation::{self as host, Result},
    circle_transport_store as store,
    execution::{Completion, Error},
    state_batch::StateBatch,
};
use octra_node_protocol::{
    circle_transport::{machine, verify, Cancel, Claim, Intent, Packet, Status},
    state::Ledger,
    transaction::{OpType, Transaction},
};
fn open(tx: &Transaction, ledger: &mut Ledger, state: &mut StateBatch, epoch: i64) -> Result<()> {
    let intent = Intent::parse(&host::document(tx)?, Some(epoch))?;
    let info = host::info(state, tx)?;
    if info.owner != tx.from {
        return Err(refused(
            "circle_access_denied",
            b"only the owner can open circle outbox intents",
        ));
    }
    machine::open_envelope(&intent, epoch)?;
    let snapshot = state.snapshot();
    let policy = store::policy(&snapshot, &tx.to)?;
    let deliverable = store::deliverable(&snapshot, &tx.to, &intent, epoch, intent.expiry)?;
    let exists = store::intent(&snapshot, &tx.to, &intent.id)?.is_some();
    machine::open(&intent, epoch, &policy, deliverable, exists)?;
    host::debit(ledger, tx)?;
    store::save_intent(state, &tx.to, &intent)
}
fn claim(tx: &Transaction, ledger: &mut Ledger, state: &mut StateBatch, epoch: i64) -> Result<()> {
    let claim = Claim::parse(&host::document(tx)?)?;
    host::info(state, tx)?;
    machine::claim_envelope(&claim, &tx.from, epoch)?;
    let snapshot = state.snapshot();
    let policy = store::policy(&snapshot, &tx.to)?;
    machine::claim_policy(&claim, &policy)?;
    verify::signature(
        ledger,
        &claim.relay,
        &claim.signature,
        &claim.subject(&tx.to),
    )?;
    let intent = store::intent(&snapshot, &tx.to, &claim.intent)?
        .ok_or_else(|| refused("circle_outbox_not_found", b"outbox intent does not exist"))?;
    let status = store::status(&snapshot, &tx.to, &claim.intent);
    let existing = store::claims(&snapshot, &tx.to, &claim.intent)?;
    let active = store::active_claims(&snapshot, &tx.to, &claim.intent, epoch)?;
    let deliverable = store::deliverable(&snapshot, &tx.to, &intent, epoch, claim.expiry)?;
    machine::claim(
        &claim,
        epoch,
        &policy,
        &intent,
        status,
        deliverable,
        &existing,
        &active,
    )?;
    host::debit(ledger, tx)?;
    store::save_claim(state, &tx.to, &claim)?;
    store::set_status(state, &tx.to, &claim.intent, Status::Claimed)
}
fn cancel(tx: &Transaction, ledger: &mut Ledger, state: &mut StateBatch, epoch: i64) -> Result<()> {
    let cancel = Cancel::parse(&host::document(tx)?)?;
    host::info(state, tx)?;
    machine::cancel_envelope(&cancel, &tx.from, epoch)?;
    verify::signature(
        ledger,
        &cancel.relay,
        &cancel.signature,
        &cancel.subject(&tx.to),
    )?;
    let snapshot = state.snapshot();
    let intent = store::intent(&snapshot, &tx.to, &cancel.intent)?
        .ok_or_else(|| refused("circle_outbox_not_found", b"outbox intent does not exist"))?;
    let status = store::status(&snapshot, &tx.to, &cancel.intent);
    let existing = store::claims(&snapshot, &tx.to, &cancel.intent)?;
    let active = store::active_claims(&snapshot, &tx.to, &cancel.intent, epoch)?;
    let key = store::delivery_state(&snapshot, &tx.to, &intent, epoch)?;
    let plan = machine::cancel(&cancel, epoch, &intent, status, key, &existing, &active)?;
    host::debit(ledger, tx)?;
    store::save_resolution(state, &tx.to, &plan.claim, Some(&cancel.relay))?;
    if let Some(resolution) = plan.outbox {
        store::save_resolution(state, &tx.to, &resolution, None)?;
    }
    store::set_status(state, &tx.to, &cancel.intent, plan.status)
}
fn ingress(
    tx: &Transaction,
    ledger: &mut Ledger,
    state: &mut StateBatch,
    epoch: i64,
) -> Result<()> {
    let packet = Packet::parse(&host::document(tx)?)?;
    host::info(state, tx)?;
    machine::ingress_envelope(&packet, &tx.from)?;
    verify::signature(
        ledger,
        &packet.relay,
        &packet.signature,
        &packet.subject(&tx.to),
    )
    .map_err(|mut error| {
        if error.tag == "circle_relay_signature_invalid" {
            error.tag = "circle_ingress_signature_invalid";
        }
        error
    })?;
    let snapshot = state.snapshot();
    let intent = store::intent(&snapshot, &tx.to, &packet.intent)?
        .ok_or_else(|| refused("circle_outbox_not_found", b"outbox intent does not exist"))?;
    let status = store::status(&snapshot, &tx.to, &packet.intent);
    let active = store::active_claims(&snapshot, &tx.to, &packet.intent, epoch)?;
    let policy = store::policy(&snapshot, &tx.to)?;
    let key = store::delivery_state(&snapshot, &tx.to, &intent, epoch)?;
    let exists = store::packet(&snapshot, &tx.to, &packet.intent)?.is_some();
    let resolution = machine::ingress(
        &packet, epoch, &policy, &intent, status, key, &active, exists,
    )?;
    host::debit(ledger, tx)?;
    store::save_packet(state, &tx.to, &packet)?;
    store::save_resolution(state, &tx.to, &resolution, None)?;
    store::set_status(state, &tx.to, &packet.intent, Status::Fulfilled)
}
pub(crate) fn execute(
    tx: &Transaction,
    ledger: &mut Ledger,
    state: &mut StateBatch,
    epoch: i64,
) -> std::result::Result<Completion, Error> {
    completion(match tx.op_type {
        OpType::CircleOutboxOpen => open(tx, ledger, state, epoch),
        OpType::CircleRelayClaim => claim(tx, ledger, state, epoch),
        OpType::CircleRelayCancel => cancel(tx, ledger, state, epoch),
        OpType::CircleIngressCommit => ingress(tx, ledger, state, epoch),
        _ => Err(unavailable("Circle transport operation host unavailable")),
    })
}
