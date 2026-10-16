// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native settlement admission over pinned input trees. Replay is injected by
//! the execution host; this service never substitutes reported provider work.
use crate::{
    compute_input,
    compute_record::{self, Origin, Session},
    compute_roots::Root,
    compute_transaction::{FundingStatus, Settlement},
    state_batch::StateBatch,
};
use octra_node_protocol::{
    consensus::hash::validator_set_hash,
    resource_compute::{
        bill::{self, Bill, Measured},
        call::Header,
        record::Record,
        Error, Result,
    },
};
use std::collections::BTreeSet;

pub struct Inputs {
    roots: Vec<(Root, Root)>,
}
impl Inputs {
    /// Native lookup chooses the first retained model/call root at the requested
    /// height. Replay additionally supplies the exact state root it will read.
    pub fn find(&self, epoch: i64, state: Option<&[u8]>) -> Option<&Root> {
        self.roots
            .iter()
            .flat_map(|(call, model)| [model, call])
            .find(|root| root.epoch() == epoch && state.is_none_or(|state| root.state() == state))
    }
}
/// Implement with the adopted provider engine: one CPU lane, a 67,108,864-byte
/// memory budget, bounded requests/replies and a 300-second execution timeout.
/// Programs and model data must be loaded exclusively from these captured roots.
pub trait Replay {
    fn replay(&mut self, session: &Session<'_>, inputs: &Inputs) -> Result<Vec<Measured>>;
}
pub struct Service<R> {
    replay: R,
}
impl<R> Service<R> {
    pub fn new(replay: R) -> Self {
        Self { replay }
    }
}
fn refused(reason: &[u8]) -> Error {
    Error::rejected(reason)
}
fn malformed(error: Error) -> Error {
    if error.is_operational() {
        error
    } else {
        refused(b"compute payment records refused")
    }
}
pub fn decode(raw: &[u8]) -> Result<Vec<Record>> {
    let request = bill::decode_request(raw)?;
    let records = request
        .records
        .iter()
        .map(|raw| Record::decode(raw).map_err(malformed))
        .collect::<Result<Vec<_>>>()?;
    let mut total = 0_i64;
    for record in &records {
        let call = &record.call;
        let request = &call.request;
        bill::resources(request).map_err(malformed)?;
        let fuel = request
            .limits
            .fuel_limit
            .ok_or_else(|| refused(b"compute payment records refused"))?;
        if fuel > bill::MAX_FUEL - total {
            return Err(refused(b"compute payment records refused"));
        }
        let signature = match &record.validators {
            Some(validators) => {
                validator_set_hash(validators)
                    .map_err(Error::from)
                    .map_err(malformed)?
                    .as_slice()
                    == request.validator_set_root
                    && compute_record::verify_node(
                        validators,
                        &call.coordinator,
                        &call.sign_bytes().map_err(malformed)?,
                        &call.signature,
                    )
            }
            None => false,
        };
        if !signature {
            return Err(refused(b"compute payment records refused"));
        }
        total += fuel;
    }
    if total != request.fuel {
        return Err(refused(b"compute payment work differs"));
    }
    Ok(records)
}
impl<R: Replay> Settlement for Service<R> {
    fn verify(
        &mut self,
        state: &StateBatch,
        epoch: i64,
        funded: &mut dyn FnMut(&Header) -> Result<FundingStatus>,
        raw: &[u8],
    ) -> Result<Vec<Bill>> {
        let records = decode(raw)?;
        let snapshot = state.snapshot();
        let mut roots = Vec::new();
        for record in &records {
            roots.push(compute_input::read(&snapshot, &record.call.header()?)?);
        }
        let inputs = Inputs { roots };
        if records.is_empty() {
            return Err(refused(b"compute payment empty"));
        }
        let mut unpaid = false;
        let mut paid = Vec::new();
        for record in &records {
            let header = record.call.header()?;
            let at = match funded(&header)? {
                FundingStatus::Due(at) => {
                    unpaid = true;
                    at
                }
                FundingStatus::Paid(at) => at,
            };
            paid.insert(0, (header.request().id()?, at));
        }
        if !unpaid {
            return Err(refused(b"compute payment has no unpaid work"));
        }
        let first = &records[0].call.request;
        let mut epochs = BTreeSet::from([first.model_epoch]);
        epochs.extend(records.iter().map(|record| record.call.request.epoch_id));
        for height in epochs {
            if height >= epoch {
                return Err(refused(b"compute payment origin not finalized"));
            }
            if inputs.find(height, None).is_none() {
                return Err(Error::Unavailable(b"compute input epoch missing".to_vec()));
            }
        }
        let model = inputs
            .find(first.model_epoch, None)
            .ok_or_else(|| Error::Unavailable(b"compute input epoch missing".to_vec()))?;
        let entries = records
            .iter()
            .map(|record| {
                let root = inputs
                    .find(record.call.request.epoch_id, None)
                    .ok_or_else(|| Error::Unavailable(b"compute input epoch missing".to_vec()))?;
                Ok((Origin::Pinned(root), record))
            })
            .collect::<Result<Vec<_>>>()?;
        let session = Session::verify(epoch, Origin::Pinned(model), &entries, |call| {
            let id = call.request.id()?;
            Ok(paid
                .iter()
                .find(|(prior, _)| prior == &id)
                .map_or(epoch, |(_, at)| *at))
        })?;
        let measured = self.replay.replay(&session, &inputs)?;
        session.bills(&measured)
    }
}
