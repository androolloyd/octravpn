use super::{bill, refused, verify_selection, Bill, Call, Error, Measured, Origin, Record, Result};
use octra_node_protocol::resource_compute::bill::Outcome;

struct Entry<'a> {
    origin: Origin<'a>,
    record: &'a Record,
    selected: Vec<Vec<u8>>,
    epoch: i64,
}
pub struct Session<'a> {
    epoch: i64,
    model: Origin<'a>,
    entries: Vec<Entry<'a>>,
}
fn encoding(error: Error) -> Error {
    if error.is_operational() {
        error
    } else {
        refused(b"compute session encoding refused")
    }
}
impl<'a> Session<'a> {
    pub fn verify(
        epoch: i64,
        model: Origin<'a>,
        records: &[(Origin<'a>, &'a Record)],
        mut at: impl FnMut(&Call) -> Result<i64>,
    ) -> Result<Self> {
        if records.is_empty() {
            return Err(refused(b"compute session empty"));
        }
        if records.len() > 64 {
            return Err(refused(b"compute session step count"));
        }
        let first = &records[0].1.call.request;
        let mut sequence = 1_i64;
        let mut previous = model.epoch();
        let mut fuel = 0_i64;
        let mut bytes = 0_usize;
        let mut entries = Vec::new();
        for (origin, record) in records {
            let call = &record.call;
            let request = &call.request;
            let checked = at(call).map_err(encoding)?;
            if !call.shape().map_err(encoding)? {
                return Err(refused(b"compute session call shape"));
            }
            if checked < request.epoch_id || checked > epoch {
                return Err(refused(b"compute session payment epoch"));
            }
            if request.sequence != sequence {
                return Err(refused(b"compute session sequence differs"));
            }
            if request.epoch_id < previous || request.epoch_id < model.epoch() {
                return Err(refused(b"compute session epoch order differs"));
            }
            if request.chain_id != model.chain_id()
                || request.caller != first.caller
                || request.session_id != first.session_id
                || request.circle_id != first.circle_id
                || request.model_epoch != model.epoch()
                || request.model_state_root != model.state()
                || request.graph_root != first.graph_root
                || request.model_root != first.model_root
                || request.program_root != first.program_root
                || request.executor_root != first.executor_root
            {
                return Err(refused(b"compute session model or owner differs"));
            }
            let used = request.limits.fuel_limit.unwrap_or(10_000_001);
            let size = record.encode().map_err(encoding)?.len();
            if used <= 0 || used > 10_000_000 - fuel {
                return Err(refused(b"compute session fuel limit"));
            }
            if size > 8_000_000 - bytes {
                return Err(refused(b"compute session input limit"));
            }
            let header = call.header()?;
            let selection = verify_selection(*origin, checked, &header, record)?;
            entries.push(Entry {
                origin: *origin,
                record,
                selected: selection.members.into_iter().map(|v| v.node_id).collect(),
                epoch: checked,
            });
            sequence = sequence.wrapping_add(1);
            previous = request.epoch_id;
            fuel += used;
            bytes += size;
        }
        Ok(Self {
            epoch,
            model,
            entries,
        })
    }
    pub fn epoch(&self) -> i64 {
        self.epoch
    }
    pub fn model(&self) -> Origin<'a> {
        self.model
    }
    pub fn calls(&self) -> impl ExactSizeIterator<Item = &'a Call> + '_ {
        self.entries.iter().map(|entry| &entry.record.call)
    }
    pub fn bills(&self, measured: &[Measured]) -> Result<Vec<Bill>> {
        let mut bills = Vec::new();
        // Native checks the matching prefix before a length mismatch, retaining
        // prior-stop and certificate refusal priority over measurement count.
        for (index, (entry, measured)) in self.entries.iter().zip(measured).enumerate() {
            if index + 1 < self.entries.len() && measured.outcome() != Outcome::Complete {
                return Err(refused(b"compute session prior call stopped"));
            }
            let header = entry.record.call.header()?;
            let votes = entry
                .record
                .results
                .iter()
                .map(|result| result.vote.clone())
                .collect::<Vec<_>>();
            bills.push(bill::verify(
                entry.epoch,
                &header,
                entry.origin.validators(),
                &entry.selected,
                &votes,
                measured,
            )?);
        }
        if self.entries.len() != measured.len() {
            return Err(refused(b"compute session measurement count"));
        }
        Ok(bills)
    }
}
