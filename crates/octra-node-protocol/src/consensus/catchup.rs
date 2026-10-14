// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native catch-up gates. Validator-set hashes must come from trusted local history.
use super::{engine, hash, qc, Bytes, CatchupEpochRecord, CatchupFinality, Error};
pub const RANGE_EPOCHS: i64 = 16;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerHead {
    pub responder_addr: Bytes,
    pub responder_head_epoch: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LagDecision {
    InSync,
    Catchup(i64),
    SnapshotRequired(i64),
    AheadOfTarget(i64),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LagMode {
    Soft,
    Quarantine,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeSample {
    Fresh,
    Stale { start_head: i64, live_head: i64 },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyPoint {
    pub epoch: i64,
    pub root: Bytes,
    pub eic: Option<Bytes>,
    pub txid: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkRepair {
    None,
    Rollback(i64),
    SnapshotRequired(&'static str),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    Quarantine,
    Retry,
    AlreadyApplied,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordApply {
    Apply,
    SkipApplied,
    RetryMovedHead,
}
pub fn pick_target_epoch(responses: &[PeerHead], faults: i64, fallback: i64) -> Result<i64, Error> {
    if faults < 0 {
        return Err("List.nth".into());
    }
    let mut heads: Vec<_> = responses.iter().map(|r| r.responder_head_epoch).collect();
    heads.sort_unstable_by(|a, b| b.cmp(a));
    Ok(heads.get(faults as usize).copied().unwrap_or(fallback))
}
fn bounded_distance(high: i64, low: i64) -> i64 {
    (i128::from(high) - i128::from(low)).min((1i128 << 62) - 1) as i64
}
pub fn classify_lag(target: i64, our_head: i64, max_lag: i64) -> LagDecision {
    match target.cmp(&our_head) {
        std::cmp::Ordering::Equal => LagDecision::InSync,
        std::cmp::Ordering::Less => LagDecision::AheadOfTarget(bounded_distance(our_head, target)),
        std::cmp::Ordering::Greater => {
            let lag = bounded_distance(target, our_head);
            if lag > max_lag {
                LagDecision::SnapshotRequired(lag)
            } else {
                LagDecision::Catchup(lag)
            }
        }
    }
}
pub fn lag_mode(lag: i64, soft_lag: i64) -> LagMode {
    if lag <= soft_lag.max(0) {
        LagMode::Soft
    } else {
        LagMode::Quarantine
    }
}
pub fn base_gate_recovery(target: i64, start_head: i64, current_head: i64) -> Recovery {
    if current_head >= target {
        Recovery::AlreadyApplied
    } else if current_head > start_head {
        Recovery::Retry
    } else {
        Recovery::Quarantine
    }
}
pub fn apply_recovery(
    _gap_active: bool,
    target: i64,
    start_head: i64,
    current_head: i64,
) -> Recovery {
    base_gate_recovery(target, start_head, current_head)
}
pub fn record_apply_decision(head: i64, record_epoch: i64) -> RecordApply {
    match head.cmp(&record_epoch) {
        std::cmp::Ordering::Less => RecordApply::Apply,
        std::cmp::Ordering::Equal => RecordApply::SkipApplied,
        std::cmp::Ordering::Greater => RecordApply::RetryMovedHead,
    }
}
pub fn classify_probe_sample(start_head: i64, live_head: i64) -> ProbeSample {
    if start_head == live_head {
        ProbeSample::Fresh
    } else {
        ProbeSample::Stale {
            start_head,
            live_head,
        }
    }
}
pub fn genesis_state_attested(
    head: i64,
    target: i64,
    has_committed_root: bool,
    responses: i64,
    required: i64,
) -> bool {
    head < 0 && target == head && !has_committed_root && responses >= required
}
#[allow(clippy::fn_params_excessive_bools)] // Native fork-recovery predicate.
pub fn decide_fork_repair(
    our_head: i64,
    target: i64,
    current_root_quorum: bool,
    target_root_quorum: bool,
    target_local_matches: bool,
    empty_fork: bool,
) -> ForkRepair {
    if target >= our_head || current_root_quorum || !target_root_quorum {
        ForkRepair::None
    } else if !target_local_matches {
        ForkRepair::SnapshotRequired("target_root_mismatch")
    } else if !empty_fork {
        ForkRepair::SnapshotRequired("non_empty_fork")
    } else {
        ForkRepair::Rollback(target)
    }
}
pub fn valid_chunk_first_epoch(
    status: &[u8],
    records: &[CatchupEpochRecord],
    from_epoch: i64,
) -> bool {
    status == b"ok" && records.first().is_some_and(|r| r.epoch_id == from_epoch)
}
fn hash_hex(hash: &[u8]) -> Bytes {
    if hash.len() == 64 {
        hash.iter().map(u8::to_ascii_lowercase).collect()
    } else {
        hex::encode(hash).into_bytes()
    }
}
pub fn verify_record_hashes(
    record: &CatchupEpochRecord,
    parsed_tx_hashes: &[Bytes],
) -> Result<(), Error> {
    if engine::tx_list_hash_for_header(&record.tx_hashes).as_slice() != record.tx_list_hash {
        return Err(format!("tx_list_hash mismatch at epoch = {}", record.epoch_id).into());
    }
    if record.tx_hashes.len() != parsed_tx_hashes.len() {
        return Err(format!(
            "tx_hash count mismatch at epoch = {}: expected = {} got = {}",
            record.epoch_id,
            record.tx_hashes.len(),
            parsed_tx_hashes.len()
        )
        .into());
    }
    for (expected, got) in record.tx_hashes.iter().zip(parsed_tx_hashes) {
        let expected = hash_hex(expected);
        let got = hash_hex(got);
        if expected != got {
            let mut message = format!(
                "tx hash mismatch at epoch = {}: expected = ",
                record.epoch_id
            )
            .into_bytes();
            message.extend_from_slice(&expected[..expected.len().min(16)]);
            message.extend_from_slice(b" got = ");
            message.extend_from_slice(&got[..got.len().min(16)]);
            return Err(Error::new(message));
        }
    }
    Ok(())
}
pub fn verify_record_receipts(record: &CatchupEpochRecord) -> Result<(), Error> {
    if hash::receipt_root(&record.receipts_json)?.as_slice() == record.receipt_root {
        Ok(())
    } else {
        Err(format!("receipt_root mismatch at epoch = {}", record.epoch_id).into())
    }
}
pub fn verify_record_finality<'a>(
    chain: &[u8],
    expected_validator_set_hash: &[u8],
    expected_txid: i64,
    record: &'a CatchupEpochRecord,
) -> Result<&'a CatchupFinality, Error> {
    let finality = record.finality.as_ref().ok_or_else(|| {
        Error::from(format!(
            "finality is missing at epoch = {}",
            record.epoch_id
        ))
    })?;
    let f = &finality.finalize;
    let h = &f.header;
    if hash::validator_set_hash(&finality.validator_set)?.as_slice() != expected_validator_set_hash
    {
        return Err(format!(
            "finality validator set mismatch at epoch = {}",
            record.epoch_id
        )
        .into());
    }
    qc::validate_finalize(
        chain,
        &finality.validator_set,
        f,
        qc::FinalityMode::Persisted,
    )
    .map_err(|e| {
        Error::from(format!(
            "finality qc is invalid at epoch = {} reason = {e}",
            record.epoch_id
        ))
    })?;
    let error = if f.epoch_id != record.epoch_id {
        Some("finality epoch mismatch")
    } else if h.prev_state_root != record.prev_state_root {
        Some("finality previous root mismatch")
    } else if h.proposed_state_root != record.state_root {
        Some("finality state root mismatch")
    } else if h.tx_list_hash != record.tx_list_hash {
        Some("finality transaction root mismatch")
    } else if h.receipt_root != record.receipt_root {
        Some("finality receipt root mismatch")
    } else if h.txid_hi != expected_txid.wrapping_sub(1) {
        Some("finality transaction high-water mismatch")
    } else if h.ts.to_bits() != record.epoch_ts.to_bits() {
        Some("finality timestamp mismatch")
    } else if h.creator_addr != record.creator_addr {
        Some("finality proposer mismatch")
    } else if f.commit_round != record.commit_round {
        Some("finality round mismatch")
    } else {
        None
    };
    if let Some(error) = error {
        Err(error.into())
    } else {
        Ok(finality)
    }
}
pub fn verify_chain_continuity(
    records: &[CatchupEpochRecord],
    from_epoch: i64,
    prev_root: &[u8],
) -> Result<(), Error> {
    let mut expected_epoch = from_epoch;
    let mut expected_prev = if from_epoch == 0 {
        records
            .first()
            .map_or(prev_root, |r| r.prev_state_root.as_slice())
    } else {
        prev_root
    };
    for record in records {
        if record.epoch_id != expected_epoch {
            return Err(format!(
                "epoch_id chain break at {}: expected = {} got = {}",
                record.epoch_id, expected_epoch, record.epoch_id
            )
            .into());
        }
        if record.prev_state_root != expected_prev {
            return Err(
                format!("prev_state_root chain break at epoch = {}", record.epoch_id).into(),
            );
        }
        expected_epoch = record.epoch_id.wrapping_add(1);
        expected_prev = &record.state_root;
    }
    Ok(())
}
pub fn verify_apply_base(from_epoch: i64, head: &ApplyPoint) -> Result<(), Error> {
    let expected = from_epoch.wrapping_sub(1);
    if head.epoch != expected {
        Err(format!(
            "catchup base epoch moved: expected = {expected} got = {}",
            head.epoch
        )
        .into())
    } else if head.root.is_empty() {
        Err("catchup base root missing".into())
    } else {
        Ok(())
    }
}
pub fn verify_apply_final(
    last_epoch: i64,
    expected_root: &[u8],
    expected_eic: &[u8],
    expected_txid: i64,
    head: &ApplyPoint,
) -> Result<(), Error> {
    if head.epoch != last_epoch {
        Err(format!(
            "catchup final epoch mismatch: expected = {last_epoch} got = {}",
            head.epoch
        )
        .into())
    } else if head.root != expected_root {
        Err(format!("catchup final root mismatch at epoch = {last_epoch}").into())
    } else if head.eic.as_deref() != Some(expected_eic) {
        Err(format!("catchup final EIC mismatch at epoch = {last_epoch}").into())
    } else if head.txid != expected_txid {
        Err(format!("catchup final txid mismatch at epoch = {last_epoch} expected = {expected_txid} got = {}",head.txid).into())
    } else {
        Ok(())
    }
}
