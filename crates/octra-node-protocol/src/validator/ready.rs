// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{set_fold::State, Error};
use crate::{consensus::ParentCommit, control_payload::ReadyExtra};
pub const WINDOW: i64 = 2;
pub const WINDOW_ID: &str = "proposal_delay2_inclusion_first";
pub fn delivery(epoch: i64, head: i64) -> bool {
    epoch > 0
        && head >= 0
        && head < epoch
        && !crate::duty::ready_expired(epoch.wrapping_sub(1), head)
}
pub fn reference(
    epoch: i64,
    head: i64,
    proposal: Option<&[u8]>,
    parent: Option<&ParentCommit>,
    state: &State,
) -> Result<(), Error> {
    if !delivery(epoch, head) {
        return Err("head_epoch outside delivery window".into());
    }
    let proposal = proposal
        .filter(|v| {
            v.len() == 64
                && v.iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        })
        .ok_or("head_proposal_id missing or invalid")?;
    let expected = if head == epoch.wrapping_sub(1) {
        parent
            .filter(|p| p.certificate.epoch_id == head)
            .map(|p| p.certificate.proposal_id.as_slice())
    } else {
        state.find_final(head).map(|p| p.proposal_id.as_slice())
    }
    .ok_or("head_proposal_id reference unavailable")?;
    if proposal == hex::encode(expected).as_bytes() {
        Ok(())
    } else {
        Err("head_proposal_id mismatch".into())
    }
}
pub fn validate(
    chain: &[u8],
    config: &[u8],
    head: i64,
    claim: &ReadyExtra,
    prior: bool,
) -> Result<(), Error> {
    for (label, expected, actual) in [
        ("chain_id", chain, claim.chain_id.as_deref()),
        ("config_hash", config, claim.config_hash.as_deref()),
    ] {
        match actual {
            Some(v) if v == expected => (),
            Some(_) => return Err(format!("{label} mismatch").into()),
            None => return Err(format!("{label} missing").into()),
        }
    }
    match claim.catchup_head_epoch {
        Some(n) if if prior { n >= head } else { n == head } => Ok(()),
        Some(_) => Err(if prior {
            "catchup_head_epoch too low"
        } else {
            "catchup_head_epoch mismatch"
        }
        .into()),
        None => Err("catchup_head_epoch missing".into()),
    }
}
