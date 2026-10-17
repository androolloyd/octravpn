// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted `Consensus_liveness` policy. The host supplies native clock seconds and
//! authenticated admission state; a reset is a request, not permission to vote.
use super::{engine::TimeoutConfig, Bytes, RoundStep};

pub const PROTOCOL_TIMEOUT_GRACE_SEC: f64 = 30.0;

#[derive(Clone, Debug, PartialEq)]
pub struct State {
    pub key: Bytes,
    pub key_started_at: f64,
    pub height_key: Bytes,
    pub height_started_at: f64,
    /// Native OCaml `int`, including its signed 63-bit wrap behavior.
    pub resets: i64,
}

impl State {
    pub fn new(now: f64) -> Self {
        Self {
            key: Vec::new(),
            key_started_at: now,
            height_key: Vec::new(),
            height_started_at: now,
            resets: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Sample<'a> {
    pub height: i64,
    pub round: i64,
    pub step: &'a [u8],
    pub expected: i64,
    pub now: f64,
    pub source: &'a [u8],
    pub stall_sec: f64,
    pub step_timeout_sec: Option<f64>,
    pub observer: bool,
    pub voting: bool,
    pub catchup_active: bool,
    pub quarantine_active: bool,
    pub state_attested: bool,
    pub pending_finalized: bool,
    pub proposal_active: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Reset {
    pub height: i64,
    pub round: i64,
    pub step: Bytes,
    pub expected: i64,
    pub source: Bytes,
    pub stall_sec: f64,
    pub step_timeout_sec: Option<f64>,
    pub state_age: f64,
    pub height_age: f64,
    pub resets: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Outcome {
    pub state: State,
    pub reset: Option<Reset>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DriverSnapshot {
    pub height: i64,
    pub round: i64,
    pub step: Bytes,
    pub step_timeout_sec: Option<f64>,
}

pub fn protocol_realign_sec(sample: &Sample<'_>) -> Option<f64> {
    sample
        .step_timeout_sec
        .map(|timeout| timeout + PROTOCOL_TIMEOUT_GRACE_SEC)
}

pub fn effective_stall_sec(sample: &Sample<'_>) -> f64 {
    protocol_realign_sec(sample).map_or(sample.stall_sec, |protocol| {
        // OCaml Stdlib.max is `if x >= y then x else y`. f64::max has
        // different NaN and signed-zero selection, so retain both operands.
        if sample.stall_sec >= protocol {
            sample.stall_sec
        } else {
            protocol
        }
    })
}

pub fn blocked(sample: &Sample<'_>, stalled: bool) -> bool {
    sample.observer
        || !sample.voting
        || sample.catchup_active
        || sample.quarantine_active
        || !sample.state_attested
        || sample.proposal_active
        || !stalled
        || sample.height != sample.expected
        || sample.pending_finalized
}

pub fn record(state: &State, sample: &Sample<'_>) -> Outcome {
    let mut key = format!("{}:{}:", sample.height, sample.round).into_bytes();
    key.extend_from_slice(sample.step);
    let height_key = sample.height.to_string().into_bytes();
    let mut state = State {
        key_started_at: if key == state.key {
            state.key_started_at
        } else {
            sample.now
        },
        height_started_at: if height_key == state.height_key {
            state.height_started_at
        } else {
            sample.now
        },
        key,
        height_key,
        resets: state.resets,
    };
    if sample.proposal_active {
        state.key_started_at = sample.now;
    }
    let state_age = sample.now - state.key_started_at;
    let height_age = sample.now - state.height_started_at;
    let stall_sec = effective_stall_sec(sample);
    let state_stalled = state_age >= stall_sec;
    let height_stalled = height_age >= sample.stall_sec;
    let protocol_realign_allowed =
        protocol_realign_sec(sample).is_none_or(|protocol| state_age >= protocol);
    let height_realign_allowed = height_stalled && protocol_realign_allowed && sample.round > 0;
    if blocked(sample, state_stalled || height_realign_allowed) {
        return Outcome { state, reset: None };
    }
    let resets = (state.resets.wrapping_add(1) << 1) >> 1;
    state.key_started_at = sample.now;
    state.height_started_at = sample.now;
    state.resets = resets;
    Outcome {
        state,
        reset: Some(Reset {
            height: sample.height,
            round: sample.round,
            step: sample.step.to_vec(),
            expected: sample.expected,
            source: sample.source.to_vec(),
            stall_sec,
            step_timeout_sec: sample.step_timeout_sec,
            state_age,
            height_age,
            resets,
        }),
    }
}

pub const fn step_label(step: RoundStep) -> &'static [u8] {
    match step {
        RoundStep::Propose => b"propose",
        RoundStep::Prevote => b"prevote",
        RoundStep::Precommit => b"precommit",
    }
}

/// Project a host driver snapshot using its configured native timeout policy.
/// No driver acquisition, scheduling or voting side effect occurs here.
#[allow(clippy::cast_precision_loss)] // Native float_of_int followed by /.1000.0.
pub fn driver_snapshot(
    height: i64,
    round: i64,
    step: RoundStep,
    timeouts: TimeoutConfig,
) -> DriverSnapshot {
    DriverSnapshot {
        height,
        round,
        step: step_label(step).to_vec(),
        step_timeout_sec: Some(timeouts.milliseconds(round, step) as f64 / 1000.0),
    }
}

#[cfg(test)]
mod tests;
