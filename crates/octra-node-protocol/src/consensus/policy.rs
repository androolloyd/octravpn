// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native historical quorum/proposal version and epoch-time activation rules.
use super::{Error, CURRENT_VERSION, LEGACY_VERSION};
pub const DEVNET: &[u8] = b"octra-devnet-9871-cluster";
pub const QUORUM_ACTIVATION: i64 = 1_306_547;
pub fn quorum_active(chain_id: &[u8], epoch_id: i64) -> bool {
    epoch_id
        >= if chain_id == DEVNET {
            QUORUM_ACTIVATION
        } else {
            0
        }
}
pub fn quorum_consensus_id(chain_id: &[u8]) -> &'static str {
    if chain_id == DEVNET {
        "resilient:1306321:c19278aec1ff53c4796aea354c9cc7845d8421fc7d6ffe971b5fecea29299a04:1306547"
    } else {
        "resilient:genesis"
    }
}
pub fn rewind_allowed(chain_id: &[u8], from_epoch: i64, to_epoch: i64) -> bool {
    let activation = if chain_id == DEVNET {
        QUORUM_ACTIVATION
    } else {
        0
    };
    !(from_epoch >= activation && to_epoch < activation)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Protocol {
    activation_epoch: i64,
}
impl Protocol {
    pub const ACTIVATION_ENV: &'static str = "OCTRA_PROPOSAL_PROTOCOL_ACTIVATION_EPOCH";
    pub fn from_activation_value(value: Option<&[u8]>) -> Result<Self, Error> {
        match value {
            None | Some(b"") => Ok(Self::default()),
            Some(raw) => Self::new(
                crate::native_integer::parse_int64(raw)
                    .ok_or_else(|| Error::from("invalid proposal protocol activation epoch"))?,
            ),
        }
    }
    pub fn consensus_id(self) -> String {
        self.activation_epoch.to_string()
    }
    pub fn new(activation_epoch: i64) -> Result<Self, Error> {
        if activation_epoch < 0 {
            return Err("invalid proposal protocol activation epoch".into());
        }
        Ok(Self { activation_epoch })
    }
    pub const fn activation_epoch(self) -> i64 {
        self.activation_epoch
    }
    pub const fn version_at(self, epoch_id: i64) -> i64 {
        if epoch_id < self.activation_epoch {
            LEGACY_VERSION
        } else {
            CURRENT_VERSION
        }
    }
}
pub const fn supported_version(version: i64) -> bool {
    version == LEGACY_VERSION || version == CURRENT_VERSION
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeRule {
    Historical,
    Uniform,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalKind {
    Fresh,
    Reproposal,
}
pub fn time_rule(chain_id: &[u8], epoch_id: i64) -> TimeRule {
    if chain_id == b"octra-mainnet" || (chain_id == DEVNET && epoch_id < 1_320_000) {
        TimeRule::Historical
    } else {
        TimeRule::Uniform
    }
}
pub fn time_of_seconds(seconds: f64) -> Result<i64, Error> {
    if !seconds.is_finite() {
        return Err("epoch time is not finite".into());
    }
    if !(0.0..=9.22e15).contains(&seconds) {
        return Err("epoch time is out of range".into());
    }
    Ok((seconds * 1000.0).floor() as i64)
}
pub fn next_delay_ms(now: f64, previous: f64) -> i64 {
    match (time_of_seconds(now), time_of_seconds(previous)) {
        (Ok(now), Ok(previous)) => {
            let target = previous.wrapping_add(10_000);
            if now >= target {
                0
            } else {
                target.wrapping_sub(now)
            }
        }
        _ => 10_000,
    }
}
pub fn check_candidate(previous: Option<i64>, candidate: f64) -> Result<i64, Error> {
    let candidate = time_of_seconds(candidate)?;
    if let Some(previous) = previous {
        if candidate < previous {
            return Err("epoch time is not monotonic".into());
        }
        if candidate.wrapping_sub(previous) < 10_000 {
            return Err("epoch time interval is below protocol minimum".into());
        }
    }
    Ok(candidate)
}
pub fn check_time(now: f64, previous: Option<i64>, candidate: f64) -> Result<i64, Error> {
    let now = time_of_seconds(now)?;
    let candidate = check_candidate(previous, candidate)?;
    if previous.is_none() {
        if candidate.wrapping_sub(now).wrapping_abs() > 300_000 {
            return Err("initial epoch time drift exceeds limit".into());
        }
    } else if candidate > now && candidate.wrapping_sub(now) > 5000 {
        return Err("epoch time is too far in the future".into());
    }
    Ok(candidate)
}
pub fn check_proposal_time(
    rule: TimeRule,
    kind: ProposalKind,
    now: f64,
    previous: Option<i64>,
    candidate: f64,
) -> Result<i64, Error> {
    match (rule, kind) {
        (TimeRule::Historical, ProposalKind::Reproposal) => check_candidate(previous, candidate),
        _ => check_time(now, previous, candidate),
    }
}
