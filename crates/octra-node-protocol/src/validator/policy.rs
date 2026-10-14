// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    admission::{Candidate, Parameters},
    Error,
};
use crate::{native_integer::parse_int63, transaction::RuleMode};

pub const ENV_NAME: &str = "OCTRA_VALIDATOR_ADMISSION_ACTIVATION_EPOCH";
pub const STANDARD_NAME: &[u8] = b"bonded_stake";
pub const EXIT_WINDOW: i64 = 4096;
pub const EXIT_WAIT: i64 = 8192;
pub const EXIT_ID: &str = "8192:4096";
pub fn parameters() -> Parameters {
    Parameters {
        min_bond: 1_000_000.into(),
        max_validators: 64,
        activation_delay: 64,
        unbonding_epochs: 172_800,
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Active {
    pub activation_epoch: i64,
    pub parameters: Parameters,
    pub snapshot_interval: i64,
    pub evidence_epochs: i64,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Policy {
    #[default]
    Inactive,
    Bonded(Active),
}
impl Policy {
    /// Read configuration once at boot; replay must not observe environment changes.
    pub fn from_value(raw: Option<&[u8]>) -> Result<Self, Error> {
        let Some(raw) = raw.filter(|v| !v.is_empty()) else {
            return Ok(Self::Inactive);
        };
        let activation_epoch =
            parse_int63(raw).ok_or("invalid validator admission activation epoch")?;
        if activation_epoch < 64 {
            return Err("validator admission activation precedes snapshot delay".into());
        }
        Ok(Self::Bonded(Active {
            activation_epoch,
            parameters: parameters(),
            snapshot_interval: 64,
            evidence_epochs: 86_400,
        }))
    }
    pub fn activation_epoch(&self) -> Option<i64> {
        match self {
            Self::Inactive => None,
            Self::Bonded(v) => Some(v.activation_epoch),
        }
    }
    pub fn lifecycle_enabled(&self) -> bool {
        matches!(self, Self::Bonded(_))
    }
    pub fn consensus_id(&self) -> String {
        match self {
            Self::Inactive => "inactive".into(),
            Self::Bonded(v) => format!(
                "bonded_stake:{}:{}:{}:{}:{}:{}:{}",
                v.activation_epoch,
                v.parameters.min_bond,
                v.parameters.max_validators,
                v.parameters.activation_delay,
                v.snapshot_interval,
                v.parameters.unbonding_epochs,
                v.evidence_epochs
            ),
        }
    }
    pub fn snapshot_activation(&self, source: i64) -> Result<Option<i64>, Error> {
        match self {
            Self::Inactive => Ok(None),
            Self::Bonded(v) => {
                self.snapshot_at(source, v.snapshot_interval, v.parameters.activation_delay)
            }
        }
    }
    pub fn snapshot_at(&self, source: i64, cadence: i64, delay: i64) -> Result<Option<i64>, Error> {
        let Self::Bonded(v) = self else {
            return Ok(None);
        };
        let first_source = v.activation_epoch.wrapping_sub(delay);
        if source < first_source {
            return Ok(None);
        }
        // Native Int64.rem raises Division_by_zero here. Report a host error,
        // never substitute a cadence or silently change activation behavior.
        if cadence == 0 {
            return Err("Division_by_zero".into());
        }
        let elapsed = source.wrapping_sub(first_source);
        Ok((elapsed.wrapping_rem(cadence) == 0).then(|| source.wrapping_add(delay)))
    }
}
pub fn exit_parameters(mode: RuleMode, value: &Parameters) -> Parameters {
    let mut value = value.clone();
    if mode == RuleMode::Active {
        value.unbonding_epochs = EXIT_WAIT;
    }
    value
}
pub fn evidence_age(mode: RuleMode, prior: i64) -> i64 {
    match mode {
        RuleMode::Prior => prior,
        RuleMode::Active => EXIT_WINDOW,
    }
}
/// The caller resolves the chain's trusted rule graph and activation anchor.
pub fn withdraw_epoch(
    mode: RuleMode,
    activation: Option<i64>,
    candidate: &Candidate,
) -> Result<i64, Error> {
    let due = exit_parameters(mode, &parameters()).withdraw_epoch(candidate)?;
    Ok(if mode == RuleMode::Active {
        activation.map_or(due, |v| due.max(v))
    } else {
        due
    })
}
