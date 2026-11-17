// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native historical quorum/proposal version and epoch-time activation rules.
use super::{Error, CURRENT_VERSION, LEGACY_VERSION};
pub const DEVNET: &[u8] = b"octra-devnet-9871-cluster";
pub const QUORUM_ACTIVATION: i64 = 1_306_547;
pub const STAKE_ACTIVATION: i64 = 1_737_333;
pub const ROUND_ACTIVATION: i64 = 1_740_000;
/// Seatless (weight-only) voting: anchored at `SEATLESS_ANCHOR_EPOCH` with
/// `SEATLESS_ANCHOR_ROOT`, in force from `SEATLESS_ACTIVATION`.
pub const SEATLESS_ANCHOR_EPOCH: i64 = 1_829_338;
pub const SEATLESS_ANCHOR_ROOT: &str =
    "621bc1164a85fc654cc8aeb34e8b23e8146edbc8448c4fbba5e8f9debcdd70af";
pub const SEATLESS_ACTIVATION: i64 = 1_845_000;
pub const ROUND_WAIT_ID: &str = "quorum_timers:stored_vote_resume:durable_past_votes:checked_relief_limit:quorum_phase:signed_progress_retry:stalled_signed_step:past_precommits";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    Prior,
    Capped,
    Stake,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuorumPolicy {
    pub count_epoch: i64,
    pub stake_epoch: Option<i64>,
    pub round_epoch: Option<i64>,
    /// First epoch of seatless voting; only meaningful with `stake_epoch`.
    pub seatless_epoch: Option<i64>,
}
impl QuorumPolicy {
    pub fn new(
        count_epoch: i64,
        stake_epoch: Option<i64>,
        round_epoch: Option<i64>,
    ) -> Result<Self, Error> {
        if count_epoch < 0 || stake_epoch.is_some_and(|epoch| epoch <= count_epoch) {
            return Err("quorum activation order".into());
        }
        if round_epoch.is_some_and(|round| stake_epoch.is_none_or(|stake| round < stake)) {
            return Err("round activation order".into());
        }
        Ok(Self {
            count_epoch,
            stake_epoch,
            round_epoch,
            seatless_epoch: None,
        })
    }
    pub fn with_round_epoch(self, round_epoch: Option<i64>) -> Result<Self, Error> {
        if round_epoch.is_some_and(|round| self.stake_epoch.is_none_or(|stake| round < stake)) {
            return Err("round activation order".into());
        }
        Ok(Self {
            round_epoch,
            ..self
        })
    }
    pub fn with_seatless_epoch(self, seatless_epoch: Option<i64>) -> Result<Self, Error> {
        match (self.stake_epoch, seatless_epoch) {
            (None, None) => Ok(self),
            (None, Some(_)) => Err("seatless activation requires stake".into()),
            (Some(stake), Some(epoch)) if epoch < stake => Err("seatless activation order".into()),
            (Some(_), seatless_epoch) => Ok(Self {
                seatless_epoch,
                ..self
            }),
        }
    }
    pub fn id_at(self, chain: &[u8], epoch: i64) -> String {
        let prior = quorum_consensus_id(chain);
        match self.stake_epoch {
            Some(first) if self.select(epoch) == Rule::Stake => {
                let stake = format!("{prior}:stake:{first}");
                match self.seatless_epoch {
                    Some(seatless) if epoch >= seatless => {
                        format!("{stake}:seatless:{seatless}:single_seat_survival")
                    }
                    _ => stake,
                }
            }
            _ => prior.to_owned(),
        }
    }
    pub fn for_chain(chain: &[u8]) -> Self {
        Self {
            count_epoch: if chain == DEVNET {
                QUORUM_ACTIVATION
            } else {
                0
            },
            stake_epoch: stake_epoch(chain),
            round_epoch: round_epoch(chain),
            seatless_epoch: seatless_epoch(chain),
        }
    }
    pub fn select(self, epoch: i64) -> Rule {
        if epoch < self.count_epoch {
            Rule::Prior
        } else if self.stake_epoch.is_some_and(|first| epoch >= first) {
            Rule::Stake
        } else {
            Rule::Capped
        }
    }
    /// Seatless voting needs the stake rule; without it the epoch is inert.
    pub fn seatless(self, epoch: i64) -> bool {
        self.stake_epoch.is_some() && self.seatless_epoch.is_some_and(|first| epoch >= first)
    }
    fn seatless_start(self) -> Option<i64> {
        self.stake_epoch.and(self.seatless_epoch)
    }
    pub fn round_wait(self, epoch: i64) -> bool {
        self.round_epoch.is_some_and(|first| epoch >= first)
    }
    pub fn rewind_allowed(self, from: i64, to: i64) -> bool {
        !std::iter::once(self.count_epoch)
            .chain(self.epochs())
            .any(|first| from >= first && to < first)
    }
    pub fn epochs(self) -> Vec<i64> {
        let mut epochs: Vec<_> = [self.stake_epoch, self.seatless_start(), self.round_epoch]
            .into_iter()
            .flatten()
            .collect();
        epochs.sort_unstable();
        epochs.dedup();
        epochs
    }
}
pub fn stake_epoch(chain: &[u8]) -> Option<i64> {
    (chain == DEVNET).then_some(STAKE_ACTIVATION)
}
pub fn round_epoch(chain: &[u8]) -> Option<i64> {
    (chain == DEVNET).then_some(ROUND_ACTIVATION)
}
pub fn seatless_epoch(chain: &[u8]) -> Option<i64> {
    (chain == DEVNET).then_some(SEATLESS_ACTIVATION)
}
pub fn quorum_rule(chain: &[u8], epoch: i64) -> Rule {
    QuorumPolicy::for_chain(chain).select(epoch)
}
pub fn quorum_active(chain_id: &[u8], epoch_id: i64) -> bool {
    quorum_rule(chain_id, epoch_id) != Rule::Prior
}
pub fn quorum_consensus_id(chain_id: &[u8]) -> &'static str {
    if chain_id == DEVNET {
        "resilient:1306321:c19278aec1ff53c4796aea354c9cc7845d8421fc7d6ffe971b5fecea29299a04:1306547"
    } else {
        "resilient:genesis"
    }
}
pub fn quorum_consensus_id_at(chain_id: &[u8], epoch: i64) -> String {
    QuorumPolicy::for_chain(chain_id).id_at(chain_id, epoch)
}
pub fn rewind_allowed(chain_id: &[u8], from_epoch: i64, to_epoch: i64) -> bool {
    QuorumPolicy::for_chain(chain_id).rewind_allowed(from_epoch, to_epoch)
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
