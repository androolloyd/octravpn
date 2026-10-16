// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Sync_cycle scheduling; events do not confer snapshot authority.
use super::{require, Result};
use crate::consensus::ValidatorSet;
pub const POLL_SECONDS: u64 = 15;
pub const ROLE_RETRY_SECONDS: u64 = 60;
pub const VALID_FOR_SECONDS: i64 = 2_678_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    interval: i64,
    retain: usize,
}
impl Policy {
    pub fn interval(self) -> i64 {
        self.interval
    }
    pub fn retention(self) -> usize {
        self.retain
    }
    pub fn new(interval: i64, retain: i64) -> Result<Self> {
        require(interval >= 1, "sync interval must be positive")?;
        require(retain >= 2, "sync retention must be at least two")?;
        Ok(Self {
            interval,
            retain: retain as usize,
        })
    }
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            interval: 360,
            retain: 2,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Published(i64),
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Finalized(i64),
    FinalizedAfter { epoch: i64, minimum: i64 },
    Completed { epoch: i64, outcome: Outcome },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Capture(i64),
    Retain(usize),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cycle {
    pub published: Option<i64>,
    pub running: Option<i64>,
    pub seen: Option<i64>,
}
impl Cycle {
    pub fn new(published: Option<i64>) -> Self {
        Self {
            published,
            running: None,
            seen: published,
        }
    }
    pub fn step(self, policy: Policy, event: Event) -> Result<(Self, Vec<Effect>)> {
        match event {
            Event::Finalized(epoch) => self.finalized(policy, epoch, 0),
            Event::FinalizedAfter { epoch, minimum } => self.finalized(policy, epoch, minimum),
            Event::Completed { epoch, outcome } => {
                let running = self
                    .running
                    .ok_or("sync completion has no active capture")?;
                require(running == epoch, "sync completion epoch mismatch")?;
                match outcome {
                    Outcome::Failed => Ok((
                        Self {
                            running: None,
                            ..self
                        },
                        vec![],
                    )),
                    Outcome::Published(published) => {
                        require(
                            published >= epoch,
                            "sync published epoch precedes capture target",
                        )?;
                        Ok((
                            Self {
                                published: Some(
                                    self.published
                                        .map_or(published, |prior| prior.max(published)),
                                ),
                                running: None,
                                ..self
                            },
                            vec![Effect::Retain(policy.retain)],
                        ))
                    }
                }
            }
        }
    }
    fn finalized(self, policy: Policy, epoch: i64, minimum: i64) -> Result<(Self, Vec<Effect>)> {
        require(epoch >= 0, "finalized epoch is negative")?;
        require(minimum >= 0, "sync minimum epoch is negative")?;
        require(
            minimum <= epoch,
            "sync minimum epoch exceeds finalized head",
        )?;
        if self.seen.is_some_and(|seen| epoch < seen) {
            return Ok((self, vec![]));
        }
        let next = Self {
            seen: Some(epoch),
            ..self
        };
        let target = minimum.max(epoch - epoch % policy.interval);
        if self.running.is_none() && self.published.is_none_or(|prior| target > prior) {
            Ok((
                Self {
                    running: Some(target),
                    ..next
                },
                vec![Effect::Capture(target)],
            ))
        } else {
            Ok((next, vec![]))
        }
    }
}

/// Native publisher_override accepts no spelling aliases.
pub fn publisher_override(value: Option<&[u8]>) -> Result<bool> {
    match value {
        None | Some(b"" | b"0") => Ok(false),
        Some(b"1") => Ok(true),
        Some(_) => Err("state sync publisher override must be 0 or 1".into()),
    }
}

pub fn publisher_addresses(exporters: &ValidatorSet) -> Vec<Vec<u8>> {
    let mut addresses = exporters
        .validators
        .iter()
        .map(|v| v.address.clone())
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    addresses.truncate(2);
    addresses
}
pub fn exporter_wallet(
    force: bool,
    exporters: &ValidatorSet,
    address: &[u8],
    public: &[u8],
) -> Result<()> {
    match exporters.public_key(address) {
        Some(expected)
            if expected == public
                && (force || publisher_addresses(exporters).iter().any(|v| v == address)) =>
        {
            Ok(())
        }
        Some(expected) if expected == public => Err("state sync publisher is not selected".into()),
        Some(_) => Err("state sync exporter wallet public key differs".into()),
        None => Err("state sync exporter wallet is not configured".into()),
    }
}

/// Latest two by epoch then bytewise ID, plus the current certificate's ID.
/// This is only a deletion plan; the caller must hold archive ownership.
pub fn retention_plan(retain: usize, current: &[u8], snapshots: &[(Vec<u8>, i64)]) -> Vec<Vec<u8>> {
    let mut ordered = snapshots.to_vec();
    ordered.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut keep = ordered
        .iter()
        .take(retain)
        .map(|x| x.0.as_slice())
        .collect::<Vec<_>>();
    keep.push(current);
    ordered
        .iter()
        .filter(|x| !keep.contains(&x.0.as_slice()))
        .map(|x| x.0.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_head_does_not_replace_capture_and_completion_preserves_latest_observation() {
        let policy = Policy::default();
        let (cycle, effects) = Cycle::new(Some(360))
            .step(policy, Event::Finalized(800))
            .unwrap();
        assert_eq!(effects, vec![Effect::Capture(720)]);
        let (cycle, effects) = cycle.step(policy, Event::Finalized(1200)).unwrap();
        assert!(effects.is_empty());
        assert!(cycle
            .step(
                policy,
                Event::Completed {
                    epoch: 721,
                    outcome: Outcome::Failed
                }
            )
            .is_err());
        let (cycle, effects) = cycle
            .step(
                policy,
                Event::Completed {
                    epoch: 720,
                    outcome: Outcome::Published(800),
                },
            )
            .unwrap();
        assert_eq!(effects, vec![Effect::Retain(2)]);
        assert_eq!(cycle.published, Some(800));
        let (same, effects) = cycle.step(policy, Event::Finalized(900)).unwrap();
        assert_eq!(same, cycle);
        assert!(effects.is_empty());
        let (cycle, effects) = cycle.step(policy, Event::Finalized(1200)).unwrap();
        assert_eq!(effects, vec![Effect::Capture(1080)]);
        assert_eq!(cycle.seen, Some(1200));
    }
    #[test]
    fn failed_capture_can_retry_but_force_cannot_create_exporter_authority() {
        use crate::consensus::Validator;
        let set = ValidatorSet::unweighted(
            (b'a'..=b'c')
                .map(|v| Validator {
                    address: vec![v],
                    pubkey: vec![v; 32],
                })
                .collect(),
        );
        assert!(exporter_wallet(false, &set, b"c", &[b'c'; 32]).is_err());
        assert!(exporter_wallet(true, &set, b"c", &[b'c'; 32]).is_ok());
        assert!(exporter_wallet(true, &set, b"c", &[b'a'; 32]).is_err());
        assert!(exporter_wallet(true, &set, b"d", &[b'd'; 32]).is_err());
        let policy = Policy::default();
        let (cycle, _) = Cycle::new(None)
            .step(
                policy,
                Event::FinalizedAfter {
                    epoch: 10,
                    minimum: 7,
                },
            )
            .unwrap();
        assert_eq!(cycle.running, Some(7));
        let (cycle, _) = cycle
            .step(
                policy,
                Event::Completed {
                    epoch: 7,
                    outcome: Outcome::Failed,
                },
            )
            .unwrap();
        assert_eq!(
            cycle
                .step(
                    policy,
                    Event::FinalizedAfter {
                        epoch: 10,
                        minimum: 7
                    }
                )
                .unwrap()
                .1,
            vec![Effect::Capture(7)]
        );
        for invalid in [b"true".as_slice(), b" 1", b"01", b"yes"] {
            assert!(publisher_override(Some(invalid)).is_err());
        }
    }
}
