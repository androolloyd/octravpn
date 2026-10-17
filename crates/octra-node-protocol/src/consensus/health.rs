// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted native health admission policy. Root agreement counts distinct
//! authenticated peers; weighted consensus proof is a separate host decision.
use crate::{native_integer::parse_int63, native_table::Table};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub state_attest_min_peers: i64,
    pub ahead_streak_threshold: i64,
    pub ahead_grace_epochs: i64,
    pub ahead_drift_tolerance: i64,
    pub soft_catchup_max_lag: i64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            state_attest_min_peers: 0,
            ahead_streak_threshold: 5,
            ahead_grace_epochs: 32,
            ahead_drift_tolerance: 2,
            soft_catchup_max_lag: 4,
        }
    }
}
impl Config {
    /// Native Env.int_value does not trim. Malformed Int63 values use the
    /// default; bounded settings outside their interval also use the default.
    /// Trusted launcher inputs alone select these local admission limits.
    pub fn from_inputs<'a>(mut get: impl FnMut(&str) -> Option<&'a [u8]>) -> Self {
        fn bounded(raw: Option<&[u8]>, default: i64, low: i64, high: i64) -> i64 {
            raw.and_then(parse_int63)
                .filter(|value| (low..=high).contains(value))
                .unwrap_or(default)
        }
        Self {
            state_attest_min_peers: get("OCTRA_STATE_ATTEST_MIN_PEERS")
                .and_then(parse_int63)
                .unwrap_or(0),
            ahead_streak_threshold: bounded(
                get("OCTRA_QUARANTINE_AHEAD_STREAK_THRESHOLD"),
                5,
                1,
                100,
            ),
            ahead_grace_epochs: bounded(get("OCTRA_QUARANTINE_AHEAD_GRACE_EPOCHS"), 32, 0, 100_000),
            ahead_drift_tolerance: bounded(
                get("OCTRA_QUARANTINE_AHEAD_DRIFT_TOLERANCE"),
                2,
                0,
                10_000,
            ),
            soft_catchup_max_lag: bounded(get("OCTRA_CATCHUP_SOFT_MAX_LAG"), 4, 0, 10_000),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Majority {
    pub root: Vec<u8>,
    pub count: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootQuorum {
    NoRoot,
    Missing(Majority),
    Matching(Majority),
    Mismatching(Majority),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InSyncPlan {
    PeerRootMismatch(Majority),
    AcceptGenesis,
    MissingPeerRootQuorum(i64),
    AcceptCurrentRoot,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryPlan {
    Retry(i64),
    Stop,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AheadNoQuorumPlan {
    WaitCurrentHead,
    ProbeCurrentHead,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AheadCurrentRootPlan {
    CurrentRootMatches,
    CurrentRootMismatch(Majority),
    WaitCurrentRootQuorum,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AheadQuorumPlan {
    StayActive { wake_ready: bool },
    DelayQuarantine { wake_ready: bool },
    QuarantineAhead,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LagMode {
    Soft,
    Quarantine,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LagPlan {
    SnapshotFallback(i64),
    LaggingSoft(i64),
    LaggingQuarantine(i64),
}

fn int63(value: i64) -> i64 {
    (value << 1) >> 1
}

pub fn required_attesters(active_f: i64, validator_count: i64, configured: i64) -> i64 {
    let max_peer_attesters = int63(validator_count.wrapping_sub(1)).max(0);
    let base = int63(active_f.wrapping_add(1)).max(configured);
    if max_peer_attesters == 0 {
        0
    } else {
        max_peer_attesters.min(base)
    }
}

/// The caller authenticates, deduplicates and validates root lengths first.
/// Native Hashtbl.create(8) traversal decides equal-count ties, including its
/// insertion/replacement/resize ordering; lexical root order is not equivalent.
pub fn peer_root_majority<'a>(
    roots: impl IntoIterator<Item = Option<&'a [u8]>>,
) -> Option<Majority> {
    let mut counts = Table::new(8);
    for root in roots.into_iter().flatten() {
        let count = int63(counts.get(root).copied().unwrap_or(0_i64).wrapping_add(1));
        counts.replace(root.to_vec(), count);
    }
    let mut best: Option<Majority> = None;
    for (root, count) in counts.iter() {
        if best.as_ref().is_none_or(|best| *count > best.count) {
            best = Some(Majority {
                root: root.to_vec(),
                count: *count,
            });
        }
    }
    best
}

pub fn root_with_quorum(required: i64, majority: Option<Majority>) -> Option<Majority> {
    majority.filter(|majority| majority.count >= required)
}

pub fn compare_root(required: i64, local_root: &[u8], majority: Option<Majority>) -> RootQuorum {
    match majority {
        None => RootQuorum::NoRoot,
        Some(majority) if majority.count < required => RootQuorum::Missing(majority),
        Some(majority) if majority.root == local_root => RootQuorum::Matching(majority),
        Some(majority) => RootQuorum::Mismatching(majority),
    }
}

pub fn peer_root_quorum<'a>(
    required: i64,
    local_root: &[u8],
    roots: impl IntoIterator<Item = Option<&'a [u8]>>,
) -> RootQuorum {
    compare_root(required, local_root, peer_root_majority(roots))
}

pub fn root_quorum_count(quorum: &RootQuorum) -> i64 {
    match quorum {
        RootQuorum::NoRoot => 0,
        RootQuorum::Missing(majority)
        | RootQuorum::Matching(majority)
        | RootQuorum::Mismatching(majority) => majority.count,
    }
}

pub fn root_quorum_has_quorum(quorum: &RootQuorum) -> bool {
    matches!(quorum, RootQuorum::Matching(_) | RootQuorum::Mismatching(_))
}

pub fn peer_root_with_quorum<'a>(
    required: i64,
    roots: impl IntoIterator<Item = Option<&'a [u8]>>,
) -> Option<Majority> {
    root_with_quorum(required, peer_root_majority(roots))
}

pub fn in_sync_plan(
    required: i64,
    has_committed_root: bool,
    genesis_attested: bool,
    quorum: &RootQuorum,
) -> InSyncPlan {
    match quorum {
        RootQuorum::Mismatching(majority) => InSyncPlan::PeerRootMismatch(majority.clone()),
        _ if genesis_attested => InSyncPlan::AcceptGenesis,
        _ if required == 0 && has_committed_root => InSyncPlan::AcceptCurrentRoot,
        RootQuorum::NoRoot => InSyncPlan::MissingPeerRootQuorum(0),
        RootQuorum::Missing(majority) => InSyncPlan::MissingPeerRootQuorum(majority.count),
        RootQuorum::Matching(_) => InSyncPlan::AcceptCurrentRoot,
    }
}

pub fn moving_head_plan(stale_retries: i64) -> RetryPlan {
    if stale_retries > 0 {
        RetryPlan::Retry(stale_retries - 1)
    } else {
        RetryPlan::Stop
    }
}

pub fn stale_sample_plan(live_head_attested: bool, stale_retries: i64) -> RetryPlan {
    if !live_head_attested && stale_retries > 0 {
        RetryPlan::Retry(stale_retries - 1)
    } else {
        RetryPlan::Stop
    }
}

pub fn within_ahead_grace(
    head: i64,
    ahead_by: i64,
    grace_epochs: i64,
    drift_tolerance: i64,
) -> bool {
    head < grace_epochs || ahead_by <= drift_tolerance
}

pub fn ahead_no_quorum_plan(
    head: i64,
    ahead_by: i64,
    grace_epochs: i64,
    drift_tolerance: i64,
    quarantine_active: bool,
) -> AheadNoQuorumPlan {
    if !quarantine_active && within_ahead_grace(head, ahead_by, grace_epochs, drift_tolerance) {
        AheadNoQuorumPlan::WaitCurrentHead
    } else {
        AheadNoQuorumPlan::ProbeCurrentHead
    }
}

pub fn ahead_current_root_plan(quorum: &RootQuorum) -> AheadCurrentRootPlan {
    match quorum {
        RootQuorum::Matching(_) => AheadCurrentRootPlan::CurrentRootMatches,
        RootQuorum::Mismatching(majority) => {
            AheadCurrentRootPlan::CurrentRootMismatch(majority.clone())
        }
        RootQuorum::NoRoot | RootQuorum::Missing(_) => AheadCurrentRootPlan::WaitCurrentRootQuorum,
    }
}

#[allow(clippy::too_many_arguments)] // Native ahead policy arguments.
pub fn ahead_quorum_plan(
    head: i64,
    ahead_by: i64,
    streak: i64,
    grace_epochs: i64,
    drift_tolerance: i64,
    streak_threshold: i64,
    quarantine_active: bool,
) -> AheadQuorumPlan {
    let wake_ready = !quarantine_active;
    if within_ahead_grace(head, ahead_by, grace_epochs, drift_tolerance) {
        AheadQuorumPlan::StayActive { wake_ready }
    } else if streak < streak_threshold {
        AheadQuorumPlan::DelayQuarantine { wake_ready }
    } else {
        AheadQuorumPlan::QuarantineAhead
    }
}

pub fn classify_lag_mode(lag: i64, soft_lag: i64) -> LagMode {
    if lag <= soft_lag.max(0) {
        LagMode::Soft
    } else {
        LagMode::Quarantine
    }
}

pub fn snapshot_plan(lag: i64) -> LagPlan {
    LagPlan::SnapshotFallback(lag)
}

pub fn catchup_lag_plan(lag: i64, soft_lag: i64) -> LagPlan {
    match classify_lag_mode(lag, soft_lag) {
        LagMode::Soft => LagPlan::LaggingSoft(lag),
        LagMode::Quarantine => LagPlan::LaggingQuarantine(lag),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_count_is_separate_from_weighted_source_agreement() {
        assert_eq!(required_attesters(1, 4, 3), 3);
        assert_eq!(required_attesters(1, 4, 100), 3);
        assert_eq!(required_attesters(1, 4, -1), 2);
        assert_eq!(required_attesters(0, 1, 100), 0);
        let roots = [Some(b"same".as_slice()), Some(b"same".as_slice())];
        assert!(matches!(
            peer_root_quorum(3, b"same", roots),
            RootQuorum::Missing(_)
        ));
        assert!(matches!(
            peer_root_quorum(2, b"same", roots),
            RootQuorum::Matching(_)
        ));
    }

    #[test]
    fn native_config_falls_back_without_whitespace_normalization_or_saturation() {
        assert_eq!(Config::from_inputs(|_| None), Config::default());
        let config = Config::from_inputs(|name| match name {
            "OCTRA_STATE_ATTEST_MIN_PEERS" => Some(b"-1"),
            "OCTRA_QUARANTINE_AHEAD_STREAK_THRESHOLD" => Some(b"101"),
            "OCTRA_QUARANTINE_AHEAD_GRACE_EPOCHS" => Some(b"0x20"),
            "OCTRA_QUARANTINE_AHEAD_DRIFT_TOLERANCE" => Some(b" 5"),
            "OCTRA_CATCHUP_SOFT_MAX_LAG" => Some(b"0"),
            _ => None,
        });
        assert_eq!(config.state_attest_min_peers, -1);
        assert_eq!(config.ahead_streak_threshold, 5);
        assert_eq!(config.ahead_grace_epochs, 32);
        assert_eq!(config.ahead_drift_tolerance, 2);
        assert_eq!(config.soft_catchup_max_lag, 0);
    }

    #[test]
    fn proven_mismatch_is_not_waived_by_genesis_or_zero_required() {
        let mismatch = RootQuorum::Mismatching(Majority {
            root: vec![8; 32],
            count: 2,
        });
        assert!(matches!(
            in_sync_plan(0, true, true, &mismatch),
            InSyncPlan::PeerRootMismatch(_)
        ));
        assert_eq!(
            in_sync_plan(0, true, false, &RootQuorum::NoRoot),
            InSyncPlan::AcceptCurrentRoot
        );
        assert_eq!(
            in_sync_plan(2, true, false, &RootQuorum::NoRoot),
            InSyncPlan::MissingPeerRootQuorum(0)
        );
    }

    #[test]
    fn ahead_grace_and_streak_do_not_wake_an_active_quarantine() {
        assert_eq!(
            ahead_no_quorum_plan(31, 100, 32, 2, false),
            AheadNoQuorumPlan::WaitCurrentHead
        );
        assert_eq!(
            ahead_no_quorum_plan(31, 100, 32, 2, true),
            AheadNoQuorumPlan::ProbeCurrentHead
        );
        assert_eq!(
            ahead_quorum_plan(32, 3, 4, 32, 2, 5, false),
            AheadQuorumPlan::DelayQuarantine { wake_ready: true }
        );
        assert_eq!(
            ahead_quorum_plan(32, 3, 5, 32, 2, 5, false),
            AheadQuorumPlan::QuarantineAhead
        );
        assert_eq!(
            ahead_quorum_plan(32, 2, 5, 32, 2, 5, true),
            AheadQuorumPlan::StayActive { wake_ready: false }
        );
        assert_eq!(classify_lag_mode(1, -1), LagMode::Quarantine);
    }
}
