// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted runtime quarantine cause and recovery-evidence policy. These rules
//! authorize admission changes only; they grant no authority to rewind history.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootEvidence {
    GenesisInSync,
    InSync,
    AheadWaitCurrentHead,
    AheadCurrentRootQuorum,
    SoftLagCurrentRoot,
}
impl RootEvidence {
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::GenesisInSync => b"genesis_in_sync",
            Self::InSync => b"in_sync",
            Self::AheadWaitCurrentHead => b"ahead_wait_current_head",
            Self::AheadCurrentRootQuorum => b"ahead_current_root_quorum",
            Self::SoftLagCurrentRoot => b"soft_lag_current_root",
        }
    }
}

pub fn root_attestation_recovers(reason: &[u8]) -> bool {
    [
        b"peer_root_mismatch_at_head ".as_slice(),
        b"ahead_of_target_by_",
        b"lag_",
        b"prev_state_root_mismatch_streak = ",
        b"state_root_mismatch_streak = ",
    ]
    .iter()
    .any(|prefix| reason.starts_with(prefix))
}

pub fn consensus_root_attestation_recovers(reason: &[u8]) -> bool {
    reason.starts_with(b"catchup_failed:") || reason.starts_with(b"catchup_apply_failed:")
}

pub fn root_recovery_evidence<'a>(
    reason: &[u8],
    evidence: &'a [u8],
    consensus_proved: bool,
) -> Option<&'a [u8]> {
    if root_attestation_recovers(reason) {
        Some(evidence)
    } else if consensus_root_attestation_recovers(reason)
        && evidence == b"in_sync"
        && consensus_proved
    {
        Some(b"in_sync_consensus_quorum")
    } else {
        None
    }
}

pub fn catchup_recovers(reason: &[u8]) -> bool {
    root_attestation_recovers(reason)
        || reason.starts_with(b"lag_")
        || reason.starts_with(b"catchup_")
}

pub fn recoverable_reason(reason: &[u8]) -> bool {
    catchup_recovers(reason) || reason.starts_with(b"bundle_wait_timeout_epoch_")
}

pub fn root_evidence(evidence: &[u8]) -> bool {
    matches!(
        evidence,
        b"genesis_in_sync"
            | b"in_sync"
            | b"ahead_wait_current_head"
            | b"ahead_current_root_quorum"
            | b"soft_lag_current_root"
    )
}

pub fn clear_allowed(reason: &[u8], evidence: &[u8]) -> bool {
    reason == evidence
        || evidence == b"fork_empty_rollback"
        || (catchup_recovers(reason) && evidence.starts_with(b"catchup_complete:root_verified:"))
        || (root_attestation_recovers(reason) && root_evidence(evidence))
        || (root_attestation_recovers(reason) && evidence.starts_with(b"direct_finalized_apply:"))
        || (consensus_root_attestation_recovers(reason) && evidence == b"in_sync_consensus_quorum")
}

/// An existing hard cause survives later recoverable observations. A hard
/// cause may replace a recoverable one; repeated causes retain their origin.
pub fn replace_reason(existing: &[u8], incoming: &[u8]) -> bool {
    recoverable_reason(existing) && !recoverable_reason(incoming)
}
