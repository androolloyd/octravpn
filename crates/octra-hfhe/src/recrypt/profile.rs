// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Exact native reset-proof resource arithmetic, including unsigned overflow behavior.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Params {
    pub rounds: usize,
    pub branches: usize,
    pub opened_branches: usize,
    pub target_bits: usize,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    #[default]
    None,
    FieldNative,
    ShaCompat,
    Unknown(u8),
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Profile {
    pub kind: Kind,
    pub params: Params,
    pub soundness_bits: usize,
    pub branch_commits: usize,
    pub branch_openings: usize,
    pub trace_units: usize,
    pub commit_bytes: usize,
    pub opening_bytes: usize,
    pub transcript_bytes: usize,
    pub total_bytes: usize,
    pub baseline_bytes: usize,
    pub ratio_milli: usize,
    pub compact: bool,
    pub admitted: bool,
}
fn branch_milli_bits(branches: usize, opened: usize) -> usize {
    if branches == 3 && opened == 1 {
        584
    } else {
        0
    }
}
pub fn rounds_for_target(target: usize, branches: usize, opened: usize) -> usize {
    let bits = branch_milli_bits(branches, opened);
    if bits == 0 {
        return 0;
    }
    target
        .checked_mul(1000)
        .map_or(0, |value| value.wrapping_add(bits).wrapping_sub(1) / bits)
}
impl Params {
    pub fn new(target_bits: usize, branches: usize, opened_branches: usize) -> Self {
        Self {
            target_bits,
            branches,
            opened_branches,
            rounds: rounds_for_target(target_bits, branches, opened_branches),
        }
    }
    pub fn soundness_bits(self) -> usize {
        self.rounds
            .checked_mul(branch_milli_bits(self.branches, self.opened_branches))
            .map_or(usize::MAX, |value| value / 1000)
    }
    pub fn branch_commits(self) -> usize {
        self.rounds.checked_mul(self.branches).unwrap_or(0)
    }
    pub fn branch_openings(self) -> usize {
        self.rounds.checked_mul(self.opened_branches).unwrap_or(0)
    }
    pub fn admitted(self) -> bool {
        self.target_bits >= 128
            && self.branches == 3
            && self.opened_branches == 1
            && self.soundness_bits() >= self.target_bits
    }
}
pub fn profile_bytes(units: usize) -> usize {
    units.saturating_mul(32).saturating_add(128)
}
pub fn plan(kind: Kind, target: usize) -> Profile {
    let mut profile = Profile {
        kind,
        ..Profile::default()
    };
    if !matches!(kind, Kind::FieldNative | Kind::ShaCompat) {
        return profile;
    }
    profile.params = Params::new(target, 3, 1);
    profile.soundness_bits = profile.params.soundness_bits();
    profile.branch_commits = profile.params.branch_commits();
    profile.branch_openings = profile.params.branch_openings();
    profile.trace_units = profile.branch_commits.wrapping_add(profile.branch_openings);
    profile.commit_bytes = profile_bytes(profile.branch_commits);
    profile.opening_bytes = profile_bytes(profile.branch_openings);
    profile.transcript_bytes = profile_bytes(profile.trace_units);
    profile.total_bytes = profile
        .commit_bytes
        .saturating_add(profile.opening_bytes)
        .saturating_add(profile.transcript_bytes);
    let baseline = Params::new(target, 3, 1);
    let baseline_bytes = profile_bytes(
        baseline
            .branch_commits()
            .wrapping_add(baseline.branch_openings()),
    );
    profile.baseline_bytes = baseline_bytes
        .saturating_add(baseline_bytes)
        .saturating_add(baseline_bytes);
    profile.ratio_milli = profile
        .total_bytes
        .wrapping_mul(1000)
        .checked_div(profile.baseline_bytes)
        .unwrap_or(0);
    profile.compact = kind == Kind::FieldNative
        && profile.params.rounds < baseline.rounds
        && profile.total_bytes < profile.baseline_bytes;
    profile.admitted = profile.params.admitted();
    profile
}
