// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native complete/legacy finality routing and monotonic retry scheduling.
pub const MAX_ATTEMPTS: i64 = 3;
pub const RETRY_NS: i64 = 5_000_000_000;
pub const REST_NS: i64 = 60_000_000_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Query {
    #[default]
    Idle,
    Sent {
        epoch: i64,
        attempts: i64,
        sent_at: i64,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    Wait,
    Rest,
    Send(Query),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Unmarked,
    Range,
    Finality,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proof {
    Complete,
    LegacyComplete,
    LegacyPartial,
    Invalid,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Complete,
    LegacyRange,
    Finality,
    IgnoreLegacy,
    Reject,
}
pub fn scope(complete_request: bool, finality_request: bool) -> Scope {
    if !complete_request {
        Scope::Unmarked
    } else if finality_request {
        Scope::Finality
    } else {
        Scope::Range
    }
}
#[allow(clippy::fn_params_excessive_bools)] // Exact native validation predicates.
pub fn proof(complete_valid: bool, legacy_valid: bool, legacy_complete: bool) -> Proof {
    if complete_valid {
        Proof::Complete
    } else if legacy_valid && legacy_complete {
        Proof::LegacyComplete
    } else if legacy_valid {
        Proof::LegacyPartial
    } else {
        Proof::Invalid
    }
}
pub fn route(scope: Scope, proof: Proof) -> Route {
    match (scope, proof) {
        (Scope::Range | Scope::Finality, Proof::Complete) => Route::Complete,
        (Scope::Range, Proof::LegacyComplete) => Route::LegacyRange,
        (Scope::Finality, Proof::LegacyComplete) => Route::Finality,
        (Scope::Range | Scope::Finality, Proof::LegacyPartial) => Route::IgnoreLegacy,
        (Scope::Unmarked, _) | (Scope::Range | Scope::Finality, Proof::Invalid) => Route::Reject,
    }
}
impl Query {
    pub fn plan(self, now: i64, epoch: i64) -> Plan {
        let send = |attempts| {
            Plan::Send(Self::Sent {
                epoch,
                attempts,
                sent_at: now,
            })
        };
        match self {
            Self::Idle => send(1),
            Self::Sent { epoch: prior, .. } if prior != epoch => send(1),
            Self::Sent {
                attempts, sent_at, ..
            } if attempts >= MAX_ATTEMPTS => {
                if now.wrapping_sub(sent_at) < REST_NS {
                    Plan::Rest
                } else {
                    send(1)
                }
            }
            Self::Sent {
                attempts, sent_at, ..
            } => {
                if now.wrapping_sub(sent_at) < RETRY_NS {
                    Plan::Wait
                } else {
                    send(attempts + 1)
                }
            }
        }
    }
}
