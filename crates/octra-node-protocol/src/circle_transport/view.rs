// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native read-time outbox evaluation; this never persists a transition.
use super::{Claim, Intent, Reason, Resolution, Status};
use crate::circle_policy::{
    key,
    transport::{Ingress, Lease, Policy},
};

pub struct Evaluation {
    pub status: Status,
    pub resolution: Option<Resolution>,
}
pub fn evaluate(
    epoch: i64,
    policy: &Policy,
    intent: &Intent,
    stored_status: Status,
    stored_resolution: Option<&Resolution>,
    active: &[Claim],
    delivery: key::State,
) -> Evaluation {
    let stored = || Evaluation {
        status: stored_status,
        resolution: stored_resolution.cloned(),
    };
    let resolved = |status, reason, related_key: Option<&[u8]>| Evaluation {
        status,
        resolution: stored_resolution.cloned().or_else(|| {
            Some(Resolution::make(
                &intent.id,
                epoch,
                None,
                related_key,
                reason,
            ))
        }),
    };
    if matches!(stored_status, Status::Fulfilled | Status::Cancelled) {
        return stored();
    }
    if let Some(reason) = Reason::from_key(delivery) {
        return resolved(Status::Cancelled, reason, intent.delivery_key.as_deref());
    }
    if intent.expiry <= epoch {
        return resolved(Status::Expired, Reason::IntentExpired, None);
    }
    if stored_status == Status::Claimed && active.is_empty() {
        return match policy.lease {
            Lease::Reopen => Evaluation {
                status: Status::Open,
                resolution: stored_resolution.cloned(),
            },
            Lease::Terminal => resolved(Status::Expired, Reason::ClaimExpired, None),
            Lease::Cancel => resolved(Status::Cancelled, Reason::ClaimSetExhausted, None),
        };
    }
    stored()
}
pub fn compare_newest(left: &Claim, right: &Claim) -> std::cmp::Ordering {
    right
        .epoch
        .cmp(&left.epoch)
        .then(right.expiry.cmp(&left.expiry))
        .then(left.relay.cmp(&right.relay))
}
/// Stable native rankings preserve relay ordering when epoch/expiry tie.
pub fn eligible<'a>(policy: &Policy, claims: &'a [Claim]) -> Vec<&'a Claim> {
    let mut ranked = claims.iter().collect::<Vec<_>>();
    ranked.sort_by(|left, right| match policy.ingress {
        Ingress::AnyReady | Ingress::Newest => compare_newest(left, right),
        Ingress::Oldest => compare_newest(right, left),
        Ingress::Heaviest | Ingress::HeaviestNewest => policy
            .weight(&right.relay)
            .cmp(&policy.weight(&left.relay))
            .then_with(|| compare_newest(left, right)),
        Ingress::HeaviestOldest => policy
            .weight(&right.relay)
            .cmp(&policy.weight(&left.relay))
            .then_with(|| compare_newest(right, left)),
    });
    if policy.ingress != Ingress::AnyReady {
        ranked.truncate(1);
    }
    ranked
}
