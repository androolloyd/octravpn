// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native quorum measure (`C_measure`): the one place that decides what a
//! group of signers proves under each quorum rule, including the seatless
//! rule where declared weight alone decides and seat counts no longer do.
use super::policy::{QuorumPolicy, Rule};
use super::Bytes;
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use std::collections::BTreeSet;

/// What a caller is asking a group of signers to prove.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ask {
    Quorum,
    Skip,
    Source,
    Pair,
    Ahead,
    Start,
    Promise,
}
/// Why two validator sets cannot be shown to intersect safely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gap {
    FewSeats,
    LowWeight,
    NoProof,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shape {
    pub n: i64,
    pub f: i64,
    pub quorum: i64,
    pub total_weight: BigInt,
    pub quorum_weight: BigInt,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Space {
    rule: Rule,
    seatless: bool,
    declared: bool,
    shape: Shape,
}
/// Smallest weight strictly above two thirds of `total`.
pub fn quota(total: &BigInt) -> BigInt {
    (total * 2) / 3 + 1
}
pub fn shape(seats: i64, total: BigInt) -> Shape {
    let f = (seats - 1) / 3;
    let quorum = if seats <= 0 {
        0
    } else if seats < 4 {
        seats
    } else {
        seats - f
    };
    let quorum_weight = if total.is_positive() {
        quota(&total)
    } else {
        BigInt::zero()
    };
    Shape {
        n: seats,
        f,
        quorum,
        total_weight: total,
        quorum_weight,
    }
}
/// Whether a set that loses `lost` weight can still reach its own quota.
pub fn live(total: &BigInt, lost: &BigInt) -> bool {
    total - lost >= quota(total)
}
fn sum(weights: &[(Bytes, BigInt)]) -> BigInt {
    weights.iter().map(|(_, weight)| weight).sum()
}
pub fn ruled(rule: Rule, declared: bool, weights: &[(Bytes, BigInt)]) -> Space {
    Space {
        rule,
        seatless: false,
        declared,
        shape: shape(weights.len() as i64, sum(weights)),
    }
}
pub fn space(
    policy: QuorumPolicy,
    epoch: i64,
    declared: bool,
    weights: &[(Bytes, BigInt)],
) -> Space {
    Space {
        seatless: policy.seatless(epoch),
        ..ruled(policy.select(epoch), declared, weights)
    }
}
/// Weight that blocks a quorum: everything a quorum does not need, plus one.
pub fn minority(shape: &Shape) -> BigInt {
    &shape.total_weight - &shape.quorum_weight + 1
}
fn lowest(count: i64, weights: &[(Bytes, BigInt)]) -> BigInt {
    let mut sorted: Vec<_> = weights.iter().map(|(_, weight)| weight).collect();
    sorted.sort_unstable();
    sorted.into_iter().take(count.max(0) as usize).sum()
}
impl Space {
    pub const fn seatless(&self) -> bool {
        self.seatless
    }
    pub const fn shape(&self) -> &Shape {
        &self.shape
    }
    pub fn valid(&self) -> bool {
        match self.rule {
            Rule::Prior | Rule::Capped => true,
            Rule::Stake => self.declared,
        }
    }
    fn start_seats(&self) -> i64 {
        if self.seatless {
            return 1;
        }
        match self.rule {
            Rule::Prior => 1,
            Rule::Capped | Rule::Stake => (self.shape.quorum - 1).max(1),
        }
    }
    fn promise_seats(&self) -> i64 {
        (self.shape.quorum - 1).max(0)
    }
    pub fn meets(&self, ask: Ask, seats: i64, weight: &BigInt) -> bool {
        let seated = seats >= self.shape.quorum;
        let present = seats > self.shape.f;
        let heavy = weight >= &self.shape.quorum_weight;
        let minority = minority(&self.shape);
        let blocking = weight >= &minority;
        if self.seatless {
            let funded = self.declared && self.shape.total_weight.is_positive();
            return match ask {
                Ask::Quorum | Ask::Pair => funded && heavy,
                Ask::Skip | Ask::Source | Ask::Ahead | Ask::Promise => funded && blocking,
                Ask::Start => seats >= 1,
            };
        }
        match (ask, self.rule) {
            (Ask::Quorum, Rule::Prior) => heavy,
            (Ask::Quorum, Rule::Capped) | (Ask::Pair, _) => seated && heavy,
            (Ask::Quorum, Rule::Stake) => self.valid() && seated && heavy,
            (Ask::Skip | Ask::Source, Rule::Prior) => blocking,
            (Ask::Skip, Rule::Capped) | (Ask::Source, Rule::Capped | Rule::Stake) => {
                present && blocking
            }
            (Ask::Skip, Rule::Stake) => self.valid() && present && blocking,
            (Ask::Ahead, _) => minority.is_positive() && blocking,
            (Ask::Start, _) => seats >= self.start_seats(),
            (Ask::Promise, _) => seats >= self.promise_seats(),
        }
    }
    pub fn attested(&self, required: i64, seats: i64, weight: &BigInt) -> bool {
        if self.seatless {
            self.declared
                && self.shape.total_weight.is_positive()
                && weight >= &minority(&self.shape)
        } else {
            seats >= required
        }
    }
    pub fn replies(&self, configured: i64) -> i64 {
        if self.seatless {
            return i64::from(self.shape.n > 1);
        }
        let limit = (self.shape.n - 1).max(0);
        if limit == 0 {
            0
        } else {
            limit.min((self.shape.f + 1).max(configured))
        }
    }
    pub fn wave(&self) -> i64 {
        (self.shape.f + 2).max(1)
    }
    pub fn fanout(&self) -> i64 {
        if self.seatless {
            self.shape.n
        } else {
            (self.shape.f + 2).max(1)
        }
    }
    /// Whether every quorum of this set must share an honest member with
    /// every quorum of `target`.
    pub fn overlap(&self, target: &[(Bytes, BigInt)]) -> Result<(), Gap> {
        let current = &self.shape;
        let faults = &current.total_weight - &current.quorum_weight;
        if self.seatless {
            let total = sum(target);
            let names: BTreeSet<_> = target.iter().map(|(name, _)| name).collect();
            if !self.declared
                || !current.total_weight.is_positive()
                || !total.is_positive()
                || total > current.total_weight
                || target.iter().any(|(_, weight)| !weight.is_positive())
                || names.len() != target.len()
            {
                return Err(Gap::NoProof);
            }
            return if &current.quorum_weight + quota(&total) - &current.total_weight <= faults {
                Err(Gap::LowWeight)
            } else {
                Ok(())
            };
        }
        let next = shape(target.len() as i64, sum(target));
        let shared = current.quorum + next.quorum - current.n;
        if shared <= current.f {
            return Err(Gap::FewSeats);
        }
        let by_count = lowest(shared, target);
        let by_weight = &current.quorum_weight + &next.quorum_weight - &current.total_weight;
        if by_count.max(by_weight) <= faults {
            Err(Gap::LowWeight)
        } else {
            Ok(())
        }
    }
    pub const fn label(&self) -> &'static str {
        if self.seatless {
            return "seatless";
        }
        match self.rule {
            Rule::Prior => "prior",
            Rule::Capped => "capped",
            Rule::Stake => "stake",
        }
    }
    pub fn start_text(&self) -> String {
        self.start_seats().to_string()
    }
    pub fn promise_text(&self) -> String {
        if self.seatless {
            minority(&self.shape).to_string()
        } else {
            self.promise_seats().to_string()
        }
    }
}
