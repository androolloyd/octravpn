// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native C_limit resource algebra. Derived bounds use unbounded integers and
//! are checked explicitly rather than saturating or wrapping at host width.
use num_bigint::{BigInt, Sign};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Axis {
    Steps,
    Depth,
    Work,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Limit {
    pub steps: BigInt,
    pub depth: BigInt,
    pub work: BigInt,
}
impl Limit {
    pub fn at(&self, axis: Axis) -> &BigInt {
        match axis {
            Axis::Steps => &self.steps,
            Axis::Depth => &self.depth,
            Axis::Work => &self.work,
        }
    }
    pub fn valid(&self) -> bool {
        let maximum = BigInt::from(super::super::limits::NATURAL);
        [Axis::Steps, Axis::Depth, Axis::Work]
            .into_iter()
            .all(|axis| {
                let value = self.at(axis);
                value.sign() != Sign::Minus && value <= &maximum
            })
    }
    pub fn one() -> Self {
        Self::make(BigInt::from(1))
    }
    pub fn make(steps: BigInt) -> Self {
        Self {
            work: steps.clone(),
            steps,
            depth: BigInt::from(0),
        }
    }
    pub fn level(depth: BigInt) -> Self {
        Self {
            depth,
            ..Self::default()
        }
    }
    pub fn effort(work: BigInt) -> Self {
        Self {
            work,
            ..Self::default()
        }
    }
    pub fn used(steps: BigInt, work: BigInt) -> Self {
        Self {
            steps,
            work,
            depth: BigInt::from(0),
        }
    }
    pub fn add(&self, right: &Self) -> Self {
        Self {
            steps: &self.steps + &right.steps,
            depth: &self.depth + &right.depth,
            work: &self.work + &right.work,
        }
    }
    pub fn successor(&self) -> Self {
        Self::one().add(self)
    }
    pub fn maximum(&self, right: &Self) -> Self {
        Self {
            steps: self.steps.clone().max(right.steps.clone()),
            depth: self.depth.clone().max(right.depth.clone()),
            work: self.work.clone().max(right.work.clone()),
        }
    }
    pub fn scale(&self, count: &BigInt) -> Self {
        Self {
            steps: count * &self.steps,
            depth: count * &self.depth,
            work: count * &self.work,
        }
    }
    pub fn le(&self, right: &Self) -> bool {
        self.steps <= right.steps && self.depth <= right.depth && self.work <= right.work
    }
}
impl std::fmt::Display for Limit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{steps[{}],depth[{}],work[{}]}}",
            self.steps, self.depth, self.work
        )
    }
}
