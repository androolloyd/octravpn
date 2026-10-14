// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Epoch pacing uses monotonic nanoseconds and generation-bound deadlines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pace {
    pub height: i64,
    pub generation: i64,
    pub until: i64,
}
impl Pace {
    pub fn new(
        height: i64,
        generation: i64,
        now: i64,
        started: i64,
        interval: i64,
        delay: i64,
    ) -> Option<Self> {
        let remaining = delay.max(started.wrapping_add(interval).wrapping_sub(now));
        (remaining > 100_000_000).then_some(Self {
            height,
            generation,
            until: now.wrapping_add(remaining),
        })
    }
    pub fn current(&self, height: i64, generation: i64) -> bool {
        self.height == height && self.generation == generation
    }
    pub fn remaining(plan: Option<&Self>, height: i64, generation: i64, now: i64) -> i64 {
        plan.filter(|p| p.current(height, generation))
            .map_or(0, |p| p.until.wrapping_sub(now).max(0))
    }
}
