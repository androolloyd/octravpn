// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_ent deterministic production planning and rule-version binding.
use super::{rule, Natural};
use num_bigint::BigInt;
use num_traits::{One, Zero};

pub(crate) const BASIS: u32 = 337;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rate {
    num: BigInt,
    shift: Natural,
}
impl Rate {
    pub fn num(&self) -> &BigInt {
        &self.num
    }
    pub fn shift(&self) -> Natural {
        self.shift
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    basis: Natural,
    max_depth: Natural,
    base: BigInt,
    slope: BigInt,
    r2: Rate,
    r3: Rate,
}
impl Profile {
    pub fn basis(&self) -> Natural {
        self.basis
    }
    pub fn max_depth(&self) -> Natural {
        self.max_depth
    }
    pub fn base(&self) -> &BigInt {
        &self.base
    }
    pub fn slope(&self) -> &BigInt {
        &self.slope
    }
    pub fn r2(&self) -> &Rate {
        &self.r2
    }
    pub fn r3(&self) -> &Rate {
        &self.r3
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    depth: Natural,
    capacity: BigInt,
    binary: BigInt,
    ternary: BigInt,
    groups: BigInt,
    edges: BigInt,
}
impl Plan {
    pub fn depth(&self) -> Natural {
        self.depth
    }
    pub fn capacity(&self) -> &BigInt {
        &self.capacity
    }
    pub fn binary(&self) -> &BigInt {
        &self.binary
    }
    pub fn ternary(&self) -> &BigInt {
        &self.ternary
    }
    pub fn groups(&self) -> &BigInt {
        &self.groups
    }
    pub fn edges(&self) -> &BigInt {
        &self.edges
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Binary64,
    Integer,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limit {
    rule: rule::Id,
    mode: Mode,
    plan: Plan,
}
impl Limit {
    pub fn rule(&self) -> &rule::Id {
        &self.rule
    }
    pub fn mode(&self) -> Mode {
        self.mode
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Profile,
    Depth(BigInt, BigInt),
    Rule(rule::Error),
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::Profile => b"entropy profile is invalid".to_vec(),
            Self::Depth(actual, limit) => {
                format!("entropy depth exceeds profile actual = {actual} limit = {limit}")
                    .into_bytes()
            }
            Self::Rule(error) => error.to_string().into_bytes(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}
fn fixed(value: u32) -> Natural {
    Natural::from_u32(value).expect("fixed entropy profile natural")
}
pub fn production() -> Profile {
    Profile {
        basis: fixed(BASIS),
        max_depth: fixed(1_000_000),
        base: 120.into(),
        slope: 16.into(),
        r2: Rate {
            num: 4_719_964_527_767_381_u64.into(),
            shift: fixed(57),
        },
        r3: Rate {
            num: 5_149_052_212_109_869_u64.into(),
            shift: fixed(58),
        },
    }
}
pub fn valid(value: &Profile) -> bool {
    let rate_ok = |rate: &Rate| rate.num > BigInt::zero() && rate.shift.get() <= 127;
    value.basis.get() > 0
        && value.base > BigInt::zero()
        && value.slope >= BigInt::zero()
        && rate_ok(&value.r2)
        && rate_ok(&value.r3)
}
pub fn plan(value: &Profile, depth: Natural) -> Result<Plan, Error> {
    if !valid(value) {
        return Err(Error::Profile);
    }
    if depth > value.max_depth {
        return Err(Error::Depth(
            depth.get().into(),
            value.max_depth.get().into(),
        ));
    }
    let capacity = &value.base + &value.slope * BigInt::from(depth.get());
    let scale =
        |rate: &Rate| (&capacity * &rate.num) / (BigInt::one() << rate.shift.get() as usize);
    let binary = scale(&value.r2);
    let ternary = scale(&value.r3);
    Ok(Plan {
        depth,
        capacity,
        groups: &binary + &ternary,
        edges: BigInt::from(8) + BigInt::from(2) * &binary + BigInt::from(3) * &ternary,
        binary,
        ternary,
    })
}
pub fn mode(rule: &rule::Id) -> Mode {
    if rule.version() >= 2 {
        Mode::Integer
    } else {
        Mode::Binary64
    }
}
pub fn bind(rule: &rule::Id, profile: &Profile, depth: Natural) -> Result<Limit, Error> {
    Ok(Limit {
        rule: rule.clone(),
        mode: mode(rule),
        plan: plan(profile, depth)?,
    })
}
pub fn bind_at(
    schedule: &rule::Schedule,
    epoch: &BigInt,
    profile: &Profile,
    depth: Natural,
) -> Result<Limit, Error> {
    let selected = schedule.select(epoch).map_err(Error::Rule)?;
    bind(selected.id(), profile, depth)
}
