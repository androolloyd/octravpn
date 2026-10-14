// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native security-curve emission binding. Configuration is supplied by the
//! authenticated node profile, never inferred from a peer's metadata.
use crate::{
    native_integer::{parse_int63, parse_integer},
    transaction::Error,
};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
pub const DURATION: i64 = 47_304_000;
pub const KEYS: [&[u8]; 4] = [
    b"emission_standard",
    b"emission_activation_epoch",
    b"emission_initial",
    b"supply_retired",
];
#[derive(Clone, Copy, Debug)]
pub enum Schedule {
    Inactive,
    SecurityCurve { activation_epoch: i64 },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub initial: BigInt,
    pub remaining: BigInt,
    pub retired: BigInt,
    pub active: bool,
    pub activated: bool,
    pub writes: Vec<(Vec<u8>, Vec<u8>)>,
}
fn error(reason: &str) -> Error {
    Error(reason.into())
}
fn nonnegative(label: &str, raw: &[u8]) -> Result<BigInt, Error> {
    let value = parse_integer(raw).ok_or_else(|| error(&format!("invalid {label}")))?;
    if value.is_negative() {
        return Err(error(&format!("{label} must be nonnegative")));
    }
    Ok(value)
}
pub fn parse_epoch(label: &str, raw: &[u8]) -> Result<i64, Error> {
    let value = parse_int63(raw).ok_or_else(|| error(&format!("invalid {label}")))?;
    if value < 0 {
        return Err(error(&format!("{label} must be nonnegative")));
    }
    Ok(value)
}
pub fn bind(
    schedule: Schedule,
    epoch: i64,
    remaining: &BigInt,
    headroom: &BigInt,
    stored: [Option<&[u8]>; 4],
) -> Result<Binding, Error> {
    let inactive = || Binding {
        initial: remaining.clone(),
        remaining: remaining.clone(),
        retired: BigInt::zero(),
        active: false,
        activated: false,
        writes: vec![],
    };
    let empty = stored.iter().all(Option::is_none);
    let Schedule::SecurityCurve { activation_epoch } = schedule else {
        return if empty {
            Ok(inactive())
        } else {
            Err(error(
                "active emission standard requires activation configuration",
            ))
        };
    };
    if let [Some(standard), Some(activation), Some(initial), Some(retired)] = stored {
        if standard != b"security_curve" {
            return Err(error("emission standard metadata mismatch"));
        }
        if epoch < activation_epoch {
            return Err(error("emission activation is ahead of canonical epoch"));
        }
        if headroom.is_negative() {
            return Err(error("emission headroom is negative"));
        }
        if remaining > headroom {
            return Err(error("emission remaining exceeds supply headroom"));
        }
        if parse_epoch("stored emission activation epoch", activation)? != activation_epoch {
            return Err(error("emission activation metadata mismatch"));
        }
        let initial = nonnegative("emission initial reserve", initial)?;
        if remaining > &initial {
            return Err(error("emission remaining exceeds initial reserve"));
        }
        let retired = nonnegative("retired supply", retired)?;
        if remaining + &retired != *headroom {
            return Err(error("supply envelope metadata mismatch"));
        }
        return Ok(Binding {
            initial,
            remaining: remaining.clone(),
            retired,
            active: true,
            activated: false,
            writes: vec![],
        });
    }
    if !empty {
        return Err(error("incomplete emission activation metadata"));
    }
    if epoch < activation_epoch {
        return Ok(inactive());
    }
    if epoch > activation_epoch {
        return Err(error("emission activation metadata missing"));
    }
    if headroom.is_negative() {
        return Err(error("emission headroom is negative"));
    }
    if remaining.is_negative() {
        return Err(error("emission remaining is negative"));
    }
    if remaining > headroom {
        return Err(error("emission remaining exceeds supply headroom"));
    }
    let initial = if remaining.is_positive() {
        remaining.clone()
    } else {
        headroom.clone()
    };
    let retired = headroom - &initial;
    let values = [
        b"security_curve".to_vec(),
        activation_epoch.to_string().into_bytes(),
        initial.to_string().into_bytes(),
        retired.to_string().into_bytes(),
    ];
    Ok(Binding {
        remaining: initial.clone(),
        initial,
        retired,
        active: true,
        activated: true,
        writes: KEYS
            .into_iter()
            .zip(values)
            .map(|(k, v)| (k.to_vec(), v))
            .collect(),
    })
}
pub fn cumulative(initial: &BigInt, elapsed: i64) -> BigInt {
    let k = BigInt::from(elapsed.clamp(0, DURATION));
    let duration = BigInt::from(DURATION);
    initial * (17 * &duration * &k - 7 * &k * &k) / (10 * &duration * &duration)
}
pub fn reward(schedule: Schedule, epoch: i64, binding: &Binding) -> Result<BigInt, Error> {
    let Schedule::SecurityCurve { activation_epoch } = schedule else {
        return Ok(BigInt::zero());
    };
    // OCaml int arithmetic wraps at 63 bits, even at historical boundaries.
    let elapsed = (epoch.wrapping_sub(activation_epoch) << 1) >> 1;
    if elapsed < 0 {
        return Ok(BigInt::zero());
    }
    let issued = cumulative(&binding.initial, elapsed);
    if binding.remaining != &binding.initial - &issued {
        return Err(error("emission schedule state mismatch"));
    }
    if elapsed >= DURATION {
        return Ok(BigInt::zero());
    }
    let reward = cumulative(&binding.initial, elapsed + 1) - issued;
    if reward.is_negative() || reward > binding.remaining {
        return Err(error("emission schedule reward out of bounds"));
    }
    Ok(reward)
}
