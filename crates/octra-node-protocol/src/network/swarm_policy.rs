// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native swarm role, capacity, duplicate-connection and retry decisions.
use super::{budget::PeerClass, handshake::node_id, Error};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}
pub fn preferred_direction(local: &[u8], peer: &[u8]) -> Direction {
    if local < peer {
        Direction::Outbound
    } else {
        Direction::Inbound
    }
}
pub fn role(validators: Option<&[Vec<u8>]>, peer: &[u8]) -> PeerClass {
    if validators.map_or(true, |keys| keys.iter().any(|key| node_id(key) == peer)) {
        PeerClass::Validator
    } else {
        PeerClass::Observer
    }
}
pub fn local_is_validator(validators: Option<&[Vec<u8>]>, public: &[u8]) -> bool {
    validators.map_or(true, |keys| keys.iter().any(|k| k == public))
}
pub fn accepts_observers(validators: Option<&[Vec<u8>]>, public: &[u8]) -> bool {
    validators.is_some() && local_is_validator(validators, public)
}
pub fn validate_validators(keys: &[Vec<u8>]) -> Result<(), Error> {
    if keys.is_empty() {
        Err("active validator public keys are empty".into())
    } else if keys.iter().any(|k| k.len() != 32) {
        Err("active validator public key must contain 32 bytes".into())
    } else if keys.iter().collect::<std::collections::BTreeSet<_>>().len() != keys.len() {
        Err("active validator public keys contain duplicates".into())
    } else {
        Ok(())
    }
}
pub fn capacity(maximum: i64, validators: i64, observers: i64, role: PeerClass) -> bool {
    match role {
        PeerClass::Validator => validators < maximum,
        PeerClass::Observer => observers < 8,
    }
}
pub fn record_dial_due(now: f64, due: Option<f64>, active: usize) -> Option<f64> {
    if active >= 4 || due.is_some_and(|t| now < t) {
        None
    } else {
        Some(now + 30.0)
    }
}
pub fn keep_profile(target: &[u8], current: &[u8], offered: Option<&[u8]>) -> bool {
    current == target || offered == Some(target)
}
/// After authenticating the handshake, a live duplicate is replaced only by the
/// deterministic preferred direction. Dead entries do not consume capacity.
pub fn replace_existing(
    local: &[u8],
    peer: &[u8],
    incoming: Direction,
    existing: Direction,
    connected: bool,
) -> bool {
    !connected
        || (existing != preferred_direction(local, peer)
            && incoming == preferred_direction(local, peer))
}
