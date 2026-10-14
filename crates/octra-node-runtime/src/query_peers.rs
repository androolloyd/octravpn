// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native deterministic query rotation and validator-first peer waves.
use octra_node_protocol::{
    consensus::{Bytes, ValidatorSet},
    network::handshake,
};
use std::collections::BTreeSet;

pub fn offset(seed: &[u8], count: usize) -> usize {
    if count == 0 {
        return 0;
    }
    seed.iter()
        .take(16)
        .fold(0, |value, byte| (value * 257 + usize::from(*byte)) % count)
}
pub fn ordered(set: &ValidatorSet, seed: &[u8], connected: &[Bytes]) -> Vec<Bytes> {
    let active: BTreeSet<_> = set
        .validators
        .iter()
        .map(|v| handshake::node_id(&v.pubkey))
        .collect();
    let (mut validators, mut others): (Vec<_>, Vec<_>) = connected
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .partition(|id| active.contains(id));
    for peers in [&mut validators, &mut others] {
        let start = offset(seed, peers.len());
        peers.rotate_left(start);
    }
    validators.extend(others);
    validators
}
pub fn bundle_waves(mut peers: Vec<Bytes>) -> Vec<Vec<Bytes>> {
    let mut second = peers.split_off(peers.len().min(2));
    let third = second.split_off(second.len().min(4));
    [peers, second, third]
        .into_iter()
        .filter(|v| !v.is_empty())
        .collect()
}
