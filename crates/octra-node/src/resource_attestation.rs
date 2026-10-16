// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Accepted resource-gossip observations, independent of committee activation.
use octra_node_protocol::consensus::{
    resource_attestation_flow::Gossip, resource_attestations::attestation_kind_to_string,
};
use std::io::{self, Write};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub seen_epoch: i64,
    pub node: Vec<u8>,
    pub kind: &'static str,
    pub weight: i64,
}
pub fn seen(gossip: &Gossip) -> Seen {
    let a = &gossip.attestation;
    let mut node = a.node_id[..a.node_id.len().min(12)].to_vec();
    if a.node_id.len() > 12 {
        node.extend_from_slice(b"..");
    }
    Seen {
        seen_epoch: gossip.seen_epoch,
        node,
        kind: attestation_kind_to_string(a.kind),
        weight: a.weight,
    }
}
impl Seen {
    /// Preserve the native message's arbitrary node bytes; presentation remains
    /// the node logger's concern rather than part of the resource protocol.
    pub fn message(&self) -> Vec<u8> {
        let mut out = format!(
            "resource_attestation seen_epoch = {} node = ",
            self.seen_epoch
        )
        .into_bytes();
        out.extend_from_slice(&self.node);
        out.extend_from_slice(format!(" kind = {} weight = {}", self.kind, self.weight).as_bytes());
        out
    }
}
pub fn log_seen(gossip: &Gossip) -> std::future::Ready<io::Result<()>> {
    // Native log_seen emits before returning an already-resolved Lwt promise.
    let result = (|| {
        let mut stderr = io::stderr().lock();
        stderr.write_all(b"consensus: ")?;
        stderr.write_all(&seen(gossip).message())?;
        stderr.write_all(b"\n")
    })();
    std::future::ready(result)
}
