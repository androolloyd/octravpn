// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native startup recovery orchestration. The host supplies authenticated,
//! deduplicated epoch-root replies and canonical catch-up; missing evidence
//! keeps the pending record and prevents startup.
use crate::consensus_recovery::Restored;
use octra_node_protocol::consensus::{pending_log::PendingCommit, Bytes, Error};

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Confirmed {
        agreed: i64,
        quorum: i64,
    },
    Missing {
        responses: i64,
    },
    Inconclusive {
        agreed: i64,
        peers: i64,
        responses: i64,
        quorum: i64,
    },
}
pub fn root(raw: &[u8]) -> Option<Bytes> {
    if raw.len() != 64
        || !raw
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return None;
    }
    hex::decode(raw).ok()
}
pub fn decide(
    validators: i64,
    peer_quorum: i64,
    promised: Option<&[u8]>,
    responses: &[Option<Bytes>],
) -> Decision {
    let agreed = responses
        .iter()
        .filter(|r| r.as_deref().is_some_and(|r| Some(r) == promised))
        .count() as i64;
    let count = responses.len() as i64;
    let peers = validators.wrapping_sub(1);
    if agreed >= peer_quorum {
        Decision::Confirmed {
            agreed,
            quorum: peer_quorum,
        }
    } else if count >= peers && responses.iter().all(Option::is_none) {
        Decision::Missing { responses: count }
    } else {
        Decision::Inconclusive {
            agreed,
            peers,
            responses: count,
            quorum: peer_quorum,
        }
    }
}

#[async_trait::async_trait]
pub trait Host: Send {
    fn head_epoch(&self) -> Result<i64, Error>;
    fn pending(&self) -> Result<Vec<PendingCommit>, Error>;
    fn restore(&mut self, pending: &PendingCommit) -> Restored;
    /// Every reply must come from a distinct authenticated validator and match
    /// this query's epoch. The recovery policy does not authenticate raw peers.
    async fn query(&mut self, epoch: i64) -> Result<Vec<Option<Bytes>>, Error>;
    async fn catchup(&mut self, epoch: i64) -> Result<(), Error>;
    fn delete(&mut self, epoch: i64, round: i64) -> Result<(), Error>;
}
fn unresolved(host: &impl Host) -> Result<(i64, Vec<PendingCommit>), Error> {
    let head = host.head_epoch()?;
    let records = host
        .pending()?
        .into_iter()
        .filter(|r| r.epoch_id > head)
        .collect();
    Ok((head, records))
}
/// False is a startup hold. Query, catch-up or deletion errors propagate; no
/// record is removed until the canonical head has reached its epoch.
pub async fn run_once(
    host: &mut impl Host,
    validators: i64,
    peer_quorum: i64,
) -> Result<bool, Error> {
    let Ok((head, pending)) = unresolved(host) else {
        return Ok(false);
    };
    if pending.is_empty() {
        return Ok(true);
    }
    if pending.iter().any(|p| p.epoch_id != head.wrapping_add(1)) {
        return Ok(false);
    }
    // Equal-round records retain the first entry, as in the native fold.
    let latest = pending.iter().fold(
        &pending[0],
        |latest, p| if p.round > latest.round { p } else { latest },
    );
    match host.restore(latest) {
        Restored::Lock => return Ok(true),
        Restored::Invalid(_) => return Ok(false),
        Restored::Legacy => (),
    }
    for record in pending {
        let responses = host.query(record.epoch_id).await?;
        let promised = root(&record.proposed_state_root);
        if matches!(
            decide(validators, peer_quorum, promised.as_deref(), &responses),
            Decision::Confirmed { .. }
        ) {
            host.catchup(record.epoch_id).await?;
            if host.head_epoch()? >= record.epoch_id {
                host.delete(record.epoch_id, record.round)?;
            }
        }
    }
    Ok(unresolved(host).is_ok_and(|(_, remaining)| remaining.is_empty()))
}
