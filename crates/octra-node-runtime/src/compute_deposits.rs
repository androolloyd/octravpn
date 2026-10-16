// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native compute/funds leaves inside the caller's speculative epoch. Loading a
//! signed record alone is not proof of the snapshot's finality or escrow funds.
use crate::{
    execution,
    state_batch::{Snapshot, StateBatch},
};
use octra_node_protocol::resource_compute::{
    call::Header,
    funding::{self, Deposit},
    Error, Result,
};

/// Evidence minted only by a read of an authenticated canonical snapshot. The
/// header and deposit cannot be replaced after the observation is constructed.
#[derive(Clone, Debug)]
pub struct Funded {
    header: Header,
    deposit: Deposit,
    epoch: i64,
    state_root: Vec<u8>,
}
impl Funded {
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn deposit(&self) -> &Deposit {
        &self.deposit
    }
    pub fn epoch(&self) -> i64 {
        self.epoch
    }
    pub fn state_root(&self) -> &[u8] {
        &self.state_root
    }
}

pub async fn observe(
    history: &crate::canonical::Reader,
    chain: &[u8],
    epoch: i64,
    state_root: &[u8],
    index_root: Option<&[u8]>,
    header: &Header,
) -> Result<Option<Funded>> {
    let request = header.request();
    if request.chain_id != chain || epoch < request.epoch_id || epoch > request.expires_epoch {
        return Err(Error::rejected(b"compute funding observation scope"));
    }
    if history.chain().chain_id.as_bytes() != chain {
        return Err(Error::rejected(b"compute funding chain differs"));
    }
    if !(0..=(1_i64 << 62) - 1).contains(&epoch) {
        return Err(Error::rejected(b"store snapshot epoch refused"));
    }
    let unavailable =
        |error: crate::canonical::Error| Error::Unavailable(error.to_string().into_bytes());
    let head = history
        .head_for_epoch_opt(epoch as u64)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| Error::Unavailable(b"store snapshot branch missing".to_vec()))?;
    let snapshot = history.snapshot_at(&head).await.map_err(unavailable)?;
    if snapshot.get(&[b"meta", b"last_epoch"]) != Some(epoch.to_string().as_bytes()) {
        return Err(Error::rejected(b"store snapshot epoch differs"));
    }
    let matches = if let Some(index) = index_root {
        let is_hash = |bytes: &[u8]| bytes.len() == 64 && bytes.iter().all(u8::is_ascii_hexdigit);
        if !is_hash(index) || !is_hash(state_root) {
            return Err(Error::rejected(b"store snapshot commitment refused"));
        }
        hex::encode(
            octra_node_protocol::epoch_index::folded_state_root(head.ledger_root.as_bytes(), index)
                .map_err(|error| Error::Unavailable(error.to_string().into_bytes()))?,
        )
        .as_bytes()
            == state_root.to_ascii_lowercase()
    } else {
        head.ledger_root.as_bytes() == state_root
    };
    if !matches {
        return Err(Error::rejected(b"store snapshot root differs"));
    }
    let id = request.id()?;
    let path = funding::deposit_path(&id)?;
    let Some(raw) = snapshot.get(&[&path[0], &path[1], &path[2]]) else {
        return Ok(None);
    };
    let deposit = funding::verify_deposit(raw, chain, epoch, header)?;
    Ok(Some(Funded {
        header: header.clone(),
        deposit,
        epoch,
        state_root: state_root.to_vec(),
    }))
}

pub fn read(state: &Snapshot, id: &[u8]) -> Result<Option<Deposit>> {
    let path = funding::deposit_path(id)?;
    let Some(raw) = state.get(&[&path[0], &path[1], &path[2]]) else {
        return Ok(None);
    };
    let deposit = Deposit::decode(raw)?;
    if deposit.request_id() != id {
        return Err(Error::rejected(b"compute deposit id differs"));
    }
    Ok(Some(deposit))
}
pub fn save(
    state: &mut StateBatch,
    deposit: &Deposit,
) -> std::result::Result<(), execution::Error> {
    let unavailable = |error: Error| execution::Error(error.to_string());
    let path = funding::deposit_path(deposit.request_id()).map_err(unavailable)?;
    let raw = deposit.encode().map_err(unavailable)?;
    state
        .set(&[&path[0], &path[1], &path[2]], raw)
        .map_err(|error| execution::Error(error.to_string()))
}
