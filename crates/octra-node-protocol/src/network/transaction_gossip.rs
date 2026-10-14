// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native inventory/request/transaction transport. Payload admission remains a host duty.
use super::Error;
use crate::oce1::{Reader, Writer};
use std::collections::BTreeSet;
pub const MAX_HASHES: usize = 512;
pub const MAX_JSON: usize = 5_000_000;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Inventory(Vec<Vec<u8>>),
    Get(Vec<Vec<u8>>),
    Transaction { hash: Vec<u8>, json: Vec<u8> },
}
fn hash(raw: &[u8]) -> Result<Vec<u8>, Error> {
    if raw.len() != 64 || !raw.iter().all(u8::is_ascii_hexdigit) {
        return Err("p2p_tx_gossip: bad hash".into());
    }
    Ok(raw.to_ascii_lowercase())
}
impl Message {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new();
        w.put_u8(1)?;
        match self {
            Self::Inventory(hashes) | Self::Get(hashes) => {
                w.put_u8(if matches!(self, Self::Inventory(_)) {
                    1
                } else {
                    2
                })?;
                if hashes.len() > MAX_HASHES {
                    return Err("p2p_tx_gossip: too many hashes".into());
                }
                let hashes = hashes
                    .iter()
                    .map(|h| hash(h))
                    .collect::<Result<Vec<_>, _>>()?;
                w.put_u16(hashes.len() as u16)?;
                for h in hashes {
                    w.put_bytes(&h)?;
                }
            }
            Self::Transaction { hash: h, json } => {
                let h = hash(h)?;
                if json.len() > MAX_JSON {
                    return Err("p2p_tx_gossip: tx json too large".into());
                }
                w.put_u8(3)?;
                w.put_bytes(&h)?;
                w.put_bytes(json)?;
            }
        }
        Ok(w.into_bytes())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.get_u8()? != 1 {
            return Err("p2p_tx_gossip: bad version".into());
        }
        let message = match r.get_u8()? {
            kind @ (1 | 2) => {
                let count = usize::from(r.get_u16()?);
                if count > MAX_HASHES {
                    return Err("p2p_tx_gossip: too many hashes".into());
                }
                let hashes = (0..count)
                    .map(|_| hash(r.get_bytes()?))
                    .collect::<Result<Vec<_>, _>>()?;
                if kind == 1 {
                    Self::Inventory(hashes)
                } else {
                    Self::Get(hashes)
                }
            }
            3 => {
                let h = hash(r.get_bytes()?)?;
                let json = r.get_bytes()?;
                if json.len() > MAX_JSON {
                    return Err("p2p_tx_gossip: tx json too large".into());
                }
                Self::Transaction {
                    hash: h,
                    json: json.to_vec(),
                }
            }
            _ => return Err("p2p_tx_gossip: bad kind".into()),
        };
        r.finish()?;
        Ok(message)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    Request(Vec<Vec<u8>>),
    Serve(Vec<Vec<u8>>),
    Receive { hash: Vec<u8>, json: Vec<u8> },
    Legacy,
}
pub fn plan(
    payload: &[u8],
    has: impl Fn(&[u8]) -> bool,
    max_request: usize,
    max_reply: usize,
) -> Plan {
    match Message::decode(payload) {
        Ok(Message::Inventory(hashes)) => Plan::Request(select(hashes, |h| !has(h), max_request)),
        Ok(Message::Get(hashes)) => Plan::Serve(select(hashes, has, max_reply)),
        Ok(Message::Transaction { hash, json }) => Plan::Receive { hash, json },
        Err(_) => Plan::Legacy,
    }
}
fn select(hashes: Vec<Vec<u8>>, has: impl Fn(&[u8]) -> bool, maximum: usize) -> Vec<Vec<u8>> {
    let mut seen = BTreeSet::new();
    hashes
        .into_iter()
        .filter(|h| seen.insert(h.clone()))
        .filter(|h| has(h))
        .take(maximum)
        .collect()
}
