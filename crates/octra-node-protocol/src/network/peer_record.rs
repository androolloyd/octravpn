// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Signed native peer discovery and its expiring, eclipse-resistant registry.
use super::{domain_hash, handshake::node_id, verify_ed25519, Error};
use crate::{
    native_integer::parse_int63,
    oce1::{Reader, Writer},
};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub chain_id: Vec<u8>,
    pub node_id: Vec<u8>,
    pub node_address: Vec<u8>,
    pub public_key: Vec<u8>,
    pub binary_hash: Vec<u8>,
    pub config_hash: Vec<u8>,
    pub host: Vec<u8>,
    pub port: i64,
    pub features: Vec<Vec<u8>>,
    pub timestamp: i64,
    pub signature: Vec<u8>,
}
impl Record {
    fn put_unsigned(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_u16(1)?;
        w.put_bytes(&self.chain_id)?;
        w.put_bytes(&self.node_id)?;
        w.put_bytes(&self.node_address)?;
        w.put_raw(&self.public_key)?;
        w.put_hash32(&self.binary_hash)?;
        w.put_hash32(&self.config_hash)?;
        w.put_bytes(&self.host)?;
        w.put_u16(self.port as u16)?;
        w.put_list(&self.features, |w, v| w.put_bytes(v))?;
        w.put_u64(self.timestamp as u64)
    }
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        self.put_unsigned(w)?;
        w.put_sig64(&self.signature)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        if r.get_u16()? != 1 {
            return Err("peer record proto mismatch".into());
        }
        let record = Self {
            chain_id: r.get_bytes_bounded(128)?.to_vec(),
            node_id: r.get_bytes_bounded(64)?.to_vec(),
            node_address: r.get_bytes_bounded(128)?.to_vec(),
            public_key: r.get_raw(32)?.to_vec(),
            binary_hash: r.get_hash32()?.to_vec(),
            config_hash: r.get_hash32()?.to_vec(),
            host: r.get_bytes_bounded(255)?.to_vec(),
            port: i64::from(r.get_u16()?),
            features: r.get_list(32, |r| Ok(r.get_bytes_bounded(64)?.to_vec()))?,
            timestamp: r.get_u64()? as i64,
            signature: r.get_sig64()?.to_vec(),
        };
        if record.node_id.len() != 64 {
            return Err("peer record node id length".into());
        }
        Ok(record)
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new();
        self.put(&mut w)?;
        Ok(w.into_bytes())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let record = Self::get(&mut r)?;
        r.finish()?;
        Ok(record)
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32], Error> {
        let mut w = Writer::new();
        self.put_unsigned(&mut w)?;
        Ok(domain_hash(b"octra:p2p_peer_record:v1", &w.into_bytes()))
    }
    pub fn sign(&mut self, key: &SigningKey) -> Result<(), Error> {
        self.public_key = key.verifying_key().to_bytes().to_vec();
        self.node_id = node_id(&self.public_key);
        self.signature = key.sign(&self.sign_bytes()?).to_bytes().to_vec();
        Ok(())
    }
    pub fn validate(
        &self,
        chain: &[u8],
        config: &[u8],
        binary: Option<&[u8]>,
        allowed: &[Vec<u8>],
    ) -> Result<(), Error> {
        let reason = if self.chain_id != chain {
            Some("chain_id")
        } else if self.config_hash != config {
            Some("config_hash")
        } else if binary.is_some_and(|h| self.binary_hash != h) {
            Some("binary_hash")
        } else if !(1..=65535).contains(&self.port) {
            Some("port")
        } else if self.host.is_empty() || self.host.len() > 255 || self.host.contains(&0) {
            Some("host")
        } else if self.node_id != node_id(&self.public_key) {
            Some("node_id")
        } else if !allowed.is_empty() && !allowed.contains(&self.public_key) {
            Some("pubkey")
        } else if self.features.len() > 32
            || self.features.iter().any(|s| s.len() > 64 || s.contains(&0))
        {
            Some("features")
        } else if !verify_ed25519(&self.public_key, &self.sign_bytes()?, &self.signature) {
            Some("signature")
        } else {
            None
        };
        reason.map_or(Ok(()), |s| Err(s.into()))
    }
}
pub fn encode_list(records: &[Record]) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new();
    w.put_list(records, |w, r| r.put(w))?;
    Ok(w.into_bytes())
}
pub fn decode_list(bytes: &[u8]) -> Result<Vec<Record>, Error> {
    let mut r = Reader::new(bytes);
    let values = r.get_list(32, Record::get)?;
    r.finish()?;
    Ok(values)
}
pub fn transport_config_hash(config: &[u8], binary: &[u8]) -> Result<[u8; 32], Error> {
    let mut w = Writer::new();
    w.put_hash32(config)?;
    w.put_hash32(binary)?;
    Ok(domain_hash(
        b"octra:p2p_transport_config:v1",
        &w.into_bytes(),
    ))
}

pub fn bucket(host: &[u8]) -> Vec<u8> {
    let parts: Vec<_> = host.split(|b| *b == b'.').collect();
    let four = parts.len() == 4;
    let private = four
        && (parts[0] == b"127"
            || parts[0] == b"10"
            || (parts[0] == b"192" && parts[1] == b"168")
            || (parts[0] == b"169" && parts[1] == b"254")
            || (parts[0] == b"172"
                && parse_int63(parts[1]).is_some_and(|n| (16..=31).contains(&n))));
    if host == b"localhost" || host == b"::1" || private {
        return b"local".to_vec();
    }
    let overlay = four
        && parts[0] == b"100"
        && parse_int63(parts[1]).is_some_and(|n| (64..=127).contains(&n));
    let v4 = four && parts.iter().all(|p| parse_int63(p).is_some());
    if overlay && !v4 {
        return b"overlay".to_vec();
    }
    let mut out = if overlay {
        b"overlay:".to_vec()
    } else if v4 {
        b"v4:".to_vec()
    } else {
        b"dns:".to_vec()
    };
    if v4 {
        out.extend(parts[..3].join(&b'.'));
    } else {
        out.extend_from_slice(host);
    }
    out
}
pub fn allow_bucket<'a>(
    max_per_bucket: i64,
    records: impl IntoIterator<Item = &'a Record>,
    record: &Record,
) -> bool {
    let b = bucket(&record.host);
    !(b.starts_with(b"v4:") || b.starts_with(b"dns:"))
        || (records.into_iter().filter(|r| bucket(&r.host) == b).count() as i64) < max_per_bucket
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added {
    New,
    Refreshed,
}
pub struct Registry {
    rows: BTreeMap<Vec<u8>, Record>,
    ttl: f64,
    max_per_bucket: i64,
}
impl Default for Registry {
    fn default() -> Self {
        Self::new(300.0, 4)
    }
}
impl Registry {
    pub fn new(ttl: f64, max_per_bucket: i64) -> Self {
        Self {
            rows: BTreeMap::new(),
            ttl,
            max_per_bucket,
        }
    }
    pub fn clear(&mut self) {
        self.rows.clear();
    }
    pub fn prune(&mut self, now: f64) {
        self.rows.retain(|_, r| live(now, self.ttl, r.timestamp));
    }
    pub fn values(&mut self, now: f64) -> impl Iterator<Item = &Record> {
        self.prune(now);
        self.rows.values()
    }
    /// The caller validates the signature, chain and transport policy before insertion.
    pub fn add(&mut self, now: f64, record: Record) -> Result<Added, Error> {
        self.prune(now);
        if !live(now, self.ttl, record.timestamp) {
            return Err("ttl".into());
        }
        if !allow_bucket(
            self.max_per_bucket,
            self.rows.values().filter(|r| r.node_id != record.node_id),
            &record,
        ) {
            return Err("eclipse_bucket".into());
        }
        Ok(
            if self.rows.insert(record.node_id.clone(), record).is_some() {
                Added::Refreshed
            } else {
                Added::New
            },
        )
    }
}
#[allow(clippy::cast_precision_loss)] // Native Int64.to_float uses this rounding.
fn live(now: f64, ttl: f64, timestamp: i64) -> bool {
    let age = now - timestamp as f64;
    age >= -30.0 && age <= ttl
}
