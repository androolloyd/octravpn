// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Trusted transport upgrade schedules; peers cannot select activation rules.
use super::{domain_hash, endpoint::native_trim, peer_record::transport_config_hash, Error};
use crate::{native_integer::parse_int63, oce1::Writer};
#[derive(Clone, Debug)]
pub struct Target {
    pub epoch: i64,
    pub binary_hash: Vec<u8>,
    pub config_hash: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct Plan {
    pub target: Target,
    pub rollback: Option<Target>,
}
pub fn normalize_hash(label: &str, raw: &[u8]) -> Result<Vec<u8>, Error> {
    if raw.len() == 32 {
        return Ok(raw.to_vec());
    }
    let raw = native_trim(raw);
    if raw.len() == 32 {
        return Ok(raw.to_vec());
    }
    if raw.len() == 64 {
        let parsed: Option<Vec<_>> = raw
            .chunks_exact(2)
            .map(|pair| {
                parse_int63(&[b"0x".as_slice(), pair].concat()).and_then(|n| u8::try_from(n).ok())
            })
            .collect();
        if let Some(bytes) = parsed {
            return Ok(bytes);
        }
    }
    Err(format!("{label} must be 32 raw bytes or 64 hex chars").into())
}
impl Plan {
    pub fn schedule_hash(&self, base: &[u8]) -> Result<[u8; 32], Error> {
        let mut w = Writer::new();
        w.put_hash32(base)?;
        w.put_u64(self.target.epoch as u64)?;
        w.put_hash32(&self.target.binary_hash)?;
        w.put_hash32(&self.target.config_hash)?;
        w.put_option(self.rollback.as_ref(), |w, r| {
            w.put_u64(r.epoch as u64)?;
            w.put_hash32(&r.binary_hash)?;
            w.put_hash32(&r.config_hash)
        })?;
        Ok(domain_hash(
            b"octra:p2p_upgrade_schedule:v1",
            &w.into_bytes(),
        ))
    }
    pub fn active(&self, epoch: i64) -> bool {
        epoch >= self.target.epoch
    }
    pub fn rollback_active(&self, epoch: i64) -> bool {
        self.rollback.as_ref().is_some_and(|r| epoch >= r.epoch)
    }
    pub fn ready(
        &self,
        epoch: i64,
        config: &[u8],
        binary: &[u8],
        require_binary: bool,
    ) -> Result<(), Error> {
        if !self.active(epoch) {
            return Ok(());
        }
        let target = self
            .rollback
            .as_ref()
            .filter(|r| epoch >= r.epoch)
            .unwrap_or(&self.target);
        if require_binary && binary != target.binary_hash {
            Err("binary_hash".into())
        } else if config != target.config_hash {
            Err("config_hash".into())
        } else {
            Ok(())
        }
    }
}
pub fn handshake_hash(
    epoch: i64,
    config: &[u8],
    binary: &[u8],
    require_binary: bool,
    plan: Option<&Plan>,
) -> Result<Vec<u8>, Error> {
    if !require_binary {
        return Ok(config.to_vec());
    }
    match plan {
        Some(p) if !p.active(epoch) => Ok(p.schedule_hash(config)?.to_vec()),
        _ => Ok(transport_config_hash(config, binary)?.to_vec()),
    }
}
pub fn binary_required(epoch: i64, require_binary: bool, plan: Option<&Plan>) -> bool {
    require_binary && plan.is_none_or(|p| p.active(epoch))
}
pub fn expected_binary<'a>(epoch: i64, binary: &'a [u8], plan: Option<&'a Plan>) -> &'a [u8] {
    match plan {
        Some(p) if p.rollback_active(epoch) => &p.rollback.as_ref().unwrap().binary_hash,
        Some(p) if p.active(epoch) => &p.target.binary_hash,
        _ => binary,
    }
}
