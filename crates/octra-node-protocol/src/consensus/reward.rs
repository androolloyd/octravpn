// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Bytes, Error, RewardMember, RewardSource};
use crate::oce1::{Reader, Writer};
use num_bigint::BigInt;
use num_traits::Zero;
use std::collections::BTreeSet;

pub fn parse_weight(raw: &[u8]) -> Option<BigInt> {
    crate::native_integer::parse_integer(raw)
}
fn valid_address(value: &[u8]) -> bool {
    value.len() > 3 && value.len() <= 128
}
fn valid_key(value: Option<&Bytes>) -> bool {
    value.is_none_or(|key| key.len() == 32)
}
pub fn validate(source: &RewardSource) -> Result<RewardSource, Error> {
    let mut source = source.clone();
    source
        .reward_members
        .sort_by(|a, b| a.reward_address.cmp(&b.reward_address));
    if !valid_address(&source.reward_proposer_addr) {
        return Err("reward proposer address is invalid".into());
    }
    if !valid_key(source.reward_proposer_public_key.as_ref()) {
        return Err("reward proposer public key is invalid".into());
    }
    if source.reward_members.is_empty() {
        return Err("reward source has no members".into());
    }
    if source.reward_members.len() > 4096 {
        return Err("reward source has too many members".into());
    }
    if source.reward_members.iter().any(|v| {
        !valid_address(&v.reward_address)
            || !valid_key(v.reward_public_key.as_ref())
            || v.reward_weight <= BigInt::zero()
    }) {
        return Err("reward source member is invalid".into());
    }
    let addresses: BTreeSet<_> = source
        .reward_members
        .iter()
        .map(|v| &v.reward_address)
        .collect();
    if addresses.len() != source.reward_members.len() {
        return Err("reward source has duplicate addresses".into());
    }
    let public_keys: Vec<_> = source
        .reward_members
        .iter()
        .filter_map(|v| v.reward_public_key.as_ref())
        .collect();
    if public_keys.iter().collect::<BTreeSet<_>>().len() != public_keys.len() {
        return Err("reward source has duplicate public keys".into());
    }
    Ok(source)
}
fn put_key(writer: &mut Writer, value: Option<&Bytes>) -> Result<(), Error> {
    writer.put_option(value, |w, v| w.put_bytes(v))
}
pub fn put(writer: &mut Writer, source: &RewardSource) -> Result<(), Error> {
    let source = validate(source)?;
    writer.put_bytes(&source.reward_proposer_addr)?;
    put_key(writer, source.reward_proposer_public_key.as_ref())?;
    writer.put_list(&source.reward_members, |writer, member| {
        writer.put_bytes(&member.reward_address)?;
        put_key(writer, member.reward_public_key.as_ref())?;
        writer.put_bytes(member.reward_weight.to_string().as_bytes())
    })
}
fn get_key(reader: &mut Reader<'_>) -> Result<Option<Bytes>, Error> {
    reader.get_option(|reader| {
        let key = reader.get_bytes_bounded(32)?;
        if key.len() != 32 {
            return Err("reward source public key length is invalid".into());
        }
        Ok(key.to_vec())
    })
}
pub fn get(reader: &mut Reader<'_>) -> Result<RewardSource, Error> {
    let source = RewardSource {
        reward_proposer_addr: reader.get_bytes_bounded(128)?.to_vec(),
        reward_proposer_public_key: get_key(reader)?,
        reward_members: reader.get_list(4096, |reader| {
            let reward_address = reader.get_bytes_bounded(128)?.to_vec();
            let reward_public_key = get_key(reader)?;
            let reward_weight = parse_weight(reader.get_bytes_bounded(256)?)
                .ok_or_else(|| Error::from("reward source weight is invalid"))?;
            Ok(RewardMember {
                reward_address,
                reward_public_key,
                reward_weight,
            })
        })?,
    };
    let canonical = validate(&source)?;
    if source != canonical {
        return Err("reward source is not canonical".into());
    }
    Ok(canonical)
}
