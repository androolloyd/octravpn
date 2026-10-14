// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use crate::{
    consensus::Validator,
    native_integer::{parse_int63, parse_int64},
    transaction::decode_base64,
};
use std::collections::BTreeSet;
fn trim(raw: &[u8]) -> &[u8] {
    let space = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 12);
    let start = raw.iter().position(|b| !space(b)).unwrap_or(raw.len());
    let end = raw.iter().rposition(|b| !space(b)).map_or(start, |i| i + 1);
    &raw[start..end]
}
pub fn from_value(raw: Option<&[u8]>) -> Vec<Vec<u8>> {
    raw.filter(|r| r.len() > 3).map_or_else(Vec::new, |r| {
        r.split(|b| *b == b',')
            .map(trim)
            .filter(|v| v.len() > 3)
            .map(<[u8]>::to_vec)
            .collect()
    })
}
pub fn encoded_pair(entry: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut parts = trim(entry).split(|b| *b == b':');
    let address = parts.next()?;
    let key = parts.next()?;
    (address.len() > 3 && parts.next().is_none()).then_some((address, key))
}
pub fn parse(entry: &[u8]) -> Option<Validator> {
    let (address, key) = encoded_pair(entry)?;
    let pubkey = decode_base64(key).ok()?;
    (pubkey.len() == 32).then(|| Validator {
        address: address.to_vec(),
        pubkey,
    })
}
pub fn errors(label: &[u8], entries: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut addresses = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut errors = vec![];
    for entry in entries {
        match parse(entry) {
            None => errors.push([label, b":invalid_entry"].concat()),
            Some(v) if addresses.contains(&v.address) => {
                errors.push([label, b":duplicate_address:", &v.address].concat());
            }
            Some(v) if keys.contains(&v.pubkey) => {
                errors.push([label, b":duplicate_pubkey:", &v.address].concat());
            }
            Some(v) => {
                addresses.insert(v.address);
                keys.insert(v.pubkey);
            }
        }
    }
    errors
}
/// An invalid primary value suppresses the fallback, matching the native env.
pub fn activation(primary: Option<&[u8]>, fallback: Option<&[u8]>, host_int: bool) -> Option<i64> {
    primary
        .or(fallback)
        .and_then(if host_int { parse_int63 } else { parse_int64 })
}
