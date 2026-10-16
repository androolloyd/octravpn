// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    bin, evidence, labels, stamp, Call, Code, CodeId, Codes, Error, Result, ToPrimitive, Zero,
};
use std::collections::BTreeSet;
fn number(codes: &Codes, id: CodeId) -> Option<i64> {
    let Code::Num(value) = codes.get(id) else {
        return None;
    };
    let value = value.to_i64()?;
    (0..=labels::MAX).contains(&value).then_some(value)
}
fn unique(values: &[Call]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.entry) {
            return Err(Error::Repeated(value.entry));
        }
    }
    Ok(())
}
fn item_code(codes: &mut Codes, value: &Call) -> Result<CodeId> {
    let decoded = bin::decode(value.evidence.encode()).ok_or(Error::Bits)?;
    let evidence = codes.import(&decoded.codes, decoded.root);
    let entry = codes.num(value.entry);
    let first = codes.num(value.first);
    let fields = codes.list(&[entry, first, evidence]);
    Ok(codes.tag(0, fields))
}
fn encode_stamp(stamp: &[u8; 32], values: &[Call]) -> Result<Vec<u8>> {
    let count = values.len();
    if count == 0 || count > super::super::limits::FUNCTIONS {
        return Err(Error::Count(count));
    }
    unique(values)?;
    let mut codes = Codes::default();
    let items = values
        .iter()
        .map(|value| item_code(&mut codes, value))
        .collect::<Result<Vec<_>>>()?;
    let items = codes.list(&items);
    let stamp = codes.bytes_code(stamp);
    let fields = codes.list(&[stamp, items]);
    let root = codes.tag(0, fields);
    let bits = bin::encode(&codes, root).ok_or(Error::Bits)?;
    let body = bin::pack(&bits).ok_or(Error::Bits)?;
    let mut raw = u32::try_from(bits.len())
        .map_err(|_| Error::Bits)?
        .to_be_bytes()
        .to_vec();
    raw.extend(body);
    Ok(raw)
}
pub fn encode(image: &[u8], values: &[Call]) -> Result<Vec<u8>> {
    encode_stamp(&stamp(image), values)
}
fn item_get(codes: &Codes, id: CodeId) -> Result<Call> {
    let Code::Tag(tag, body) = codes.get(id) else {
        return Err(Error::Form);
    };
    if !tag.is_zero() {
        return Err(Error::Form);
    }
    let [entry, first, evidence] = codes.fields::<3>(*body).ok_or(Error::Form)?;
    let entry = number(codes, entry).ok_or(Error::Form)?;
    let first = number(codes, first).ok_or(Error::Form)?;
    let bits = bin::encode(codes, evidence).ok_or(Error::Form)?;
    let evidence = evidence::decode_any(&bits).map_err(Error::Evidence)?;
    Call::make(entry, first, evidence)
}
pub fn decode_all(raw: &[u8]) -> Result<([u8; 32], Vec<Call>)> {
    let size = raw
        .get(..4)
        .and_then(|size| size.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(Error::Bits)? as usize;
    if size > super::super::core::rule::LOCAL.get(super::super::core::rule::Field::Str) as usize {
        return Err(Error::Bits);
    }
    let bits =
        bin::unpack(i64::try_from(size).map_err(|_| Error::Bits)?, &raw[4..]).ok_or(Error::Bits)?;
    let decoded = bin::decode(&bits).ok_or(Error::Form)?;
    let Code::Tag(tag, body) = decoded.codes.get(decoded.root) else {
        return Err(Error::Form);
    };
    if !tag.is_zero() {
        return Err(Error::Form);
    }
    let [stamp, items] = decoded.codes.fields::<2>(*body).ok_or(Error::Form)?;
    let stamp: [u8; 32] = decoded
        .codes
        .bytes_get(stamp)
        .ok_or(Error::Form)?
        .try_into()
        .map_err(|_| Error::Form)?;
    let items = decoded.codes.list_get(items).ok_or(Error::Form)?;
    let count = items.len();
    if count == 0 || count > super::super::limits::FUNCTIONS {
        return Err(Error::Count(count));
    }
    let values = items
        .into_iter()
        .map(|item| item_get(&decoded.codes, item))
        .collect::<Result<Vec<_>>>()?;
    unique(&values)?;
    if encode_stamp(&stamp, &values).map_err(|_| Error::Form)? != raw {
        return Err(Error::Form);
    }
    Ok((stamp, values))
}
pub fn decode(raw: &[u8]) -> Result<Vec<Call>> {
    decode_all(raw).map(|(_, values)| values)
}
