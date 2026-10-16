// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_folio canonical bit image and CF1 packed-byte transport.
// Preserve the native structured diagnostic payloads and their existing API.
#![allow(clippy::result_large_err)]
use super::super::{
    bin::{self, Code, CodeId, Codes},
    project_image::{tagged, text_code, text_get},
};
use super::{epoch_valid, project_image, valid, Bits, Error, Field, Folio, Part, LOCAL};
use num_traits::ToPrimitive;
const MAGIC: &[u8; 4] = b"CF1\0";

fn bits_code(codes: &mut Codes, values: &[bool]) -> CodeId {
    let values = values
        .iter()
        .map(|value| codes.tag(u8::from(*value), codes.nil()))
        .collect::<Vec<_>>();
    codes.list(&values)
}
fn bits_get(codes: &Codes, root: CodeId) -> Option<Bits> {
    codes
        .list_get(root)?
        .into_iter()
        .map(|id| {
            let Code::Tag(tag, body) = codes.get(id) else {
                return None;
            };
            if !matches!(codes.get(*body), Code::Nil) {
                return None;
            }
            match tag.to_u8()? {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            }
        })
        .collect()
}
fn part_code(codes: &mut Codes, value: &Part) -> CodeId {
    let path = text_code(codes, &value.path);
    let name = text_code(codes, &value.name);
    let octb = text_code(codes, &value.octb);
    let seal = bits_code(codes, &value.seal);
    let map = bits_code(codes, &value.map);
    let live = bits_code(codes, &value.live);
    let fields = codes.list(&[path, name, octb, seal, map, live]);
    codes.tag(4, fields)
}
fn part_get(codes: &Codes, root: CodeId) -> Option<Part> {
    let [path, name, octb, seal, map, live] = codes.fields::<6>(tagged(codes, root, 4)?)?;
    Some(Part {
        path: text_get(codes, path)?,
        name: text_get(codes, name)?,
        octb: text_get(codes, octb)?,
        seal: bits_get(codes, seal)?,
        map: bits_get(codes, map)?,
        live: bits_get(codes, live)?,
    })
}
fn code(codes: &mut Codes, value: &Folio) -> Option<CodeId> {
    let project = project_image::code(codes, &value.project)?;
    let epoch = codes.num(value.epoch.clone());
    let parts = value
        .parts
        .iter()
        .map(|value| part_code(codes, value))
        .collect::<Vec<_>>();
    let parts = codes.list(&parts);
    let fields = codes.list(&[project, epoch, parts]);
    Some(codes.tag(5, fields))
}
fn get(codes: &Codes, root: CodeId) -> Option<Folio> {
    let [project, epoch, parts] = codes.fields::<3>(tagged(codes, root, 5)?)?;
    let Code::Num(epoch) = codes.get(epoch) else {
        return None;
    };
    if !epoch_valid(epoch) {
        return None;
    }
    let project = project_image::get(codes, project)?;
    let parts = codes
        .list_get(parts)?
        .into_iter()
        .map(|id| part_get(codes, id))
        .collect::<Option<Vec<_>>>()?;
    Some(Folio {
        project,
        epoch: epoch.as_ref().clone(),
        parts,
    })
}
pub fn encode(value: &Folio) -> Option<Bits> {
    if !valid(value) {
        return None;
    }
    let mut codes = Codes::default();
    let root = code(&mut codes, value)?;
    let bits = bin::encode(&codes, root)?;
    (bits.len() <= LOCAL.get(Field::Str) as usize).then_some(bits)
}
pub fn decode(input: &[bool]) -> Option<Folio> {
    if input.len() > LOCAL.get(Field::Str) as usize {
        return None;
    }
    let decoded = bin::decode(input)?;
    let value = get(&decoded.codes, decoded.root)?;
    (encode(&value)?.as_slice() == input).then_some(value)
}
pub fn file(value: &Folio) -> Option<Vec<u8>> {
    let bits = encode(value)?;
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(bits.len() as u64).to_be_bytes());
    out.extend_from_slice(&bin::pack(&bits)?);
    Some(out)
}
pub fn of_file(input: &[u8]) -> Result<Folio, Error> {
    let actual = input.len();
    if actual < 12 || input.get(..4) != Some(MAGIC.as_slice()) {
        return Err(Error::Header);
    }
    let size = u64::from_be_bytes(input[4..12].try_into().expect("eight-byte folio bit count"));
    let limit = LOCAL.get(Field::Str) as usize;
    if size > limit as u64 {
        return Err(Error::Size(limit, actual));
    }
    let size = size as usize;
    let expected = 12 + size.div_ceil(8);
    if actual != expected {
        return Err(Error::Size(expected, actual));
    }
    let bits = (0..size)
        .map(|index| input[12 + index / 8] & (1 << (7 - index % 8)) != 0)
        .collect::<Bits>();
    let value = decode(&bits).ok_or(Error::Form)?;
    if file(&value).is_some_and(|exact| exact == input) {
        Ok(value)
    } else {
        Err(Error::Form)
    }
}
