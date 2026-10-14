// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Constant, ConstantCell, Cursor, Error, MAX_CONSTANT_BYTES};
use crate::{native_integer::parse_integer, transaction::decode_base64};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::{BigInt, Sign};

const STATE: &[u8] = b"\0OCTRA_STATE_V1\0";
const PROOF: &[u8] = b"\0OCTRA_AML_PROOF\0";
const EMISSION: &[u8] = b"\0OCTRA_AML_EMISSION\0";
const VEIL: &[u8] = b"\0OCTRA_AML_VEIL\0";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StorageKind {
    Int = 0,
    Bool = 1,
    String = 2,
    Bytes = 3,
    Bytes32 = 4,
    U64 = 5,
    U128 = 6,
    U256 = 7,
    Addr = 8,
}
impl StorageKind {
    fn decode(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Int,
            1 => Self::Bool,
            2 => Self::String,
            3 => Self::Bytes,
            4 => Self::Bytes32,
            5 => Self::U64,
            6 => Self::U128,
            7 => Self::U256,
            8 => Self::Addr,
            _ => return None,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emission {
    Lowered,
    Specialized,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Veil {
    pub count: BigInt,
    pub depth: BigInt,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metadata {
    pub state: Option<Vec<(Vec<u8>, StorageKind)>>,
    pub proof: Option<Vec<u8>>,
    pub emission: Option<Emission>,
    pub veil: Option<Veil>,
}
fn field<'a>(
    consts: &'a [ConstantCell],
    prefix: &[u8],
    name: &str,
) -> Result<Option<&'a [u8]>, Error> {
    let mut found = None;
    for cell in consts {
        if let Constant::Str(v) = &cell.value {
            if v.starts_with(prefix) {
                if found.is_some() {
                    return Err(Error::message(format!("OCTB {name} is repeated")));
                }
                found = Some(v.as_ref());
            }
        }
    }
    Ok(found)
}
fn base64_body(value: &[u8], prefix: &[u8], name: &str) -> Result<Vec<u8>, Error> {
    let body = &value[prefix.len()..];
    let fail = || Error::message(format!("OCTB {name} is invalid"));
    let raw = decode_base64(body).map_err(|_| fail())?;
    if STANDARD.encode(&raw).as_bytes() != body {
        return Err(fail());
    }
    Ok(raw)
}
fn state_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 65_535
        && (name[0].is_ascii_alphabetic() || name[0] == b'_')
        && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}
fn state_encode(rows: &[(Vec<u8>, StorageKind)]) -> Result<Vec<u8>, Error> {
    if rows.len() > 4096 {
        return Err(Error::InvalidArgument("state schema exceeds capacity"));
    }
    let mut rows: Vec<_> = rows.iter().collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut previous: Option<&[u8]> = None;
    let mut raw = (rows.len() as u16).to_le_bytes().to_vec();
    for (name, kind) in rows {
        if !state_name(name) || previous == Some(name.as_slice()) {
            return Err(Error::InvalidArgument("state schema is invalid"));
        }
        previous = Some(name);
        raw.extend((name.len() as u16).to_le_bytes());
        raw.extend(name);
        raw.push(*kind as u8);
    }
    let mut out = STATE.to_vec();
    out.extend(STANDARD.encode(raw).bytes());
    if out.len() > MAX_CONSTANT_BYTES {
        return Err(Error::InvalidArgument("state schema exceeds byte capacity"));
    }
    Ok(out)
}
fn state_decode(value: &[u8]) -> Result<Vec<(Vec<u8>, StorageKind)>, Error> {
    let fail = || Error::message("OCTB state schema is invalid");
    let raw = base64_body(value, STATE, "state schema")?;
    let mut r = Cursor { raw: &raw, at: 0 };
    let count = r.u16().map_err(|_| fail())?;
    if count > 4096 {
        return Err(fail());
    }
    let mut rows = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let size = r.u16().map_err(|_| fail())?;
        let name = r.take(size.into()).map_err(|_| fail())?.to_vec();
        let kind = StorageKind::decode(r.u8().map_err(|_| fail())?).ok_or_else(fail)?;
        rows.push((name, kind));
    }
    if r.at != raw.len() || state_encode(&rows).map_err(|_| fail())? != value {
        return Err(fail());
    }
    Ok(rows)
}
fn veil_encode(veil: &Veil) -> Result<Vec<u8>, Error> {
    let fail = || Error::InvalidArgument("AML veil is invalid");
    if veil.count.sign() == Sign::Minus
        || veil.depth.sign() == Sign::Minus
        || (veil.count.sign() == Sign::NoSign && veil.depth.sign() != Sign::NoSign)
    {
        return Err(fail());
    }
    let body = format!("{}:{}", veil.count, veil.depth);
    if body.len() > 64 {
        return Err(fail());
    }
    let mut out = VEIL.to_vec();
    out.extend(body.bytes());
    Ok(out)
}
fn veil_decode(value: &[u8]) -> Result<Veil, Error> {
    let fail = || Error::message("OCTB AML veil is invalid");
    let body = &value[VEIL.len()..];
    if body.len() > 64 {
        return Err(fail());
    }
    let mut halves = body.split(|b| *b == b':');
    let count = halves.next().unwrap();
    let depth = halves.next().ok_or_else(fail)?;
    if halves.next().is_some() {
        return Err(fail());
    }
    let veil = Veil {
        count: parse_integer(count).ok_or_else(fail)?,
        depth: parse_integer(depth).ok_or_else(fail)?,
    };
    if veil_encode(&veil).map_err(|_| fail())? != value {
        return Err(fail());
    }
    Ok(veil)
}
impl Metadata {
    pub(super) fn decode(consts: &[ConstantCell]) -> Result<Self, Error> {
        // The native tuple is evaluated right to left. Preserve its failure priority.
        let veil = field(consts, VEIL, "AML veil")?
            .map(veil_decode)
            .transpose()?;
        let emission = field(consts, EMISSION, "AML emission")?
            .map(|v| match &v[EMISSION.len()..] {
                b"lowered" => Ok(Emission::Lowered),
                b"specialized" => Ok(Emission::Specialized),
                _ => Err(Error::message("OCTB AML emission is invalid")),
            })
            .transpose()?;
        let proof = field(consts, PROOF, "AML proof")?
            .map(|v| base64_body(v, PROOF, "AML proof"))
            .transpose()?;
        let state = field(consts, STATE, "state schema")?
            .map(state_decode)
            .transpose()?;
        Ok(Self {
            state,
            proof,
            emission,
            veil,
        })
    }
    pub(super) fn constants(&self) -> Result<Vec<Vec<u8>>, Error> {
        let mut out = Vec::new();
        if let Some(rows) = &self.state {
            out.push(state_encode(rows)?);
        }
        if let Some(proof) = &self.proof {
            let mut value = PROOF.to_vec();
            value.extend(STANDARD.encode(proof).bytes());
            if value.len() > MAX_CONSTANT_BYTES {
                return Err(Error::InvalidArgument("AML proof exceeds byte capacity"));
            }
            out.push(value);
        }
        if let Some(emission) = self.emission {
            let mut value = EMISSION.to_vec();
            value.extend(match emission {
                Emission::Lowered => b"lowered".as_slice(),
                Emission::Specialized => b"specialized",
            });
            out.push(value);
        }
        if let Some(veil) = &self.veil {
            out.push(veil_encode(veil)?);
        }
        Ok(out)
    }
}
