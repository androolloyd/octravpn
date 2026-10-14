// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! OCTB instruction images. This wire decoder preserves the prior/active rules;
//! accepting an image is separate from admission, proof checking and execution.
pub mod admission;
mod instruction;
mod metadata;
#[cfg(test)]
mod tests;
pub mod work;
use crate::native_integer::parse_integer;
pub use instruction::Instruction;
pub use metadata::{Emission, Metadata, StorageKind, Veil};
use num_bigint::BigInt;
use std::{collections::HashMap, sync::Arc};

pub const MAX_CONSTANTS: usize = 32_768;
pub const MAX_INSTRUCTIONS: usize = 1_048_576;
pub const MAX_CONSTANT_BYTES: usize = 16_777_216;
pub const MAX_BYTES: usize = 67_108_864;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("Invalid_argument(\"{0}\")")]
    InvalidArgument(&'static str),
}
impl Error {
    fn message(text: impl Into<String>) -> Self {
        Self::Message(text.into())
    }
}

/// Immutable values are shared across repeated constant references, as in native
/// lazy constant decoding. A million references must not duplicate a large integer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Int(Arc<BigInt>),
    Bool(bool),
    Str(Arc<[u8]>),
    Bytes(Arc<[u8]>),
    Addr(Arc<[u8]>),
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Constant {
    Int(Arc<[u8]>),
    Bool(bool),
    Str(Arc<[u8]>),
    Bytes(Arc<[u8]>),
    Addr(Arc<[u8]>),
}
impl Constant {
    pub fn tag(&self) -> u8 {
        match self {
            Self::Int(_) => 0,
            Self::Bool(_) => 1,
            Self::Str(_) => 2,
            Self::Bytes(_) => 3,
            Self::Addr(_) => 4,
        }
    }
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Int(v) | Self::Str(v) | Self::Bytes(v) | Self::Addr(v) => v,
            Self::Bool(true) => b"1",
            Self::Bool(false) => b"0",
        }
    }
    fn from_value(value: &Value) -> Self {
        match value {
            Value::Int(v) => Self::Int(v.to_string().into_bytes().into()),
            Value::Bool(v) => Self::Bool(*v),
            Value::Str(v) => Self::Str(v.clone()),
            Value::Bytes(v) => Self::Bytes(v.clone()),
            Value::Addr(v) => Self::Addr(v.clone()),
        }
    }
    fn value(&self) -> Result<Arc<Value>, Error> {
        Ok(Arc::new(match self {
            Self::Int(raw) => Value::Int(Arc::new(
                parse_integer(raw)
                    .ok_or(Error::InvalidArgument("Z.of_substring_base: invalid digit"))?,
            )),
            Self::Bool(v) => Value::Bool(*v),
            Self::Str(v) => Value::Str(v.clone()),
            Self::Bytes(v) => Value::Bytes(v.clone()),
            Self::Addr(v) => Value::Addr(v.clone()),
        }))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstantCell {
    pub id: usize,
    pub at: usize,
    pub size: usize,
    pub tag: u8,
    pub data: Arc<[u8]>,
    pub value: Constant,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeCell {
    pub pc: usize,
    pub at: usize,
    pub size: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    pub consts: Vec<ConstantCell>,
    pub cells: Vec<CodeCell>,
    pub text_at: usize,
    pub metadata: Metadata,
    pub code: Vec<Instruction>,
}
struct Cursor<'a> {
    raw: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if count > self.raw.len() - self.at {
            return Err(Error::InvalidArgument("index out of bounds"));
        }
        let at = self.at;
        self.at += count;
        Ok(&self.raw[at..self.at])
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
}
struct Constants<'a> {
    raw: &'a [ConstantCell],
    values: Vec<Option<Arc<Value>>>,
    active: bool,
    pc: usize,
}
impl Constants<'_> {
    fn index(&self, ci: u16) -> Result<usize, Error> {
        let ci = usize::from(ci);
        if ci >= self.raw.len() {
            return Err(if self.active {
                Error::message(format!("constant reference {ci} at pc {}", self.pc))
            } else {
                Error::InvalidArgument("index out of bounds")
            });
        }
        Ok(ci)
    }
    fn value(&mut self, ci: u16) -> Result<Arc<Value>, Error> {
        let ci = self.index(ci)?;
        if let Some(value) = &self.values[ci] {
            return Ok(value.clone());
        }
        let value = self.raw[ci].value.value()?;
        self.values[ci] = Some(value.clone());
        Ok(value)
    }
    fn string(&self, ci: u16) -> Result<Arc<[u8]>, Error> {
        Ok(match &self.raw[self.index(ci)?].value {
            Constant::Str(v) => v.clone(),
            _ => Arc::from([]),
        })
    }
}
impl Image {
    pub fn decode(raw: &[u8], active: bool) -> Result<Self, Error> {
        if raw.len() > MAX_BYTES {
            return Err(Error::message(format!(
                "OCTB too large: {} bytes (max {MAX_BYTES})",
                raw.len()
            )));
        }
        if raw.len() < 12 {
            return Err(Error::message("OCTB too short"));
        }
        if &raw[..4] != b"OCTB" {
            return Err(Error::message("bad OCTB magic"));
        }
        let mut r = Cursor { raw, at: 4 };
        let version = r.u16()?;
        if version != 1 {
            return Err(Error::message(format!(
                "unsupported OCTB version: {version}"
            )));
        }
        let count = usize::from(r.u16()?);
        let instruction_count = r.u32()? as usize;
        if count > MAX_CONSTANTS {
            return Err(Error::message(format!("OCTB too many constants: {count}")));
        }
        if instruction_count > MAX_INSTRUCTIONS {
            return Err(Error::message(format!(
                "OCTB too many instructions: {instruction_count}"
            )));
        }
        let mut consts = Vec::with_capacity(count);
        for id in 0..count {
            let at = r.at;
            if raw.len() - at < 5 {
                return Err(Error::message("OCTB truncated constant header"));
            }
            let tag = r.u8()?;
            let size = r.u32()? as usize;
            if size > MAX_CONSTANT_BYTES {
                return Err(Error::message(format!("OCTB constant too large: {size}")));
            }
            if size > raw.len() - r.at {
                return Err(Error::message("OCTB truncated constant data"));
            }
            let data: Arc<[u8]> = r.take(size)?.into();
            let value = match tag {
                0 => Constant::Int(data.clone()),
                1 => Constant::Bool(data.as_ref() == b"1"),
                2 => Constant::Str(data.clone()),
                3 => Constant::Bytes(data.clone()),
                4 => Constant::Addr(data.clone()),
                _ => return Err(Error::message("bad const tag")),
            };
            consts.push(ConstantCell {
                id,
                at,
                size: 5 + size,
                tag,
                data,
                value,
            });
        }
        let metadata = if active {
            Metadata::decode(&consts)?
        } else {
            Metadata::default()
        };
        let text_at = r.at;
        let mut code = Vec::with_capacity(instruction_count);
        let mut cells = Vec::with_capacity(instruction_count);
        let mut pool = Constants {
            raw: &consts,
            values: vec![None; consts.len()],
            active,
            pc: 0,
        };
        for pc in 0..instruction_count {
            let at = r.at;
            let truncated = || {
                Error::message(if active {
                    format!("truncated instruction at pc {pc}")
                } else {
                    "OCTB truncated instruction stream".into()
                })
            };
            if at >= raw.len() {
                return Err(truncated());
            }
            pool.pc = pc;
            let instr = Instruction::decode(&mut r, &mut pool).map_err(|error| match error {
                Error::InvalidArgument(_) if active => truncated(),
                error => error,
            })?;
            code.push(instr);
            cells.push(CodeCell {
                pc,
                at,
                size: r.at - at,
            });
        }
        if r.at != raw.len() {
            return Err(Error::message(if active {
                format!("OCTB trailing bytes: {}", raw.len() - r.at)
            } else {
                "OCTB trailing bytes".into()
            }));
        }
        Ok(Self {
            consts,
            cells,
            text_at,
            metadata,
            code,
        })
    }
}
#[derive(Default)]
struct Pool {
    entries: Vec<Constant>,
    index: HashMap<Constant, usize>,
}
impl Pool {
    fn intern(&mut self, value: Constant) -> u16 {
        if let Some(index) = self.index.get(&value) {
            return *index as u16;
        }
        let index = self.entries.len();
        self.index.insert(value.clone(), index);
        self.entries.push(value);
        index as u16
    }
}
/// Native canonical emission: metadata comes first, values are interned in
/// instruction order, and referenced integers/booleans use their canonical form.
/// The legacy writer truncates its constant-count header; admission is separate.
pub fn encode(code: &[Instruction], metadata: &Metadata, active: bool) -> Result<Vec<u8>, Error> {
    let mut pool = Pool::default();
    for value in metadata.constants()? {
        pool.intern(Constant::Str(value.into()));
    }
    let mut text = Vec::new();
    for instruction in code {
        instruction.encode(&mut text, &mut pool);
    }
    if active && pool.entries.len() > MAX_CONSTANTS {
        return Err(Error::InvalidArgument("constant count exceeds capacity"));
    }
    let mut out = b"OCTB\x01\x00".to_vec();
    out.extend((pool.entries.len() as u16).to_le_bytes());
    out.extend((code.len() as u32).to_le_bytes());
    for value in pool.entries {
        out.push(value.tag());
        out.extend((value.data().len() as u32).to_le_bytes());
        out.extend(value.data());
    }
    out.extend(text);
    Ok(out)
}
