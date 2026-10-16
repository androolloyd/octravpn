// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{parse_integer, wire, Arc, Constant, ConstantRow, Context, DecodeError, Result};
pub(super) struct Reader<'a> {
    raw: &'a [u8],
    pub at: usize,
}
impl<'a> Reader<'a> {
    pub(super) fn new(raw: &'a [u8]) -> Self {
        Self { raw, at: 0 }
    }
    fn take(&mut self, count: usize, error: DecodeError) -> Result<&'a [u8]> {
        if count > self.raw.len() - self.at {
            return Err(error);
        }
        let at = self.at;
        self.at += count;
        Ok(&self.raw[at..self.at])
    }
    fn u8(&mut self, error: DecodeError) -> Result<u8> {
        Ok(self.take(1, error)?[0])
    }
    pub(super) fn u16(&mut self, error: DecodeError) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.take(2, error)?.try_into().expect("two bytes"),
        ))
    }
    fn u32(&mut self, error: DecodeError) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4, error)?.try_into().expect("four bytes"),
        ))
    }
    pub(super) fn header(&mut self) -> Result<(usize, u32)> {
        if self.raw.len() > wire::MAX_BYTES {
            return Err(DecodeError::InputSize(self.raw.len()));
        }
        if self.raw.len() < 12 {
            return Err(DecodeError::Header);
        }
        if self.take(4, DecodeError::Header)? != b"OCTB" {
            return Err(DecodeError::Magic);
        }
        let version = self.u16(DecodeError::Header)?;
        if version != 1 {
            return Err(DecodeError::Version(version));
        }
        let constants = self.u16(DecodeError::Header)? as usize;
        if constants > wire::MAX_CONSTANTS {
            return Err(DecodeError::ConstantCount(constants));
        }
        let instructions = self.u32(DecodeError::Header)?;
        if instructions as usize > wire::MAX_INSTRUCTIONS {
            return Err(DecodeError::InstructionCount(instructions));
        }
        Ok((constants, instructions))
    }
    pub(super) fn claim_header(&mut self, open: bool) -> Result<(usize, u32)> {
        // Claim probes do not impose the full instruction-count decoder bound.
        if self.raw.len() > wire::MAX_BYTES || self.raw.len() < 12 {
            return Err(DecodeError::Header);
        }
        if self.take(4, DecodeError::Header)? != b"OCTB" || self.u16(DecodeError::Header)? != 1 {
            return Err(DecodeError::Header);
        }
        let constants = self.u16(DecodeError::Header)? as usize;
        let instructions = self.u32(DecodeError::Header)?;
        if constants > wire::MAX_CONSTANTS || open && instructions < 7 {
            return Err(DecodeError::Header);
        }
        Ok((constants, instructions))
    }
    pub(super) fn constants(
        &mut self,
        context: &mut Context<'_>,
        count: usize,
    ) -> Result<Vec<ConstantRow>> {
        let mut rows = Vec::with_capacity(count);
        for id in 0..count {
            let at = self.at;
            let tag = self.u8(DecodeError::ConstantHeader(id))?;
            let size = self.u32(DecodeError::ConstantHeader(id))? as usize;
            if size > wire::MAX_CONSTANT_BYTES {
                return Err(DecodeError::ConstantSize(id, wire::MAX_CONSTANT_BYTES));
            }
            let raw: Arc<[u8]> = self.take(size, DecodeError::ConstantData(id))?.into();
            let value = match tag {
                0 => {
                    let value = parse_integer(&raw).ok_or(DecodeError::ConstantValue(id))?;
                    if value.to_string().as_bytes() != raw.as_ref() {
                        return Err(DecodeError::ConstantValue(id));
                    }
                    Constant::Int(raw)
                }
                1 if raw.as_ref() == b"0" => Constant::Bool(false),
                1 if raw.as_ref() == b"1" => Constant::Bool(true),
                1 => return Err(DecodeError::ConstantValue(id)),
                2 => context
                    .data(&raw)
                    .map(Constant::Data)
                    .unwrap_or(Constant::Text(raw)),
                3 => Constant::Bytes(raw),
                _ => return Err(DecodeError::ConstantTag(id, tag)),
            };
            rows.push(ConstantRow {
                id,
                at,
                size: self.at - at,
                value,
            });
        }
        Ok(rows)
    }
    pub(super) fn expect(&mut self, bytes: &[u8]) -> Result<()> {
        if self.take(bytes.len(), DecodeError::Header)? == bytes {
            Ok(())
        } else {
            Err(DecodeError::Header)
        }
    }
    pub(super) fn word(&mut self, value: u16) -> Result<()> {
        if self.u16(DecodeError::Header)? == value {
            Ok(())
        } else {
            Err(DecodeError::Header)
        }
    }
    pub(super) fn wide(&mut self, value: u32) -> Result<()> {
        if self.u32(DecodeError::Header)? == value {
            Ok(())
        } else {
            Err(DecodeError::Header)
        }
    }
}
