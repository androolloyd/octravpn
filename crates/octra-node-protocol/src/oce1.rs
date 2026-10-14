// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! OCE1 binary framing. Strings are bytes; 32-bit lengths are signed on decode.
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(Vec<u8>);

impl Error {
    pub fn new(message: impl Into<Vec<u8>>) -> Self {
        Self(message.into())
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}
impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self::new(value.as_bytes())
    }
}
impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::new(value.into_bytes())
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}
impl std::error::Error for Error {}

#[derive(Default)]
pub struct Writer {
    bytes: Vec<u8>,
}
impl Writer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn put_raw(&mut self, value: &[u8]) -> Result<(), Error> {
        self.bytes
            .try_reserve(value.len())
            .map_err(|_| Error::from("OCE1: allocation unavailable"))?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    pub fn put_u8(&mut self, value: u8) -> Result<(), Error> {
        self.put_raw(&[value])
    }
    pub fn put_u16(&mut self, value: u16) -> Result<(), Error> {
        self.put_raw(&value.to_be_bytes())
    }
    pub fn put_u32(&mut self, value: u32) -> Result<(), Error> {
        self.put_raw(&value.to_be_bytes())
    }
    pub fn put_u64(&mut self, value: u64) -> Result<(), Error> {
        self.put_raw(&value.to_be_bytes())
    }
    pub fn put_bool(&mut self, value: bool) -> Result<(), Error> {
        self.put_u8(u8::from(value))
    }
    pub fn put_bytes(&mut self, value: &[u8]) -> Result<(), Error> {
        self.put_u32(value.len() as u32)?;
        self.put_raw(value)
    }
    pub fn put_hash32(&mut self, value: &[u8]) -> Result<(), Error> {
        self.put_raw(&hash32_bytes(value)?)
    }
    pub fn put_sig64(&mut self, value: &[u8]) -> Result<(), Error> {
        if value.len() != 64 {
            return Err("sig64 length must be 64".into());
        }
        self.put_raw(value)
    }
    pub fn put_option<T>(
        &mut self,
        value: Option<&T>,
        write: impl FnOnce(&mut Self, &T) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match value {
            None => self.put_u8(0),
            Some(value) => {
                self.put_u8(1)?;
                write(self, value)
            }
        }
    }
    pub fn put_list<T>(
        &mut self,
        values: &[T],
        mut write: impl FnMut(&mut Self, &T) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.put_u32(values.len() as u32)?;
        for value in values {
            write(self, value)?;
        }
        Ok(())
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

pub fn hash32_bytes(value: &[u8]) -> Result<[u8; 32], Error> {
    if value.len() == 32 {
        return Ok(value.try_into().unwrap());
    }
    if value.len() != 64 {
        return Err("hash32 hex length must be 64".into());
    }
    let mut output = [0; 32];
    fn nibble(value: u8) -> Result<u8, Error> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err("hash32 contains non-hex characters".into()),
        }
    }
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (nibble(value[index * 2])? << 4) | nibble(value[index * 2 + 1])?;
    }
    Ok(output)
}

pub struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
    pub const fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
    pub fn get_raw(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if count > self.remaining() {
            return Err(format!("OCE1: need {count} bytes, have {}", self.remaining()).into());
        }
        let value = &self.data[self.position..self.position + count];
        self.position += count;
        Ok(value)
    }
    pub fn get_u8(&mut self) -> Result<u8, Error> {
        Ok(self.get_raw(1)?[0])
    }
    pub fn get_u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.get_raw(2)?.try_into().unwrap()))
    }
    pub fn get_u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.get_raw(4)?.try_into().unwrap()))
    }
    pub fn get_u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.get_raw(8)?.try_into().unwrap()))
    }
    pub fn get_bool(&mut self) -> Result<bool, Error> {
        match self.get_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("OCE1: bad bool tag".into()),
        }
    }
    pub fn get_bytes_bounded(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        let count = self.get_u32()? as i32;
        if count < 0 || count as usize > maximum {
            return Err("OCE1: bytes len out of range".into());
        }
        self.get_raw(count as usize)
    }
    pub fn get_bytes(&mut self) -> Result<&'a [u8], Error> {
        self.get_bytes_bounded(10_000_000)
    }
    pub fn get_hash32(&mut self) -> Result<[u8; 32], Error> {
        Ok(self.get_raw(32)?.try_into().unwrap())
    }
    pub fn get_sig64(&mut self) -> Result<[u8; 64], Error> {
        Ok(self.get_raw(64)?.try_into().unwrap())
    }
    pub fn get_option<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        match self.get_u8()? {
            0 => Ok(None),
            1 => read(self).map(Some),
            _ => Err("OCE1: bad option tag".into()),
        }
    }
    pub fn get_list<T>(
        &mut self,
        maximum: usize,
        mut read: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let count = self.get_u32()? as i32;
        if count < 0 || count as usize > maximum {
            return Err("OCE1: list count out of range".into());
        }
        let mut output = Vec::new();
        // Grow as values are decoded: an untrusted count cannot allocate an empty million-item list.
        for _ in 0..count {
            let value = read(self)?;
            output
                .try_reserve(1)
                .map_err(|_| Error::from("OCE1: allocation unavailable"))?;
            output.push(value);
        }
        Ok(output)
    }
    pub fn finish(self) -> Result<(), Error> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(format!("OCE1: {} trailing bytes", self.remaining()).into())
        }
    }
}
