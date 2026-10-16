// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Document, Error, Result, Value};
use std::collections::BTreeSet;
const SOURCE_BYTES: usize = 1_048_576;
const TOTAL_BYTES: usize = 2_097_152;
const FILES: usize = 64;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct File {
    pub path: Vec<u8>,
    pub source: Vec<u8>,
}
pub(super) fn valid_path(path: &[u8]) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && path[0] != b'/'
        && path
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
        && path
            .split(|byte| *byte == b'/')
            .all(|part| !part.is_empty() && part != b"." && part != b"..")
}
pub(super) fn read(doc: &Document, items: &[usize]) -> Result<Vec<File>> {
    read_with(doc, items, 0, None)
}
pub(super) fn read_with(
    doc: &Document,
    items: &[usize],
    source_len: usize,
    reserved: Option<&[u8]>,
) -> Result<Vec<File>> {
    if source_len > SOURCE_BYTES {
        return Err(Error::invalid("program source exceeds compile limit"));
    }
    if items.len() > FILES {
        return Err(Error::invalid("program file count exceeds compile limit"));
    }
    let mut files = vec![];
    let mut validation = Validation::new(source_len, reserved);
    for id in items {
        let item = doc.get(*id).expect("native JSON arena child");
        let count = match item {
            Value::Object(fields) => fields.len(),
            _ => 0,
        };
        let (Some(Value::String(path)), Some(Value::String(source))) =
            (doc.field(item, b"path"), doc.field(item, b"source"))
        else {
            return Err(Error::invalid("invalid program source file"));
        };
        if count != 2 || path.is_empty() {
            return Err(Error::invalid("invalid program source file"));
        }
        validation.next(path, source)?;
        files.push(File {
            path: path.clone(),
            source: source.clone(),
        });
    }
    Ok(files)
}
pub fn validate(source: &[u8], files: Option<&[File]>, reserved: Option<&[u8]>) -> Result<()> {
    if source.len() > SOURCE_BYTES {
        return Err(Error::invalid("program source exceeds compile limit"));
    }
    let Some(files) = files else {
        return Ok(());
    };
    if files.len() > FILES {
        return Err(Error::invalid("program file count exceeds compile limit"));
    }
    let mut validation = Validation::new(source.len(), reserved);
    for file in files {
        validation.next(&file.path, &file.source)?;
    }
    Ok(())
}
struct Validation<'a> {
    seen: BTreeSet<&'a [u8]>,
    total: usize,
    reserved: Option<&'a [u8]>,
}
impl<'a> Validation<'a> {
    fn new(total: usize, reserved: Option<&'a [u8]>) -> Self {
        Self {
            seen: BTreeSet::new(),
            total,
            reserved,
        }
    }
    fn next(&mut self, path: &'a [u8], source: &[u8]) -> Result<()> {
        if !valid_path(path) {
            return Err(Error::invalid("program source path is invalid"));
        }
        if self.reserved == Some(path) {
            return Err(Error::invalid("program source path is reserved"));
        }
        if !self.seen.insert(path) {
            return Err(Error::invalid("program source path is duplicated"));
        }
        if source.len() > SOURCE_BYTES {
            return Err(Error::invalid("program source file exceeds compile limit"));
        }
        self.total = self
            .total
            .checked_add(path.len())
            .and_then(|total| total.checked_add(source.len()))
            .ok_or_else(|| Error::invalid("program sources exceed compile limit"))?;
        if self.total > TOTAL_BYTES {
            return Err(Error::invalid("program sources exceed compile limit"));
        }
        Ok(())
    }
}
