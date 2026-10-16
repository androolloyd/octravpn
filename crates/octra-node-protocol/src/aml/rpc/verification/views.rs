// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{json_string, Document, Error, ReadError, ReadMode, Record, Result, Value};
fn parsed(raw: &[u8]) -> Result<Option<Document>> {
    match Document::parse_native(raw, ReadMode::Safe) {
        Ok(doc) => Ok(Some(doc)),
        Err(ReadError::Json { .. }) => Ok(None),
        Err(ReadError::Unavailable(error)) => Err(Error::unavailable(error)),
    }
}
pub fn abi_response(address: &[u8], record: Option<&Record>) -> Result<Option<Vec<u8>>> {
    let Some(record) = record else {
        return Ok(None);
    };
    let Some(doc) = parsed(&record.abi)? else {
        return Ok(None);
    };
    if matches!(
        doc.field(doc.root(), b"functions"),
        None | Some(Value::Null)
    ) {
        return Ok(None);
    }
    let mut out = b"{\"address\":".to_vec();
    json_string(&mut out, address);
    out.extend_from_slice(b",\"abi\":");
    out.extend_from_slice(&doc.write(doc.root(), false).map_err(Error::unavailable)?);
    out.push(b'}');
    Ok(Some(out))
}
pub fn source_response(record: Option<&Record>) -> Result<Vec<u8>> {
    let mut out = b"{\"source\":".to_vec();
    match record {
        None => out.extend_from_slice(b"null"),
        Some(record) => {
            match parsed(&record.source)? {
                Some(doc) if matches!(doc.root(), Value::Object(_)) => {
                    let files = doc.field(doc.root(), b"files");
                    if matches!(files, Some(Value::Object(_))) {
                        match (doc.field(doc.root(), b"main"), files) {
                            (Some(Value::String(main)), Some(files)) => {
                                if let Some(Value::String(source)) = doc.field(files, main) {
                                    json_string(&mut out, source);
                                    out.extend_from_slice(b",\"main\":");
                                    json_string(&mut out, main);
                                    out.extend_from_slice(b",\"files\":");
                                    out.extend_from_slice(
                                        &doc.write(files, false).map_err(Error::unavailable)?,
                                    );
                                } else {
                                    out.extend_from_slice(b"null");
                                }
                            }
                            _ => out.extend_from_slice(b"null"),
                        }
                    } else {
                        let source = match doc.field(doc.root(), b"main.aml") {
                            Some(Value::String(source)) => source.as_slice(),
                            _ => record.source.as_slice(),
                        };
                        json_string(&mut out, source);
                        out.extend_from_slice(b",\"files\":");
                        out.extend_from_slice(
                            &doc.write(doc.root(), false).map_err(Error::unavailable)?,
                        );
                    }
                }
                _ => json_string(&mut out, &record.source),
            }
            if let Some(raw) = &record.report {
                super::super::response::optional(&mut out, b"verification", raw)?;
            }
            if let Some(raw) = &record.certificate {
                super::super::response::optional(&mut out, b"certificate", raw)?;
            }
        }
    }
    out.push(b'}');
    Ok(out)
}
