// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Contract_rpc.verify compilation, hash matching and auxiliary record views.
//! A successful match is source metadata, not a formal proof or VM admission.
use super::{
    compiler, decode_base64, json_string, package, source, validate, AbiMode, BTreeMap, Document,
    Engine, Error, File, Output, ReadError, ReadMode, Result, SourceMode, Value, Version, STANDARD,
};
use crate::program_record::Record;
use sha2::{Digest, Sha256};
mod compile;
mod input;
mod views;
pub use input::{prepare, Material, Prepared};
pub use views::{abi_response, source_response};
pub struct Verified {
    address: Vec<u8>,
    record: Record,
    source_entry: bool,
}
impl Verified {
    pub fn address(&self) -> &[u8] {
        &self.address
    }
    pub fn record(&self) -> &Record {
        &self.record
    }
    pub fn publishable(&self) -> bool {
        self.source_entry
    }
    pub fn response(&self, published: bool) -> Result<Vec<u8>> {
        let mut out =
            format!("{{\"verified\":true,\"published\":{published},\"code_hash\":").into_bytes();
        json_string(&mut out, &self.record.code_hash);
        if let Some(raw) = &self.record.report {
            super::response::optional(&mut out, b"verification", raw)?;
        }
        if let Some(raw) = &self.record.certificate {
            super::response::optional(&mut out, b"certificate", raw)?;
        }
        out.push(b'}');
        Ok(out)
    }
}
fn source_record(material: &Material) -> Vec<u8> {
    let Some(files) = &material.files else {
        return material.source.clone();
    };
    let mut files: Vec<_> = files.iter().collect();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let mut out = vec![b'{'];
    if material.main != b"main.aml" {
        out.extend_from_slice(b"\"main\":");
        json_string(&mut out, &material.main);
        out.extend_from_slice(b",\"files\":{");
    }
    json_string(&mut out, &material.main);
    out.push(b':');
    json_string(&mut out, &material.source);
    for file in files {
        out.push(b',');
        json_string(&mut out, &file.path);
        out.push(b':');
        json_string(&mut out, &file.source);
    }
    out.push(b'}');
    if material.main != b"main.aml" {
        out.push(b'}');
    }
    out
}
pub fn verify(material: Material, source_entry: bool, stored_base64: &[u8]) -> Result<Verified> {
    let stored = decode_base64(stored_base64)
        .ok()
        .filter(|raw| STANDARD.encode(raw).as_bytes() == stored_base64)
        .ok_or_else(|| Error::compile(b"stored Program encoding is invalid"))?;
    let results = compile::candidates(&material, source_entry).map_err(|error| match error {
        Error::Rpc(fault) => {
            Error::compile([b"compile error: ".as_slice(), &fault.message].concat())
        }
        other @ Error::Unavailable(_) => other,
    })?;
    let hash = hex::encode(Sha256::digest(&stored)).into_bytes();
    let result = results
        .iter()
        .find(|result| {
            hex::encode(Sha256::digest(compile::executable(result))).as_bytes() == hash.as_slice()
        })
        .ok_or_else(|| {
            let compiled = results.first().map_or_else(Vec::new, |result| {
                hex::encode(Sha256::digest(compile::executable(result))).into_bytes()
            });
            Error::compile(
                [
                    b"bytecode mismatch: stored=".as_slice(),
                    &hash[..16],
                    b" compiled=",
                    &compiled[..compiled.len().min(16)],
                ]
                .concat(),
            )
        })?;
    let record = Record {
        source: source_record(&material),
        abi: result.abi_json.clone(),
        report: (!result.verification_json.is_empty()).then(|| result.verification_json.clone()),
        certificate: (!result.certificate_json.is_empty()).then(|| result.certificate_json.clone()),
        code_hash: hash,
    };
    Ok(Verified {
        address: material.address,
        record,
        source_entry,
    })
}
