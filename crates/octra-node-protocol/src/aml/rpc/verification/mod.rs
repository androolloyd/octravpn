// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Contract_rpc.verify compilation, hash matching and auxiliary record views.
//! A successful match is source metadata, not a formal proof or VM admission.
use super::{
    compiler, decode_base64, json_string, package, source, validate, AbiMode, BTreeMap, Document,
    Engine, Error, File, Output, ReadError, ReadMode, Result, SourceMode, Value, Version, STANDARD,
};
use crate::program_record::{source as records, Record};
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
    publication: Option<records::Sources>,
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
    pub fn response_with(
        &self,
        published: bool,
        committed: bool,
        metered: bool,
    ) -> Result<Vec<u8>> {
        let mut out = format!("{{\"committed\":{committed},").into_bytes();
        let response = self.response(published)?;
        out.extend_from_slice(&response[1..response.len() - 1]);
        if let Some(sources) = &self.publication {
            if !metered
                || !matches!(
                    sources.compiler.as_slice(),
                    b"historical" | b"package_historical"
                )
            {
                out.extend_from_slice(b",\"publication\":{\"requires_rule\":\"program_records\",\"op_type\":\"upgrade\",\"to\":");
                json_string(&mut out, &self.address);
                out.extend_from_slice(b",\"amount\":\"0\",\"ou\":");
                json_string(&mut out, records::fee(&self.record).to_string().as_bytes());
                out.extend_from_slice(b",\"message\":");
                json_string(
                    &mut out,
                    &crate::program_upgrade::source_message(&self.record.code_hash),
                );
                out.extend_from_slice(b",\"encrypted_data\":");
                json_string(&mut out, STANDARD.encode(sources.encode()).as_bytes());
                out.push(b'}');
            }
        }
        out.push(b'}');
        Ok(out)
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
fn record_error(error: records::Error) -> Error {
    match error {
        records::Error::Invalid(raw) => Error::compile(raw),
        records::Error::Unavailable(raw) => Error::Unavailable(raw),
    }
}
pub fn verify(
    mut material: Material,
    source_entry: bool,
    stored_base64: &[u8],
) -> Result<Verified> {
    if material.main == b"main.aml" && material.files.as_ref().is_some_and(Vec::is_empty) {
        material.files = None;
    }
    let stored = decode_base64(stored_base64)
        .ok()
        .filter(|raw| STANDARD.encode(raw).as_bytes() == stored_base64)
        .ok_or_else(|| Error::compile(b"stored Program encoding is invalid"))?;
    let stored_image = records::executable(&stored).map_err(record_error)?;
    let results = compile::candidates(&material, source_entry).map_err(|error| match error {
        Error::Rpc(fault) => {
            Error::compile([b"compile error: ".as_slice(), &fault.message].concat())
        }
        other @ Error::Unavailable(_) => other,
    })?;
    let hash = hex::encode(Sha256::digest(&stored)).into_bytes();
    let mut matching = results.iter().find(|row| row.code == stored);
    if matching.is_none() && !source_entry {
        for row in &results {
            match records::executable(&row.code) {
                Ok(image) if image == stored_image => {
                    matching = Some(row);
                    break;
                }
                Err(records::Error::Unavailable(reason)) => return Err(Error::Unavailable(reason)),
                _ => (),
            }
        }
    }
    let result = matching.ok_or_else(|| {
        let compiled = results.first().map_or_else(Vec::new, |row| {
            hex::encode(Sha256::digest(&row.code)).into_bytes()
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
    let files = material.sources()?;
    let record = records::make(
        &records::source_text(&material.main, &files),
        &stored,
        &result.result,
    );
    let mut publication = None;
    for &(compiler, loops) in records::PROFILES {
        let sources = records::Sources {
            main: material.main.clone(),
            files: files.clone(),
            compiler: compiler.to_vec(),
            loops,
        };
        let metered = !matches!(compiler, b"historical" | b"package_historical");
        match sources.verify(metered, source_entry, &stored) {
            Ok(checked) if checked.matches_verification(&record) => {
                publication = Some(sources);
                break;
            }
            Err(records::Error::Unavailable(reason)) => return Err(Error::Unavailable(reason)),
            _ => (),
        }
    }
    Ok(Verified {
        address: material.address,
        record,
        source_entry,
        publication,
    })
}
