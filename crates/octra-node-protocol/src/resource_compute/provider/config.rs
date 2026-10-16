// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{parse_int64, refused, Error, Result};
use crate::{native_integer::parse_int63, resource_compute::capability::Accelerator};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub accelerator: Accelerator,
    pub lanes: i64,
    pub memory_bytes: i64,
    pub max_request_bytes: i64,
    pub max_response_bytes: i64,
    pub timeout_seconds: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Config {
    Disabled,
    Enabled(Limits),
}
fn trim(raw: &[u8]) -> &[u8] {
    let space = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 12);
    let start = raw
        .iter()
        .position(|byte| !space(byte))
        .unwrap_or(raw.len());
    let end = raw
        .iter()
        .rposition(|byte| !space(byte))
        .map_or(start, |n| n + 1);
    &raw[start..end]
}
fn invalid(name: &str) -> Error {
    refused(format!("invalid {name}").as_bytes())
}
fn number(
    getenv: &mut impl FnMut(&str) -> Option<Vec<u8>>,
    name: &str,
    default: i64,
    min: i64,
    max: i64,
    wide: bool,
) -> Result<i64> {
    let Some(raw) = getenv(name) else {
        return Ok(default);
    };
    let value = if wide {
        parse_int64(trim(&raw))
    } else {
        parse_int63(trim(&raw))
    };
    value
        .filter(|value| (min..=max).contains(value))
        .ok_or_else(|| invalid(name))
}
impl Config {
    pub fn from_inputs(
        cli_enabled: bool,
        mut getenv: impl FnMut(&str) -> Option<Vec<u8>>,
    ) -> Result<Self> {
        let enabled = match getenv("OCTRA_COMPUTE_PROVIDER") {
            None => false,
            Some(raw) => match trim(&raw).to_ascii_lowercase().as_slice() {
                b"1" | b"true" | b"yes" | b"on" => true,
                b"0" | b"false" | b"no" | b"off" => false,
                _ => return Err(invalid("OCTRA_COMPUTE_PROVIDER")),
            },
        };
        if !(cli_enabled || enabled) {
            return Ok(Self::Disabled);
        }
        let accelerator = match getenv("OCTRA_COMPUTE_ACCELERATOR") {
            None => Accelerator::Cpu,
            Some(raw) => match trim(&raw).to_ascii_lowercase().as_slice() {
                b"cpu" => Accelerator::Cpu,
                b"cuda" => Accelerator::Cuda,
                b"metal" => Accelerator::Metal,
                b"rocm" => Accelerator::Rocm,
                _ => return Err(invalid("OCTRA_COMPUTE_ACCELERATOR")),
            },
        };
        let lanes = number(&mut getenv, "OCTRA_COMPUTE_LANES", 1, 1, 4, false)?;
        let memory_bytes = number(
            &mut getenv,
            "OCTRA_COMPUTE_MEMORY_BYTES",
            4_294_967_296,
            1_073_741_824,
            1_099_511_627_776,
            true,
        )?;
        let max_request_bytes = number(
            &mut getenv,
            "OCTRA_COMPUTE_MAX_REQUEST_BYTES",
            65_536,
            1024,
            1_048_576,
            false,
        )?;
        let max_response_bytes = number(
            &mut getenv,
            "OCTRA_COMPUTE_MAX_RESPONSE_BYTES",
            262_144,
            1024,
            1_048_576,
            false,
        )?;
        let timeout_seconds = number(
            &mut getenv,
            "OCTRA_COMPUTE_TIMEOUT_SEC",
            300,
            1,
            1800,
            false,
        )?;
        Ok(Self::Enabled(Limits {
            accelerator,
            lanes,
            memory_bytes,
            max_request_bytes,
            max_response_bytes,
            timeout_seconds,
        }))
    }
}
