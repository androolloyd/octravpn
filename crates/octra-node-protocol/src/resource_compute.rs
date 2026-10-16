// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted resource-compute domains and evidence. These types do not grant
//! ledger mutation or replace epoch finality authentication.
pub mod bill;
pub mod call;
pub mod capability;
pub mod certificate;
pub mod funding;
pub mod graph;
pub mod message;
pub mod provider;
pub mod read;
pub mod record;
pub mod request;
pub mod selection;
pub mod wire;
use crate::{
    network::domain_hash,
    oce1::{self, Writer},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Rejected(Vec<u8>),
    Unavailable(Vec<u8>),
}
impl Error {
    pub fn rejected(reason: impl AsRef<[u8]>) -> Self {
        Self::Rejected(reason.as_ref().to_vec())
    }
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Rejected(reason) | Self::Unavailable(reason) => reason,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.as_bytes()))
    }
}
impl std::error::Error for Error {}
impl From<oce1::Error> for Error {
    fn from(error: oce1::Error) -> Self {
        if error.as_bytes() == b"OCE1: allocation unavailable" {
            Self::Unavailable(error.into_bytes())
        } else {
            Self::Rejected(error.into_bytes())
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn hash(
    domain: &[u8],
    put: impl FnOnce(&mut Writer) -> std::result::Result<(), oce1::Error>,
) -> Result<[u8; 32]> {
    let mut out = Writer::new();
    put(&mut out)?;
    Ok(domain_hash(domain, &out.into_bytes()))
}
pub(crate) fn nonempty(value: &[u8], maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum
}
pub(crate) fn protected(evaluate: impl FnOnce() -> bool) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(evaluate)).unwrap_or(false)
}
/// OCE1 checks trailing bytes even when the decoder returns an ordinary
/// refusal. Operational exceptions bypass that final check upstream.
pub(crate) fn frame<T>(
    raw: &[u8],
    malformed: &[u8],
    parse: impl FnOnce(&mut oce1::Reader<'_>) -> std::result::Result<Result<T>, oce1::Error>,
) -> Result<T> {
    let project = |error: oce1::Error| {
        let error = Error::from(error);
        if error.is_operational() {
            error
        } else {
            Error::rejected(malformed)
        }
    };
    let mut input = oce1::Reader::new(raw);
    let value = parse(&mut input).map_err(project)?;
    if value.as_ref().is_err_and(Error::is_operational) {
        return value;
    }
    input.finish().map_err(project)?;
    value
}
