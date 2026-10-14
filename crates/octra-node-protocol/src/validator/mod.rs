// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Bonded validator admission and persistent registry, matching the adopted node.
pub mod admission;
pub mod config;
pub mod evidence;
pub mod policy;
pub mod ready;
pub mod registry;
pub mod set_fold;
pub mod update;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub String);
impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}
impl From<String> for Error {
    fn from(value: String) -> Self {
        Self(value)
    }
}
pub(crate) fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value);
}
